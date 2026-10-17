package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type result struct {
	code           int
	stdout, stderr string
}

// run は、cli.Run を、stdin と環境変数を与えて実行する。
func run(t testing.TB, stdin string, env map[string]string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb, func(k string) string { return env[k] })
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// noLeak は、stderr に、元の値が出ていないことを確認する(受け入れ基準)。
func noLeak(t testing.TB, r result, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(r.stderr, v) {
			t.Errorf("stderr contains the original value %q:\n%s", v, r.stderr)
		}
	}
}

func listDir(t testing.TB, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

const keyEnv = "LOGSCRUB_KEY"

// ---- 基本(受け入れ基準) ----

func TestMaskFromStdin(t *testing.T) {
	r := run(t, "taro@example.com 192.168.0.1\n", nil, "mask")
	if r.code != 0 || r.stdout != "<email_1> <ipv4_private_1>\n" || r.stderr != "" {
		t.Errorf("%+v", r)
	}
}

func TestMaskDashMeansStdin(t *testing.T) {
	r := run(t, "a@x.com\n", nil, "mask", "-")
	if r.code != 0 || r.stdout != "<email_1>\n" {
		t.Errorf("%+v", r)
	}
}

func TestMaskLabelsAndDeterminism(t *testing.T) {
	in := "a@x.com b@x.com a@x.com 10.0.0.1 203.0.113.5 192.168.0.1\n"
	a := run(t, in, nil, "mask")
	b := run(t, in, nil, "mask")
	want := "<email_1> <email_2> <email_1> <ipv4_private_1> <ipv4_global_1> <ipv4_private_2>\n"
	if a.stdout != want || a != b {
		t.Errorf("got %+v, want stdout %q", a, want)
	}
}

func TestMaskIsIdempotent(t *testing.T) {
	in := "taro@example.com 192.168.0.1\npassword=abc123&user=x\nAuthorization: Bearer xxxxx\n" +
		`"api_key": "abc def"` + "\n::ffff:10.0.0.1 https://user:pass@10.0.0.1/\n"
	for name, args := range map[string][]string{
		"default":       {"mask"},
		"custom format": {"mask", "--mask-format", "[{type}-{n}]"},
	} {
		once := run(t, in, nil, args...)
		twice := run(t, once.stdout, nil, args...)
		if once.code != 0 || twice.code != 0 || twice.stdout != once.stdout {
			t.Errorf("%s: mask(mask(x)) != mask(x)\n once:  %q\n twice: %q", name, once.stdout, twice.stdout)
		}
	}
	// 受け入れ基準の例
	for _, in := range []string{"password=<secret_1>\n", "Authorization: Bearer <secret_1>\n"} {
		if r := run(t, in, nil, "mask"); r.stdout != in {
			t.Errorf("mask(%q) = %q", in, r.stdout)
		}
	}
	if r := run(t, "x=[email-1] y=[secret-2]\n", nil, "mask", "--mask-format", "[{type}-{n}]"); r.stdout != "x=[email-1] y=[secret-2]\n" {
		t.Errorf("custom format re-run: %q", r.stdout)
	}
}

func TestMaskJapaneseCRLFAndNoFinalNewline(t *testing.T) {
	cases := map[string]string{
		"ユーザー taro@example.com が 192.168.0.1 から接続\n": "ユーザー <email_1> が <ipv4_private_1> から接続\n",
		"a@x.com\r\nb@x.com\r\n": "<email_1>\r\n<email_2>\r\n",
		"a@x.com\r\nb@x.com":     "<email_1>\r\n<email_2>",
		"\xff a@x.com \x80\n":    "\xff <email_1> \x80\n",
	}
	for in, want := range cases {
		if r := run(t, in, nil, "mask"); r.stdout != want || r.code != 0 {
			t.Errorf("mask(%q) = %q (code %d), want %q", in, r.stdout, r.code, want)
		}
	}
}

func TestMaskLongLine(t *testing.T) {
	line := `{"events":[` + strings.Repeat(`{"user":"taro@example.com","password":"hunter2"},`, 25000) + `{}]}`
	if len(line) < 1<<20 {
		t.Fatal("setup")
	}
	r := run(t, line+"\n", nil, "mask")
	if r.code != 0 || strings.Contains(r.stdout, "hunter2") || strings.Contains(r.stdout, "taro@") ||
		!strings.HasPrefix(r.stdout, `{"events":[{"user":"<email_1>","password":"<secret_1>"},`) {
		t.Errorf("code %d, stdout %.100q", r.code, r.stdout)
	}
}

// 受け入れ基準(仕様 9 章「AWS」): 署名付き URL の X-Amz-Signature と、SigV4 の Authorization の Signature が、
// 既定の種別で <secret_N> になる(語と `=` は残る)。64 桁の 16 進数でないものは、署名として置換されない。
func TestAWSSignature(t *testing.T) {
	const sig = "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
	in := "GET https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20130524T000000Z&X-Amz-Signature=" + sig + "&x=1\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + sig + "\n" +
		"Signature=" + sig[:63] + " Signature=" + sig + "0 Signature=" + strings.ToUpper(sig) + "\n"
	want := "GET https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20130524T000000Z&X-Amz-Signature=<secret_1>&x=1\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=<secret_2>/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=<secret_1>\n" +
		"Signature=" + sig[:63] + " Signature=" + sig + "0 Signature=" + strings.ToUpper(sig) + "\n"
	r := run(t, in, nil, "mask")
	if r.code != 0 || r.stdout != want {
		t.Fatalf("%+v\nwant stdout %q", r, want)
	}
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	back := run(t, r.stdout, nil, "restore", "--source", src)
	if back.code != 0 || back.stdout != in {
		t.Errorf("restore: %+v", back)
	}
	if again := run(t, r.stdout, nil, "mask"); again.stdout != r.stdout {
		t.Errorf("mask is not idempotent: %q", again.stdout)
	}
}

// 受け入れ基準(仕様 9 章「AWS」): EC2 のホスト名に埋め込まれた IPv4 が、既定の種別で置換される。
// `-` 区切りと `.` 区切りは別の値(別のラベル)。restore で元に戻り、mask・hash の出力を再度流しても変わらない。
func TestEC2HostNames(t *testing.T) {
	in := "ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com connected from ip-10-0-1-23.ec2.internal\n" +
		"[ec2-user@ip-10-0-1-23 ~]$ ping 10.0.1.23\n" +
		"ec2-0-0-0-0.compute-1.amazonaws.com ship-10-0-1-23 ip-10-0-1-256 ip-10-0-1-23-4 ec2-54-250-1-2.example.com\n"
	want := "ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com connected from ip-<ipv4_private_1>.ec2.internal\n" +
		"[ec2-user@ip-<ipv4_private_1> ~]$ ping <ipv4_private_2>\n" +
		"ec2-0-0-0-0.compute-1.amazonaws.com ship-10-0-1-23 ip-10-0-1-256 ip-10-0-1-23-4 ec2-54-250-1-2.example.com\n"
	r := run(t, in, nil, "mask")
	if r.code != 0 || r.stdout != want {
		t.Fatalf("%+v\nwant stdout %q", r, want)
	}
	if g := run(t, "ip-10-0-1-23 ec2-54-250-1-2.compute-1.amazonaws.com\n", nil, "mask", "--ip-scope", "global"); g.stdout != "ip-10-0-1-23 ec2-<ipv4_global_1>.compute-1.amazonaws.com\n" {
		t.Errorf("--ip-scope global: %+v", g)
	}
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	if back := run(t, r.stdout, nil, "restore", "--source", src); back.code != 0 || back.stdout != in {
		t.Errorf("restore: %+v", back)
	}
	if again := run(t, r.stdout, nil, "mask"); again.stdout != r.stdout || again.stderr == "" {
		t.Errorf("mask is not idempotent: %+v", again)
	}
	env := map[string]string{keyEnv: "test-key"}
	h := run(t, in, env, "mask", "--mode", "hash")
	if h.code != 0 || !strings.Contains(h.stdout, "ec2-ipv4_global_") || !strings.Contains(h.stdout, "ip-ipv4_private_") {
		t.Fatalf("hash: %+v", h)
	}
	if again := run(t, h.stdout, env, "mask", "--mode", "hash"); again.stdout != h.stdout {
		t.Errorf("hash is not idempotent:\n%s\n%s", h.stdout, again.stdout)
	}
}

// 受け入れ基準(仕様 9 章「AWS」): ARN・ECR・SQS の、アカウント ID の部分だけが <aws_account_N> になり、
// 同じアカウント ID は、どの形でも同じラベルになる。既定の種別では置換されない。
func TestAWSAccount(t *testing.T) {
	in := "assumed arn:aws:iam::123456789012:role/deployer from 10.0.0.1\n" +
		"pull 123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/app:latest\n" +
		"send https://sqs.ap-northeast-1.amazonaws.com/123456789012/orders\n" +
		"arn:aws-cn:s3:::bucket arn:aws:iam::aws:policy/ReadOnlyAccess arn:aws:lambda:ap-northeast-1:210987654321:function:x\n" +
		"account 123456789012\n"
	wantAWS := "assumed arn:aws:iam::<aws_account_1>:role/deployer from 10.0.0.1\n" +
		"pull <aws_account_1>.dkr.ecr.ap-northeast-1.amazonaws.com/app:latest\n" +
		"send https://sqs.ap-northeast-1.amazonaws.com/<aws_account_1>/orders\n" +
		"arn:aws-cn:s3:::bucket arn:aws:iam::aws:policy/ReadOnlyAccess arn:aws:lambda:ap-northeast-1:<aws_account_2>:function:x\n" +
		"account 123456789012\n"
	// まとまり(aws、cloud)は aws_s3_bucket も含むので、arn:aws-cn:s3:::bucket のバケット名も置換される。
	wantAccountOnly := wantAWS
	wantAWS = strings.Replace(wantAWS, "arn:aws-cn:s3:::bucket", "arn:aws-cn:s3:::<aws_s3_bucket_1>", 1)
	wantDefaultAWS := strings.Replace(wantAWS, "10.0.0.1", "<ipv4_private_1>", 1)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"mask"}, strings.Replace(in, "10.0.0.1", "<ipv4_private_1>", 1)},
		{[]string{"mask", "--types", "aws"}, wantAWS},
		{[]string{"mask", "--types", "cloud"}, wantAWS},
		{[]string{"mask", "--types", "aws_account"}, wantAccountOnly},
		{[]string{"mask", "--types", "default,aws"}, wantDefaultAWS},
	} {
		r := run(t, in, nil, tt.args...)
		if r.code != 0 || r.stdout != tt.want {
			t.Errorf("%v: %+v\nwant stdout %q", tt.args, r, tt.want)
		}
	}
	// --stats: aws_account は uuid のあと
	r := run(t, in+"123e4567-e89b-42d3-a456-426614174000\n", nil, "mask", "--types", "default,uuid,aws", "--stats")
	if r.stderr != "logscrub: ipv4_private=1\nlogscrub: uuid=1\nlogscrub: aws_account=4\nlogscrub: aws_s3_bucket=1\n" {
		t.Errorf("--stats: %q", r.stderr)
	}
	// restore の往復、mask・hash の冪等性
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	masked := run(t, "", nil, "mask", "--types", "default,aws", src)
	if back := run(t, masked.stdout, nil, "restore", "--source", src, "--types", "default,aws"); back.code != 0 || back.stdout != in {
		t.Errorf("restore: %+v", back)
	}
	if again := run(t, masked.stdout, nil, "mask", "--types", "default,aws"); again.stdout != masked.stdout {
		t.Errorf("mask is not idempotent: %q", again.stdout)
	}
	env := map[string]string{keyEnv: "test-key"}
	h := run(t, in, env, "mask", "--mode", "hash", "--types", "default,aws")
	// 決まった形の中の 4 つは hash の出力になり、単独の 12 桁(対象外)だけが残る。
	if h.code != 0 || strings.Count(h.stdout, "aws_account_") != 4 || strings.Count(h.stdout, "123456789012") != 1 ||
		!strings.Contains(h.stdout, "account 123456789012\n") {
		t.Fatalf("hash: %+v", h)
	}
	if again := run(t, h.stdout, env, "mask", "--mode", "hash", "--types", "default,aws"); again.stdout != h.stdout {
		t.Errorf("hash is not idempotent:\n%s\n%s", h.stdout, again.stdout)
	}
}

// 受け入れ基準(仕様 9 章「AWS」): s3://・s3a://・s3n://、バーチャルホスト形式(`.` を含むバケット名を含む)、
// パス形式、arn:aws:s3::: のバケット名の部分だけが <aws_s3_bucket_N> になり、同じバケットは同じラベルになる。
// バケット名の規則に合わないものは置換されない。
func TestAWSS3Bucket(t *testing.T) {
	in := "cp s3://my-bucket/logs/a.gz s3a://my-bucket/x s3n://other-bucket/y\n" +
		"GET https://my-bucket.s3.ap-northeast-1.amazonaws.com/a.txt https://logs.example.com.s3.amazonaws.com/b\n" +
		"GET https://s3.ap-northeast-1.amazonaws.com/my-bucket/a.txt\n" +
		`{"Resource": "arn:aws:s3:::my-bucket/logs/*", "Principal": "arn:aws:iam::123456789012:root"}` + "\n" +
		"s3://ab/ s3://" + strings.Repeat("a", 64) + "/ s3://My-Bucket/ s3://abc_def/ s3://.abc/ s3://abc-/ s3://10.0.0.1/\n"
	want := "cp s3://<aws_s3_bucket_1>/logs/a.gz s3a://<aws_s3_bucket_1>/x s3n://<aws_s3_bucket_2>/y\n" +
		"GET https://<aws_s3_bucket_1>.s3.ap-northeast-1.amazonaws.com/a.txt https://<aws_s3_bucket_3>.s3.amazonaws.com/b\n" +
		"GET https://s3.ap-northeast-1.amazonaws.com/<aws_s3_bucket_1>/a.txt\n" +
		`{"Resource": "arn:aws:s3:::<aws_s3_bucket_1>/logs/*", "Principal": "arn:aws:iam::<aws_account_1>:root"}` + "\n" +
		"s3://ab/ s3://" + strings.Repeat("a", 64) + "/ s3://My-Bucket/ s3://abc_def/ s3://.abc/ s3://abc-/ s3://<ipv4_private_1>/\n"
	r := run(t, in, nil, "mask", "--types", "default,aws")
	if r.code != 0 || r.stdout != want {
		t.Fatalf("%+v\nwant stdout %q", r, want)
	}
	if c := run(t, in, nil, "mask", "--types", "cloud"); c.stdout != run(t, in, nil, "mask", "--types", "aws").stdout ||
		!strings.Contains(c.stdout, "s3://<aws_s3_bucket_1>/") || strings.Contains(c.stdout, "<ipv4_") {
		t.Errorf("--types cloud: %+v", c)
	}
	if d := run(t, in, nil, "mask"); strings.Contains(d.stdout, "aws_") || !strings.Contains(d.stdout, "s3://my-bucket/") {
		t.Errorf("default types replaced AWS values: %q", d.stdout)
	}
	// --stats: aws_account、aws_s3_bucket の順で、uuid のあと
	st := run(t, in, nil, "mask", "--types", "default,aws", "--stats")
	if st.stderr != "logscrub: ipv4_private=1\nlogscrub: aws_account=1\nlogscrub: aws_s3_bucket=7\n" {
		t.Errorf("--stats: %q", st.stderr)
	}
	// restore の往復、mask・hash の冪等性
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	if back := run(t, r.stdout, nil, "restore", "--source", src, "--types", "default,aws"); back.code != 0 || back.stdout != in {
		t.Errorf("restore: %+v", back)
	}
	if again := run(t, r.stdout, nil, "mask", "--types", "default,aws"); again.stdout != r.stdout {
		t.Errorf("mask is not idempotent: %q", again.stdout)
	}
	env := map[string]string{keyEnv: "test-key"}
	h := run(t, in, env, "mask", "--mode", "hash", "--types", "default,aws")
	if h.code != 0 || strings.Count(h.stdout, "aws_s3_bucket_") != 7 || strings.Contains(h.stdout, "my-bucket") {
		t.Fatalf("hash: %+v", h)
	}
	if again := run(t, h.stdout, env, "mask", "--mode", "hash", "--types", "default,aws"); again.stdout != h.stdout {
		t.Errorf("hash is not idempotent:\n%s\n%s", h.stdout, again.stdout)
	}
}

// ---- 種別の指定 ----

func TestTypes(t *testing.T) {
	const in = "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n"
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"mask"}, "<email_1> <ipv4_private_1> 123e4567-e89b-42d3-a456-426614174000\n"},
		{"email only", []string{"mask", "--types", "email"}, "<email_1> 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n"},
		{"default and uuid", []string{"mask", "--types", "default,uuid"}, "<email_1> <ipv4_private_1> <uuid_1>\n"},
		{"uuid only", []string{"mask", "--types", "uuid"}, "a@x.com 10.0.0.1 <uuid_1>\n"},
		{"uuid versions v4", []string{"mask", "--uuid-versions", "4"}, "<email_1> <ipv4_private_1> <uuid_1>\n"},
		{"uuid versions v7 only", []string{"mask", "--uuid-versions", "7"}, "<email_1> <ipv4_private_1> 123e4567-e89b-42d3-a456-426614174000\n"},
		{"uuid versions override types", []string{"mask", "--types", "default,uuid", "--uuid-versions", "7"}, "<email_1> <ipv4_private_1> 123e4567-e89b-42d3-a456-426614174000\n"},
		// AWS の種別だけを指定すると、既定の種別は含まない(入力に AWS の値がないので、何も置換しない)。
		{"aws only", []string{"mask", "--types", "aws"}, "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n"},
		{"cloud only", []string{"mask", "--types", "cloud"}, "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n"},
		{"aws types by name", []string{"mask", "--types", "aws_account,aws_s3_bucket"}, "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n"},
		{"default and aws", []string{"mask", "--types", "default,aws"}, "<email_1> <ipv4_private_1> 123e4567-e89b-42d3-a456-426614174000\n"},
		{"default and cloud", []string{"mask", "--types", "default,cloud"}, "<email_1> <ipv4_private_1> 123e4567-e89b-42d3-a456-426614174000\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, in, nil, tt.args...)
			if r.code != 0 || r.stdout != tt.want {
				t.Errorf("%+v, want stdout %q", r, tt.want)
			}
		})
	}
}

func TestInvalidOptionValuesAreErrors(t *testing.T) {
	for _, args := range [][]string{
		{"mask", "--types", "email,foo"},
		{"mask", "--types", ""},
		{"mask", "--types", "Email"},
		{"mask", "--uuid-versions", "9"},
		{"mask", "--uuid-versions", "0"},
		{"mask", "--uuid-versions", "4,x"},
		{"mask", "--ip-scope", "public"},
		{"mask", "--mask-format", "[{type}]"},
		{"mask", "--mask-format", "[{n}]"},
		{"mask", "--mask-format", "{type}{type}{n}"},
		{"mask", "--mode", "encrypt"},
		{"restore", "--source", "x", "--types", "foo"},
		{"mask", "--types", "AWS"},
		{"mask", "--types", "default,aws_hosts"},
		{"restore", "--source", "x", "--types", "aws_"},
		{"restore", "--source", "x", "--mask-format", "{n}"},
	} {
		r := run(t, "a@x.com\n", nil, args...)
		if r.code != 1 || r.stdout != "" || r.stderr == "" {
			t.Errorf("%v: %+v, want code 1 with an error on stderr only", args, r)
		}
	}
	// エラーメッセージには、指定した種別名が出る(値ではない)。
	if r := run(t, "", nil, "mask", "--types", "phone_jp"); !strings.Contains(r.stderr, "phone_jp") {
		t.Errorf("stderr: %q", r.stderr)
	}
}

// ---- 重なり・各種別(受け入れ基準) ----

func TestOverlapsAndKinds(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:10.0.0.1\n":                               "<ipv6_private_1>\n",
		"https://user:pass@10.0.0.1/\n":                   "https://user:<secret_1>@<ipv4_private_1>/\n",
		"10.0.0.1:8080 [::1]:8080 10.0.0.0/8\n":           "<ipv4_private_1>:8080 [<ipv6_private_1>]:8080 <ipv4_private_2>/8\n",
		"0.0.0.0 255.255.255.255 :: 224.0.0.1\n":          "0.0.0.0 255.255.255.255 :: 224.0.0.1\n",
		"999.1.1.1 1.2 1.2.3.4.5\n":                       "999.1.1.1 1.2 1.2.3.4.5\n",
		"connected to 10.0.0.1.\n":                        "connected to <ipv4_private_1>.\n",
		"password=abc123&user=x\n":                        "password=<secret_1>&user=x\n",
		"X-Auth-Token: xxx\nDB_PASSWORD=xxx\n":            "X-Auth-Token: <secret_1>\nDB_PASSWORD=<secret_1>\n",
		"max_tokens: 4096 token_count=5 PWD=/home/user\n": "max_tokens: 4096 token_count=5 PWD=/home/user\n",
		"03-1234-5678 09012345678 123-4567\n":             "03-1234-5678 09012345678 123-4567\n",
	} {
		if r := run(t, in, nil, "mask"); r.stdout != want || r.code != 0 {
			t.Errorf("mask(%q) = %q (code %d), want %q", in, r.stdout, r.code, want)
		}
	}
}

func TestIPScopeOption(t *testing.T) {
	const in = "10.0.0.1 203.0.113.5 fe80::1 2001:db8::1\n"
	for scope, want := range map[string]string{
		"all":     "<ipv4_private_1> <ipv4_global_1> <ipv6_private_1> <ipv6_global_1>\n",
		"global":  "10.0.0.1 <ipv4_global_1> fe80::1 <ipv6_global_1>\n",
		"private": "<ipv4_private_1> 203.0.113.5 <ipv6_private_1> 2001:db8::1\n",
	} {
		if r := run(t, in, nil, "mask", "--ip-scope", scope); r.stdout != want {
			t.Errorf("--ip-scope %s: %q, want %q", scope, r.stdout, want)
		}
	}
}

func TestAllowOption(t *testing.T) {
	const in = "support@example.com taro@example.com ops@example.com\n"
	r := run(t, in, nil, "mask", "--allow", "support@example.com")
	if r.stdout != "support@example.com <email_1> <email_2>\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	// 複数回指定すると、すべて反映される(受け入れ基準)
	r = run(t, in, nil, "mask", "--allow", "support@example.com", "--allow", "ops@example.com")
	if r.stdout != "support@example.com <email_1> ops@example.com\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	r = run(t, in, nil, "mask", "--allow=support@example.com", "-allow", "ops@example.com")
	if r.stdout != "support@example.com <email_1> ops@example.com\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

// ---- hash モード ----

func TestHashMode(t *testing.T) {
	env := map[string]string{keyEnv: "test-key"}
	r := run(t, "taro@example.com\n", env, "mask", "--mode", "hash")
	if r.code != 0 || r.stdout != "email_99a207efd719\n" {
		t.Errorf("full: %+v", r)
	}
	r = run(t, "taro@example.com\n", env, "mask", "--mode", "hash", "--email-hash", "local")
	if r.code != 0 || r.stdout != "hash_a746604745a4@example.com\n" {
		t.Errorf("local: %+v", r)
	}
	r = run(t, "taro@example.com\n", env, "mask", "--mode=hash", "--hash-length", "8")
	if r.code != 0 || r.stdout != "email_99a207ef\n" {
		t.Errorf("length 8: %+v", r)
	}
	// 再度流しても変わらない(受け入れ基準)。
	once := run(t, "taro@example.com password=hunter2 10.0.0.1\n", env, "mask", "--mode", "hash", "--email-hash", "local")
	twice := run(t, once.stdout, env, "mask", "--mode", "hash", "--email-hash", "local")
	if once.code != 0 || twice.stdout != once.stdout {
		t.Errorf("hash(hash(x)) != hash(x)\n once:  %q\n twice: %q", once.stdout, twice.stdout)
	}
	if r := run(t, "password=secret_3f9a1c0b7d2e\n", env, "mask", "--mode", "hash"); r.stdout != "password=secret_3f9a1c0b7d2e\n" {
		t.Errorf("rehashed: %q", r.stdout)
	}
}

func TestHashModeNeedsKey(t *testing.T) {
	r := run(t, "taro@example.com\n", nil, "mask", "--mode", "hash")
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "LOGSCRUB_KEY") {
		t.Errorf("%+v", r)
	}
	// --key-file が優先される
	dir := t.TempDir()
	kf := writeFile(t, dir, "key", "test-key\n")
	r = run(t, "taro@example.com\n", map[string]string{keyEnv: "other-key"}, "mask", "--mode", "hash", "--key-file", kf)
	if r.code != 0 || r.stdout != "email_99a207efd719\n" {
		t.Errorf("key file: %+v", r)
	}
	if r := run(t, "x\n", nil, "mask", "--mode", "hash", "--key-file", filepath.Join(dir, "missing")); r.code != 1 {
		t.Errorf("missing key file: %+v", r)
	}
}

// Q25: hash 専用のオプションは、mask モードで指定するとエラー。
func TestHashOnlyOptionsInMaskModeAreErrors(t *testing.T) {
	env := map[string]string{keyEnv: "test-key"}
	for _, args := range [][]string{
		{"mask", "--hash-length", "8"},
		{"mask", "--email-hash", "local"},
		{"mask", "--key-file", "key"},
		{"mask", "--mode", "mask", "--hash-length", "12"},
	} {
		r := run(t, "a@x.com\n", env, args...)
		if r.code != 1 || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	for _, args := range [][]string{
		{"mask", "--mode", "hash", "--hash-length", "7"},
		{"mask", "--mode", "hash", "--hash-length", "65"},
		{"mask", "--mode", "hash", "--hash-length", "abc"},
		{"mask", "--mode", "hash", "--email-hash", "partial"},
	} {
		r := run(t, "a@x.com\n", env, args...)
		if r.code != 1 || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	// restore には、hash 専用のオプションはない。
	if r := run(t, "", env, "restore", "--source", "x", "--hash-length", "8"); r.code != 1 {
		t.Errorf("restore --hash-length: %+v", r)
	}
}

// ---- 統計・終了コード・通知 ----

func TestStatsGoToStderr(t *testing.T) {
	r := run(t, "a@x.com b@x.com 10.0.0.1 203.0.113.5 password=abc\n", nil, "mask", "--stats")
	if r.code != 0 || r.stdout != "<email_1> <email_2> <ipv4_private_1> <ipv4_global_1> password=<secret_1>\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	want := "logscrub: email=2\nlogscrub: ipv4_global=1\nlogscrub: ipv4_private=1\nlogscrub: secret=1\n"
	if r.stderr != want {
		t.Errorf("stderr = %q, want %q", r.stderr, want)
	}
	noLeak(t, r, "a@x.com", "10.0.0.1", "abc")
	// 検出がなければ、何も出さない
	if r := run(t, "hello\n", nil, "mask", "--stats"); r.stderr != "" || r.code != 0 {
		t.Errorf("%+v", r)
	}
}

func TestFailOnDetect(t *testing.T) {
	r := run(t, "a@x.com\n", nil, "mask", "--fail-on-detect")
	if r.code != 2 || r.stdout != "<email_1>\n" {
		t.Errorf("detected: %+v", r)
	}
	r = run(t, "hello\n", nil, "mask", "--fail-on-detect")
	if r.code != 0 || r.stdout != "hello\n" {
		t.Errorf("not detected: %+v", r)
	}
	// 置換済みの形だけの入力は、検出に数えない(仕様 6 章)
	r = run(t, "<email_1> password=<secret_1>\n", nil, "mask", "--fail-on-detect")
	if r.code != 0 {
		t.Errorf("placeholders only: %+v", r)
	}
}

// Q28: エラー(1)は、終了コード 2 より優先する。
func TestErrorTakesPrecedenceOverFailOnDetect(t *testing.T) {
	var errb bytes.Buffer
	code := Run([]string{"mask", "--fail-on-detect"}, strings.NewReader(strings.Repeat("a@x.com\n", 100000)),
		failingWriter{}, &errb, func(string) string { return "" })
	if code != 1 || !strings.Contains(errb.String(), "logscrub:") {
		t.Errorf("code %d, stderr %q", code, errb.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// Q31: 置換済みの形のため残した文字列は、件数と行番号を、stderr に通知する(値は出さない)。
func TestNotificationOfUnchangedStrings(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 40; i++ {
		switch i {
		case 12, 40:
			sb.WriteString("from <email_1> to <ipv4_private_2>\n")
		default:
			sb.WriteString("line\n")
		}
	}
	r := run(t, sb.String(), nil, "mask")
	want := "logscrub: 4 strings were left unchanged because they look already replaced (lines 12, 40). Check them before sharing.\n"
	if r.code != 0 || r.stderr != want {
		t.Errorf("stderr = %q, want %q", r.stderr, want)
	}
	if r.stdout != sb.String() {
		t.Error("the input was changed")
	}
	// 1 件: 単数形
	r = run(t, "x <email_1>\n", nil, "mask")
	if want := "logscrub: 1 string was left unchanged because it looks already replaced (line 1). Check them before sharing.\n"; r.stderr != want {
		t.Errorf("stderr = %q, want %q", r.stderr, want)
	}
	// 6 行以上: 最初の 5 行と、省略
	r = run(t, strings.Repeat("<email_1>\n", 8), nil, "mask")
	if want := "logscrub: 8 strings were left unchanged because they look already replaced (lines 1, 2, 3, 4, 5, ...). Check them before sharing.\n"; r.stderr != want {
		t.Errorf("stderr = %q, want %q", r.stderr, want)
	}
	// 検出と同時にあっても、終了コードは変わらない。--stats の件数に含めない。
	r = run(t, "<email_1> a@x.com\n", nil, "mask", "--stats", "--fail-on-detect")
	if r.code != 2 || !strings.Contains(r.stderr, "logscrub: email=1\n") || !strings.Contains(r.stderr, "1 string was left unchanged") {
		t.Errorf("%+v", r)
	}
	// hash モードでも、同じ通知
	r = run(t, "email_3f9a1c0b7d2e\n", map[string]string{keyEnv: "k"}, "mask", "--mode", "hash")
	if !strings.Contains(r.stderr, "1 string was left unchanged") {
		t.Errorf("hash: %+v", r)
	}
}

// ---- ファイル・出力 ----

func TestMaskFilesAreConcatenated(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.log", "a@x.com\nb@x.com")
	b := writeFile(t, dir, "b.log", "b@x.com a@x.com\n")
	r := run(t, "", nil, "mask", a, b)
	// 末尾改行のない入力と、次の入力の最初の行は、別の行(Q22)。番号は通し。
	if r.code != 0 || r.stdout != "<email_1>\n<email_2><email_2> <email_1>\n" {
		t.Errorf("%+v", r)
	}
}

func TestOutputFile(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.log", "a@x.com\n")
	out := filepath.Join(dir, "out.log")
	for _, flag := range []string{"--output", "-o", "-output"} {
		os.Remove(out)
		r := run(t, "", nil, "mask", in, flag, out)
		if r.code != 0 || r.stdout != "" || readFile(t, out) != "<email_1>\n" {
			t.Errorf("%s: %+v, file %q", flag, r, readFile(t, out))
		}
	}
	r := run(t, "", nil, "mask", in, "--output="+out)
	if r.code != 0 || r.stdout != "" {
		t.Errorf("--output=: %+v", r)
	}
}

// Q26: 出力先が、入力と同じファイルなら、エラー(入力を消さない)。
func TestOutputMustNotBeAnInput(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "app.log", "a@x.com\n")
	t.Chdir(dir)
	for _, args := range [][]string{
		{"mask", "app.log", "-o", "app.log"},
		{"mask", "app.log", "--output", "./app.log"},
		{"mask", in, "-o", "app.log"},
		{"restore", "--source", "app.log", "-o", "app.log", in},
		{"restore", "--source", "other.log", "-o", "app.log", "app.log"},
	} {
		writeFile(t, dir, "other.log", "b@x.com\n")
		r := run(t, "<email_1>\n", nil, args...)
		if r.code != 1 || r.stdout != "" || r.stderr == "" {
			t.Errorf("%v: %+v", args, r)
		}
		if got := readFile(t, in); got != "a@x.com\n" {
			t.Fatalf("%v: the input file was changed: %q", args, got)
		}
	}
}

// 標準入力が、出力先と同じファイルからのリダイレクト(`mask -o app.log < app.log`)でも、エラー(入力を消さない)。
func TestOutputMustNotBeTheRedirectedStdin(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "app.log", "a@x.com\n")
	answer := writeFile(t, dir, "answer.txt", "<email_1>\n")
	for _, args := range [][]string{
		{"mask", "-o", in},
		{"mask", "-", "-o", in},
		{"restore", "--source", "-", "-o", in, answer},
	} {
		f, err := os.Open(in)
		if err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := Run(args, f, &out, &errb, func(string) string { return "" })
		f.Close()
		if code != 1 || out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
		if got := readFile(t, in); got != "a@x.com\n" {
			t.Fatalf("%v: the input file was changed: %q", args, got)
		}
	}
	// 別のファイルへの出力は、そのまま行う
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	other := filepath.Join(dir, "out.log")
	var out, errb bytes.Buffer
	if code := Run([]string{"mask", "-o", other}, f, &out, &errb, func(string) string { return "" }); code != 0 {
		t.Fatalf("other output: code %d, stderr %q", code, errb.String())
	}
	if got := readFile(t, other); got != "<email_1>\n" {
		t.Errorf("other output: %q", got)
	}
}

// 入力が開けない場合は、出力を始める前に、エラーにする(出力ファイルを作らない)。
func TestMissingInputFailsBeforeAnyOutput(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.log", "a@x.com\n")
	out := filepath.Join(dir, "out.log")
	r := run(t, "", nil, "mask", a, filepath.Join(dir, "missing.log"), "-o", out)
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "missing.log") {
		t.Errorf("%+v", r)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("the output file was created")
	}
	r = run(t, "", nil, "mask", a, filepath.Join(dir, "missing.log"))
	if r.code != 1 || r.stdout != "" {
		t.Errorf("stdout: %+v", r)
	}
}

func TestStdinCanBeUsedOnlyOnce(t *testing.T) {
	if r := run(t, "a@x.com\n", nil, "mask", "-", "-"); r.code != 1 {
		t.Errorf("%+v", r)
	}
}

// ---- オプションの位置・書き方(受け入れ基準) ----

func TestOptionsBeforeOrAfterFileNames(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "app.log", "a@x.com\n")
	a := run(t, "", nil, "mask", f, "--stats")
	b := run(t, "", nil, "mask", "--stats", f)
	c := run(t, "", nil, "mask", "-stats", f)
	d := run(t, "", nil, "mask", f, "-stats")
	if a != b || a != c || a != d || a.code != 0 || a.stdout != "<email_1>\n" || a.stderr != "logscrub: email=1\n" {
		t.Errorf("a=%+v b=%+v c=%+v d=%+v", a, b, c, d)
	}
	// ファイルの間にオプションがあってもよい
	g := writeFile(t, dir, "b.log", "b@x.com\n")
	r := run(t, "", nil, "mask", f, "--fail-on-detect", g, "--allow", "b@x.com")
	if r.code != 2 || r.stdout != "<email_1>\nb@x.com\n" {
		t.Errorf("%+v", r)
	}
}

func TestDoubleDashEndsOptions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "-weird-name.log", "a@x.com\n")
	t.Chdir(dir)
	r := run(t, "", nil, "mask", "--", "-weird-name.log")
	if r.code != 0 || r.stdout != "<email_1>\n" {
		t.Errorf("%+v", r)
	}
	// "--" の後ろは、オプションに見えても、ファイル名
	r = run(t, "", nil, "mask", "--stats", "--", "-weird-name.log")
	if r.code != 0 || r.stderr != "logscrub: email=1\n" {
		t.Errorf("%+v", r)
	}
	// "--" の後ろの "--stats" は、ファイル名として開こうとして、エラー
	if r := run(t, "", nil, "mask", "--", "--stats"); r.code != 1 {
		t.Errorf("%+v", r)
	}
	// フラグの値としての "--" は、終端ではない
	if r := run(t, "a@x.com\n", nil, "mask", "--allow", "--", "-"); r.code != 0 || r.stdout != "<email_1>\n" {
		t.Errorf("flag value --: %+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"mask", "--nope"}, {"restore"}, {"types", "--nope"}, {"mask", "--allow"}} {
		r := run(t, "a@x.com\n", nil, args...)
		if r.code != 1 || r.stdout != "" || r.stderr == "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	r := run(t, "", nil)
	if !strings.Contains(r.stderr, "Usage:") || !strings.Contains(r.stderr, "logscrub mask") {
		t.Errorf("no subcommand: stderr = %q", r.stderr)
	}
	r = run(t, "", nil, "unknown")
	if !strings.Contains(r.stderr, "Usage:") || !strings.Contains(r.stderr, "unknown") {
		t.Errorf("unknown subcommand: stderr = %q", r.stderr)
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		r := run(t, "", nil, args...)
		if r.code != 0 || !strings.Contains(r.stdout, "Usage:") || r.stderr != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	for _, sub := range []string{"mask", "restore", "types"} {
		for _, flag := range []string{"--help", "-h"} {
			r := run(t, "", nil, sub, flag)
			if r.code != 0 || !strings.Contains(r.stdout, "logscrub "+sub) || r.stderr != "" {
				t.Errorf("%s %s: %+v", sub, flag, r)
			}
		}
	}
	// mask の --help には、secret の対応形式を列挙する(仕様 4.1)
	r := run(t, "", nil, "mask", "--help")
	for _, want := range []string{"AKIA", "X-Amz-Signature=", "Signature=", "ghp_", "xoxb-", "sk_live_", "AIza", "sk-", "JWT", "Bearer", "password"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("mask --help lacks %q", want)
		}
	}
	// --types の説明に、種別とまとまりを出す
	for _, want := range []string{"uuid", "aws_account", "aws_s3_bucket", "aws_host", "default", "aws,", "cloud"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("mask --help lacks %q", want)
		}
	}
}

// ---- types ----

func TestTypesCommand(t *testing.T) {
	r := run(t, "", nil, "types")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("%+v", r)
	}
	// 1 行 1 種別(種別 ID、既定、説明)。共通の種別のあとに、クラウドごとにまとめる(仕様 6 章)。
	wantDefault := map[string]string{
		"email": "on", "ipv4": "on", "ipv6": "on", "secret": "on", "uuid": "off", "aws_account": "off", "aws_s3_bucket": "off", "aws_host": "off",
	}
	var order []string
	for _, line := range strings.Split(r.stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if want, ok := wantDefault[fields[0]]; ok {
			order = append(order, fields[0])
			if fields[1] != want {
				t.Errorf("%s line: %q, want %q", fields[0], line, want)
			}
		}
	}
	if got := strings.Join(order, ","); got != "email,ipv4,ipv6,secret,uuid,aws_account,aws_s3_bucket,aws_host" {
		t.Errorf("type order: %s", got)
	}
	if !strings.Contains(r.stdout, "\nAWS:\naws_account ") {
		t.Errorf("types lacks the AWS heading:\n%s", r.stdout)
	}
	// 最後に、まとまりと、それぞれに含まれる種別。
	if !strings.HasSuffix(r.stdout, "\nGroups for --types:\n"+
		"  default  email, ipv4, ipv6, secret\n"+
		"  aws      aws_account, aws_s3_bucket, aws_host\n"+
		"  cloud    aws_account, aws_s3_bucket, aws_host\n") {
		t.Errorf("types lacks the groups:\n%s", r.stdout)
	}
	if strings.Contains(r.stdout, "AKIA") {
		t.Error("types without --verbose lists the secret formats")
	}
	v := run(t, "", nil, "types", "--verbose")
	if v.code != 0 || !strings.Contains(v.stdout, "AKIA") || !strings.Contains(v.stdout, "X-Amz-Signature=") ||
		!strings.Contains(v.stdout, "ghp_") || !strings.Contains(v.stdout, "password") {
		t.Errorf("--verbose: %+v", v)
	}
	if !strings.HasPrefix(v.stdout, r.stdout) {
		t.Error("--verbose output does not extend the plain output")
	}
}

// types は、引数を取らない。
func TestTypesCommandRejectsArguments(t *testing.T) {
	r := run(t, "", nil, "types", "bogus")
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "bogus") {
		t.Errorf("%+v", r)
	}
}

// ---- restore ----

func TestRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := "from taro@example.com (192.168.0.1)\npassword=hunter2&user=x\r\nlast a@x.com"
	srcFile := writeFile(t, dir, "app.log", src)
	masked := run(t, "", nil, "mask", srcFile)
	if masked.code != 0 || masked.stdout == src {
		t.Fatalf("%+v", masked)
	}
	// 回答を stdin から
	r := run(t, masked.stdout, nil, "restore", "--source", srcFile)
	if r.code != 0 || r.stdout != src || r.stderr != "" {
		t.Errorf("stdin answer: %+v", r)
	}
	// 回答をファイルから
	ans := writeFile(t, dir, "answer.txt", masked.stdout)
	r = run(t, "", nil, "restore", "--source", srcFile, ans)
	if r.code != 0 || r.stdout != src {
		t.Errorf("file answer: %+v", r)
	}
	// --output
	out := filepath.Join(dir, "restored.txt")
	r = run(t, "", nil, "restore", "--source", srcFile, ans, "-o", out)
	if r.code != 0 || r.stdout != "" || readFile(t, out) != src {
		t.Errorf("output: %+v", r)
	}
	// ファイル名の後ろにオプション
	r = run(t, "", nil, "restore", ans, "--source", srcFile)
	if r.code != 0 || r.stdout != src {
		t.Errorf("options after file: %+v", r)
	}
}

func TestRestoreMultipleSourcesAndAppend(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.log", "a@x.com 10.0.0.1\n")
	b := writeFile(t, dir, "b.log", "b@x.com a@x.com\n")
	masked := run(t, "", nil, "mask", a, b)
	r := run(t, masked.stdout, nil, "restore", "--source", a, "--source", b)
	if r.code != 0 || r.stdout != "a@x.com 10.0.0.1\nb@x.com a@x.com\n" {
		t.Errorf("%+v", r)
	}
	// --source を追記しても、追記前のラベルは戻る
	writeFile(t, dir, "b.log", "b@x.com a@x.com\nc@x.com\n")
	r = run(t, masked.stdout, nil, "restore", "--source", a, "--source", b)
	if r.code != 0 || r.stdout != "a@x.com 10.0.0.1\nb@x.com a@x.com\n" {
		t.Errorf("after append: %+v", r)
	}
}

func TestRestoreWithOptionsOfMask(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n")
	masked := run(t, "", nil, "mask", "--types", "default,uuid", "--mask-format", "[{type}-{n}]", "--ip-scope", "private", src)
	r := run(t, masked.stdout, nil, "restore", "--source", src, "--types", "default,uuid", "--mask-format", "[{type}-{n}]", "--ip-scope", "private")
	if r.code != 0 || r.stdout != "a@x.com 10.0.0.1 123e4567-e89b-42d3-a456-426614174000\n" || r.stderr != "" {
		t.Errorf("%+v", r)
	}
}

// 受け入れ基準: オプションが mask と違う場合、対応しないラベルはそのまま残り、
// 件数とラベル名が stderr に出て、終了コードは 0 になる。元の値は出ない。
func TestRestoreWithMismatchedOptions(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", "a@x.com 10.0.0.1 password=hunter2\n")
	masked := run(t, "", nil, "mask", src)
	r := run(t, masked.stdout, nil, "restore", "--source", src, "--types", "email")
	if r.code != 0 || r.stdout != "a@x.com <ipv4_private_1> password=<secret_1>\n" {
		t.Errorf("%+v", r)
	}
	want := "logscrub: 2 labels could not be restored: <ipv4_private_1>, <secret_1> (check that --source and options match the mask run)\n"
	if r.stderr != want {
		t.Errorf("stderr = %q, want %q", r.stderr, want)
	}
	noLeak(t, r, "a@x.com", "10.0.0.1", "hunter2")
	// 1 件: 単数形
	r = run(t, "<email_1> <email_2>\n", nil, "restore", "--source", src)
	if want := "logscrub: 1 label could not be restored: <email_2> (check that --source and options match the mask run)\n"; r.stderr != want || r.code != 0 {
		t.Errorf("%+v", r)
	}
}

func TestRestoreSourceFromStdin(t *testing.T) {
	dir := t.TempDir()
	ans := writeFile(t, dir, "answer.txt", "<email_1>\n")
	// --source - は、ANSWER_FILE を指定した場合だけ使える
	r := run(t, "a@x.com\n", nil, "restore", "--source", "-", ans)
	if r.code != 0 || r.stdout != "a@x.com\n" {
		t.Errorf("%+v", r)
	}
	for _, args := range [][]string{
		{"restore", "--source", "-"},      // 回答も stdin
		{"restore", "--source", "-", "-"}, // 回答に - を明示
		{"restore", "--source", "-", "--source", "-", ans},
	} {
		r := run(t, "a@x.com\n", nil, args...)
		if r.code != 1 || r.stdout != "" || r.stderr == "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

func TestRestoreArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", "a@x.com\n")
	ans := writeFile(t, dir, "answer.txt", "<email_1>\n")
	for _, args := range [][]string{
		{"restore"},                            // --source は必須
		{"restore", ans},                       // --source なし
		{"restore", "--source", src, ans, ans}, // ANSWER_FILE は 1 つだけ
		{"restore", "--source", filepath.Join(dir, "missing")},
		{"restore", "--source", src, filepath.Join(dir, "missing")},
	} {
		r := run(t, "<email_1>\n", nil, args...)
		if r.code != 1 || r.stdout != "" || r.stderr == "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

// 受け入れ基準: restore の実行後に、対応表のファイルが残らない。
func TestRestoreLeavesNoFiles(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", "a@x.com password=abc\n")
	ans := writeFile(t, dir, "answer.txt", "<email_1> <secret_1>\n")
	t.Chdir(dir)
	t.Setenv("TMPDIR", dir)
	before := listDir(t, dir)
	r := run(t, "", nil, "restore", "--source", src, ans)
	if r.code != 0 || r.stdout != "a@x.com abc\n" {
		t.Fatalf("%+v", r)
	}
	if after := listDir(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("files changed: before %v, after %v", before, after)
	}
}

// 元の入力に、ラベルと同じ形の文字列があると、restore でも通知する(Q31)。
func TestRestoreNotifiesUnchangedStrings(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", "ok\nfrom <email_1> to a@x.com\n")
	r := run(t, "<email_1>\n", nil, "restore", "--source", src)
	if want := "logscrub: 1 string was left unchanged because it looks already replaced (line 2). Check them before sharing.\n"; r.stderr != want || r.code != 0 {
		t.Errorf("%+v", r)
	}
}

// 受け入れ基準: 出力が、そのまま stdout へ書かれ、stderr と混ざらない(全体を通して)。
func TestStdoutOnlyHasTheTransformedText(t *testing.T) {
	r := run(t, "a@x.com <email_1>\n", nil, "mask", "--stats", "--fail-on-detect")
	if r.stdout != "<email_1> <email_1>\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "email=1") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

var _ io.Writer = failingWriter{}

// 受け入れ基準(仕様 9 章「AWS のホスト名」): 利用者ごとの部分だけが <aws_host_N> になり、サービス名・リージョン・
// ドメインは残る。同じホスト名は同じラベル、違うホスト名は別のラベルになる。既定の種別では置換されない。
func TestAWSHost(t *testing.T) {
	in := "db mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432 from 10.0.0.1\n" +
		"lb my-alb-1234567890.ap-northeast-1.elb.amazonaws.com my-nlb-0123456789abcdef.elb.ap-northeast-1.amazonaws.com\n" +
		"cdn d111111abcdef8.cloudfront.net again mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com\n" +
		"env my-env.ap-northeast-1.elasticbeanstalk.com fn abcdefghij0123456789klmnop.lambda-url.ap-northeast-1.on.aws\n" +
		"mail admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com api https://kafka.ap-northeast-1.amazonaws.com/ data-ats.iot.us-east-1.amazonaws.com\n" +
		"ec2 ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com bucket my-bucket.s3.ap-northeast-1.amazonaws.com\n"
	wantHosts := "db <aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432 from 10.0.0.1\n" +
		"lb <aws_host_2>.ap-northeast-1.elb.amazonaws.com <aws_host_3>.elb.ap-northeast-1.amazonaws.com\n" +
		"cdn <aws_host_4>.cloudfront.net again <aws_host_1>.ap-northeast-1.rds.amazonaws.com\n" +
		"env <aws_host_5>.ap-northeast-1.elasticbeanstalk.com fn <aws_host_6>.lambda-url.ap-northeast-1.on.aws\n" +
		"mail <email_1> api https://kafka.ap-northeast-1.amazonaws.com/ data-ats.iot.us-east-1.amazonaws.com\n" +
		"ec2 ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com bucket my-bucket.s3.ap-northeast-1.amazonaws.com\n"
	// 既定の種別では置換されない(IP アドレスとメールアドレスだけ)
	def := run(t, in, nil, "mask")
	if def.code != 0 || strings.Contains(def.stdout, "aws_host") || !strings.Contains(def.stdout, "<email_1>") {
		t.Errorf("default types: %+v", def)
	}
	// --types aws_host だけ: ホスト名だけが置換される(メールアドレスのホスト名は、長いメールアドレスが優先されるが、
	// email が無効なので、この種別だけでは aws_host になる)
	only := run(t, in, nil, "mask", "--types", "aws_host", "--stats")
	wantOnly := strings.Replace(wantHosts, "mail <email_1>", "mail admin@<aws_host_7>.ap-northeast-1.rds.amazonaws.com", 1)
	if only.code != 0 || only.stdout != wantOnly || only.stderr != "logscrub: aws_host=8\n" {
		t.Errorf("--types aws_host: %+v\nwant stdout %q", only, wantOnly)
	}
	// 既定の種別と合わせると、メールアドレスが優先され、EC2 のホスト名の IPv4 は ipv4 として置換される
	both := run(t, in, nil, "mask", "--types", "default,aws_host")
	wantBoth := strings.Replace(wantHosts, "from 10.0.0.1", "from <ipv4_private_1>", 1)
	wantBoth = strings.Replace(wantBoth, "ec2-54-250-1-2.", "ec2-<ipv4_global_1>.", 1)
	if both.code != 0 || both.stdout != wantBoth {
		t.Errorf("default,aws_host: %+v\nwant stdout %q", both, wantBoth)
	}
	// まとまり aws・cloud にも含まれる。--stats は aws_s3_bucket のあと
	st := run(t, in, nil, "mask", "--types", "default,aws", "--stats")
	if st.code != 0 || !strings.HasSuffix(st.stderr, "logscrub: aws_s3_bucket=1\nlogscrub: aws_host=7\n") {
		t.Errorf("--stats: %q", st.stderr)
	}
	if c := run(t, in, nil, "mask", "--types", "cloud"); !strings.Contains(c.stdout, "<aws_host_6>") {
		t.Errorf("cloud: %+v", c)
	}
	// restore の往復、mask・hash の冪等性
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	for _, types := range []string{"aws_host", "default,aws"} {
		masked := run(t, "", nil, "mask", "--types", types, src)
		if back := run(t, masked.stdout, nil, "restore", "--source", src, "--types", types); back.code != 0 || back.stdout != in {
			t.Errorf("restore (%s): %+v", types, back)
		}
		if again := run(t, masked.stdout, nil, "mask", "--types", types); again.stdout != masked.stdout {
			t.Errorf("mask (%s) is not idempotent: %q", types, again.stdout)
		}
		env := map[string]string{keyEnv: "test-key"}
		h := run(t, in, env, "mask", "--mode", "hash", "--types", types)
		if h.code != 0 || strings.Contains(h.stdout, "cluster-c9akciq32") || !strings.Contains(h.stdout, "aws_host_") {
			t.Fatalf("hash (%s): %+v", types, h)
		}
		if again := run(t, h.stdout, env, "mask", "--mode", "hash", "--types", types); again.stdout != h.stdout {
			t.Errorf("hash (%s) is not idempotent:\n%s\n%s", types, h.stdout, again.stdout)
		}
	}
}

// v1.2 段階 4: S3 Control のホストのアカウント ID(ECR・ARN と同じ値は同じラベル)。既定の種別では置換されない。
func TestAWSAccountS3Control(t *testing.T) {
	in := "ctl 123456789012.s3-control.ap-northeast-1.amazonaws.com and 123456789012.s3-control.dualstack.us-east-1.amazonaws.com\n" +
		"ecr 123456789012.dkr.ecr.us-east-1.amazonaws.com/app arn:aws:iam::210987654321:role/x api s3-control.us-east-1.amazonaws.com\n"
	want := "ctl <aws_account_1>.s3-control.ap-northeast-1.amazonaws.com and <aws_account_1>.s3-control.dualstack.us-east-1.amazonaws.com\n" +
		"ecr <aws_account_1>.dkr.ecr.us-east-1.amazonaws.com/app arn:aws:iam::<aws_account_2>:role/x api s3-control.us-east-1.amazonaws.com\n"
	if r := run(t, in, nil, "mask"); r.code != 0 || r.stdout != in {
		t.Errorf("default types: %+v", r)
	}
	for _, types := range []string{"aws_account", "aws", "cloud"} {
		if r := run(t, in, nil, "mask", "--types", types); r.code != 0 || r.stdout != want {
			t.Errorf("--types %s: %+v\nwant %q", types, r, want)
		}
	}
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	masked := run(t, "", nil, "mask", "--types", "aws_account", src)
	if back := run(t, masked.stdout, nil, "restore", "--source", src, "--types", "aws_account"); back.code != 0 || back.stdout != in {
		t.Errorf("restore: %+v", back)
	}
	env := map[string]string{keyEnv: "test-key"}
	h := run(t, in, env, "mask", "--mode", "hash", "--types", "aws_account")
	if h.code != 0 || strings.Contains(h.stdout, "123456789012") || strings.Count(h.stdout, "aws_account_") != 4 {
		t.Fatalf("hash: %+v", h)
	}
	if again := run(t, h.stdout, env, "mask", "--mode", "hash", "--types", "aws_account"); again.stdout != h.stdout {
		t.Errorf("hash is not idempotent:\n%s\n%s", h.stdout, again.stdout)
	}
}

// 受け入れ基準(仕様 9 章「URL のパスワード」。v1.2): パスワードの部分だけが <secret_N> になり、メールアドレスとして
// 置換されない。既定の動作の変更(v1.1 までは <email_N> になる、またはパスワードが残る)。
func TestURLPassword(t *testing.T) {
	in := "db postgres://app:s3cret@db.example.com:5432/app\n" +
		"rds postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app\n" +
		"cache redis://:other@10.0.0.5:6379 ftp://u:a:b@host.example.org\n" +
		"web https://user:pass@10.0.0.1/ and https://taro@example.com/ and password=s3cret\n" +
		`{"origin":"https://app.example.com","email":"bob@example.com"}` + "\n"
	wantDefault := "db postgres://app:<secret_1>@db.example.com:5432/app\n" +
		"rds postgres://app:<secret_1>@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app\n" +
		"cache redis://:<secret_2>@<ipv4_private_1>:6379 ftp://u:<secret_3>@host.example.org\n" +
		"web https://user:<secret_4>@<ipv4_private_2>/ and https://<email_1>/ and password=<secret_1>\n" +
		// パスのない URL の後ろの JSON の値は、ユーザー情報として読まない(Q60)
		`{"origin":"https://app.example.com","email":"<email_2>"}` + "\n"
	if r := run(t, in, nil, "mask"); r.code != 0 || r.stdout != wantDefault {
		t.Errorf("default: %+v\nwant %q", r, wantDefault)
	}
	// aws_host も有効なら、ホスト名の情報が残る
	wantAWS := strings.Replace(wantDefault, "@mydb.cluster-c9akciq32.ap-northeast-1.rds", "@<aws_host_1>.ap-northeast-1.rds", 1)
	if r := run(t, in, nil, "mask", "--types", "default,aws"); r.code != 0 || r.stdout != wantAWS {
		t.Errorf("default,aws: %+v\nwant %q", r, wantAWS)
	}
	// secret が無効でも、メールアドレスとして扱わない(Q54)。パスワードは残る
	wantEmail := strings.NewReplacer("https://taro@example.com/", "https://<email_1>/", `"bob@example.com"`, `"<email_2>"`).Replace(in)
	if r := run(t, in, nil, "mask", "--types", "email"); r.code != 0 || r.stdout != wantEmail {
		t.Errorf("email only: %+v\nwant %q", r, wantEmail)
	}
	// restore の往復、mask・hash の冪等性
	dir := t.TempDir()
	src := writeFile(t, dir, "app.log", in)
	for _, types := range []string{"default", "default,aws"} {
		masked := run(t, "", nil, "mask", "--types", types, src)
		if back := run(t, masked.stdout, nil, "restore", "--source", src, "--types", types); back.code != 0 || back.stdout != in {
			t.Errorf("restore (%s): %+v", types, back)
		}
		if again := run(t, masked.stdout, nil, "mask", "--types", types); again.stdout != masked.stdout {
			t.Errorf("mask (%s) is not idempotent: %q", types, again.stdout)
		}
		env := map[string]string{keyEnv: "test-key"}
		h := run(t, in, env, "mask", "--mode", "hash", "--types", types)
		if h.code != 0 || strings.Contains(h.stdout, "s3cret") || strings.Contains(h.stdout, "pass@") || strings.Contains(h.stdout, "bob@") || !strings.Contains(h.stdout, ":secret_") {
			t.Fatalf("hash (%s): %+v", types, h)
		}
		if again := run(t, h.stdout, env, "mask", "--mode", "hash", "--types", types); again.stdout != h.stdout {
			t.Errorf("hash (%s) is not idempotent:\n%s\n%s", types, h.stdout, again.stdout)
		}
	}
	// --stats
	if r := run(t, in, nil, "mask", "--stats"); !strings.Contains(r.stderr, "logscrub: secret=6\n") || !strings.Contains(r.stderr, "logscrub: email=2\n") {
		t.Errorf("--stats: %q", r.stderr)
	}
	// 対応形式の一覧
	for _, args := range [][]string{{"types", "--verbose"}, {"mask", "--help"}} {
		if r := run(t, "", nil, args...); r.code != 0 || !strings.Contains(r.stdout, "URL password") {
			t.Errorf("%v lacks the URL password format", args)
		}
	}
}
