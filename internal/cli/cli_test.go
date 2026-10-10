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
		"https://user:pass@10.0.0.1/\n":                   "https://user:pass@<ipv4_private_1>/\n",
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
	for _, want := range []string{"AKIA", "ghp_", "xoxb-", "sk_live_", "AIza", "sk-", "JWT", "Bearer", "password"} {
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
	for _, want := range []string{"email", "ipv4", "ipv6", "secret", "uuid", "default"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("types lacks %q:\n%s", want, r.stdout)
		}
	}
	// uuid だけが、既定で無効
	for _, line := range strings.Split(r.stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "uuid" && fields[1] != "off" {
			t.Errorf("uuid line: %q", line)
		}
		if len(fields) >= 2 && fields[0] == "email" && fields[1] != "on" {
			t.Errorf("email line: %q", line)
		}
	}
	if strings.Contains(r.stdout, "AKIA") {
		t.Error("types without --verbose lists the secret formats")
	}
	v := run(t, "", nil, "types", "--verbose")
	if v.code != 0 || !strings.Contains(v.stdout, "AKIA") || !strings.Contains(v.stdout, "ghp_") || !strings.Contains(v.stdout, "password") {
		t.Errorf("--verbose: %+v", v)
	}
	if !strings.HasPrefix(v.stdout, r.stdout) {
		t.Error("--verbose output does not extend the plain output")
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

// ---- 標準ライブラリだけ ----

func TestGoModHasNoDependencies(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "require") {
		t.Errorf("go.mod has requirements:\n%s", b)
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
