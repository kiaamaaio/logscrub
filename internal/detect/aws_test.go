package detect

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// awsValues は、Detector を通して(kinds の種別だけで)検出した結果を、「ラベルの種別名=置換される文字列」の列で返す。
func awsValues(t *testing.T, kinds KindSet, line string) []string {
	t.Helper()
	d, err := New(Options{Kinds: kinds})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := d.Find([]byte(line), nil)
	var out []string
	for _, m := range got {
		out = append(out, m.LabelType()+"="+line[m.Start:m.End])
	}
	return out
}

var awsAccountKinds = KindSet(0).With(KindAWSAccount)

func TestAWSAccountFinderKind(t *testing.T) {
	if k := (awsAccountFinder{}).kind(); k != KindAWSAccount {
		t.Errorf("kind = %v", k)
	}
}

// cmpRange は、範囲を、開始位置、終了位置の順に比べる。
func cmpRange(a, b [2]int) int {
	if a[0] != b[0] {
		return a[0] - b[0]
	}
	return a[1] - b[1]
}

// ---- aws_account(仕様 4.4、9 章「AWS」) ----

func TestAWSAccount(t *testing.T) {
	const id = "123456789012"
	want := []string{"aws_account=" + id}
	tests := []struct {
		name string
		line string
		want []string
	}{
		// ARN: パーティションごと
		{"arn iam", "arn:aws:iam::" + id + ":role/deployer", want},
		{"arn aws-cn", "arn:aws-cn:iam::" + id + ":role/x", want},
		{"arn aws-us-gov", "arn:aws-us-gov:iam::" + id + ":role/x", want},
		{"arn aws-iso", "arn:aws-iso:iam::" + id + ":role/x", want},
		{"arn aws-iso-b", "arn:aws-iso-b:iam::" + id + ":role/x", want},
		{"arn aws-iso-e", "arn:aws-iso-e:iam::" + id + ":role/x", want},
		{"arn aws-iso-f", "arn:aws-iso-f:iam::" + id + ":role/x", want},
		{"arn aws-eusc", "arn:aws-eusc:iam::" + id + ":role/x", want},
		// ARN: リージョンあり、サービスの形、ワイルドカード
		{"arn lambda with region", "arn:aws:lambda:ap-northeast-1:" + id + ":function:x", want},
		{"arn sts", "arn:aws:sts::" + id + ":assumed-role/r/s", want},
		{"arn root", "arn:aws:iam::" + id + ":root", want},
		{"arn service with digits and hyphen", "arn:aws:s3-object-lambda:us-east-1:" + id + ":accesspoint/x", want},
		{"arn wildcard region", "arn:aws:ec2:*:" + id + ":vpc/*", want},
		{"arn wildcard service", "arn:aws:*:*:" + id + ":*", want},
		{"arn partial wildcard region", "arn:aws:ec2:us-*:" + id + ":instance/*", want},
		{"arn in json", `{"Arn":"arn:aws:iam::` + id + `:user/a"}`, want},
		{"arn after space", "assumed arn:aws:iam::" + id + ":role/x ok", want},
		{"arn after hyphen", "x-arn:aws:iam::" + id + ":role/x", want},
		{"arn after underscore", "role_arn:aws:iam::" + id + ":role/x", want}, // `arn:` の前の条件は、英数字でないことだけ
		// ECR
		{"ecr", id + ".dkr.ecr.ap-northeast-1.amazonaws.com/app:latest", want},
		{"ecr fips", id + ".dkr.ecr-fips.us-gov-west-1.amazonaws.com/app", want},
		{"ecr china", id + ".dkr.ecr.cn-north-1.amazonaws.com.cn/app", want},
		{"ecr eusc", id + ".dkr.ecr.eusc-de-east-1.amazonaws.eu/app", want},
		{"ecr docker pull", "docker pull " + id + ".dkr.ecr.us-east-1.amazonaws.com/app:1", want},
		{"ecr https", "https://" + id + ".dkr.ecr.us-east-1.amazonaws.com/v2/", want},
		{"ecr end of line", id + ".dkr.ecr.us-east-1.amazonaws.com", want},
		{"ecr with port", id + ".dkr.ecr.us-east-1.amazonaws.com:443", want},
		// SQS
		{"sqs", "https://sqs.ap-northeast-1.amazonaws.com/" + id + "/orders", want},
		{"sqs china", "https://sqs.cn-north-1.amazonaws.com.cn/" + id + "/q", want},
		{"sqs legacy region", "https://ap-northeast-1.queue.amazonaws.com/" + id + "/orders", want},
		{"sqs legacy", "https://queue.amazonaws.com/" + id + "/orders", want},
		{"sqs without scheme", "sqs.us-east-1.amazonaws.com/" + id + "/q", want},
		// 複数
		{"two forms", "arn:aws:iam::" + id + ":role/x " + id + ".dkr.ecr.us-east-1.amazonaws.com/a",
			[]string{"aws_account=" + id, "aws_account=" + id}},

		// 置換しない(受け入れ基準)
		{"arn empty account", "arn:aws:s3:::bucket", nil},
		{"arn aws managed policy", "arn:aws:iam::aws:policy/AdministratorAccess", nil},
		{"bare 12 digits", "account " + id + " was used", nil},
		{"key value", "account_id=" + id, nil},
		{"cloudtrail", `"accountId": "` + id + `"`, nil},
		// 置換しない: ARN の形
		{"arn 11 digits", "arn:aws:iam::12345678901:role/x", nil},
		{"arn 13 digits", "arn:aws:iam::1234567890123:role/x", nil},
		{"arn without colon after account", "arn:aws:iam::" + id + "/x", nil},
		{"arn account at end", "arn:aws:iam::" + id, nil},
		{"arn unknown partition", "arn:aws-xx:iam::" + id + ":role/x", nil},
		{"arn empty service", "arn:aws::us-east-1:" + id + ":x", nil},
		{"arn uppercase service", "arn:aws:IAM::" + id + ":role/x", nil},
		{"arn uppercase prefix", "ARN:aws:iam::" + id + ":role/x", nil},
		{"arn uppercase partition", "arn:AWS:iam::" + id + ":role/x", nil},
		{"arn after letter", "xarn:aws:iam::" + id + ":role/x", nil},
		{"arn after digit", "1arn:aws:iam::" + id + ":role/x", nil},
		// 置換しない: ECR の形
		{"ecr 11 digits", "12345678901.dkr.ecr.us-east-1.amazonaws.com/a", nil},
		{"ecr 13 digits", "1123456789012.dkr.ecr.us-east-1.amazonaws.com/a", nil},
		{"ecr after letter", "x" + id + ".dkr.ecr.us-east-1.amazonaws.com/a", nil},
		{"ecr after hyphen", "a-" + id + ".dkr.ecr.us-east-1.amazonaws.com/a", nil},
		{"ecr after dot", "a." + id + ".dkr.ecr.us-east-1.amazonaws.com/a", nil},
		{"ecr without region", id + ".dkr.ecr.amazonaws.com/a", nil},
		{"ecr other domain", id + ".dkr.ecr.us-east-1.example.com/a", nil},
		{"ecr iso domain", id + ".dkr.ecr.us-iso-east-1.c2s.ic.gov/a", nil},
		{"ecr then other domain", id + ".dkr.ecr.us-east-1.amazonaws.com.example.net/a", nil},
		{"ecr then letter", id + ".dkr.ecr.us-east-1.amazonaws.comx", nil},
		{"ecr uppercase", id + ".DKR.ECR.us-east-1.amazonaws.com/a", nil},
		// 置換しない: SQS の形
		{"sqs 11 digits", "https://sqs.us-east-1.amazonaws.com/12345678901/q", nil},
		{"sqs 13 digits", "https://sqs.us-east-1.amazonaws.com/1234567890123/q", nil},
		{"sqs without trailing slash", "https://sqs.us-east-1.amazonaws.com/" + id, nil},
		{"sqs without region", "https://sqs.amazonaws.com/" + id + "/q", nil},
		{"sqs other domain", "https://sqs.us-east-1.example.com/" + id + "/q", nil},
		{"sqs after letter", "https://xsqs.us-east-1.amazonaws.com/" + id + "/q", nil},
		{"sqs after dot", "https://a.sqs.us-east-1.amazonaws.com/" + id + "/q", nil},
		{"queue after hyphen", "https://my-queue.amazonaws.com/" + id + "/q", nil},
		{"queue with dotted prefix", "https://a.us-east-1.queue.amazonaws.com/" + id + "/q", nil},
		{"queue with empty region", "https://.queue.amazonaws.com/" + id + "/q", nil},
		{"queue china", "https://queue.amazonaws.com.cn/" + id + "/q", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := awsValues(t, awsAccountKinds, tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// 置換済みの形(mask のラベル、hash の出力)は、12 桁の数字でないので、再度は検出されない。
func TestAWSAccountAlreadyReplaced(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds | awsAccountKinds})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"arn:aws:iam::<aws_account_1>:role/x",
		"<aws_account_1>.dkr.ecr.us-east-1.amazonaws.com/a",
		"https://sqs.us-east-1.amazonaws.com/<aws_account_1>/q",
		"arn:aws:iam::aws_account_3f9a1c0b7d2e:role/x",
		"aws_account_3f9a1c0b7d2e.dkr.ecr.us-east-1.amazonaws.com/a",
		"https://sqs.us-east-1.amazonaws.com/aws_account_3f9a1c0b7d2e/q",
	} {
		got, kept := d.Find([]byte(line), nil)
		if len(got) != 0 || kept != 1 {
			t.Errorf("Find(%q) = %+v kept=%d, want nothing and 1 kept", line, got, kept)
		}
	}
}

// 既定の種別では、aws_account は検出しない(受け入れ基準)。
func TestAWSAccountDisabledByDefault(t *testing.T) {
	if got := awsValues(t, 0, "arn:aws:iam::123456789012:role/x"); got != nil {
		t.Errorf("default kinds: %q", got)
	}
}

// ---- 正規表現の参照実装との一致 ----

// refAWSAccountForms は、aws_account の形ごとの正規表現(仕様 4.4 から、実装の表を使わずに書いたもの)。
// 1 つ目のグループがアカウント ID。前の文字の条件と、ホスト名の末尾の条件は、refAWSAccounts で確かめる。
var (
	refPartitions      = `(?:aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f|aws-eusc)`
	refARNAccount      = regexp.MustCompile(`^arn:` + refPartitions + `:[a-z0-9*-]+:[a-z0-9*-]*:([0-9]{12}):`)
	refECRAccountForms = []*regexp.Regexp{
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com`),
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\.cn`),
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.eu`),
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr-fips\.[a-z0-9-]+\.amazonaws\.com`),
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr-fips\.[a-z0-9-]+\.amazonaws\.com\.cn`),
		regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr-fips\.[a-z0-9-]+\.amazonaws\.eu`),
	}
	refSQSAccountForms = []*regexp.Regexp{
		regexp.MustCompile(`^sqs\.[a-z0-9-]+\.(?:amazonaws\.com|amazonaws\.com\.cn|amazonaws\.eu)/([0-9]{12})/`),
		regexp.MustCompile(`^[a-z0-9-]+\.queue\.amazonaws\.com/([0-9]{12})/`),
		regexp.MustCompile(`^queue\.amazonaws\.com/([0-9]{12})/`),
	}
	refHostChar = regexp.MustCompile(`^[A-Za-z0-9_.-]$`)
)

// refAWSAccounts は、前処理を使わず、行のすべての位置で、形ごとの正規表現を試す参照実装。
// アカウント ID の範囲を、開始位置の順(重複なし)で返す。
func refAWSAccounts(line []byte) [][2]int {
	seen := map[[2]int]bool{}
	hostStart := func(p int) bool { return p == 0 || !refHostChar.Match(line[p-1:p]) }
	for p := 0; p < len(line); p++ {
		if p == 0 || !refIsAlnum(line[p-1]) {
			if loc := refARNAccount.FindSubmatchIndex(line[p:]); loc != nil {
				seen[[2]int{p + loc[2], p + loc[3]}] = true
			}
		}
		if !hostStart(p) {
			continue
		}
		for _, re := range refECRAccountForms {
			if loc := re.FindSubmatchIndex(line[p:]); loc != nil && refHostEnd.Match(line[p+loc[1]:]) {
				seen[[2]int{p + loc[2], p + loc[3]}] = true
			}
		}
		for _, re := range refSQSAccountForms {
			if loc := re.FindSubmatchIndex(line[p:]); loc != nil {
				seen[[2]int{p + loc[2], p + loc[3]}] = true
			}
		}
	}
	var out [][2]int
	for r := range seen {
		out = append(out, r)
	}
	slices.SortFunc(out, cmpRange)
	return out
}

// 乱数で作った行で、aws_account の検出が、参照実装と一致すること。
// 行は「前の文字 + 形(の変形)+ 後ろの文字」の組を並べて作る。
func TestAWSAccountMatchesRegexpReference(t *testing.T) {
	ids := []string{"123456789012", "123456789012", "000000000000", "12345678901", "1234567890123", "aws", "", "<aws_account_1>"}
	around := []string{"", "", " ", "/", "\"", ":", ".", "-", "_", "x", "0", "https://", "あ", "\xff"}
	regions := []string{"", "ap-northeast-1", "us-east-1", "*", "us-*", "AP", "a.b"}
	partitions := []string{"aws", "aws-cn", "aws-us-gov", "aws-iso-b", "aws-eusc", "aws-xx", "AWS", ""}
	services := []string{"iam", "lambda", "s3-object-lambda", "*", "", "IAM"}
	domains := []string{"amazonaws.com", "amazonaws.com.cn", "amazonaws.eu", "example.com", "amazonaws.com.example.net", "amazonaws.comx", "c2s.ic.gov"}
	rng := rand.New(rand.NewPCG(51, 52))
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }
	found := 0
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			sb.WriteString(pick(around))
			switch rng.IntN(5) {
			case 0:
				sb.WriteString(pick([]string{"arn:", "arn:", "ARN:", "xarn:"}) + pick(partitions) + ":" + pick(services) + ":" +
					pick(regions) + ":" + pick(ids) + pick([]string{":role/x", ":", "/x", ""}))
			case 1:
				sb.WriteString(pick(ids) + pick([]string{".dkr.ecr.", ".dkr.ecr-fips.", ".dkr.ecr", ".DKR.ECR."}) + pick(regions) + "." +
					pick(domains) + pick([]string{"/app", "", ":443", "."}))
			case 2:
				sb.WriteString("sqs." + pick(regions) + "." + pick(domains) + "/" + pick(ids) + pick([]string{"/q", "", "/"}))
			case 3:
				sb.WriteString(pick([]string{"", "ap-northeast-1.", "a.us-east-1.", ".", "my-"}) + "queue.amazonaws.com" +
					pick([]string{"", ".cn"}) + "/" + pick(ids) + pick([]string{"/q", ""}))
			default:
				sb.WriteString(pick(ids))
			}
			sb.WriteString(pick(around))
		}
		line := []byte(sb.String())
		want := refAWSAccounts(line)
		var got [][2]int
		for _, m := range (awsAccountFinder{}).find(line, nil) {
			if m.Kind != KindAWSAccount || m.Class != ClassNone {
				t.Fatalf("unexpected match %+v", m)
			}
			got = append(got, [2]int{m.Start, m.End})
		}
		slices.SortFunc(got, cmpRange)
		got = slices.Compact(got)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		found += len(got)
	}
	if found < 1500 {
		t.Errorf("only %d account IDs were found; the generator does not exercise the rules", found)
	}
}

// ---- 長い行 ----

func TestAWSAccountFinderOnLongLines(t *testing.T) {
	for _, line := range []string{
		strings.Repeat("arn:", 300000),
		strings.Repeat("arn:aws:iam::", 100000),
		strings.Repeat(".dkr.ecr", 150000),
		strings.Repeat("1", 1<<20) + ".dkr.ecr.us-east-1.amazonaws.com",
		strings.Repeat("sqs.", 300000),
		strings.Repeat("queue.amazonaws.com", 60000),
		strings.Repeat("a", 1<<20) + ".queue.amazonaws.com/123456789012/",
		strings.Repeat("-", 1<<20) + ".queue.amazonaws.com/123456789012/",
	} {
		_ = (awsAccountFinder{}).find([]byte(line), nil)
	}
	if got := (awsAccountFinder{}).find([]byte(strings.Repeat("arn:aws:iam::123456789012:root ", 30000)), nil); len(got) != 30000 {
		t.Errorf("many arns: got %d matches, want 30000", len(got))
	}
}

// ---- ベンチマーク ----

func BenchmarkAWSAccountFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (awsAccountFinder{}).find(line, dst[:0])
		}
	}
}

// nextAmazonaws は、`.amazonaws.` の位置を、左から順に、重なりも含めて返す。
func TestNextAmazonaws(t *testing.T) {
	all := func(line string) []int {
		var out []int
		for pos := 0; ; {
			a := nextAmazonaws([]byte(line), pos)
			if a < 0 {
				return out
			}
			out = append(out, a)
			pos = a + amazonawsNext
		}
	}
	for _, tt := range []struct {
		line string
		want []int
	}{
		{"", nil},
		{"zzz lazy amazonaws", nil},
		{".amazonaws.", []int{0}},
		{"x.amazonaws.com", []int{1}},
		{".amazonaws.amazonaws.", []int{0, 10}},
		{"zone.amazonaws.com size.amazonaws.eu", []int{4, 23}},
		{".AMAZONAWS.com .amaZonaws.com .amazonawscom", nil},
		{".amazonaws", nil},
	} {
		if got := all(tt.line); !slices.Equal(got, tt.want) {
			t.Errorf("nextAmazonaws(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// ---- aws_s3_bucket(仕様 4.4、9 章「AWS」、Q43〜Q46) ----

var awsS3BucketKinds = KindSet(0).With(KindAWSS3Bucket)

func TestAWSS3BucketFinderKind(t *testing.T) {
	if k := (awsS3BucketFinder{}).kind(); k != KindAWSS3Bucket {
		t.Errorf("kind = %v", k)
	}
}

func TestAWSS3Bucket(t *testing.T) {
	b := func(name string) []string { return []string{"aws_s3_bucket=" + name} }
	b63 := strings.Repeat("a", 63)
	b64 := strings.Repeat("a", 64)
	tests := []struct {
		name string
		line string
		want []string
	}{
		// s3:// 形式
		{"s3", "s3://my-bucket/logs/a.gz", b("my-bucket")},
		{"s3a", "s3a://my-bucket/path", b("my-bucket")},
		{"s3n", "s3n://my-bucket/path", b("my-bucket")},
		{"s3 bucket only", "s3://my-bucket", b("my-bucket")},
		{"s3 with dots", "s3://logs.example.com/x", b("logs.example.com")},
		{"s3 in quotes", `"s3://my-bucket"`, b("my-bucket")},
		{"s3 after space", "copy s3://my-bucket/a to s3://other-bucket/b", []string{"aws_s3_bucket=my-bucket", "aws_s3_bucket=other-bucket"}},
		{"s3 sentence end", "see s3://my-bucket.", b("my-bucket")},
		{"s3 followed by colon", "s3://my-bucket:x", b("my-bucket")},
		{"s3 after hyphen", "x-s3://my-bucket/", b("my-bucket")},
		// バーチャルホスト形式
		{"vhost", "https://my-bucket.s3.ap-northeast-1.amazonaws.com/a.txt", b("my-bucket")},
		{"vhost global", "https://my-bucket.s3.amazonaws.com/a.txt", b("my-bucket")},
		{"vhost legacy region", "my-bucket.s3-us-west-2.amazonaws.com", b("my-bucket")},
		{"vhost dualstack", "my-bucket.s3.dualstack.us-east-1.amazonaws.com/x", b("my-bucket")},
		{"vhost fips", "my-bucket.s3-fips.us-gov-west-1.amazonaws.com/x", b("my-bucket")},
		{"vhost fips dualstack", "my-bucket.s3-fips.dualstack.us-east-1.amazonaws.com/x", b("my-bucket")},
		{"vhost website dash", "my-bucket.s3-website-us-east-1.amazonaws.com", b("my-bucket")},
		{"vhost website dot", "my-bucket.s3-website.eu-west-1.amazonaws.com", b("my-bucket")},
		{"vhost accelerate", "my-bucket.s3-accelerate.amazonaws.com/x", b("my-bucket")},
		{"vhost accelerate dualstack", "my-bucket.s3-accelerate.dualstack.amazonaws.com/x", b("my-bucket")},
		{"vhost china", "my-bucket.s3.cn-north-1.amazonaws.com.cn/x", b("my-bucket")},
		{"vhost eusc", "my-bucket.s3.eusc-de-east-1.amazonaws.eu/x", b("my-bucket")},
		{"vhost bucket with dots", "https://logs.example.com.s3.amazonaws.com/x", b("logs.example.com")},
		{"vhost fqdn trailing dot", "my-bucket.s3.amazonaws.com. 300 IN CNAME", b("my-bucket")},
		{"vhost with port", "my-bucket.s3.amazonaws.com:443", b("my-bucket")},
		// Q43: 区切り方が 2 通りある場合は、バケット名を最も長く取る
		{"vhost longest bucket", "logs.s3.backup.s3.amazonaws.com", b("logs.s3.backup")},
		{"vhost longest bucket invalid", "ab.s3.backup.s3-x.s3.amazonaws.com", b("ab.s3.backup.s3-x")},
		{"vhost longest bucket no retry", "x..y.s3.backup.s3.amazonaws.com", nil},
		// 最も長いバケット名(64 文字)が規則に合わないので、短い区切り方(61 文字 + `s3.s3`)に戻らず、置換しない
		{"vhost no retry with shorter valid split", strings.Repeat("a", 61) + ".s3.s3.amazonaws.com", nil},
		// パス形式
		{"path", "https://s3.ap-northeast-1.amazonaws.com/my-bucket/a.txt", b("my-bucket")},
		{"path global", "https://s3.amazonaws.com/my-bucket/a.txt", b("my-bucket")},
		{"path bucket only", "https://s3.amazonaws.com/my-bucket", b("my-bucket")},
		{"path legacy region", "s3-us-west-2.amazonaws.com/my-bucket?list-type=2", b("my-bucket")},
		{"path dualstack", "https://s3.dualstack.us-east-1.amazonaws.com/my-bucket/x", b("my-bucket")},
		{"path china", "https://s3.cn-north-1.amazonaws.com.cn/my-bucket/x", b("my-bucket")},
		{"path bucket with dots", "https://s3.amazonaws.com/logs.example.com/x", b("logs.example.com")},
		{"path sentence end", "at https://s3.amazonaws.com/my-bucket.", b("my-bucket")},
		// ARN
		{"arn", "arn:aws:s3:::my-bucket/logs/*", b("my-bucket")},
		{"arn bucket only", "arn:aws:s3:::my-bucket", b("my-bucket")},
		{"arn china", "arn:aws-cn:s3:::my-bucket", b("my-bucket")},
		{"arn iso", "arn:aws-iso-b:s3:::my-bucket", b("my-bucket")},
		{"arn wildcard", `"Resource": "arn:aws:s3:::my-bucket*"`, b("my-bucket")},
		{"arn in json", `{"Resource":"arn:aws:s3:::my-bucket"}`, b("my-bucket")},
		{"arn after hyphen", "x-arn:aws:s3:::my-bucket", b("my-bucket")},
		// 長さの境界
		{"3 chars", "s3://abc/", b("abc")},
		{"63 chars", "s3://" + b63 + "/", b(b63)},
		{"63 chars vhost", b63 + ".s3.amazonaws.com", b(b63)},
		{"63 chars and sentence end", "s3://" + b63 + ".", b(b63)},
		// 複数の形で、同じバケット
		{"same bucket", "s3://my-bucket/a https://my-bucket.s3.amazonaws.com/a arn:aws:s3:::my-bucket",
			[]string{"aws_s3_bucket=my-bucket", "aws_s3_bucket=my-bucket", "aws_s3_bucket=my-bucket"}},

		// 置換しない: バケット名の規則(受け入れ基準)
		{"2 chars", "s3://ab/", nil},
		{"64 chars", "s3://" + b64 + "/", nil},
		{"64 chars vhost", b64 + ".s3.amazonaws.com", nil},
		{"uppercase", "s3://My-Bucket/", nil},
		{"uppercase inside", "s3://myBucket/", nil},
		{"underscore", "s3://abc_def/", nil},
		{"underscore vhost", "abc_def.s3.amazonaws.com", nil},
		{"underscore path", "s3.amazonaws.com/abc_def/", nil},
		{"underscore arn", "arn:aws:s3:::abc_def", nil},
		{"starts with dot", "s3://.abc/", nil},
		{"starts with hyphen", "s3://-abc/", nil},
		{"ends with hyphen", "s3://abc-/", nil},
		{"ends with two dots", "s3://abc../", nil},
		{"two dots", "s3://a..bc/", nil},
		{"ip form", "s3://192.168.5.4/", nil},
		{"ip form out of range", "s3://999.1.1.1/", nil},
		{"ip form vhost", "192.168.5.4.s3.amazonaws.com", nil},
		// 数字の組が 4 つでないものは、IP アドレスの形ではない(Q45)
		{"three numbers", "s3://1.2.3/", b("1.2.3")},
		{"five numbers", "s3://1.2.3.4.5/", b("1.2.3.4.5")},
		// 置換しない: 形
		{"scheme after letter", "xs3://my-bucket/", nil},
		{"scheme uppercase", "S3://my-bucket/", nil},
		{"other scheme", "s4://my-bucket/", nil},
		{"vhost after underscore", "x_my-bucket.s3.amazonaws.com", nil},
		{"vhost other domain", "my-bucket.s3.example.com", nil},
		{"vhost then other domain", "my-bucket.s3.amazonaws.com.example.net", nil},
		{"vhost then letter", "my-bucket.s3.amazonaws.comx", nil},
		{"vhost uppercase endpoint", "my-bucket.S3.amazonaws.com", nil},
		{"vhost not an endpoint", "my-bucket.s4.amazonaws.com", nil},
		{"vhost ec2", "ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com", nil},
		{"vhost sqs", "sqs.us-east-1.amazonaws.com/123456789012/q", nil},
		{"path after letter", "xs3.amazonaws.com/my-bucket/", nil},
		{"path after dot", "a.s3.amazonaws.com/b/", nil}, // バーチャルホスト形式のバケット `a`(2 文字)は規則に合わない
		{"arn after letter", "xarn:aws:s3:::my-bucket", nil},
		{"arn unknown partition", "arn:aws-xx:s3:::my-bucket", nil},
		// アクセスポイントは対象外
		{"access point host", "my-ap-123456789012.s3-accesspoint.us-east-1.amazonaws.com", nil},
		{"access point arn", "arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap", nil},
		{"object lambda host", "my-ap-123456789012.s3-object-lambda.us-east-1.amazonaws.com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := awsValues(t, awsS3BucketKinds, tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// `s3://10.0.0.1/` のような IP の形は、バケット名でなく、IP アドレスとして置換される。
func TestAWSS3BucketIPForm(t *testing.T) {
	kinds := DefaultKinds | awsS3BucketKinds
	if got := awsValues(t, kinds, "s3://10.0.0.1/x"); !slices.Equal(got, []string{"ipv4_private=10.0.0.1"}) {
		t.Errorf("got %q", got)
	}
}

// 置換済みの形(mask のラベル、hash の出力)は、再度は検出されない。
func TestAWSS3BucketAlreadyReplaced(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds | awsS3BucketKinds | awsAccountKinds})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"s3://<aws_s3_bucket_1>/logs",
		"https://<aws_s3_bucket_1>.s3.amazonaws.com/a",
		"https://s3.amazonaws.com/<aws_s3_bucket_1>/a",
		"arn:aws:s3:::<aws_s3_bucket_1>/*",
		"s3://aws_s3_bucket_3f9a1c0b7d2e/logs",
		"https://aws_s3_bucket_3f9a1c0b7d2e.s3.amazonaws.com/a",
		"https://s3.amazonaws.com/aws_s3_bucket_3f9a1c0b7d2e/a",
		"arn:aws:s3:::aws_s3_bucket_3f9a1c0b7d2e/*",
	} {
		got, kept := d.Find([]byte(line), nil)
		if len(got) != 0 || kept != 1 {
			t.Errorf("Find(%q) = %+v kept=%d, want nothing and 1 kept", line, got, kept)
		}
	}
}

func TestLooksLikeIPv4(t *testing.T) {
	for _, s := range []string{"192.168.5.4", "999.1.1.1", "1.2.3.4", "0000.0.0.0"} {
		if !looksLikeIPv4([]byte(s)) {
			t.Errorf("%q", s)
		}
	}
	for _, s := range []string{"", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3", "1..2.3", "1.2.3.a", "a.b.c.d", "1-2-3-4"} {
		if looksLikeIPv4([]byte(s)) {
			t.Errorf("%q", s)
		}
	}
}

// ---- aws_s3_bucket の正規表現の参照実装との一致 ----

var (
	refEndpoints = `(?:s3|s3\.[a-z0-9-]+|s3-[a-z0-9-]+|s3\.dualstack\.[a-z0-9-]+|s3-fips\.[a-z0-9-]+|s3-fips\.dualstack\.[a-z0-9-]+|` +
		`s3-website-[a-z0-9-]+|s3-website\.[a-z0-9-]+|s3-accelerate|s3-accelerate\.dualstack)`
	refDomains     = `(?:amazonaws\.com|amazonaws\.com\.cn|amazonaws\.eu)`
	refHostEndPart = `(?:$|[^A-Za-z0-9_.-]|\.(?:$|[^A-Za-z0-9]))`
	// バーチャルホスト形式: バケット名の部分(1 つ目のグループ)を、最も長く取る(最長一致。Q43)
	refS3VHost   = regexp.MustCompile(`^([a-z0-9.-]+)\.` + refEndpoints + `\.` + refDomains + refHostEndPart)
	refS3Path    = regexp.MustCompile(`^` + refEndpoints + `\.` + refDomains + `/`)
	refS3Scheme  = regexp.MustCompile(`^s3[an]?://`)
	refS3ARN     = regexp.MustCompile(`^arn:` + refPartitions + `:s3:::`)
	refBucketRun = regexp.MustCompile(`^[a-z0-9.-]*`)
	refBucket    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	refIPForm    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
	refAfter     = regexp.MustCompile(`^[A-Za-z0-9_]`)
)

func refValidBucket(b string) bool {
	return refBucket.MatchString(b) && !strings.Contains(b, "..") && !refIPForm.MatchString(b)
}

// refBucketAt は、s から始まるバケット名(`s3://`・パス形式・ARN)の範囲を返す。
func refBucketAt(line []byte, s int) ([2]int, bool) {
	e := s + len(refBucketRun.Find(line[s:]))
	if refAfter.Match(line[e:]) {
		return [2]int{}, false
	}
	if e > s && line[e-1] == '.' {
		e--
	}
	return [2]int{s, e}, refValidBucket(string(line[s:e]))
}

// refAWSS3Buckets は、前処理を使わず、行のすべての位置で、形ごとの正規表現を試す参照実装。
func refAWSS3Buckets(line []byte) [][2]int {
	seen := map[[2]int]bool{}
	for p := 0; p < len(line); p++ {
		if p == 0 || !refIsAlnum(line[p-1]) {
			if loc := refS3Scheme.FindIndex(line[p:]); loc != nil {
				if r, ok := refBucketAt(line, p+loc[1]); ok {
					seen[r] = true
				}
			}
			if loc := refS3ARN.FindIndex(line[p:]); loc != nil {
				if r, ok := refBucketAt(line, p+loc[1]); ok {
					seen[r] = true
				}
			}
		}
		if p > 0 && refHostChar.Match(line[p-1:p]) {
			continue
		}
		if loc := refS3Path.FindIndex(line[p:]); loc != nil {
			if r, ok := refBucketAt(line, p+loc[1]); ok {
				seen[r] = true
			}
		}
		if loc := refS3VHost.FindSubmatchIndex(line[p:]); loc != nil && refValidBucket(string(line[p+loc[2]:p+loc[3]])) {
			seen[[2]int{p + loc[2], p + loc[3]}] = true
		}
	}
	var out [][2]int
	for r := range seen {
		out = append(out, r)
	}
	slices.SortFunc(out, cmpRange)
	return out
}

// 乱数で作った行で、aws_s3_bucket の検出が、参照実装と一致すること。
func TestAWSS3BucketMatchesRegexpReference(t *testing.T) {
	buckets := []string{"my-bucket", "my-bucket", "logs.example.com", "abc", "ab", strings.Repeat("b", 63), strings.Repeat("c", 64),
		"My-Bucket", "abc_def", "-abc", "abc-", "a..b", "192.168.5.4", "999.1.1.1", "1.2.3", "s3", "logs.s3.backup", "",
		"<aws_s3_bucket_1>", "aws_s3_bucket_3f9a1c0b7d2e", "bucket.", "x.s3", strings.Repeat("d", 61) + ".s3"}
	endpoints := []string{"s3", "s3", "s3.ap-northeast-1", "s3-us-west-2", "s3.dualstack.us-east-1", "s3-fips.us-gov-west-1",
		"s3-fips.dualstack.us-east-1", "s3-website-us-east-1", "s3-website.eu-west-1", "s3-accelerate", "s3-accelerate.dualstack",
		"s3-accesspoint.us-east-1", "s3.backup", "S3", "s4", "", "s3.a.b.c"}
	domains := []string{"amazonaws.com", "amazonaws.com", "amazonaws.com.cn", "amazonaws.eu", "example.com",
		"amazonaws.com.example.net", "amazonaws.comx"}
	around := []string{"", "", " ", "/", "\"", ":", ".", "-", "_", "x", "X", "0", "*", "https://", "あ", "\xff"}
	after := []string{"", "/key", "/", ".", "_x", "Q", ":443", "*", "?x=1", " "}
	rng := rand.New(rand.NewPCG(61, 62))
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }
	found := 0
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			sb.WriteString(pick(around))
			switch rng.IntN(4) {
			case 0:
				sb.WriteString(pick([]string{"s3://", "s3a://", "s3n://", "S3://", "xs3://", "s4://", "://"}) + pick(buckets) + pick(after))
			case 1:
				sb.WriteString(pick(buckets) + "." + pick(endpoints) + "." + pick(domains) + pick(after))
			case 2:
				sb.WriteString(pick(endpoints) + "." + pick(domains) + pick([]string{"/", "/", ""}) + pick(buckets) + pick(after))
			default:
				sb.WriteString(pick([]string{"arn:aws:s3:::", "arn:aws-cn:s3:::", "xarn:aws:s3:::", "arn:aws-xx:s3:::",
					"arn:aws:s3:us-east-1:123456789012:"}) + pick(buckets) + pick(after))
			}
			sb.WriteString(pick(around))
		}
		line := []byte(sb.String())
		want := refAWSS3Buckets(line)
		var got [][2]int
		for _, m := range (awsS3BucketFinder{}).find(line, nil) {
			if m.Kind != KindAWSS3Bucket || m.Class != ClassNone {
				t.Fatalf("unexpected match %+v", m)
			}
			got = append(got, [2]int{m.Start, m.End})
		}
		slices.SortFunc(got, cmpRange)
		got = slices.Compact(got)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		found += len(got)
	}
	if found < 3000 {
		t.Errorf("only %d bucket names were found; the generator does not exercise the rules", found)
	}
}

func TestAWSS3BucketFinderOnLongLines(t *testing.T) {
	for _, line := range []string{
		strings.Repeat("s3://", 200000),
		strings.Repeat("://", 300000),
		strings.Repeat(".amazonaws.com", 70000),
		strings.Repeat(".amazonaws.com/", 70000),
		strings.Repeat("a", 1<<20) + ".s3.amazonaws.com",
		strings.Repeat("a.", 1<<19) + "s3.amazonaws.com",
		"s3.amazonaws.com/" + strings.Repeat("a", 1<<20),
		"s3://" + strings.Repeat("a", 1<<20),
		strings.Repeat(":s3:::", 150000),
		strings.Repeat("arn:aws:s3:::", 70000),
		strings.Repeat("s3.s3.", 1<<17) + "amazonaws.com",
	} {
		_ = (awsS3BucketFinder{}).find([]byte(line), nil)
	}
	if got := (awsS3BucketFinder{}).find([]byte(strings.Repeat("s3://my-bucket/x ", 30000)), nil); len(got) != 30000 {
		t.Errorf("many buckets: got %d matches, want 30000", len(got))
	}
}

func BenchmarkAWSS3BucketFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (awsS3BucketFinder{}).find(line, dst[:0])
		}
	}
}
