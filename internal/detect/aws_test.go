package detect

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
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
		// S3 Control(v1.2)
		{"s3 control", id + ".s3-control.ap-northeast-1.amazonaws.com", want},
		{"s3 control dualstack", id + ".s3-control.dualstack.us-east-1.amazonaws.com", want},
		{"s3 control fips", id + ".s3-control-fips.us-gov-west-1.amazonaws.com", want},
		{"s3 control fips dualstack", id + ".s3-control-fips.dualstack.us-east-1.amazonaws.com", want},
		{"s3 control china", id + ".s3-control.cn-north-1.amazonaws.com.cn", want},
		{"s3 control eusc", id + ".s3-control.eusc-de-east-1.amazonaws.eu", want},
		{"s3 control https", "https://" + id + ".s3-control.us-east-1.amazonaws.com/v20180820/configuration/publicAccessBlock", want},
		{"s3 control with port", id + ".s3-control.us-east-1.amazonaws.com:443", want},
		{"s3 control and ecr", id + ".s3-control.us-east-1.amazonaws.com " + id + ".dkr.ecr.us-east-1.amazonaws.com/a",
			[]string{"aws_account=" + id, "aws_account=" + id}},
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
		{"s3 control 11 digits", "12345678901.s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control 13 digits", "1123456789012.s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control after letter", "x" + id + ".s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control after hyphen", "a-" + id + ".s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control after dot", "a." + id + ".s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control without region", id + ".s3-control.amazonaws.com", nil},
		{"s3 control other domain", id + ".s3-control.us-east-1.example.com", nil},
		{"s3 control then other domain", id + ".s3-control.us-east-1.amazonaws.com.example.net", nil},
		{"s3 control then letter", id + ".s3-control.us-east-1.amazonaws.comx", nil},
		{"s3 control uppercase", id + ".S3-CONTROL.us-east-1.amazonaws.com", nil},
		{"s3 control unknown variant", id + ".s3-control-xx.us-east-1.amazonaws.com", nil},
		{"s3 control api endpoint", "s3-control.us-east-1.amazonaws.com", nil},
		{"s3 control api endpoint with path", "https://s3-control.us-east-1.amazonaws.com/v20180820/" + id, nil},
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
		"<aws_account_1>.s3-control.us-east-1.amazonaws.com",
		"aws_account_3f9a1c0b7d2e.s3-control.dualstack.us-east-1.amazonaws.com",
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
	// refS3ControlAccountForms は、S3 Control(v1.2)。仕様 4.4 の 4 つの語 × 3 つのドメイン
	refS3ControlAccountForms = func() []*regexp.Regexp {
		var out []*regexp.Regexp
		for _, w := range []string{`s3-control`, `s3-control\.dualstack`, `s3-control-fips`, `s3-control-fips\.dualstack`} {
			for _, d := range []string{`amazonaws\.com`, `amazonaws\.com\.cn`, `amazonaws\.eu`} {
				out = append(out, regexp.MustCompile(`^([0-9]{12})\.`+w+`\.[a-z0-9-]+\.`+d))
			}
		}
		return out
	}()
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
		for _, re := range append(slices.Clone(refECRAccountForms), refS3ControlAccountForms...) {
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
				sb.WriteString(pick(ids) + pick([]string{".dkr.ecr.", ".dkr.ecr-fips.", ".dkr.ecr", ".DKR.ECR.", ".s3-control.", ".s3-control.dualstack.",
					".s3-control-fips.", ".s3-control-fips.dualstack.", ".s3-control.dualstack", ".S3-CONTROL.", ".s3-control-fips"}) + pick(regions) + "." +
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
		strings.Repeat(".s3-control.dualstack", 100000),
		strings.Repeat("1", 1<<20) + ".s3-control.us-east-1.amazonaws.com",
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
		// オブジェクトキーの中のエンドポイントも、前が `/`(英数字・`-`・`_`・`.` でない)なので、パス形式として読む
		// (仕様の条件どおり。隠す側にずれるだけなので、そのままにする)
		{"path inside vhost key", "https://my-bucket.s3.us-east-1.amazonaws.com/s3.us-east-1.amazonaws.com/other",
			[]string{"aws_s3_bucket=my-bucket", "aws_s3_bucket=other"}},
		{"path inside path key", "https://s3.amazonaws.com/s3.amazonaws.com/inner-bucket",
			[]string{"aws_s3_bucket=s3.amazonaws.com", "aws_s3_bucket=inner-bucket"}},
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

// ---- aws_host(仕様 4.5、9 章「AWS のホスト名」) ----

var awsHostKinds = KindSet(0).With(KindAWSHost)

func TestAWSHostFinderKind(t *testing.T) {
	if k := (awsHostFinder{}).kind(); k != KindAWSHost {
		t.Errorf("kind = %v", k)
	}
}

// 仕様 4.5 の表の各サービスの例(利用者ごとの部分、末尾の形)。
var awsHostExamples = []struct{ user, tail string }{
	{"my-alb-1234567890", ".ap-northeast-1.elb.amazonaws.com"},
	{"my-nlb-0123456789abcdef", ".elb.ap-northeast-1.amazonaws.com"},
	{"a1b2c3d4e5", ".execute-api.ap-northeast-1.amazonaws.com"},
	{"abcdefghij0123456789klmnop", ".lambda-url.ap-northeast-1.on.aws"},
	{"d111111abcdef8", ".cloudfront.net"},
	{"a1234567890abcdef", ".awsglobalaccelerator.com"},
	{"0123456789ABCDEF0123456789ABCDEF.gr7", ".ap-northeast-1.eks.amazonaws.com"},
	{"mydb.cluster-c9akciq32", ".ap-northeast-1.rds.amazonaws.com"},
	{"my-cluster.c9akciq32", ".ap-northeast-1.redshift.amazonaws.com"},
	{"default.123456789012", ".ap-northeast-1.redshift-serverless.amazonaws.com"},
	{"search-my-domain-abcdefghij", ".ap-northeast-1.es.amazonaws.com"},
	{"abcdefghij0123456789", ".ap-northeast-1.aoss.amazonaws.com"},
	{"b-1-public.my-cluster.abc123.c2", ".kafka.ap-northeast-1.amazonaws.com"},
	{"b-1234abcd-12ab-34cd-56ef-1234567890ab-1", ".mq.ap-northeast-1.amazonaws.com"},
	{"b-1234abcd-12ab-34cd-56ef-1234567890ab-1", ".mq.ap-northeast-1.on.aws"},
	{"s-0123456789abcdef0", ".server.transfer.ap-northeast-1.amazonaws.com"},
	{"abcdefghijklmnopqrstuvwxyz", ".appsync-api.ap-northeast-1.amazonaws.com"},
	{"abcdefghijklmnopqrstuvwxyz", ".appsync-realtime-api.ap-northeast-1.amazonaws.com"},
	{"my-app", ".auth.ap-northeast-1.amazoncognito.com"},
	{"a1b2c3d4e5f6g7-ats", ".iot.ap-northeast-1.amazonaws.com"},
	{"abcdefghij", ".ap-northeast-1.awsapprunner.com"},
	{"main.d1a2b3c4d5e6f7", ".amplifyapp.com"},
	{"my-env", ".ap-northeast-1.elasticbeanstalk.com"},
	{"f5lnz-0khrm-nt2u3-gyqqt-nbdl5", ".ap-southeast-2.ip.aws"},
	{"f5lnz-0khrm-nt2u3-gyqqt-nbdl5-q3cdpO", ".ap-southeast-2.ip.aws"},
}

func TestAWSHost(t *testing.T) {
	for _, ex := range awsHostExamples {
		line := "conn " + ex.user + ex.tail + " ok"
		want := []string{"aws_host=" + ex.user}
		if got := awsValues(t, awsHostKinds, line); !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", line, got, want)
		}
	}
	// リージョン・ドメインの組み合わせ(Q40)
	for _, tc := range []struct{ line, want string }{
		{"x.us-gov-west-1.rds.amazonaws.com", "x"},
		{"x.cn-north-1.rds.amazonaws.com.cn", "x"},
		{"x.eusc-de-east-1.rds.amazonaws.eu", "x"},
		{"x.mars-1.rds.amazonaws.com", "x"},
		{"x.elb.cn-north-1.amazonaws.com.cn", "x"},
		{"x.kafka.eusc-de-east-1.amazonaws.eu", "x"},
		{"x.ap-northeast-1.rds.amazonaws.com:5432/app", "x"},
	} {
		if got := awsValues(t, awsHostKinds, tc.line); !slices.Equal(got, []string{"aws_host=" + tc.want}) {
			t.Errorf("%q: got %q", tc.line, got)
		}
	}
	// 置換する範囲は、利用者ごとの部分だけ(サービス名・リージョン・ドメインは残る)
	d, err := New(Options{Kinds: awsHostKinds})
	if err != nil {
		t.Fatal(err)
	}
	line := "host=mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com port=5432"
	got, _ := d.Find([]byte(line), nil)
	if len(got) != 1 || got[0].Start != 5 || line[got[0].Start:got[0].End] != "mydb.cluster-c9akciq32" || got[0].Kind != KindAWSHost {
		t.Errorf("got %+v", got)
	}
}

// 複数の末尾の形が当てはまる場合は、長いほうの形を採る(`.<リージョン>.elasticbeanstalk.com`)。
// 長い形の利用者ごとの部分が規則に合わないときは、短い形に戻る。
func TestAWSHostLongerTailWins(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"my-env.ap-northeast-1.elasticbeanstalk.com", "my-env"},
		{"my-env.elasticbeanstalk.com", "my-env"},
		{"ap-northeast-1.elasticbeanstalk.com", "ap-northeast-1"}, // 長い形は利用者ごとの部分が空
		{"a.b.ap-northeast-1.elasticbeanstalk.com", "a.b"},
		{"-x.ap-northeast-1.elasticbeanstalk.com", ""}, // どちらの形も先頭が `-`
		{"x_.ap-northeast-1.elasticbeanstalk.com", ""},
	} {
		var want []string
		if tc.want != "" {
			want = []string{"aws_host=" + tc.want}
		}
		if got := awsValues(t, awsHostKinds, tc.line); !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, want)
		}
	}
}

// 除外: API のエンドポイント、表にない形、大文字の決まった部分、末尾の形の後ろの文字、独自のドメイン。
func TestAWSHostRejects(t *testing.T) {
	for _, line := range []string{
		// AWS 自体の API のエンドポイント(利用者ごとの部分がない)
		"rds.ap-northeast-1.amazonaws.com",
		"https://kafka.ap-northeast-1.amazonaws.com/",
		"https://elasticloadbalancing.ap-northeast-1.amazonaws.com",
		"https://iot.ap-northeast-1.amazonaws.com",
		"mq.ap-northeast-1.amazonaws.com",
		// IoT の AWS 共通のエンドポイント(Q57)
		"data-ats.iot.us-east-1.amazonaws.com",
		// cloudfront.net だけ、表にない形、独自のドメイン
		"cloudfront.net", ".cloudfront.net", "https://cloudfront.net/x",
		"x.ap-northeast-1.cache.amazonaws.com", "mydb.example.com", "db.example.com",
		"x.rds.amazonaws.com", "x.ap-northeast-1.rds.example.com", "x.ap-northeast-1.rds.amazonaws.org",
		// VPC の中からしかアクセスできないサービス、api.aws の形、v1.2 の対象外の新しい形(Q49、Q50、Q59)
		"x.ap-northeast-1.api.aws", "vpce-0123456789abcdef0-abcdefgh.sqs.ap-northeast-1.vpce.amazonaws.com",
		"abcdefghij.aoss.ap-northeast-1.on.aws", "my-app.auth-fips.us-east-1.amazoncognito.com",
		// 決まった部分が大文字
		"X.CLOUDFRONT.NET", "x.ap-northeast-1.RDS.amazonaws.com", "x.AP-NORTHEAST-1.rds.amazonaws.com", "x.ap-northeast-1.rds.AMAZONAWS.com",
		// 末尾の形の後ろ(Q41)
		"x.cloudfront.net.example.org", "x.cloudfront.netx", "x.cloudfront.net-x", "x.cloudfront.net_x",
		"x.ap-northeast-1.rds.amazonaws.com.example.net", "x.ap-northeast-1.rds.amazonaws.comx",
		// 利用者ごとの部分の条件
		".d111111abcdef8.cloudfront.net.cloudfront.net", "-x.cloudfront.net", "x-.cloudfront.net", "a..b.cloudfront.net",
		"_x.cloudfront.net", "aws_host_3f9a1c0b7d2e.ap-northeast-1.rds.amazonaws.com",
		"<aws_host_1>.ap-northeast-1.rds.amazonaws.com",
		// 他の種別のホスト名(EC2、S3、ECR、SQS、S3 Control)
		"ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com", "ec2-54-250-1-2.compute-1.amazonaws.com",
		"ip-10-0-0-5.ap-northeast-1.compute.internal",
		"my-bucket.s3.ap-northeast-1.amazonaws.com", "s3.ap-northeast-1.amazonaws.com", "my-bucket.s3.amazonaws.com",
		"123456789012.dkr.ecr.ap-northeast-1.amazonaws.com", "sqs.ap-northeast-1.amazonaws.com",
		"123456789012.s3-control.ap-northeast-1.amazonaws.com",
	} {
		if got := awsValues(t, awsHostKinds, line); got != nil {
			t.Errorf("%q: got %q, want nothing", line, got)
		}
	}
}

// 利用者ごとの部分の境界: 前の文字、`.` の連続、先頭・末尾の `-`、英大文字。
func TestAWSHostUserPartBoundaries(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"https://d111111abcdef8.cloudfront.net/x.js", "d111111abcdef8"},
		{"host=d111111abcdef8.cloudfront.net", "d111111abcdef8"},
		{"\"d111111abcdef8.cloudfront.net\"", "d111111abcdef8"},
		{"[d111111abcdef8.cloudfront.net]", "d111111abcdef8"},
		{"さd111111abcdef8.cloudfront.net", "d111111abcdef8"},
		{"d111111abcdef8.cloudfront.net.", "d111111abcdef8"}, // 文末の `.`
		{"d111111abcdef8.cloudfront.net. next", "d111111abcdef8"},
		{"d111111abcdef8.cloudfront.net.-x", "d111111abcdef8"},
		{"A-B.C-d.cloudfront.net", "A-B.C-d"}, // 英大文字
		{"My-ALB-1.ap-northeast-1.elb.amazonaws.com", "My-ALB-1"},
		{"a-b.c-d.e.cloudfront.net", "a-b.c-d.e"},
		{"x-y.cloudfront.net", "x-y"},
		{"a.cloudfront.net", "a"},
		{"-x.y.cloudfront.net", ""}, // 先頭が `-`
		{"y-.cloudfront.net", ""},   // 末尾が `-`
		{"x..y.cloudfront.net", ""}, // `.` の連続
		{"x.-y.cloudfront.net", "x.-y"},
		{".y.cloudfront.net", ""},    // 先頭が `.`
		{"_y.cloudfront.net", ""},    // 前が `_`
		{"x_y.cloudfront.net", ""},   // 途中の `_`(英数字・`-`・`.` の続きの前が `_`)
		{"a.x_y.cloudfront.net", ""}, // 同上
		{".cloudfront.net.cloudfront.net", ""},
	} {
		var want []string
		if tc.want != "" {
			want = []string{"aws_host=" + tc.want}
		}
		if got := awsValues(t, awsHostKinds, tc.line); !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, want)
		}
	}
}

// 同じホスト名は同じ値として検出され、違うホスト名は別の値になる(ラベルの割り当ては transform のテスト)。
func TestAWSHostSeveralInOneLine(t *testing.T) {
	line := "a.cloudfront.net b.cloudfront.net a.cloudfront.net db1.ap-northeast-1.rds.amazonaws.com," +
		"db2.ap-northeast-1.rds.amazonaws.com;x.mq.us-east-1.on.aws"
	want := []string{"aws_host=a", "aws_host=b", "aws_host=a", "aws_host=db1", "aws_host=db2", "aws_host=x"}
	if got := awsValues(t, awsHostKinds, line); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// 他の種別との分担(仕様 4.5「範囲が重なった場合」、2.5 節): EC2・S3・ECR・SQS・S3 Control は aws_host にならず、
// `admin@<RDS のホスト名>` は長いメールアドレスが優先される。
func TestAWSHostWithOtherKinds(t *testing.T) {
	all := DefaultKinds.With(KindAWSAccount).With(KindAWSS3Bucket).With(KindAWSHost)
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com", []string{"email=admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com"}},
		{"mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com", []string{"aws_host=mydb.c9akciq32"}},
		{"ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com", []string{"ipv4_global=54-250-1-2"}},
		{"my-bucket.s3.ap-northeast-1.amazonaws.com", []string{"aws_s3_bucket=my-bucket"}},
		{"123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/app", []string{"aws_account=123456789012"}},
		{"https://sqs.ap-northeast-1.amazonaws.com/123456789012/q", []string{"aws_account=123456789012"}},
		{"https://my-bucket.s3.amazonaws.com/ db.ap-northeast-1.rds.amazonaws.com", []string{"aws_s3_bucket=my-bucket", "aws_host=db"}},
	} {
		if got := awsValues(t, all, tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, tc.want)
		}
	}
}

// 置換済みの形(mask のラベル、hash の出力)は、再度は検出されない(2.5 節)。
func TestAWSHostAlreadyReplaced(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds | awsHostKinds})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"<aws_host_1>.ap-northeast-1.rds.amazonaws.com",
		"<aws_host_12>.cloudfront.net",
		"aws_host_3f9a1c0b7d2e.ap-northeast-1.rds.amazonaws.com",
		"aws_host_3f9a1c0b7d2e.cloudfront.net",
		"https://aws_host_3f9a1c0b7d2e.ap-northeast-1.elb.amazonaws.com/x",
	} {
		got, kept := d.Find([]byte(line), nil)
		if len(got) != 0 || kept != 1 {
			t.Errorf("Find(%q) = %+v kept=%d, want nothing and 1 kept", line, got, kept)
		}
	}
}

// 既定の種別では、aws_host は検出しない(受け入れ基準)。
func TestAWSHostDisabledByDefault(t *testing.T) {
	if got := awsValues(t, 0, "db.ap-northeast-1.rds.amazonaws.com"); got != nil {
		t.Errorf("default kinds: %q", got)
	}
}

// 表の各行は、規則に合っている(終端は文中に少ない手がかりを持つ、末尾の形は `.` で始まる、など)。
func TestAWSHostTable(t *testing.T) {
	n := 0
	for _, f := range awsHostForms {
		if f.service == "" || len(f.tails) == 0 {
			t.Errorf("bad form %+v", f)
		}
		for _, s := range f.tails {
			n++
			if !strings.HasPrefix(s, ".") || s != strings.ToLower(s) && !strings.Contains(s, "{") {
				t.Errorf("bad tail %q", s)
			}
		}
	}
	if n != 25 {
		t.Errorf("%d tails, want 25 (4.5 の表の末尾の形の数)", n)
	}
	// 手がかりのバイトごとのまとまり: z(`.amazonaws.` と cognito)を含む
	hints := map[byte]bool{}
	for _, g := range awsHostTable.groups {
		if hints[g.hint] {
			t.Errorf("duplicate group %q", g.hint)
		}
		hints[g.hint] = true
	}
	if !hints['z'] || !awsHostTable.groups[0].amazonaws {
		t.Errorf("groups: %+v", awsHostTable.groups)
	}
	// 実測で決めた手がかり(hostHintRank): 走査は z(`.amazonaws.`、cognito)、w(`.aws` で始まる・終わる形)、
	// l(cloudfront.net、amplifyapp.com、elasticbeanstalk.com)の 3 回
	if len(hints) != 3 || !hints['w'] || !hints['l'] {
		t.Errorf("hint bytes = %v, want z, w, l", hints)
	}
}

// ---- 正規表現の参照実装との一致 ----

// refAWSHostTails は、仕様 4.5 の表の末尾の形を、実装の表を使わずに正規表現で書いたもの(`DOM` は対象のドメイン)。
var refAWSHostTails = []struct {
	re      string
	exclude string
}{
	{`\.[a-z0-9-]+\.elb\.DOM`, ""},
	{`\.elb\.[a-z0-9-]+\.DOM`, ""},
	{`\.execute-api\.[a-z0-9-]+\.DOM`, ""},
	{`\.lambda-url\.[a-z0-9-]+\.on\.aws`, ""},
	{`\.cloudfront\.net`, ""},
	{`\.awsglobalaccelerator\.com`, ""},
	{`\.[a-z0-9-]+\.eks\.DOM`, ""},
	{`\.[a-z0-9-]+\.rds\.DOM`, ""},
	{`\.[a-z0-9-]+\.redshift\.DOM`, ""},
	{`\.[a-z0-9-]+\.redshift-serverless\.DOM`, ""},
	{`\.[a-z0-9-]+\.es\.DOM`, ""},
	{`\.[a-z0-9-]+\.aoss\.DOM`, ""},
	{`\.kafka\.[a-z0-9-]+\.DOM`, ""},
	{`\.mq\.[a-z0-9-]+\.DOM`, ""},
	{`\.mq\.[a-z0-9-]+\.on\.aws`, ""},
	{`\.server\.transfer\.[a-z0-9-]+\.DOM`, ""},
	{`\.appsync-api\.[a-z0-9-]+\.DOM`, ""},
	{`\.appsync-realtime-api\.[a-z0-9-]+\.DOM`, ""},
	{`\.auth\.[a-z0-9-]+\.amazoncognito\.com`, ""},
	{`\.iot\.[a-z0-9-]+\.DOM`, "data-ats"},
	{`\.[a-z0-9-]+\.awsapprunner\.com`, ""},
	{`\.amplifyapp\.com`, ""},
	{`\.[a-z0-9-]+\.elasticbeanstalk\.com`, ""},
	{`\.elasticbeanstalk\.com`, ""},
	{`\.[a-z0-9-]+\.ip\.aws`, ""},
}

type refAWSHostTail struct {
	re      *regexp.Regexp
	exclude string
}

// refAWSHostForms は、refAWSHostTails の DOM を、対象のドメインごとに展開した正規表現(1 つずつ試す)。
var refAWSHostForms = func() []refAWSHostTail {
	var out []refAWSHostTail
	for _, t := range refAWSHostTails {
		if !strings.Contains(t.re, "DOM") {
			out = append(out, refAWSHostTail{regexp.MustCompile(`^` + t.re), t.exclude})
			continue
		}
		for _, d := range []string{`amazonaws\.com\.cn`, `amazonaws\.com`, `amazonaws\.eu`} {
			out = append(out, refAWSHostTail{regexp.MustCompile(`^` + strings.Replace(t.re, "DOM", d, 1)), t.exclude})
		}
	}
	return out
}()

var refHostUserPart = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// refAWSHosts は、前処理を使わず、行のすべての位置で、末尾の形を 1 つずつ試す参照実装。
// 末尾の形が同じ位置で終わる場合は、先頭が最も前の(利用者ごとの部分が最も短い)有効なものを採る。
// 利用者ごとの部分の範囲を、開始位置の順(重複なし)で返す。
func refAWSHosts(line []byte) [][2]int {
	best := map[int][2]int{} // 末尾の形の終わり → (利用者ごとの部分の先頭, 末尾の形の先頭)
	bestS := map[int]int{}
	for s := 1; s < len(line); s++ {
		for _, f := range refAWSHostForms {
			loc := f.re.FindIndex(line[s:])
			if loc == nil || !refHostEnd.Match(line[s+loc[1]:]) {
				continue
			}
			e := s + loc[1]
			for u := 0; u < s; u++ {
				part := line[u:s]
				if !refHostUserPart.Match(part) || strings.Contains(string(part), "..") ||
					u > 0 && refHostChar.Match(line[u-1:u]) || string(part) == f.exclude {
					continue
				}
				if old, ok := bestS[e]; !ok || s < old {
					bestS[e] = s
					best[e] = [2]int{u, s}
				}
			}
		}
	}
	var out [][2]int
	for _, r := range best {
		out = append(out, r)
	}
	slices.SortFunc(out, cmpRange)
	return slices.Compact(out)
}

// 乱数で作った行で、aws_host の検出が、参照実装と一致すること。
// 行は「前の文字 + 利用者ごとの部分 + 末尾の形 + 後ろの文字」の組を並べて作る。
func TestAWSHostMatchesRegexpReference(t *testing.T) {
	users := []string{"mydb", "mydb", "my-alb-1234567890", "a.b", "a-b.c", "A1-B2", "0123456789ABCDEF.gr7", "x", "ab", "a..b", "-x", "x-", ".x", "x.",
		"a.-b", "a_b", "aws_host_3f9a1c0b7d2e", "<aws_host_1>", "data-ats", "b-1-public.cl.abc.c2", "", "ap-northeast-1", "elb", "x.us-east-1", "あ"}
	regions := []string{"ap-northeast-1", "ap-northeast-1", "us-east-1", "cn-north-1", "eusc-de-east-1", "a", "0", "-", "", "US-EAST-1", "a.b", "x_y"}
	domains := []string{"amazonaws.com", "amazonaws.com", "amazonaws.com.cn", "amazonaws.eu", "amazonaws.org", "example.com", "amazonaws.comx", "AMAZONAWS.COM"}
	labels := []string{"elb", "execute-api", "lambda-url", "eks", "rds", "redshift", "redshift-serverless", "es", "aoss", "kafka", "mq", "server.transfer",
		"appsync-api", "appsync-realtime-api", "auth", "iot", "cache", "RDS", "s3", "dkr.ecr"}
	fixed := []string{".cloudfront.net", ".awsglobalaccelerator.com", ".amplifyapp.com", ".elasticbeanstalk.com", ".CLOUDFRONT.NET", ".cloudfront.org"}
	around := []string{"", "", " ", "/", "\"", ":", ".", "-", "_", "x", "0", "@", "https://", "あ", "\xff"}
	after := []string{"", "", "/x", ":443", ".", ". ", ".-", "..", "-", "_", "x", ".x", ".example.org", " ", "\""}
	rng := rand.New(rand.NewPCG(71, 72))
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }
	found := 0
	for iter := 0; iter < 80000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			sb.WriteString(pick(around))
			sb.WriteString(pick(users))
			switch rng.IntN(8) {
			case 0:
				sb.WriteString("." + pick(regions) + "." + pick(labels) + "." + pick(domains))
			case 1:
				sb.WriteString("." + pick(labels) + "." + pick(regions) + "." + pick(domains))
			case 2:
				sb.WriteString("." + pick(labels) + "." + pick(regions) + "." + pick([]string{"on.aws", "on.aws", "amazoncognito.com", "awsapprunner.com", "ip.aws", "on.awsx"}))
			case 3:
				sb.WriteString("." + pick(regions) + "." + pick([]string{"ip.aws", "awsapprunner.com", "elasticbeanstalk.com", "ip.aws.com", "IP.AWS"}))
			case 4:
				sb.WriteString(pick(fixed))
			case 5:
				// 末尾の形が 2 つ続く(長いほうの形、重なる形)
				sb.WriteString("." + pick(regions) + pick(fixed) + pick([]string{"", ".cloudfront.net", "." + pick(regions) + ".elb." + pick(domains)}))
			case 6:
				sb.WriteString("." + pick(regions) + "." + pick(labels) + "." + pick(domains) + "." + pick(regions) + "." + pick(labels) + "." + pick(domains))
			default:
				sb.WriteString("." + pick([]string{"ap-northeast-1", "us-east-1"}) + ".rds.amazonaws.com")
			}
			sb.WriteString(pick(after))
			sb.WriteString(pick(around))
		}
		line := []byte(sb.String())
		want := refAWSHosts(line)
		var got [][2]int
		for _, m := range (awsHostFinder{}).find(line, nil) {
			if m.Kind != KindAWSHost || m.Class != ClassNone {
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
	if found < 8000 {
		t.Errorf("only %d host names were found; the generator does not exercise the rules", found)
	}
}

// ---- 長い行(手前へ遡る長さの合計が、行の長さ以内に収まること) ----

func TestAWSHostFinderOnLongLines(t *testing.T) {
	type tc struct {
		name, line string
		want       int // -1: 件数を確かめない
	}
	cases := []tc{
		{"long user part", strings.Repeat("a", 1<<20) + ".cloudfront.net", 1},
		{"long dotted user part", strings.Repeat("a.", 1<<19) + "a.cloudfront.net", 1},
		{"long region", "x." + strings.Repeat("a", 1<<20) + ".rds.amazonaws.com", 1},
		{"repeated tails, dot dash", strings.Repeat("x.cloudfront.net.-", 60000), -1},
		{"repeated tails, dot dot", strings.Repeat("x.cloudfront.net..", 60000), -1},
		{"repeated tails, plain", strings.Repeat("x.cloudfront.net ", 60000), 60000},
		{"repeated tails, dash", strings.Repeat("-x.cloudfront.net", 60000), -1},
		{"repeated rds", strings.Repeat("a.ap-northeast-1.rds.amazonaws.com.-", 30000), -1},
		{"repeated beanstalk", strings.Repeat("a.ap-northeast-1.elasticbeanstalk.com.-", 30000), -1},
		{"repeated on.aws", strings.Repeat("a.ip.aws.-", 100000), -1},
		{"dots", strings.Repeat(".", 1<<20) + "cloudfront.net", 0},
		{"hints only", strings.Repeat("zwfyk", 200000), 0},
		{"tails only", strings.Repeat(".cloudfront.net", 70000), 0},
		{"amazonaws only", strings.Repeat(".amazonaws.com", 70000), 0},
		{"elb regions", strings.Repeat("a.elb.", 100000) + "us-east-1.amazonaws.com", 1},
	}
	for _, c := range cases {
		start := time.Now()
		got := (awsHostFinder{}).find([]byte(c.line), nil)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", c.name, d)
		}
		if c.want >= 0 && len(got) != c.want {
			t.Errorf("%s: %d matches, want %d", c.name, len(got), c.want)
		}
	}
	if got := (awsHostFinder{}).find([]byte(strings.Repeat("db.ap-northeast-1.rds.amazonaws.com ", 30000)), nil); len(got) != 30000 {
		t.Errorf("many hosts: got %d matches, want 30000", len(got))
	}
}

// ---- ベンチマーク ----

func BenchmarkAWSHostFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (awsHostFinder{}).find(line, dst[:0])
		}
	}
}
