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
	slices.SortFunc(out, func(a, b [2]int) int { return a[0] - b[0] })
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
		slices.SortFunc(got, func(a, b [2]int) int { return a[0] - b[0] })
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
