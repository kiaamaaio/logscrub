package transform

import (
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

// ---- ファズテスト: mask・hash の冪等性(現実的な断片の組み合わせ) ----
//
// 入力は、断片の表と区切りの表から選んで組み立てた行(fragmentText)。任意のバイト列を入力にすると、値どうしが
// 区切りなしで密着した、手で作らない限り現れない入力で、すぐに止まり続けるため(DEVELOPMENT.md 3.2 節「見つかった
// 問題の振り分け」。仕様 7 章の冪等の但し書き)。往復(FuzzRestoreRoundTrip)は、どの入力でも成り立つべき性質なので、
// 任意の文字列のまま。

// fuzzFragments は、ログ・テキストに現れる値と文脈の断片。値は、検出される形・検出されない形・置換済みの形
// (置換済みのログを流し直す使い方)を含む。
var fuzzFragments = []string{
	// メールアドレス
	"taro@example.com", "hanako.yamada+tag@mail.example.co.jp", "admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com",
	"ssh user@example.com@bastion.example.org", "mailto:bob@example.org?subject=hi", "<alice@example.net>",
	// IP アドレス
	"192.168.0.1", "10.0.0.1:8080", "8.8.8.8", "203.0.113.5", "127.0.0.1", "0.0.0.0", "version 1.2.3.4",
	"::1", "[::1]:8080", "2001:db8::1", "fe80::1%eth0", "::ffff:10.0.0.1", "2400:4050:2c41:5d00::1", "fd00::12",
	"src=10.0.0.5", "client 172.16.3.4 port 51234",
	// secret
	"password=s3cret", "passwd: hunter2", `"api_key": "abc def"`, `"token":"tok_123"`, "Authorization: Bearer abc.def-ghi",
	"Authorization: Basic dXNlcjpwYXNz", "token=Bearer xyz", "secret=abc123&user=x", "session_id=0123abcd",
	"AKIAIOSFODNN7EXAMPLE", "ghp_" + strings.Repeat("a", 36), "xoxb-0123456789-abcdef", "sk_live_" + strings.Repeat("Z", 24),
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "X-Amz-Signature=" + strings.Repeat("0a", 32),
	`{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}`, `password="p a s s"`, "token: expired",
	// URL のパスワード
	"postgres://app:s3cret@db.example.com:5432/app", "redis://:s3cret@10.0.0.5:6379", "https://user:pass@10.0.0.1/",
	"ftp://u:a:b@host", "https://taro@example.com/", "postgres://myadmin@mydemoserver:s3cret@10.0.0.6:5432/db",
	"https://bob@example.com:pw@git.example.com/repo", "password=https://u:p&q@db.example.com/", `"dsn":"mysql://root:pw@db:3306/x"`,
	"token=https://hooks.example.com/T000/XXXX", "passwd://u:s3cret@db.example.com/", "token://abc",
	// UUID
	"123e4567-e89b-42d3-a456-426614174000", "{123e4567-e89b-42d3-a456-426614174000}", "request_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	// AWS
	"123456789012", "arn:aws:iam::123456789012:role/x", "123456789012.dkr.ecr.us-east-1.amazonaws.com/a",
	"s3://my-bucket/a", "https://logs.example.com.s3.amazonaws.com/b", "arn:aws:s3:::my-bucket/*",
	"ec2-54-250-1-2.compute-1.amazonaws.com", "mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432",
	"my-alb-1234567890.ap-northeast-1.elb.amazonaws.com", "d111111abcdef8.cloudfront.net", "abcdefghij.execute-api.ap-northeast-1.amazonaws.com",
	"123456789012.s3-control.us-east-1.amazonaws.com", "data-ats.iot.us-east-1.amazonaws.com",
	// 置換済みの形(mask のラベルと hash の出力)
	"<email_1>", "<ipv4_private_1>", "password=<secret_1>", "Bearer <secret_2>", "<uuid_1>", "<aws_host_1>.cloudfront.net",
	"https://u:<secret_1>@<ipv4_private_1>/", "email_3f9a1c0b7d2e", "hash_3f9a1c0b7d2e@example.com", "password=secret_3f9a1c0b7d2e",
	"ipv4_global_a1b2c3d4e5f6", "postgres://app:secret_3f9a1c0b7d2e@db/x",
	// 文脈(値でないもの)
	"2026-10-18T12:34:56.789Z", "12:34:56", "INFO", "ERROR", "level=warn", "GET /api/v1/users?id=42 HTTP/1.1", "status=200",
	"std::string", "fmt::Error", "接続元", "から", "ユーザー", "msg=\"login failed\"", "{", "}", `"user":`, "[ec2-user@ip-10-0-1-23 ~]$",
	"\xff\xfe",
}

// fuzzSeparators は、断片の間の区切り。ログで値を区切る形(空白を含む区切り、行の区切り、JSON の区切り)だけにする。
// 区切りなしの密着や、記号だけで断片を直接つなぐ形(`…XXXX(redis://…`、`Bearer abc/token=…`)は作らない。
// そうした形は、手で作らない限り現れず、見つかっても直さない(DEVELOPMENT.md 3.2 節)ため。記号が値に隣り合う形は、
// 断片の中に書く(`[::1]:8080`、`{"token":"tok_123"}` など)。
var fuzzSeparators = []string{
	" ", " ", " ", "  ", "\t", ", ", "; ", " | ", " - ", ": ", " (", ") ", " [", "] ", "\n", "\r\n", `" "`, `","`, `":"`, "' '",
}

// maxFuzzFragments は、fragmentText が組み立てる断片の数の上限(1 回の試行を短く保つため)。
const maxFuzzFragments = 24

// fragmentText は、data を、断片と区切りの選び方として読み、テキストを組み立てる。
// 偶数番目のバイトが断片、奇数番目のバイトが、その後ろの区切りを選ぶ。
func fragmentText(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data) && i/2 < maxFuzzFragments; i += 2 {
		sb.WriteString(fuzzFragments[int(data[i])%len(fuzzFragments)])
		if i+1 < len(data) {
			sb.WriteString(fuzzSeparators[int(data[i+1])%len(fuzzSeparators)])
		}
	}
	return sb.String()
}

// checkMaskStable は、in を mask した結果の行の構造と、2 回目の検出(checkSecondPass)を確かめる。
func checkMaskStable(t *testing.T, optsList []detect.Options, dets []*detect.Detector, in string) {
	t.Helper()
	for i, opts := range optsList {
		once, _ := mask(t, opts, in)
		if strings.Count(once, "\n") != strings.Count(in, "\n") {
			t.Fatalf("the number of lines changed: %q -> %q", in, once)
		}
		if strings.HasSuffix(in, "\n") != strings.HasSuffix(once, "\n") {
			t.Fatalf("final newline changed: %q -> %q", in, once)
		}
		checkSecondPass(t, dets[i], in, once, func(b []byte) []secondPassSpan {
			var phs []secondPassSpan
			label.DefaultFormat.Scan(b, func(s, e int, _ string, _ int) { phs = append(phs, secondPassSpan{s, e}) })
			return phs
		})
	}
}

// checkHashStable は、checkMaskStable の hash 版(`--email-hash full` と `local`)。ラベルと hash 出力形の両方を、
// 置換済みの形として見る。
func checkHashStable(t *testing.T, optsList []detect.Options, dets []*detect.Detector, in string) {
	t.Helper()
	for i, opts := range optsList {
		for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
			once, _ := hashRun(t, opts, testKey, 12, mode, in)
			if strings.Count(once, "\n") != strings.Count(in, "\n") || strings.HasSuffix(in, "\n") != strings.HasSuffix(once, "\n") {
				t.Fatalf("mode %d: the line structure changed: %q -> %q", mode, in, once)
			}
			checkSecondPass(t, dets[i], in, once, func(b []byte) []secondPassSpan {
				var phs []secondPassSpan
				label.DefaultFormat.Scan(b, func(s, e int, _ string, _ int) { phs = append(phs, secondPassSpan{s, e}) })
				label.ScanHashed(b, 12, func(s, e int) { phs = append(phs, secondPassSpan{s, e}) })
				return phs
			})
		}
	}
}

// addFragmentSeeds は、各断片を 1 回ずつ使う種と、いくつかの組み合わせの種を加える。
func addFragmentSeeds(f *testing.F) {
	for i := range fuzzFragments {
		f.Add([]byte{byte(i), 0, byte(i * 7), byte(i)})
	}
	f.Add([]byte{})
	f.Add([]byte{0, 8, 6, 12, 22, 1, 40, 9, 75})
}

func FuzzMaskStable(f *testing.F) {
	addFragmentSeeds(f)
	optsList, dets := fuzzOptions(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		checkMaskStable(t, optsList, dets, fragmentText(data))
	})
}

func FuzzHashStable(f *testing.F) {
	addFragmentSeeds(f)
	optsList, dets := fuzzOptions(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		checkHashStable(t, optsList, dets, fragmentText(data))
	})
}

// TestFragmentText は、fragmentText が、表の範囲の外を選ばないことと、断片の数の上限を確かめる。
func TestFragmentText(t *testing.T) {
	if got := fragmentText(nil); got != "" {
		t.Errorf("empty: %q", got)
	}
	if got := fragmentText([]byte{0, 0}); got != fuzzFragments[0]+fuzzSeparators[0] {
		t.Errorf("one fragment: %q", got)
	}
	if got := fragmentText([]byte{byte(len(fuzzFragments))}); got != fuzzFragments[0] {
		t.Errorf("wrap around: %q", got)
	}
	long := fragmentText([]byte(strings.Repeat("\x00\x00", maxFuzzFragments+10)))
	if n := strings.Count(long, fuzzFragments[0]); n != maxFuzzFragments {
		t.Errorf("%d fragments, want %d", n, maxFuzzFragments)
	}
}

// ---- 表のテスト: 冪等性(以前のファズテストの種と、見つかって直した入力) ----

// stableExamples は、以前のファズテスト(任意の文字列を入力にしていたもの)の種。mask・hash とも、
// 2 回目の検出の条件(checkSecondPass)を満たす。
var stableExamples = []string{
	"taro@example.com 192.168.0.1\n", "password=abc123&user=x\n", `"api_key": "abc def"` + "\n",
	"Authorization: Bearer xxxxx\r\n", "::ffff:10.0.0.1 [::1]:8080 fe80::1%eth0\n", "https://user:pass@10.0.0.1/\n",
	"id=123e4567-e89b-42d3-a456-426614174000 {123e4567-e89b-42d3-a456-426614174000}\n",
	`{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}` + "\n", "std::string fmt::Error d::bad\n",
	"AKIAIOSFODNN7EXAMPLE ghp_" + strings.Repeat("a", 36) + "\n", "<email_1> password=<secret_1>\n",
	"email_3f9a1c0b7d2e password=secret_3f9a1c0b7d2e hash_3f9a1c0b7d2e@example.com\n",
	"token: Bearer abc.def-ghi\n", "接続元 10.0.0.1 から taro@example.com\n", "\xff\xfe a@b.co\r\n", "hash_3f9a1c0b7d2e@example.com\n",
	"000000A10.0.0.0fC00::\n", "10.0.0.1abc a@b.coabc\n", "0@0.AA@0.AA\n", "0@0.AA:::1\n", "ssh user@example.com@bastion.example.org\n",
	"postgres://app:s3cret@db.example.com:5432/app redis://:s3cret@10.0.0.5:6379 ftp://u:a:b@host\n",
	"https://taro@example.com/ http://u:p@h@x.com password=s3cret\n", "postgres://app:<secret_1>@db/x postgres://app:secret_3f9a1c0b7d2e@db/x\n",
	"password=https://u:p&q@db.example.com/ token=\"postgres://app:&x@10.0.0.1/\" password=https://u:<secret_1>@<ipv4_private_1>/\n",
}

// stableFixedFindings は、以前のファズテストが見つけて直した入力(以前の testdata/fuzz/ の内容)。
var stableFixedFindings = []string{
	"::1:1.0.0.0",       // v1.0
	"0@0.AA:::1",        // v1.0
	"0@0.AA@0.AA",       // v1.0
	"passwd://:&@0",     // Q63
	"0@0.ZA://:0@0",     // Q64
	"0.0.0.1passwd=0",   // Q66
	"::1::0@0.AA",       // Q67
	"0@0.AA%@0.AA@0.AA", // Q69
	"A://0@0.AA!:0@0",   // Q70
}

func TestMaskAndHashStableOnExamples(t *testing.T) {
	optsList, dets := fuzzOptions(t)
	for _, in := range append(append(append([]string{}, stableExamples...), awsFuzzSeeds...), stableFixedFindings...) {
		checkMaskStable(t, optsList, dets, in)
		checkHashStable(t, optsList, dets, in)
	}
}
