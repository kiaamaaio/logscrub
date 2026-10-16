package transform

import (
	"os"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// AWS の値(v1.1)についての、往復・冪等性(plans/v1.1.0.md 段階 6。仕様 9 章「AWS」)。

// awsKinds は、`--types default,aws` に当たる種別。
var awsKinds = detect.DefaultKinds.With(detect.KindAWSAccount).With(detect.KindAWSS3Bucket)

func readAWSSample(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile("testdata/aws.log")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// awsSyntheticLog は、AWS の値を含む合成ログ(Q39)。
func awsSyntheticLog(t testing.TB, seed uint64) string {
	t.Helper()
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 3 << 20, Seed: seed, LongLineEvery: 1 << 20, AWS: true}); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// testdata/aws.log を `--types default,aws` で mask した結果が、testdata/aws.mask.golden と一致する。
// 期待値は、手で確認したもの(1 行ごとに、仕様 4.1・4.3・4.4 の形と、置換しない形を確認した)。
func TestMaskGoldenAWS(t *testing.T) {
	want, err := os.ReadFile("testdata/aws.mask.golden")
	if err != nil {
		t.Fatal(err)
	}
	got, st := mask(t, detect.Options{Kinds: awsKinds}, readAWSSample(t))
	if got != string(want) {
		t.Errorf("mask output differs from internal/transform/testdata/aws.mask.golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if st.Count("aws_account") == 0 || st.Count("aws_s3_bucket") == 0 || st.Count("secret") == 0 || st.Count("ipv4_private") == 0 {
		t.Errorf("stats: %+v", st.Types())
	}
}

// 受け入れ基準: `--types default,aws` の mask の出力を、同じオプションで restore に通すと、元の入力と 1 バイトも違わずに戻る。
func TestRestoreRoundTripAWS(t *testing.T) {
	inputs := map[string]string{
		"sample":    readAWSSample(t),
		"synthetic": awsSyntheticLog(t, 21),
		"crlf":      "arn:aws:iam::123456789012:root\r\ns3://my-bucket/a\r\n",
		"no eol":    "ip-10-0-1-23 ec2-54-250-1-2.compute-1.amazonaws.com 54.250.1.2",
	}
	optsList := map[string]detect.Options{
		"default,aws":   {Kinds: awsKinds},
		"aws":           {Kinds: detect.KindSet(0).With(detect.KindAWSAccount).With(detect.KindAWSS3Bucket)},
		"custom format": {Kinds: awsKinds, Format: mustFormat(t, "[{type}-{n}]")},
		"global only":   {Kinds: awsKinds, IPScope: detect.ScopeGlobal},
		"allow":         {Kinds: awsKinds, Allow: map[string]struct{}{"my-bucket": {}, "123456789012": {}}},
	}
	for iname, in := range inputs {
		for oname, opts := range optsList {
			masked, restored, res := roundTrip(t, opts, in)
			if restored != in {
				t.Errorf("%s / %s: restore(mask(x)) != x", iname, oname)
			}
			if len(res.Missing) != 0 {
				t.Errorf("%s / %s: Missing = %q", iname, oname, res.Missing)
			}
			if oname == "default,aws" && masked == in {
				t.Errorf("%s / %s: nothing was masked; the round trip proves nothing", iname, oname)
			}
		}
	}
}

// 受け入れ基準: `--types default,aws` の mask・hash の出力を、同じオプションで再度流しても変わらない。
func TestAWSIsIdempotent(t *testing.T) {
	inputs := map[string]string{
		"sample":    readAWSSample(t),
		"synthetic": awsSyntheticLog(t, 22),
	}
	for iname, in := range inputs {
		for oname, opts := range map[string]detect.Options{
			"default,aws":   {Kinds: awsKinds},
			"with uuid":     {Kinds: awsKinds.With(detect.KindUUID)},
			"custom format": {Kinds: awsKinds, Format: mustFormat(t, "[{type}-{n}]")},
			"curly format":  {Kinds: awsKinds, Format: mustFormat(t, "{{type}:{n}}")},
		} {
			once, st := mask(t, opts, in)
			if st.Count("aws_account") == 0 || st.Count("aws_s3_bucket") == 0 {
				t.Fatalf("%s / %s: no AWS value was replaced", iname, oname)
			}
			twice, st2 := mask(t, opts, once)
			if once != twice || st2.Total() != 0 {
				t.Errorf("%s / %s: mask(mask(x)) != mask(x) (second pass replaced %d)", iname, oname, st2.Total())
			}
		}
		for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
			for _, n := range []int{8, 12, 64} {
				opts := detect.Options{Kinds: awsKinds}
				once, _ := hashRun(t, opts, testKey, n, mode, in)
				// 決まった形の中の値は、hash の出力になる(置換しない形の行は、元のまま)
				for _, v := range []string{"aeeed9bbccd4", "fe5f80f77d5f", "https://my-bucket.s3.", "ec2-54-250-1-2.ap-", "[ec2-user@ip-10-0-1-23 ",
					"sts::123456789012:", "s3a://logs.example.com", "on ip-10-0-1-23 ("} {
					if iname == "sample" && strings.Contains(once, v) {
						t.Errorf("%s / mode %d / length %d: hash output contains %q", iname, mode, n, v)
					}
				}
				twice, st := hashRun(t, opts, testKey, n, mode, once)
				if once != twice || st.Total() != 0 {
					t.Errorf("%s / mode %d / length %d: hash(hash(x)) != hash(x) (second pass replaced %d)", iname, mode, n, st.Total())
				}
			}
		}
	}
}
