package transform

import (
	"os"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

func readSample(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile("testdata/app.log")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// testdata/app.log を mask した結果が、testdata/app.mask.golden と一致する(internal/transform/testdata)。
// 期待値は、手で確認したもの。仕様の変更で変わる場合は、内容を確認してから更新する。
func TestMaskGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/app.mask.golden")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := mask(t, detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}, readSample(t))
	if got != string(want) {
		t.Errorf("mask output differs from internal/transform/testdata/app.mask.golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// 合成ログ(1MB の JSON 行を含む)でも、2 回流しても結果が変わらず、改行の数が保たれる。
func TestMaskSyntheticLogIsIdempotent(t *testing.T) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 3 << 20, Seed: 9, LongLineEvery: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	in := sb.String()
	opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
	once, st := mask(t, opts, in)
	if st.Total() == 0 {
		t.Fatal("nothing was replaced; the generator does not exercise the masker")
	}
	if strings.Count(once, "\n") != strings.Count(in, "\n") {
		t.Error("the number of lines changed")
	}
	twice, st2 := mask(t, opts, once)
	if once != twice || st2.Total() != 0 {
		t.Errorf("mask(mask(x)) != mask(x) (second pass replaced %d)", st2.Total())
	}
}

// ---- ファズテスト: 2 回目の変換と、行の構造の保持 ----

// secondPassSpan は、1 回目の置換結果(ラベル、hash 出力形)の範囲。
type secondPassSpan struct{ s, e int }

// checkSecondPass は、1 回目の結果 once に、2 回目の検出を行い、次を確認する。
//
//   - 検出した範囲が、ラベルと重ならない(再置換でない)
//   - 検出した範囲が、ラベルのすぐ隣(間が 1 バイト以内)にある
//
// 置換によって、隣の文字列の文脈が変わり(間に挟まっていた文字がなくなり、または、ラベルの 16 進数と
// 連なっていた区切りが切り離され)、それまで検出できなかった値が、新しく検出できることがある
// (`000000A10.0.0.0fC00::` の `fC00::`、`0@0.AA:::1` の `::1`)。これは、冪等性の定義(置換済みの値を
// 再度置換しない)には反しないので、許す。
// 一方、ラベルと重なる検出や、置換と無関係な場所での検出は、1 回目の検出漏れ、または、ラベルを値として
// 読む不具合なので、許さない。
func checkSecondPass(t *testing.T, det *detect.Detector, in, once string, placeholders func(b []byte) []secondPassSpan) {
	t.Helper()
	for _, line := range strings.SplitAfter(once, "\n") {
		content := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		b := []byte(content)
		matches, _ := det.Find(b, nil)
		if len(matches) == 0 {
			continue
		}
		phs := placeholders(b)
		for _, m := range matches {
			near := false
			for _, p := range phs {
				if m.Start < p.e && p.s < m.End {
					t.Fatalf("the second pass would replace a placeholder\n in:   %q\n once: %q\n match: %q", in, once, content[m.Start:m.End])
				}
				if m.Start-p.e <= 1 && m.Start >= p.e || p.s-m.End <= 1 && p.s >= m.End {
					near = true
				}
			}
			if !near {
				t.Fatalf("the second pass would replace a value that is not next to a placeholder\n in:   %q\n once: %q\n match: %q",
					in, once, content[m.Start:m.End])
			}
		}
	}
}

func FuzzMaskStable(f *testing.F) {
	for _, s := range []string{
		"taro@example.com 192.168.0.1\n", "password=abc123&user=x\n", `"api_key": "abc def"` + "\n",
		"Authorization: Bearer xxxxx\r\n", "::ffff:10.0.0.1 [::1]:8080 fe80::1%eth0\n", "https://user:pass@10.0.0.1/\n",
		"id=123e4567-e89b-42d3-a456-426614174000 {123e4567-e89b-42d3-a456-426614174000}\n",
		`{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}` + "\n", "std::string fmt::Error d::bad\n",
		"AKIAIOSFODNN7EXAMPLE ghp_" + strings.Repeat("a", 36) + "\n", "<email_1> password=<secret_1>\n",
		"token: Bearer abc.def-ghi\n", "接続元 10.0.0.1 から taro@example.com\n", "\xff\xfe a@b.co\r\n", "hash_3f9a1c0b7d2e@example.com\n",
		"000000A10.0.0.0fC00::\n", "0@0.AA@0.AA\n", "ssh user@example.com@bastion.example.org\n",
	} {
		f.Add(s)
	}
	for _, s := range awsFuzzSeeds {
		f.Add(s)
	}
	optsList, dets := fuzzOptions(f)
	f.Fuzz(func(t *testing.T, in string) {
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
	})
}

// awsFuzzSeeds は、AWS の値(v1.1)を含む、ファズテストの種。
var awsFuzzSeeds = []string{
	"&X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024&\n",
	"[ec2-user@ip-10-0-1-23 ~]$ ec2-54-250-1-2.compute-1.amazonaws.com 54.250.1.2\n",
	"arn:aws:iam::123456789012:role/x 123456789012.dkr.ecr.us-east-1.amazonaws.com/a https://sqs.us-east-1.amazonaws.com/123456789012/q\n",
	"s3://my-bucket/a https://logs.example.com.s3.amazonaws.com/b https://s3.amazonaws.com/my-bucket/c arn:aws:s3:::my-bucket/*\n",
	"ec2-ipv4_global_a1b2c3d4e5f6.compute-1.amazonaws.com s3://aws_s3_bucket_3f9a1c0b7d2e/ arn:aws:iam::aws_account_3f9a1c0b7d2e:root\n",
	"logs.s3.backup.s3.amazonaws.com s3://abc_def/ s3://my-bucket.\n",
}

// fuzzOptions は、ファズテストで試す検出の設定(v1.0 の既定 + uuid と、v1.1 の `--types default,aws`)と、
// それぞれの Detector を返す。
func fuzzOptions(f *testing.F) ([]detect.Options, []*detect.Detector) {
	optsList := []detect.Options{
		{Kinds: detect.DefaultKinds.With(detect.KindUUID)},
		{Kinds: detect.DefaultKinds.With(detect.KindAWSAccount).With(detect.KindAWSS3Bucket)},
	}
	dets := make([]*detect.Detector, len(optsList))
	for i, o := range optsList {
		d, err := detect.New(o)
		if err != nil {
			f.Fatal(err)
		}
		dets[i] = d
	}
	return optsList, dets
}
