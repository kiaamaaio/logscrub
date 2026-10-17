package transform

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// restoreWith は、sources から対応を作り直し、answer のラベルを戻す。
func restoreWith(t testing.TB, opts detect.Options, answer string, sources ...string) (string, RestoreResult) {
	t.Helper()
	det, err := detect.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f := opts.Format
	if f.IsZero() {
		f = label.DefaultFormat
	}
	rs := make([]io.Reader, len(sources))
	for i, s := range sources {
		rs[i] = strings.NewReader(s)
	}
	var out bytes.Buffer
	res, err := Restore(rs, strings.NewReader(answer), &out, det, f)
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), res
}

// roundTrip は、sources を mask し、その出力を、同じ sources と同じオプションで restore する。
func roundTrip(t testing.TB, opts detect.Options, sources ...string) (masked, restored string, res RestoreResult) {
	t.Helper()
	masked, _ = mask(t, opts, sources...)
	restored, res = restoreWith(t, opts, masked, sources...)
	return masked, restored, res
}

// withoutLabelLikeLines は、ラベルと同じ形の文字列を含む行を除く(往復で戻らない、仕様 5.3 の限界)。
func withoutLabelLikeLines(s string) string {
	var out []string
	for _, line := range strings.SplitAfter(s, "\n") {
		found := false
		label.DefaultFormat.Scan([]byte(line), func(int, int, string, int) { found = true })
		if !found {
			out = append(out, line)
		}
	}
	return strings.Join(out, "")
}

// ---- 往復(受け入れ基準) ----

func TestRestoreRoundTripAcceptance(t *testing.T) {
	for name, in := range map[string]string{
		"basic":         "taro@example.com 192.168.0.1\n",
		"repeat":        "a@x.com b@x.com a@x.com\n",
		"ip classes":    "10.0.0.1 203.0.113.5 192.168.0.1 10.0.0.1 8.8.8.8\n",
		"secrets":       "password=abc123&user=x\nAuthorization: Bearer xxxxx\n" + `"api_key": "abc def"` + "\n",
		"japanese":      "ユーザー taro@example.com が 192.168.0.1 から接続\n",
		"invalid utf8":  "\xff taro@example.com \x80\n",
		"crlf":          "a@x.com\r\nb@x.com\r\n",
		"no final eol":  "a@x.com b@x.com",
		"mixed eol":     "a@x.com\nb@x.com\r\n\nc",
		"nothing":       "hello world\n",
		"empty":         "",
		"ipv6":          "::ffff:10.0.0.1 [2001:db8::1]:443 fe80::1%eth0\n",
		"userinfo":      "https://user:pass@10.0.0.1/\n",
		"embedded json": `{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}` + "\n",
		"case":          "Taro@Example.com taro@example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			masked, restored, res := roundTrip(t, detect.Options{}, in)
			if restored != in {
				t.Errorf("restore(mask(x)) != x\n x:        %q\n masked:   %q\n restored: %q", in, masked, restored)
			}
			if len(res.Missing) != 0 {
				t.Errorf("Missing = %q", res.Missing)
			}
		})
	}
}

func TestRestoreRoundTripSampleLog(t *testing.T) {
	in := withoutLabelLikeLines(readSample(t))
	if in == readSample(t) {
		t.Fatal("the sample has no label-like line to exclude")
	}
	optsList := map[string]detect.Options{
		"default":       {},
		"with uuid":     {Kinds: detect.DefaultKinds.With(detect.KindUUID)},
		"custom format": {Format: mustFormat(t, "[{type}-{n}]")},
		"curly format":  {Format: mustFormat(t, "{{type}:{n}}")},
		"global only":   {IPScope: detect.ScopeGlobal},
		"private only":  {IPScope: detect.ScopePrivate},
		"email only":    {Kinds: detect.KindSet(0).With(detect.KindEmail)},
		"allow":         {Allow: map[string]struct{}{"taro@example.com": {}}},
		"uuid versions": {UUIDVersions: 1 << 4},
	}
	for name, opts := range optsList {
		t.Run(name, func(t *testing.T) {
			masked, restored, res := roundTrip(t, opts, in)
			if restored != in {
				t.Errorf("restore(mask(x)) != x\n masked:\n%s\n restored:\n%s", masked, restored)
			}
			if len(res.Missing) != 0 {
				t.Errorf("Missing = %q", res.Missing)
			}
			if masked == in {
				t.Error("nothing was masked; the round trip proves nothing")
			}
		})
	}
}

// 受け入れ基準: --source を複数指定した場合も、mask と同じ順なら往復テストが通る。
func TestRestoreRoundTripMultipleSources(t *testing.T) {
	a := "a@x.com 10.0.0.1\nb@x.com"
	b := "b@x.com a@x.com password=hunter2\n"
	c := "c@x.com\r\n"
	masked, restored, res := roundTrip(t, detect.Options{}, a, b, c)
	if restored != a+b+c {
		t.Errorf("restored %q, want %q (masked %q)", restored, a+b+c, masked)
	}
	if len(res.Missing) != 0 {
		t.Errorf("Missing = %q", res.Missing)
	}
	// 順序を変えると、番号がずれる(仕様 5.3: mask のときと同じ順に並べる)
	swapped, res2 := restoreWith(t, detect.Options{}, masked, b, a, c)
	if swapped == a+b+c {
		t.Error("a different source order restored the same text")
	}
	_ = res2
}

// 受け入れ基準: --source のファイルに行を追記したあとでも、追記前のラベルは正しく戻る。
func TestRestoreAfterAppendingToSource(t *testing.T) {
	original := "a@x.com 10.0.0.1\nb@x.com password=hunter2\n"
	appended := original + "c@x.com 10.0.0.2 d@x.com\na@x.com\n"
	masked, _ := mask(t, detect.Options{}, original)
	restored, res := restoreWith(t, detect.Options{}, masked, appended)
	if restored != original {
		t.Errorf("restored %q, want %q", restored, original)
	}
	if len(res.Missing) != 0 {
		t.Errorf("Missing = %q", res.Missing)
	}
}

// ---- 回答(AI の回答など)の処理 ----

func TestRestoreAnswerText(t *testing.T) {
	source := "from taro@example.com (192.168.0.1) and hanako@example.com\npassword=hunter2\n"
	answer := "The user <email_1> at <ipv4_private_1> is suspicious; compare with <email_2>.\n" +
		"Rotate <secret_1> now. <email_1> appears twice: <email_1>\r\nlast line without eol <email_2>"
	want := "The user taro@example.com at 192.168.0.1 is suspicious; compare with hanako@example.com.\n" +
		"Rotate hunter2 now. taro@example.com appears twice: taro@example.com\r\nlast line without eol hanako@example.com"
	got, res := restoreWith(t, detect.Options{}, answer, source)
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if res.Restored != 7 || len(res.Missing) != 0 {
		t.Errorf("Restored = %d, Missing = %q", res.Restored, res.Missing)
	}
}

// Q23: 戻せないラベルは、そのまま残し、種類数で、回答に現れた順に数える。
func TestRestoreMissingLabels(t *testing.T) {
	source := "a@x.com\n"
	answer := "<email_1> <email_3> <secret_2> <email_3> <ipv4_private_1> <email_3> <secret_2>\n"
	got, res := restoreWith(t, detect.Options{}, answer, source)
	want := "a@x.com <email_3> <secret_2> <email_3> <ipv4_private_1> <email_3> <secret_2>\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !slices.Equal(res.Missing, []string{"<email_3>", "<secret_2>", "<ipv4_private_1>"}) {
		t.Errorf("Missing = %q", res.Missing)
	}
	if res.Restored != 1 {
		t.Errorf("Restored = %d, want 1", res.Restored)
	}
}

// Q23: ラベルとみなすのは、既知の種別名と、先頭が 0 でない 1 以上の整数だけ。
func TestRestoreIgnoresNonLabels(t *testing.T) {
	answer := "<email_0> <email_01> <unknown_1> <email_> <email_1 email_1> <Email_1> <ipv4_1> [email_1]\n"
	got, res := restoreWith(t, detect.Options{}, answer, "a@x.com\n")
	if got != answer {
		t.Errorf("got %q, want unchanged", got)
	}
	if len(res.Missing) != 0 || res.Restored != 0 {
		t.Errorf("Missing = %q, Restored = %d", res.Missing, res.Restored)
	}
}

// 回答のラベルは、現在の書式のものだけ。別の書式のラベルは、そのまま。
func TestRestoreUsesTheGivenFormat(t *testing.T) {
	opts := detect.Options{Format: mustFormat(t, "[{type}-{n}]")}
	got, _ := restoreWith(t, opts, "[email-1] <email_1>\n", "a@x.com\n")
	if want := "a@x.com <email_1>\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// 復元した値は、再度ラベルとして読まない(1 回の走査)。
func TestRestoreDoesNotRescanRestoredValues(t *testing.T) {
	// 値そのものがラベルの形になる入力(<email_2> を含む値)は、mask で保護範囲になり、置換されないので、
	// ここでは、別の場所の値が、ラベルの形の文字列を含む場合を作る。
	source := `password="<email_2>x"` + "\n" + "a@x.com b@x.com\n"
	answer := "<secret_1> <email_1> <email_2>\n"
	got, _ := restoreWith(t, detect.Options{}, answer, source)
	// <secret_1> は、`<email_2>x`(引用符の内側。置換済みの形を含む値全体)に戻る。その中の <email_2> は、再度は戻さない。
	if want := "<email_2>x a@x.com b@x.com\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---- オプションが mask と違う場合(受け入れ基準) ----

func TestRestoreWithDifferentOptionsLeavesUnmatchedLabels(t *testing.T) {
	source := "a@x.com 10.0.0.1 password=abc\n"
	masked, _ := mask(t, detect.Options{}, source)
	// --types email だけで restore: ipv4 と secret の対応が作れない
	got, res := restoreWith(t, detect.Options{Kinds: detect.KindSet(0).With(detect.KindEmail)}, masked, source)
	if want := "a@x.com <ipv4_private_1> password=<secret_1>\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !slices.Equal(res.Missing, []string{"<ipv4_private_1>", "<secret_1>"}) {
		t.Errorf("Missing = %q", res.Missing)
	}
	// 元の値は、Missing に含めない
	for _, m := range res.Missing {
		if strings.Contains(m, "x.com") || strings.Contains(m, "abc") || strings.Contains(m, "10.0.0.1") {
			t.Errorf("Missing contains a value: %q", m)
		}
	}
}

// 番号がずれるオプションの違い(--allow)では、別の値に戻りうる(仕様 5.3: 連番がずれる)。
func TestRestoreWithShiftedNumbering(t *testing.T) {
	source := "a@x.com b@x.com\n"
	masked, _ := mask(t, detect.Options{}, source) // <email_1> <email_2>
	got, res := restoreWith(t, detect.Options{Allow: map[string]struct{}{"a@x.com": {}}}, masked, source)
	// a@x.com が番号を消費しないので、b@x.com が <email_1> になる。<email_2> は戻せない。
	if want := "b@x.com <email_2>\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !slices.Equal(res.Missing, []string{"<email_2>"}) {
		t.Errorf("Missing = %q", res.Missing)
	}
}

// ---- --source の処理の集計(Q31) ----

func TestRestoreReportsLabelLikeStringsInSource(t *testing.T) {
	source := "ok\nfrom <email_1> to a@x.com\nx\n"
	_, res := restoreWith(t, detect.Options{}, "<email_1>\n", source)
	if res.Source.Kept != 1 || !slices.Equal(res.Source.KeptLines, []int{2}) {
		t.Errorf("Source.Kept = %d, KeptLines = %v", res.Source.Kept, res.Source.KeptLines)
	}
	if res.Source.Lines != 3 {
		t.Errorf("Source.Lines = %d", res.Source.Lines)
	}
}

// 仕様 5.3 の限界: 元の入力に、ラベルと同じ形の文字列があると、正しく戻らないことがある。
func TestRestoreLimitationWithLabelLikeSource(t *testing.T) {
	source := "<email_1> a@x.com\n"
	masked, restored, _ := roundTrip(t, detect.Options{}, source)
	if masked != "<email_1> <email_1>\n" {
		t.Fatalf("masked = %q", masked)
	}
	if restored == source {
		t.Error("the round trip succeeded; update the README limitation if this is now handled")
	}
}

// ---- 入力・出力 ----

func TestRestoreLongAnswerLine(t *testing.T) {
	var sb strings.Builder
	for sb.Len() < 1<<20 {
		sb.WriteString("<email_1> and <ipv4_private_1>, ")
	}
	got, res := restoreWith(t, detect.Options{}, sb.String()+"\n", "a@x.com 10.0.0.1\n")
	if strings.Contains(got, "<email_1>") || !strings.HasPrefix(got, "a@x.com and 10.0.0.1, a@x.com and 10.0.0.1, ") {
		t.Errorf("unexpected output: %.100q", got)
	}
	if res.Restored < 2000 {
		t.Errorf("Restored = %d", res.Restored)
	}
}

func TestRestoreWithNoLabelsPassesAnswerThrough(t *testing.T) {
	answer := "no labels here\r\n日本語 \xff\n"
	got, res := restoreWith(t, detect.Options{}, answer, "a@x.com\n")
	if got != answer || len(res.Missing) != 0 {
		t.Errorf("got %q, Missing %q", got, res.Missing)
	}
}

func TestRestoreIsDeterministic(t *testing.T) {
	in := withoutLabelLikeLines(readSample(t))
	masked, _ := mask(t, detect.Options{}, in)
	a, ra := restoreWith(t, detect.Options{}, masked, in)
	b, rb := restoreWith(t, detect.Options{}, masked, in)
	if a != b || ra.Restored != rb.Restored {
		t.Error("two runs differ")
	}
}

// 合成ログ(1MB の JSON 行を含む)でも、往復で 1 バイトも変わらない。
func TestRestoreRoundTripSyntheticLog(t *testing.T) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 3 << 20, Seed: 5, LongLineEvery: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	in := sb.String()
	opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
	masked, restored, res := roundTrip(t, opts, in)
	if restored != in {
		t.Errorf("restore(mask(x)) != x (masked %d bytes, restored %d bytes, input %d bytes)", len(masked), len(restored), len(in))
	}
	if len(res.Missing) != 0 {
		t.Errorf("Missing = %d labels", len(res.Missing))
	}
}

// 受け入れ基準: restore の実行後に、対応表のファイルが残らない(restore は、ファイルを作らない)。
func TestRestoreCreatesNoFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("TMPDIR", dir)
	restoreWith(t, detect.Options{}, "<email_1> <secret_1>\n", "a@x.com password=abc\n")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, filepath.Join(dir, e.Name()))
		}
		t.Errorf("files were created: %v", names)
	}
}

func TestRestoreReturnsErrors(t *testing.T) {
	det, _ := detect.New(detect.Options{})
	f := label.DefaultFormat
	// --source の読み込みエラー
	_, err := Restore([]io.Reader{strings.NewReader("a@x.com\n"), failReader{}}, strings.NewReader("<email_1>\n"), io.Discard, det, f)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("source read error: %v", err)
	}
	// 回答の読み込みエラー
	_, err = Restore([]io.Reader{strings.NewReader("a@x.com\n")}, failReader{}, io.Discard, det, f)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("answer read error: %v", err)
	}
	// 書き込みエラー
	_, err = Restore([]io.Reader{strings.NewReader("a@x.com\n")}, strings.NewReader(strings.Repeat("<email_1>\n", 100000)),
		failWriter{io.ErrClosedPipe}, det, f)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("write error: %v", err)
	}
}

// ---- Masker の逆引き ----

func TestMaskerValue(t *testing.T) {
	det, _ := detect.New(detect.Options{})
	k := NewMasker(label.DefaultFormat)
	eng := &Engine{Det: det, Rep: k}
	if err := eng.Run([]io.Reader{strings.NewReader("a@x.com b@x.com 10.0.0.1 a@x.com\n")}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		typ  string
		n    int
		want string
		ok   bool
	}{
		{"email", 1, "a@x.com", true}, {"email", 2, "b@x.com", true}, {"email", 3, "", false},
		{"ipv4_private", 1, "10.0.0.1", true}, {"ipv4_global", 1, "", false}, {"email", 0, "", false},
		{"email", -1, "", false}, {"unknown", 1, "", false},
	} {
		got, ok := k.Value(tt.typ, tt.n)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Value(%q, %d) = %q, %v; want %q, %v", tt.typ, tt.n, got, ok, tt.want, tt.ok)
		}
	}
}

// ---- ファズテスト: 往復 ----

// ラベルと同じ形の文字列を含まない入力は、mask したあとに restore すると、1 バイトも変わらずに戻る。
func FuzzRestoreRoundTrip(f *testing.F) {
	for _, s := range []string{
		"taro@example.com 192.168.0.1\n", "password=abc123&user=x\n", `"api_key": "abc def"` + "\n",
		"Authorization: Bearer xxxxx\r\n", "::ffff:10.0.0.1 [::1]:8080 fe80::1%eth0\n", "https://user:pass@10.0.0.1/\n",
		"id=123e4567-e89b-42d3-a456-426614174000 {123e4567-e89b-42d3-a456-426614174000}\n",
		`{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}` + "\n", "std::string fmt::Error d::bad\n",
		"AKIAIOSFODNN7EXAMPLE ghp_" + strings.Repeat("a", 36) + "\n", "接続元 10.0.0.1 から taro@example.com\n",
		"\xff\xfe a@b.co\r\n", "0@0.AA@0.AA\n", "ssh user@example.com@bastion.example.org\n", "a@b.co a@b.co c@d.co",
		"postgres://app:s3cret@db.example.com:5432/app redis://:s3cret@10.0.0.5:6379 ftp://u:a:b@host\n",
		"https://taro@example.com/ http://u:p@h@x.com password=s3cret\n",
	} {
		f.Add(s)
	}
	for _, s := range awsFuzzSeeds {
		f.Add(s)
	}
	optsList, _ := fuzzOptions(f)
	f.Fuzz(func(t *testing.T, in string) {
		found := false
		label.DefaultFormat.Scan([]byte(in), func(int, int, string, int) { found = true })
		if found {
			t.Skip("the input contains a label-like string (limitation in SPEC 5.3)")
		}
		for _, opts := range optsList {
			masked, restored, res := roundTrip(t, opts, in)
			if restored != in {
				t.Fatalf("restore(mask(x)) != x\n x:        %q\n masked:   %q\n restored: %q", in, masked, restored)
			}
			if len(res.Missing) != 0 {
				t.Fatalf("Missing = %q for %q", res.Missing, in)
			}
		}
	})
}
