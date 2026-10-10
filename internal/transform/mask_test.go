package transform

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

// mask は、inputs を、opts の検出設定で mask し、出力と統計を返す。
// format は、検出器の置換済みの形の判定と、ラベルの生成で、同じものを使う。
func mask(t testing.TB, opts detect.Options, inputs ...string) (string, *Stats) {
	t.Helper()
	det, err := detect.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f := opts.Format
	if f.IsZero() {
		f = label.DefaultFormat
	}
	eng := &Engine{Det: det, Rep: NewMasker(f)}
	rs := make([]io.Reader, len(inputs))
	for i, s := range inputs {
		rs[i] = strings.NewReader(s)
	}
	var out bytes.Buffer
	if err := eng.Run(rs, &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), &eng.Stats
}

func maskDefault(t testing.TB, input string) string {
	t.Helper()
	out, _ := mask(t, detect.Options{}, input)
	return out
}

func mustFormat(t testing.TB, s string) label.Format {
	t.Helper()
	f, err := label.ParseFormat(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---- 受け入れ基準(基本) ----

func TestMaskAcceptanceBasics(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"basic", "taro@example.com 192.168.0.1\n", "<email_1> <ipv4_private_1>\n"},
		{"same value same label", "a@x.com b@x.com a@x.com\n", "<email_1> <email_2> <email_1>\n"},
		{"ip classes numbered separately", "10.0.0.1 203.0.113.5 192.168.0.1 10.0.0.1 8.8.8.8\n",
			"<ipv4_private_1> <ipv4_global_1> <ipv4_private_2> <ipv4_private_1> <ipv4_global_2>\n"},
		{"number across lines", "a@x.com\nb@x.com\na@x.com\n", "<email_1>\n<email_2>\n<email_1>\n"},
		// Q3: 同じ値の判定は、バイト列が完全に同じものだけ
		{"case sensitive", "Taro@Example.com taro@example.com\n", "<email_1> <email_2>\n"},
		{"ipv6 case sensitive", "2001:DB8::1 2001:db8::1\n", "<ipv6_global_1> <ipv6_global_2>\n"},
		// 日本語・全角、不正な UTF-8
		{"japanese", "ユーザー taro@example.com が 192.168.0.1 から接続\n", "ユーザー <email_1> が <ipv4_private_1> から接続\n"},
		{"fullwidth", "Ｔａｒｏ：taro@example.com　です\n", "Ｔａｒｏ：<email_1>　です\n"},
		{"invalid utf8", "\xff taro@example.com \x80\n", "\xff <email_1> \x80\n"},
		// 改行コードと末尾改行の有無
		{"crlf", "a@x.com\r\nb@x.com\r\n", "<email_1>\r\n<email_2>\r\n"},
		{"no final newline", "a@x.com", "<email_1>"},
		{"crlf no final newline", "a@x.com\r\nb@x.com", "<email_1>\r\n<email_2>"},
		{"mixed eol", "a@x.com\nb@x.com\r\n\nc", "<email_1>\n<email_2>\r\n\nc"},
		{"empty", "", ""},
		{"only newline", "\n", "\n"},
		{"unchanged line is passed through", "nothing to hide here\n", "nothing to hide here\n"},
		// 種別
		{"secret keyed", "password=abc123&user=x\n", "password=<secret_1>&user=x\n"},
		{"secret json", `"api_key": "abc def"` + "\n", `"api_key": "<secret_1>"` + "\n"},
		{"secret bearer", "Authorization: Bearer xxxxx\n", "Authorization: Bearer <secret_1>\n"},
		{"ipv4 mapped", "::ffff:10.0.0.1\n", "<ipv6_private_1>\n"},
		{"userinfo with ip", "https://user:pass@10.0.0.1/\n", "https://user:pass@<ipv4_private_1>/\n"},
		{"port and cidr", "10.0.0.1:8080 10.0.0.0/8 [::1]:8080\n", "<ipv4_private_1>:8080 <ipv4_private_2>/8 [<ipv6_private_1>]:8080\n"},
		// 特殊アドレスは置換せず、番号も消費しない
		{"special addresses keep numbers", "0.0.0.0 10.0.0.1 255.255.255.255 ::\n", "0.0.0.0 <ipv4_private_1> 255.255.255.255 ::\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskDefault(t, tt.in); got != tt.want {
				t.Errorf("mask(%q)\n got  %q\n want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskUUIDRanges(t *testing.T) {
	const u = "123e4567-e89b-42d3-a456-426614174000"
	opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
	for in, want := range map[string]string{
		"id=" + u + "\n":          "id=<uuid_1>\n",
		"{" + u + "}\n":           "{<uuid_1>}\n",
		"urn:uuid:" + u + "\n":    "urn:uuid:<uuid_1>\n",
		"req-" + u + "\n":         "req-<uuid_1>\n",
		u + " " + u + "\n":        "<uuid_1> <uuid_1>\n",
		strings.ToUpper(u) + "\n": "<uuid_1>\n",
	} {
		if got, _ := mask(t, opts, in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- 検出のオプション ----

func TestMaskTypes(t *testing.T) {
	got, _ := mask(t, detect.Options{Kinds: detect.KindSet(0).With(detect.KindEmail)}, "a@x.com 10.0.0.1 password=abc\n")
	if want := "<email_1> 10.0.0.1 password=abc\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMaskAllow(t *testing.T) {
	opts := detect.Options{Allow: map[string]struct{}{"support@example.com": {}}}
	got, _ := mask(t, opts, "support@example.com taro@example.com\n")
	if want := "support@example.com <email_1>\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMaskIPScope(t *testing.T) {
	for _, tt := range []struct {
		scope detect.Scope
		want  string
	}{
		{detect.ScopeAll, "<ipv4_private_1> <ipv4_global_1>\n"},
		{detect.ScopeGlobal, "10.0.0.1 <ipv4_global_1>\n"},
		{detect.ScopePrivate, "<ipv4_private_1> 203.0.113.5\n"},
	} {
		got, _ := mask(t, detect.Options{IPScope: tt.scope}, "10.0.0.1 203.0.113.5\n")
		if got != tt.want {
			t.Errorf("scope %d: got %q, want %q", tt.scope, got, tt.want)
		}
	}
}

// 受け入れ基準: --mask-format が反映される。再度流しても変わらない。
func TestMaskCustomFormat(t *testing.T) {
	opts := detect.Options{Format: mustFormat(t, "[{type}-{n}]")}
	got, _ := mask(t, opts, "a@x.com b@x.com 10.0.0.1 password=abc\n")
	want := "[email-1] [email-2] [ipv4_private-1] password=[secret-1]\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	again, stats := mask(t, opts, got)
	if again != got {
		t.Errorf("not idempotent: %q -> %q", got, again)
	}
	if stats.Total() != 0 || stats.Kept != 4 {
		t.Errorf("total=%d kept=%d", stats.Total(), stats.Kept)
	}
}

func TestMaskNumberFirstFormat(t *testing.T) {
	opts := detect.Options{Format: mustFormat(t, "#{n}:{type}")}
	got, _ := mask(t, opts, "a@x.com b@x.com a@x.com\n")
	if want := "#1:email #2:email #1:email\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---- 入力 ----

// 複数の入力は、連番を通しで振り、ファイルごとに行を区切る(Q22)。
func TestMaskMultipleInputs(t *testing.T) {
	got, stats := mask(t, detect.Options{}, "a@x.com", "b@x.com a@x.com\n", "c@x.com\r\n")
	want := "<email_1>" + "<email_2> <email_1>\n" + "<email_3>\r\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if stats.Lines != 3 {
		t.Errorf("Lines = %d, want 3", stats.Lines)
	}
}

// 受け入れ基準: 64KB を超える 1 行(1MB の JSON 1 行)が処理できる。
func TestMaskLongLine(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"events":[`)
	for sb.Len() < 1<<20 {
		sb.WriteString(`{"user":"taro@example.com","ip":"10.0.0.1","password":"hunter2","msg":"ok"},`)
	}
	sb.WriteString(`{}]}`)
	in := sb.String() + "\n"
	got, stats := mask(t, detect.Options{}, in)
	if strings.Contains(got, "taro@example.com") || strings.Contains(got, "hunter2") || strings.Contains(got, "10.0.0.1") {
		t.Error("a value was not replaced")
	}
	if !strings.HasPrefix(got, `{"events":[{"user":"<email_1>","ip":"<ipv4_private_1>","password":"<secret_1>","msg":"ok"},`) {
		t.Errorf("unexpected prefix: %.120q", got)
	}
	if !strings.HasSuffix(got, `{}]}`+"\n") {
		t.Error("unexpected suffix")
	}
	if stats.Total() < 3 {
		t.Errorf("Total = %d", stats.Total())
	}
}

// ---- 決定性・冪等性(受け入れ基準) ----

func TestMaskIsDeterministic(t *testing.T) {
	in := readSample(t)
	a, sa := mask(t, detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}, in)
	b, sb := mask(t, detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}, in)
	if a != b || !reflect.DeepEqual(sa, sb) {
		t.Error("two runs with the same input and options differ")
	}
}

func TestMaskIsIdempotent(t *testing.T) {
	inputs := map[string]string{
		"sample": readSample(t),
		"acceptance": "taro@example.com 192.168.0.1\npassword=abc123&user=x\nAuthorization: Bearer xxxxx\n" +
			`"api_key": "abc def"` + "\n::ffff:10.0.0.1 https://user:pass@10.0.0.1/\n",
		"quoted values": "password=\"a b c\" token='x y' secret: z\n",
		"json":          `{"user":"a@x.com","password":"p","n":1,"ip":"10.0.0.1"}` + "\n",
		"embedded json": `{"m":"{\"password\":\"abc\",\"ip\":\"10.0.0.1\"}"}` + "\n",
		"crlf":          "a@x.com\r\nb@x.com\r\n",
		"japanese":      "接続元 10.0.0.1 から taro@example.com\n",
	}
	optsList := map[string]detect.Options{
		"default":       {},
		"with uuid":     {Kinds: detect.DefaultKinds.With(detect.KindUUID)},
		"custom format": {Format: mustFormat(t, "[{type}-{n}]")},
		"curly format":  {Format: mustFormat(t, "{{type}:{n}}")},
		"global only":   {IPScope: detect.ScopeGlobal},
	}
	for iname, in := range inputs {
		for oname, opts := range optsList {
			once, _ := mask(t, opts, in)
			twice, stats := mask(t, opts, once)
			if once != twice {
				t.Errorf("%s / %s: mask(mask(x)) != mask(x)\n once:  %q\n twice: %q", iname, oname, once, twice)
			}
			if stats.Total() != 0 {
				t.Errorf("%s / %s: second pass replaced %d values", iname, oname, stats.Total())
			}
		}
	}
}

// 受け入れ基準: 再置換されない(個別の形)。
func TestMaskDoesNotReplacePlaceholders(t *testing.T) {
	for _, in := range []string{
		"password=<secret_1>\n", "Authorization: Bearer <secret_1>\n", `"api_key": "<secret_1>"` + "\n",
		"from <email_1> to <ipv4_private_2>\n", "x=<uuid_3> y=<ipv6_global_4>\n",
	} {
		if got := maskDefault(t, in); got != in {
			t.Errorf("mask(%q) = %q, want unchanged", in, got)
		}
	}
}

// ---- 統計・通知(Q19、Q31) ----

func TestStatsCountsOccurrencesInTypeOrder(t *testing.T) {
	opts := detect.Options{Allow: map[string]struct{}{"support@example.com": {}}}
	_, st := mask(t, opts, "a@x.com a@x.com b@x.com 10.0.0.1 203.0.113.5 0.0.0.0 support@example.com\n"+
		"password=abc 123e4567-e89b-42d3-a456-426614174000\n")
	// 置換した出現回数だけ(--allow で残したもの、特殊アドレスは数えない)。uuid は既定で無効。
	want := []TypeCount{{"email", 3}, {"ipv4_global", 1}, {"ipv4_private", 1}, {"secret", 1}}
	got := st.Types()
	if len(got) != len(want) {
		t.Fatalf("Types() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Types()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if st.Total() != 6 {
		t.Errorf("Total() = %d, want 6", st.Total())
	}
	if st.Count("email") != 3 || st.Count("uuid") != 0 || st.Count("nope") != 0 {
		t.Errorf("Count: email=%d uuid=%d", st.Count("email"), st.Count("uuid"))
	}
	if st.Lines != 2 {
		t.Errorf("Lines = %d", st.Lines)
	}
}

func TestStatsKeptLines(t *testing.T) {
	_, st := mask(t, detect.Options{},
		"ok\n<email_1> and <email_2>\nx\npassword=<secret_1>\n", "y\n<uuid_1>\n")
	if st.Kept != 4 {
		t.Errorf("Kept = %d, want 4", st.Kept)
	}
	// 行番号は、入力をまたいで通しで数える(1 始まり)。重なりなく、昇順。
	want := []int{2, 4, 6}
	if len(st.KeptLines) != len(want) {
		t.Fatalf("KeptLines = %v, want %v", st.KeptLines, want)
	}
	for i := range want {
		if st.KeptLines[i] != want[i] {
			t.Errorf("KeptLines = %v, want %v", st.KeptLines, want)
		}
	}
}

func TestStatsKeptLinesAreLimitedToFive(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString("<email_1>\n")
	}
	_, st := mask(t, detect.Options{}, sb.String())
	if st.Kept != 20 {
		t.Errorf("Kept = %d, want 20", st.Kept)
	}
	if len(st.KeptLines) != MaxKeptLines || st.KeptLines[0] != 1 || st.KeptLines[4] != 5 {
		t.Errorf("KeptLines = %v", st.KeptLines)
	}
}

func TestStatsNothingDetected(t *testing.T) {
	_, st := mask(t, detect.Options{}, "hello\nworld\n")
	if st.Total() != 0 || st.Kept != 0 || len(st.Types()) != 0 || len(st.KeptLines) != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// ---- 書き込みエラー ----

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestEngineReturnsWriteError(t *testing.T) {
	det, _ := detect.New(detect.Options{})
	eng := &Engine{Det: det, Rep: NewMasker(label.DefaultFormat)}
	err := eng.Run([]io.Reader{strings.NewReader(strings.Repeat("a@x.com\n", 100000))}, failWriter{io.ErrClosedPipe})
	if err != io.ErrClosedPipe {
		t.Errorf("err = %v, want %v", err, io.ErrClosedPipe)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEngineReturnsReadError(t *testing.T) {
	det, _ := detect.New(detect.Options{})
	eng := &Engine{Det: det, Rep: NewMasker(label.DefaultFormat)}
	var out bytes.Buffer
	if err := eng.Run([]io.Reader{strings.NewReader("a@x.com\n"), failReader{}}, &out); err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
}
