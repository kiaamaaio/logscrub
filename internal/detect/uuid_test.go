package detect

import (
	"bytes"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	uuidV4 = "123e4567-e89b-42d3-a456-426614174000"
	uuidV1 = "123e4567-e89b-12d3-a456-426614174000"
	uuidV7 = "01890a5d-ac96-774b-bcce-b302099a8057"
)

// uuidsIn は、バージョンを絞った(0 はすべて) uuid 検出器だけを直接動かし、候補の文字列を返す。
func uuidsIn(line string, versions uint16) []string {
	var got []string
	for _, m := range (uuidFinder{versions: versions}).find([]byte(line), nil) {
		if m.Kind != KindUUID || m.Class != ClassNone {
			panic("uuidFinder returned a match that is not a plain uuid")
		}
		got = append(got, line[m.Start:m.End])
	}
	return got
}

func TestUUIDFinderKind(t *testing.T) {
	if k := (uuidFinder{}).kind(); k != KindUUID {
		t.Errorf("kind = %v", k)
	}
}

func TestUUIDFinderMatches(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"v4", uuidV4, []string{uuidV4}},
		{"v1", uuidV1, []string{uuidV1}},
		{"v7", uuidV7, []string{uuidV7}},
		{"uppercase", strings.ToUpper(uuidV4), []string{strings.ToUpper(uuidV4)}},
		{"mixed case", "123E4567-e89B-42D3-A456-426614174000", []string{"123E4567-e89B-42D3-A456-426614174000"}},
		{"variant 8", "123e4567-e89b-42d3-8456-426614174000", []string{"123e4567-e89b-42d3-8456-426614174000"}},
		{"variant 9", "123e4567-e89b-42d3-9456-426614174000", []string{"123e4567-e89b-42d3-9456-426614174000"}},
		{"variant a", "123e4567-e89b-42d3-a456-426614174000", []string{"123e4567-e89b-42d3-a456-426614174000"}},
		{"variant b", "123e4567-e89b-42d3-b456-426614174000", []string{"123e4567-e89b-42d3-b456-426614174000"}},
		{"variant upper A", "123e4567-e89b-42d3-A456-426614174000", []string{"123e4567-e89b-42d3-A456-426614174000"}},
		// 括弧・接頭辞は範囲に含めない(Q9: UUID 部分だけ)
		{"braces", "{" + uuidV4 + "}", []string{uuidV4}},
		{"urn", "urn:uuid:" + uuidV4, []string{uuidV4}},
		{"urn upper", "URN:UUID:" + strings.ToUpper(uuidV4), []string{strings.ToUpper(uuidV4)}},
		// 前後が英数字でなければ検出する(ハイフンでもよい)
		{"hyphen before", "req-" + uuidV4, []string{uuidV4}},
		{"hyphen after", uuidV4 + "-suffix", []string{uuidV4}},
		{"underscore around", "_" + uuidV4 + "_", []string{uuidV4}},
		{"key value", "user_id=" + uuidV4 + "&x=1", []string{uuidV4}},
		{"json", `{"id":"` + uuidV4 + `"}`, []string{uuidV4}},
		{"path", "/users/" + uuidV4 + "/orders", []string{uuidV4}},
		{"sentence end", "created " + uuidV4 + ".", []string{uuidV4}},
		{"parentheses", "(" + uuidV4 + ")", []string{uuidV4}},
		{"japanese around", "ID" + "：" + uuidV4 + "です", []string{uuidV4}},
		{"invalid utf8 around", "\xff" + uuidV4 + "\x80", []string{uuidV4}},
		{"two", uuidV4 + " " + uuidV1, []string{uuidV4, uuidV1}},
		{"adjacent with hyphen", uuidV4 + "-" + uuidV1, []string{uuidV4, uuidV1}},
		{"in text", "from " + uuidV4 + " to " + uuidV7 + " ok", []string{uuidV4, uuidV7}},

		// 検出しない
		{"nil uuid", "00000000-0000-0000-0000-000000000000", nil},
		{"max uuid", "ffffffff-ffff-ffff-ffff-ffffffffffff", nil},
		{"version 0", "123e4567-e89b-02d3-a456-426614174000", nil},
		{"version 9", "123e4567-e89b-92d3-a456-426614174000", nil},
		{"version a", "123e4567-e89b-a2d3-a456-426614174000", nil},
		{"variant 0", "123e4567-e89b-42d3-0456-426614174000", nil},
		{"variant 7", "123e4567-e89b-42d3-7456-426614174000", nil},
		{"variant c", "123e4567-e89b-42d3-c456-426614174000", nil},
		{"variant f", "123e4567-e89b-42d3-f456-426614174000", nil},
		{"no hyphens", "123e4567e89b42d3a456426614174000", nil},
		{"short first group", "123e456-e89b-42d3-a456-426614174000", nil},
		{"short last group", "123e4567-e89b-42d3-a456-42661417400", nil},
		{"long last group", "123e4567-e89b-42d3-a456-4266141740001", nil},
		{"long first group", "0123e4567-e89b-42d3-a456-426614174000", nil},
		{"non hex", "123e4567-e89b-42d3-a456-42661417400g", nil},
		{"spaces", "123e4567 e89b 42d3 a456 426614174000", nil},
		{"underscores", "123e4567_e89b_42d3_a456_426614174000", nil},
		{"alnum before", "x" + uuidV4, nil},
		{"alnum after", uuidV4 + "x", nil},
		{"digit after", uuidV4 + "1", nil},
		{"five groups", "123e4567-e89b-42d3-a456", nil},
		{"empty", "", nil},
		{"short", "123e4567-e89b", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uuidsIn(tt.line, 0); !slices.Equal(got, tt.want) {
				t.Errorf("uuids(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// すべてのバージョン(1〜8)が、バージョンの指定なしで検出される。
func TestUUIDFinderAllVersions(t *testing.T) {
	for v := 1; v <= 8; v++ {
		u := "123e4567-e89b-" + string(rune('0'+v)) + "2d3-a456-426614174000"
		if got := uuidsIn(u, 0); !slices.Equal(got, []string{u}) {
			t.Errorf("version %d: got %q", v, got)
		}
	}
}

// --uuid-versions: 指定したバージョンだけが対象(ビット i がバージョン i)。
func TestUUIDFinderVersionFilter(t *testing.T) {
	line := uuidV1 + " " + uuidV4 + " " + uuidV7
	tests := []struct {
		name     string
		versions uint16
		want     []string
	}{
		{"all", 0, []string{uuidV1, uuidV4, uuidV7}},
		{"v4 only", 1 << 4, []string{uuidV4}},
		{"v1 only", 1 << 1, []string{uuidV1}},
		{"v7 only", 1 << 7, []string{uuidV7}},
		{"v4 and v7", 1<<4 | 1<<7, []string{uuidV4, uuidV7}},
		{"v2 only", 1 << 2, nil},
		{"v8 only", 1 << 8, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uuidsIn(line, tt.versions); !slices.Equal(got, tt.want) {
				t.Errorf("versions=%b: got %q, want %q", tt.versions, got, tt.want)
			}
		})
	}
}

// ---- Detector を通した動作(受け入れ基準) ----

func TestDetectorUUIDIsDisabledByDefault(t *testing.T) {
	d, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	check(t, d, "id="+uuidV4, nil, 0)
}

func TestDetectorUUIDWithTypes(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds.With(KindUUID)})
	if err != nil {
		t.Fatal(err)
	}
	check(t, d, "x "+uuidV4+" y", []Match{m(KindUUID, 2, 38)}, 0)
	check(t, d, "{"+uuidV4+"}", []Match{m(KindUUID, 1, 37)}, 0)
	check(t, d, "urn:uuid:"+uuidV4, []Match{m(KindUUID, 9, 45)}, 0)
	check(t, d, "req-"+uuidV4, []Match{m(KindUUID, 4, 40)}, 0)
	check(t, d, strings.ToUpper(uuidV7), []Match{m(KindUUID, 0, 36)}, 0)
}

func TestDetectorUUIDOnly(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindUUID)})
	if err != nil {
		t.Fatal(err)
	}
	check(t, d, "a@example.com 10.0.0.1 "+uuidV4, []Match{m(KindUUID, 23, 59)}, 0)
}

// --uuid-versions だけで、uuid が対象に加わり、指定したバージョンだけが対象になる。
func TestDetectorUUIDVersionsEnableAndFilter(t *testing.T) {
	d, err := New(Options{UUIDVersions: 1 << 4})
	if err != nil {
		t.Fatal(err)
	}
	line := uuidV1 + " " + uuidV4 + " " + uuidV7
	check(t, d, line, []Match{m(KindUUID, 37, 73)}, 0)
}

// 両方を指定した場合は、--uuid-versions を優先してバージョンを絞る。
func TestDetectorUUIDVersionsOverrideTypes(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds.With(KindUUID), UUIDVersions: 1<<1 | 1<<7})
	if err != nil {
		t.Fatal(err)
	}
	line := uuidV1 + " " + uuidV4 + " " + uuidV7
	check(t, d, line, []Match{m(KindUUID, 0, 36), m(KindUUID, 74, 110)}, 0)
}

func TestDetectorUUIDPlaceholders(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindUUID)})
	if err != nil {
		t.Fatal(err)
	}
	check(t, d, "id=<uuid_1> x=uuid_3f9a1c0b7d2e", nil, 2)
}

// 種別が重なる場合は、同じ範囲なら email → ip → secret → uuid の順(仕様 4 章)。
func TestDetectorUUIDPriority(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds.With(KindUUID)})
	if err != nil {
		t.Fatal(err)
	}
	// キー名ベースの値と同じ範囲なので、secret が優先される。
	got, _ := d.Find([]byte("session_id="+uuidV4), nil)
	if len(got) != 1 || got[0].Kind != KindSecret || got[0].Start != 11 || got[0].End != 47 {
		t.Errorf("session_id=<uuid>: %+v", got)
	}
	// キー名がなければ、uuid として検出される。
	got, _ = d.Find([]byte("request "+uuidV4), nil)
	if len(got) != 1 || got[0].Kind != KindUUID {
		t.Errorf("request <uuid>: %+v", got)
	}
}

// 受け入れ基準「除外の確認」: 電話番号・郵便番号の形式は、どの種別でも検出されない。
func TestPhoneAndPostalCodesAreNotDetected(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds.With(KindUUID)})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"03-1234-5678", "09012345678", "123-4567", "090-1234-5678", "0120-123-456", "+81-3-1234-5678",
		"TEL: 03-1234-5678", "tel=09012345678", "〒123-4567", "郵便番号 123-4567 です", "(03) 1234-5678",
		"2026-10-11", "2026-10-11 12:34:56", "ID-123-4567",
	} {
		if got, kept := d.Find([]byte(line), nil); len(got) != 0 || kept != 0 {
			t.Errorf("Find(%q) = %+v kept=%d, want none", line, got, kept)
		}
	}
}

// ---- 正規表現による別実装との一致(Q2) ----

var refUUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}`)

// refUUIDs は、前処理(ハイフンの位置の確認)を使わず、全位置に正規表現を当てる別実装。
func refUUIDs(line []byte, versions uint16) [][2]int {
	var out [][2]int
	for p := 0; p < len(line); {
		if p > 0 && refIsAlnum(line[p-1]) {
			p++
			continue
		}
		loc := refUUID.FindIndex(line[p:])
		if loc == nil {
			p++
			continue
		}
		e := p + loc[1]
		if e < len(line) && refIsAlnum(line[e]) {
			p++
			continue
		}
		v := uint(line[p+14] - '0')
		if versions != 0 && versions&(1<<v) == 0 {
			p++
			continue
		}
		out = append(out, [2]int{p, e})
		p = e
	}
	return out
}

func TestUUIDFinderMatchesRegexpReference(t *testing.T) {
	alphabet := []string{
		"123e4567", "e89b", "42d3", "a456", "426614174000", "12d3", "72d3", "92d3", "02d3", "c456", "8456", "-", "-", "-",
		"x", "G", "{", "}", "urn:uuid:", "A", "f", "0", "1", " ", "_", ":", "あ", "\xff", "00000000", "ffff",
		"123e4567-e89b-42d3-a456-426614174000", "123e4567-e89b-12d3-9456-426614174000", "01890a5d-ac96-774b-bcce-b302099a8057",
	}
	rng := rand.New(rand.NewPCG(41, 42))
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(12); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		versions := []uint16{0, 0, 1 << 4, 1<<1 | 1<<7, 1 << 8}[rng.IntN(5)]
		want := refUUIDs(line, versions)
		var got [][2]int
		for _, m := range (uuidFinder{versions: versions}).find(line, nil) {
			got = append(got, [2]int{m.Start, m.End})
		}
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, versions %b, line %q\n got  %v\n want %v", iter, versions, line, got, want)
		}
	}
}

func TestUUIDFinderLongLines(t *testing.T) {
	// ハイフンだけ・16 進数とハイフンだけの長い連なりと、多数の UUID
	for name, line := range map[string]string{
		"hyphens":    strings.Repeat("-", 1<<20),
		"hex hyph":   strings.Repeat("0123456789-", 100000),
		"five apart": strings.Repeat("abcd-", 200000),
	} {
		_ = uuidsIn(line, 0)
		t.Logf("%s ok", name)
	}
	many := strings.Repeat(uuidV4+" ", 20000)
	if got := uuidsIn(many, 0); len(got) != 20000 {
		t.Errorf("got %d matches, want 20000", len(got))
	}
	if !bytes.Contains([]byte(many), []byte(uuidV4)) {
		t.Fatal("setup")
	}
}

func BenchmarkUUIDFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	f := uuidFinder{}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = f.find(line, dst[:0])
		}
	}
}
