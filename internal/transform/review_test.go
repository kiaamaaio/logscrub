package transform

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

var ansiColor = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func review(t *testing.T, r *Review, inputs ...string) (string, *Stats) {
	t.Helper()
	readers := make([]io.Reader, len(inputs))
	for i, in := range inputs {
		readers[i] = strings.NewReader(in)
	}
	var out strings.Builder
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), Review: r}
	if err := e.Run(readers, &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), &e.Stats
}

func TestReviewColors(t *testing.T) {
	got, st := review(t, &Review{Color: true}, "to taro@example.com\n")
	if want := "to " + colorReplaced + "<email_1>" + colorReset + "\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if st.Count("email") != 1 {
		t.Errorf("%+v", st)
	}
	token := "abcdefghij0123456789"
	got, st = review(t, &Review{Color: true}, "id "+token+" end\n")
	if want := "id " + colorSuspect + token + colorReset + " end\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if st.Suspects != 1 || st.SuspectLineCount != 1 || st.SuspectLines[0] != 1 || st.Total() != 0 {
		t.Errorf("%+v", st)
	}
}

func TestReviewWithoutColor(t *testing.T) {
	got, st := review(t, &Review{}, "to taro@example.com abcdefghij0123456789\n")
	if want := "to <email_1> abcdefghij0123456789\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if st.Suspects != 1 {
		t.Errorf("%+v", st)
	}
}

func TestSuspects(t *testing.T) {
	for _, tt := range []struct {
		line string
		want int
	}{
		{"abcdefghij0123456789", 1},
		{"abcdefghij012345678", 0},                  // 短い
		{"abcdefghijklmnopqrstuvwxyz", 0},           // 数字がない
		{"12345678901234567890123", 0},              // 英字がない
		{"ERR_CONNECTION_REFUSED_BY_THE_PEER", 0},   // 数字がない
		{"/usr/local/lib/python3/site-packages", 0}, // `/` で切れる
		{"2026-10-18T12:34:56.789Z", 0},             // `:` で切れる
		{"a1b2c3d4e5f6a7b8c9d0 a1b2c3d4e5f6a7b8c9d0", 2},
		{"x=abcdefghij0123456789", 1},
		{"123e4567-e89b-42d3-a456-426614174000", 1}, // uuid が無効のとき
	} {
		if _, st := review(t, &Review{}, tt.line+"\n"); st.Suspects != tt.want {
			t.Errorf("%q: %d, want %d", tt.line, st.Suspects, tt.want)
		}
	}
}

func TestReviewShowsControlCharacters(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"a\x1b[8mhidden\x1b[0mb", "a^[[8mhidden^[[0mb"},
		{"a\rb", "a^Mb"},
		{"a\x07b\x7fc", "a^Gb^?c"},
		{"tab\there", "tab\there"},
		{"csi\u009b8m", `csi\u009b8m`},
		{"bidi\u202eevil\u2066x", `bidi\u202eevil\u2066x`},
		{"bad\x9bbyte\xff", `bad\x9bbyte\xff`},
		{"日本語 é", "日本語 é"},
		{"cut\xe6\x97", `cut\xe6\x97`},
	} {
		if got, _ := review(t, &Review{Color: true}, tt.in+"\n"); got != tt.want+"\n" {
			t.Errorf("%q: got %q, want %q", tt.in, got, tt.want)
		}
	}
	// 改行コードは保つ。
	if got, _ := review(t, &Review{}, "a\r\nb"); got != "a\r\nb" {
		t.Errorf("got %q", got)
	}
}

// 色の指定を除くと、通常の mask の出力と同じになる。件数も同じ(仕様 9 章)。
func TestReviewMatchesMask(t *testing.T) {
	for _, name := range []string{"testdata/app.log", "testdata/pem.log", "testdata/paths.log", "testdata/custom.log"} {
		in, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		want, wantSt := mask(t, detect.Options{}, string(in))
		got, st := review(t, &Review{Color: true}, string(in))
		if s := ansiColor.ReplaceAllString(got, ""); s != want {
			t.Errorf("%s:\n--- got ---\n%s\n--- want ---\n%s", name, s, want)
		}
		if st.Total() != wantSt.Total() || st.Kept != wantSt.Kept || st.Unclosed != wantSt.Unclosed {
			t.Errorf("%s: stats %+v, want %+v", name, st, wantSt)
		}
		t.Logf("%s: %d suspects in %d lines", name, st.Suspects, st.Lines)
	}
}
