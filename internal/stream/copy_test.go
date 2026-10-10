package stream

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func readers(ss ...string) []io.Reader {
	rs := make([]io.Reader, len(ss))
	for i, s := range ss {
		rs[i] = strings.NewReader(s)
	}
	return rs
}

// 入力を恒等変換で書き戻すと、1 バイトも変わらない。
// 受け入れ基準: CRLF の入力が CRLF のまま出力され、末尾改行の有無も保たれる。
func TestCopyIsIdentity(t *testing.T) {
	long := strings.Repeat("{\"k\":\"v\"},", 100000) // 約 1MB の 1 行
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"lf", "a\nb\n"},
		{"crlf", "a\r\nb\r\n"},
		{"crlf without final eol", "a\r\nb"},
		{"lf without final eol", "a\nb"},
		{"mixed", "a\nb\r\n\r\nc\rd\n"},
		{"only eols", "\n\r\n\n"},
		{"japanese", "ログ\r\n全角：ＡＢＣ\n"},
		{"invalid utf8", "\xff\xfe\n\x80"},
		{"1MB line lf", long + "\n"},
		{"1MB line crlf", long + "\r\n"},
		{"1MB line no eol", long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Copy(&out, strings.NewReader(tt.in)); err != nil {
				t.Fatal(err)
			}
			if out.String() != tt.in {
				t.Errorf("output differs from input (got %d bytes, want %d bytes)", out.Len(), len(tt.in))
			}
		})
	}
}

// Q22: 複数の入力は、ファイルごとに行を区切る。
// 末尾改行のないファイルの最後の行と、次のファイルの最初の行は別の行になる。
func TestForEachLineDoesNotJoinAcrossInputs(t *testing.T) {
	var got []line
	err := ForEachLine(readers("ab", "cd\n", "ef\r\ngh"), func(content, eol []byte) error {
		got = append(got, line{string(content), string(eol)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []line{{"ab", ""}, {"cd", "\n"}, {"ef", "\r\n"}, {"gh", ""}}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Q22: 出力は、各入力の出力をそのままつないだもの(間に改行を足さない)。
func TestCopyConcatenatesInputsWithoutAddingNewlines(t *testing.T) {
	tests := []struct {
		name string
		ins  []string
	}{
		{"first has no final eol", []string{"a", "b\n"}},
		{"crlf then no eol", []string{"a\r\n", "b"}},
		{"empty inputs in between", []string{"", "a\n", "", "b", ""}},
		{"all empty", []string{"", ""}},
		{"single", []string{"a\r\nb"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Copy(&out, readers(tt.ins...)...); err != nil {
				t.Fatal(err)
			}
			if want := strings.Join(tt.ins, ""); out.String() != want {
				t.Errorf("output = %q, want %q", out.String(), want)
			}
		})
	}
}

func TestCopyWithNoInputsWritesNothing(t *testing.T) {
	var out bytes.Buffer
	if err := Copy(&out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want empty", out.String())
	}
}

func TestForEachLineStopsOnCallbackError(t *testing.T) {
	stop := errors.New("stop")
	calls := 0
	err := ForEachLine(readers("a\nb\nc\n"), func(_, _ []byte) error {
		calls++
		if calls == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want %v", err, stop)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCopyReturnsWriteError(t *testing.T) {
	boom := errors.New("disk full")
	err := Copy(failWriter{boom}, strings.NewReader(strings.Repeat("a\n", 100000)))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

type failReader struct{ err error }

func (r failReader) Read([]byte) (int, error) { return 0, r.err }

func TestCopyReturnsReadError(t *testing.T) {
	boom := errors.New("read failed")
	var out bytes.Buffer
	err := Copy(&out, strings.NewReader("a\n"), failReader{boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}
