package stream

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

type line struct {
	content string
	eol     string
}

// readLines は Reader から全行を読み、(行の中身, 改行コード)の列を返す。
// Next が返すスライスは次の呼び出しまでしか有効でないので、ここでコピーする。
func readLines(t *testing.T, r io.Reader) []line {
	t.Helper()
	sr := NewReader(r)
	var got []line
	for {
		content, eol, err := sr.Next()
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, line{string(content), string(eol)})
	}
}

func join(ls []line) string {
	var sb strings.Builder
	for _, l := range ls {
		sb.WriteString(l.content)
		sb.WriteString(l.eol)
	}
	return sb.String()
}

// 改行コード(LF / CRLF)と末尾改行の有無を判別でき、
// 行の中身と改行コードをつなぐと元の入力に 1 バイトも違わず戻ること。
func TestReaderSplitsLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []line
	}{
		{"empty", "", nil},
		{"lf only", "\n", []line{{"", "\n"}}},
		{"crlf only", "\r\n", []line{{"", "\r\n"}}},
		{"no eol", "a", []line{{"a", ""}}},
		{"lf", "a\n", []line{{"a", "\n"}}},
		{"crlf", "a\r\n", []line{{"a", "\r\n"}}},
		{"two lf", "a\nb\n", []line{{"a", "\n"}, {"b", "\n"}}},
		{"two crlf", "a\r\nb\r\n", []line{{"a", "\r\n"}, {"b", "\r\n"}}},
		{"last line has no eol", "a\nb", []line{{"a", "\n"}, {"b", ""}}},
		{"crlf last line has no eol", "a\r\nb", []line{{"a", "\r\n"}, {"b", ""}}},
		{"mixed", "a\nb\r\nc", []line{{"a", "\n"}, {"b", "\r\n"}, {"c", ""}}},
		{"blank lines", "a\n\n\nb\n", []line{{"a", "\n"}, {"", "\n"}, {"", "\n"}, {"b", "\n"}}},
		{"blank crlf lines", "\r\n\r\n", []line{{"", "\r\n"}, {"", "\r\n"}}},
		// 単独の \r は改行ではなく、行の中身として扱う(PLAN 1 章 stream)。
		{"lone cr inside", "a\rb\n", []line{{"a\rb", "\n"}}},
		{"lone cr at end", "a\r", []line{{"a\r", ""}}},
		{"only cr", "\r", []line{{"\r", ""}}},
		{"cr before crlf", "a\r\r\n", []line{{"a\r", "\r\n"}}},
		{"lf then crlf", "\n\r\n", []line{{"", "\n"}, {"", "\r\n"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readLines(t, strings.NewReader(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("lines = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
			if s := join(got); s != tt.in {
				t.Errorf("rejoined = %q, want %q", s, tt.in)
			}
		})
	}
}

// 受け入れ基準: 64KB を超える 1 行(例: 1MB の JSON 1 行)が処理できる。
func TestReaderLongLines(t *testing.T) {
	const bufSize = 64 * 1024
	sizes := []int{bufSize - 2, bufSize - 1, bufSize, bufSize + 1, bufSize + 2, 2*bufSize - 1, 2 * bufSize, 2*bufSize + 1, 1 << 20}
	eols := []string{"\n", "\r\n", ""}
	for _, n := range sizes {
		for _, eol := range eols {
			content := strings.Repeat("x", n)
			in := content + eol
			got := readLines(t, strings.NewReader(in))
			if len(got) != 1 {
				t.Fatalf("size=%d eol=%q: got %d lines, want 1", n, eol, len(got))
			}
			if got[0].content != content || got[0].eol != eol {
				t.Errorf("size=%d eol=%q: content len=%d eol=%q", n, eol, len(got[0].content), got[0].eol)
			}
		}
	}
}

// バッファの境界が \r と \n の間、または改行の直前・直後に来る位置を総当たりする。
func TestReaderLongLineBoundarySweep(t *testing.T) {
	const bufSize = 64 * 1024
	for n := bufSize - 8; n <= bufSize+8; n++ {
		for _, eol := range []string{"\n", "\r\n"} {
			in := strings.Repeat("a", n) + eol + "tail\r\n"
			got := readLines(t, strings.NewReader(in))
			if len(got) != 2 {
				t.Fatalf("n=%d eol=%q: got %d lines", n, eol, len(got))
			}
			if got[0].content != strings.Repeat("a", n) || got[0].eol != eol {
				t.Errorf("n=%d eol=%q: first line wrong (len=%d, eol=%q)", n, eol, len(got[0].content), got[0].eol)
			}
			if got[1] != (line{"tail", "\r\n"}) {
				t.Errorf("n=%d eol=%q: second line = %q", n, eol, got[1])
			}
		}
	}
}

// 長い行のあとの短い行・長い行が、前の行の内容を引きずらないこと。
func TestReaderLongThenShortThenLong(t *testing.T) {
	long1 := strings.Repeat("A", 300*1024)
	long2 := strings.Repeat("B", 200*1024)
	in := long1 + "\n" + "short\r\n" + long2 + "\r\n" + "end"
	got := readLines(t, strings.NewReader(in))
	want := []line{{long1, "\n"}, {"short", "\r\n"}, {long2, "\r\n"}, {"end", ""}}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d differs (content len got=%d want=%d, eol got=%q want=%q)",
				i, len(got[i].content), len(want[i].content), got[i].eol, want[i].eol)
		}
	}
}

// 受け入れ基準: 日本語・全角文字混じりの行が正しく処理される。
// 不正な UTF-8 のバイト列も、そのまま通す(落とさない・置き換えない)。
func TestReaderPassesNonASCIIAndInvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"japanese", "ユーザー taro@example.com が ＩＰ １９２．１６８．０．１ から接続\r\n"},
		{"fullwidth space and symbols", "　全角スペース｜「括弧」\n"},
		{"emoji", "🙂 ok\n"},
		{"invalid bytes", "\xff\xfe\x80abc\n"},
		{"truncated multibyte at end", "abc\xe3\x81"},
		{"truncated multibyte before eol", "abc\xe3\x81\r\n"},
		{"NUL and control", "a\x00b\x1b[0m\n"},
		{"overlong and surrogate", "\xc0\xaf\xed\xa0\x80\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readLines(t, strings.NewReader(tt.in))
			if s := join(got); s != tt.in {
				t.Errorf("rejoined = %q, want %q", s, tt.in)
			}
		})
	}
}

// 多バイト文字がバッファの境界をまたいでも、バイト列は変わらない。
func TestReaderMultibyteAcrossBufferBoundary(t *testing.T) {
	const bufSize = 64 * 1024
	for pad := bufSize - 4; pad <= bufSize+1; pad++ {
		in := strings.Repeat("a", pad) + "あいう" + "\xff" + "\r\n"
		got := readLines(t, strings.NewReader(in))
		if s := join(got); s != in {
			t.Fatalf("pad=%d: bytes changed", pad)
		}
	}
}

// 読み込み側が 1 バイトずつ・半分ずつ返す、データと EOF を同時に返す場合でも結果が変わらない。
func TestReaderToleratesShortReads(t *testing.T) {
	in := "ログ\r\n" + strings.Repeat("z", 70000) + "\n\nlast"
	want := readLines(t, strings.NewReader(in))
	wrappers := map[string]func(io.Reader) io.Reader{
		"one byte":     iotest.OneByteReader,
		"half":         iotest.HalfReader,
		"data and eof": iotest.DataErrReader,
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			got := readLines(t, wrap(strings.NewReader(in)))
			if len(got) != len(want) {
				t.Fatalf("got %d lines, want %d", len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("line %d differs", i)
				}
			}
		})
	}
}

// 読み込みエラーは握りつぶさず、そのまま返す。
func TestReaderReturnsReadError(t *testing.T) {
	boom := errors.New("boom")
	sr := NewReader(io.MultiReader(strings.NewReader("a\nb"), iotest.ErrReader(boom)))

	content, eol, err := sr.Next()
	if err != nil || string(content) != "a" || string(eol) != "\n" {
		t.Fatalf("first Next = %q, %q, %v", content, eol, err)
	}
	_, _, err = sr.Next()
	if !errors.Is(err, boom) {
		t.Fatalf("second Next error = %v, want %v", err, boom)
	}
}

// EOF のあとは何度呼んでも io.EOF を返す。
func TestReaderEOFIsSticky(t *testing.T) {
	sr := NewReader(strings.NewReader("a"))
	if _, _, err := sr.Next(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := sr.Next(); err != io.EOF {
			t.Fatalf("call %d: err = %v, want io.EOF", i, err)
		}
	}
}

// 受け入れ基準の性能目標(50MB/s)のため、通常の行はコピーも割り当てもしない。
func TestReaderShortLinesDoNotAllocate(t *testing.T) {
	data := bytes.Repeat([]byte("2026-10-11 INFO user=taro@example.com ip=192.168.0.1 ok\r\n"), 10000)
	sr := NewReader(bytes.NewReader(data))
	// ウォームアップ(内部バッファの確保)
	if _, _, err := sr.Next(); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		if _, _, err := sr.Next(); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("allocs per Next = %v, want 0", allocs)
	}
}
