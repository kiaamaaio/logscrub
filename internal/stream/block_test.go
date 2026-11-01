package stream

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"testing/iotest"
)

// readBlocks は BlockReader から全行を読み、最後のエラーと一緒に返す。
func readBlocks(t *testing.T, b *BlockReader) ([]line, error) {
	t.Helper()
	var got []line
	var buf []byte
	for {
		var err error
		buf, err = b.Next(buf)
		if err != nil {
			return got, err
		}
		if len(buf) == 0 {
			t.Fatal("Next returned an empty block")
		}
		for rest := buf; len(rest) > 0; {
			var content, eol []byte
			content, eol, rest = NextLine(rest)
			got = append(got, line{string(content), string(eol)})
		}
	}
}

// readAllLines は Reader から全行を読み、最後のエラーと一緒に返す。
func readAllLines(r io.Reader) ([]line, error) {
	sr := NewReader(r)
	var got []line
	for {
		content, eol, err := sr.Next()
		if err != nil {
			return got, err
		}
		got = append(got, line{string(content), string(eol)})
	}
}

func equalLines(a, b []line) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// chunkReader は、data を乱数の大きさに分けて返す。最後のデータと一緒に、または次の Read で err を返す。
// 途中で、データもエラーもない Read を混ぜる。
type chunkReader struct {
	data []byte
	rng  *rand.Rand
	err  error
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, c.err
	}
	if c.rng.IntN(10) == 0 {
		return 0, nil
	}
	n := min(1+c.rng.IntN(c.rng.IntN(70000)+1), len(p), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	if len(c.data) == 0 && c.rng.IntN(2) == 0 {
		return n, c.err
	}
	return n, nil
}

// randomLines は、改行コード、空行、単独の \r、長い行、末尾の改行の有無を混ぜた入力を返す。
func randomLines(rng *rand.Rand) []byte {
	var b bytes.Buffer
	lengths := []int{0, 1, 2, 40, 300, 64<<10 - 1, 64 << 10, 64<<10 + 1, blockSize - 1, blockSize, blockSize + 1, 2*blockSize + 3}
	for range rng.IntN(12) {
		n := lengths[rng.IntN(len(lengths))]
		if n > 1000 && rng.IntN(3) != 0 {
			n = rng.IntN(1000)
		}
		b.Write(bytes.Repeat([]byte{'a' + byte(rng.IntN(26))}, n))
		switch rng.IntN(6) {
		case 0:
			b.WriteString("\r\n")
		case 1:
			b.WriteString("\r")
		case 2:
			b.WriteString("\r\r\n")
		default:
			b.WriteString("\n")
		}
	}
	if rng.IntN(2) == 0 {
		b.WriteString("tail")
		if rng.IntN(2) == 0 {
			b.WriteString("\r")
		}
	}
	return b.Bytes()
}

// 行の分け方とエラーが、Reader と同じであること。
func TestBlockReaderMatchesReader(t *testing.T) {
	boom := errors.New("boom")
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 3000 {
		data := randomLines(rng)
		err := io.EOF
		if i%3 == 0 {
			err = boom
		}
		size := blockSize
		if i%2 == 0 {
			size = 1 + rng.IntN(100) // 小さな Read でも、同じ結果になること
		}
		seed := rng.Uint64()
		want, wantErr := readAllLines(&chunkReader{data, rand.New(rand.NewPCG(seed, 0)), err})
		b := NewBlockReader(&chunkReader{data, rand.New(rand.NewPCG(seed, 0)), err})
		b.size = size
		got, gotErr := readBlocks(t, b)
		if gotErr != wantErr {
			t.Fatalf("case %d: error %v, want %v", i, gotErr, wantErr)
		}
		if !equalLines(got, want) {
			t.Fatalf("case %d: got %d lines, want %d", i, len(got), len(want))
		}
	}
}

func TestBlockReaderToleratesShortReads(t *testing.T) {
	const input = "one\r\n\ntwo\rx\nlast"
	want, _ := readAllLines(strings.NewReader(input))
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"one byte":     iotest.OneByteReader,
		"half":         iotest.HalfReader,
		"data and eof": iotest.DataErrReader,
	} {
		got, err := readBlocks(t, NewBlockReader(wrap(strings.NewReader(input))))
		if err != io.EOF || !equalLines(got, want) {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

// 空の入力では、ブロックを返さない。
func TestBlockReaderEmptyInput(t *testing.T) {
	if got, err := readBlocks(t, NewBlockReader(strings.NewReader(""))); err != io.EOF || len(got) != 0 {
		t.Errorf("got %q, %v", got, err)
	}
}

// エラーの前の完全な行は返し、読みかけの行は返さない。エラーは次の呼び出しでも同じ。
func TestBlockReaderErrorAfterCompleteLines(t *testing.T) {
	boom := errors.New("boom")
	r := io.MultiReader(strings.NewReader("a\nb\npartial"), iotest.ErrReader(boom))
	b := NewBlockReader(r)
	got, err := readBlocks(t, b)
	if err != boom || !equalLines(got, []line{{"a", "\n"}, {"b", "\n"}}) {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := b.Next(nil); err != boom {
		t.Errorf("second error: %v", err)
	}
}

// oneShotErrReader は、データと一緒に 1 度だけエラーを返し、そのあとは入力の終わりを返す。
type oneShotErrReader struct {
	data string
	err  error
}

func (o *oneShotErrReader) Read(p []byte) (int, error) {
	n := copy(p, o.data)
	o.data = o.data[n:]
	err := o.err
	o.err = io.EOF
	return n, err
}

// 完全な行のあとに返すエラーは、次の Read の結果で失われない。
func TestBlockReaderKeepsTheErrorForTheNextCall(t *testing.T) {
	boom := errors.New("boom")
	got, err := readBlocks(t, NewBlockReader(&oneShotErrReader{"a\n", boom}))
	if err != boom || !equalLines(got, []line{{"a", "\n"}}) {
		t.Errorf("got %q, %v", got, err)
	}
}

type stalledReader struct {
	data  string
	reads int
}

func (s *stalledReader) Read(p []byte) (int, error) {
	s.reads++
	if s.reads > 1 {
		panic("read past the available data")
	}
	return copy(p, s.data), nil
}

// 届いた行は、次のデータを待たずに返す(`tail -f | logscrub`)。読みかけの部分は、次のブロックに回す。
func TestBlockReaderDoesNotWaitForAFullBlock(t *testing.T) {
	s := &stalledReader{data: "one\ntwo\npart"}
	block, err := NewBlockReader(s).Next(nil)
	if err != nil || string(block) != "one\ntwo\n" {
		t.Errorf("got %q, %v", block, err)
	}
}

func TestBlockReaderCarriesThePartialLine(t *testing.T) {
	b := NewBlockReader(iotest.OneByteReader(strings.NewReader("ab\ncd\n")))
	var got []string
	var buf []byte
	for {
		var err error
		if buf, err = b.Next(buf); err != nil {
			break
		}
		got = append(got, string(buf))
	}
	if strings.Join(got, "|") != "ab\n|cd\n" {
		t.Errorf("got %q", got)
	}
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, nil }

func TestBlockReaderNoProgress(t *testing.T) {
	_, want := readAllLines(emptyReader{})
	if _, err := readBlocks(t, NewBlockReader(emptyReader{})); err != want {
		t.Errorf("got %v, want %v", err, want)
	}
}

// 短い行の入力では、読みかけの部分は小さいので、前のバッファを大きくせずに使い回せる。
func TestBlockReaderReusesTheBuffer(t *testing.T) {
	input := strings.Repeat("0123456789\n", 1<<17)
	b := NewBlockReader(strings.NewReader(input))
	buf := make([]byte, 0, 2*blockSize)
	var out strings.Builder
	allocs := 0
	for {
		next, err := b.Next(buf)
		if err != nil {
			break
		}
		if cap(next) != cap(buf) {
			allocs++
		}
		out.Write(next)
		buf = next
	}
	if allocs != 0 {
		t.Errorf("the buffer was reallocated %d times", allocs)
	}
	if out.String() != input {
		t.Error("the blocks do not add up to the input")
	}
}

func TestNextLine(t *testing.T) {
	tests := []struct {
		block        string
		content, eol string
		rest         string
	}{
		{"a\nb", "a", "\n", "b"},
		{"a\r\n", "a", "\r\n", ""},
		{"\n", "", "\n", ""},
		{"a\rb\n", "a\rb", "\n", ""},
		{"a\r", "a\r", "", ""},
		{"a", "a", "", ""},
	}
	for _, tt := range tests {
		content, eol, rest := NextLine([]byte(tt.block))
		if string(content) != tt.content || string(eol) != tt.eol || string(rest) != tt.rest {
			t.Errorf("%q: got %q, %q, %q", tt.block, content, eol, rest)
		}
	}
}

func BenchmarkBlockReader(b *testing.B) {
	data := bytes.Repeat([]byte("2026-10-24T12:00:00Z INFO request served by node-17 in 12ms status=200\n"), 1<<16)
	b.SetBytes(int64(len(data)))
	var buf []byte
	for b.Loop() {
		r := NewBlockReader(bytes.NewReader(data))
		for {
			var err error
			if buf, err = r.Next(buf); err != nil {
				break
			}
			for rest := buf; len(rest) > 0; {
				_, _, rest = NextLine(rest)
			}
		}
	}
}

func BenchmarkReader(b *testing.B) {
	data := bytes.Repeat([]byte("2026-10-24T12:00:00Z INFO request served by node-17 in 12ms status=200\n"), 1<<16)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		r := NewReader(bytes.NewReader(data))
		for {
			if _, _, err := r.Next(); err != nil {
				break
			}
		}
	}
}
