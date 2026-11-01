package transform

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/stream"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// runSequential は、Run の参照実装。1 行ずつ、検出と置き換えを同じ goroutine で行う。
func runSequential(e *Engine, inputs []io.Reader, w io.Writer) error {
	bw := bytes.NewBuffer(nil)
	var matches []detect.Match
	var out []byte
	err := stream.ForEachLine(inputs, func(content, eol []byte) error {
		e.Stats.Lines++
		var kept int
		matches, kept = e.Det.Find(content, matches[:0])
		line := content
		if len(matches) > 0 {
			out = out[:0]
			last := 0
			for _, m := range matches {
				out = append(out, content[last:m.Start]...)
				out = e.Rep.Append(out, content, m)
				last = m.End
				e.Stats.add(m)
			}
			line = append(out, content[last:]...)
			out = line
		}
		if e.Inspect != nil {
			kept += e.Inspect(line)
		}
		if kept > 0 {
			e.Stats.addKept(kept, e.Stats.Lines)
		}
		bw.Write(line)
		bw.Write(eol)
		return nil
	})
	if _, werr := w.Write(bw.Bytes()); werr != nil {
		return werr
	}
	return err
}

func synth(t *testing.T, size int, aws bool) []byte {
	t.Helper()
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: size, Seed: 1, LongLineEvery: 2 << 20, AWS: aws}); err != nil {
		t.Fatal(err)
	}
	return []byte(sb.String())
}

func newDet(t *testing.T, o detect.Options) *detect.Detector {
	t.Helper()
	d, err := detect.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func readers(inputs [][]byte) []io.Reader {
	rs := make([]io.Reader, len(inputs))
	for i, in := range inputs {
		rs[i] = bytes.NewReader(in)
	}
	return rs
}

// longLines は、長さの違う長い行と短い行が混ざった入力を返す。
func longLines() []byte {
	var b bytes.Buffer
	for i, n := range []int{3 << 20, 2 << 20, 10, 5 << 20, 1 << 20, 20, 4 << 20, 4 << 20, 1<<20 + 1, 30} {
		fmt.Fprintf(&b, "u%d@example.com ", i)
		b.Write(bytes.Repeat([]byte("x"), n))
		fmt.Fprintf(&b, " v%d@example.com\n", i)
	}
	return b.Bytes()
}

// 出力、集計、通知の行番号が、ワーカー数によらず、1 行ずつの処理と同じであること。
func TestEngineMatchesSequential(t *testing.T) {
	log, awsLog := synth(t, 6<<20, false), synth(t, 6<<20, true)
	awsOpts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindAWSAccount).With(detect.KindAWSS3Bucket).With(detect.KindAWSHost)}
	hasher := func() Replacer {
		h, err := NewHasher([]byte("test-key"), 12, EmailHashLocal)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	masker := func() Replacer { return NewMasker(label.DefaultFormat) }
	tests := []struct {
		name   string
		opts   detect.Options
		rep    func() Replacer
		inputs [][]byte
	}{
		{"default", detect.Options{}, masker, [][]byte{log}},
		{"aws", awsOpts, masker, [][]byte{awsLog}},
		{"hash", detect.Options{}, hasher, [][]byte{log}},
		{"deny and domain", detect.Options{Deny: []string{"Orders", "app"}, Domains: []string{"example.com"}}, masker, [][]byte{log}},
		{"hash with deny", detect.Options{Deny: []string{"example"}}, hasher, [][]byte{log}},
		// 入力の間で、行をつながない。末尾改行のない入力の次の入力は、別の行になる。
		{"several inputs", detect.Options{}, masker, [][]byte{
			[]byte("a@example.com no newline"), []byte("b@example.com\r\n<email_1> \r\n"), {}, []byte("c@example.com\n\n\r"), log[:1<<20],
		}},
		{"labels in the input", detect.Options{}, masker, [][]byte{bytes.Repeat([]byte("<email_1> email_3f9a1c0b7d2e x@example.com\n"), 20000)}},
		{"empty", detect.Options{}, masker, nil},
		// 長い行のバッファを、次のブロックに使い回す場合。
		{"long lines", detect.Options{}, masker, [][]byte{longLines(), longLines()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := &Engine{Det: newDet(t, tt.opts), Rep: tt.rep()}
			var want bytes.Buffer
			if err := runSequential(ref, readers(tt.inputs), &want); err != nil {
				t.Fatal(err)
			}
			for _, workers := range []int{0, 1, 2, 4, 8} {
				e := &Engine{Det: newDet(t, tt.opts), Rep: tt.rep(), workers: workers}
				var got bytes.Buffer
				if err := e.Run(readers(tt.inputs), &got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					t.Errorf("workers %d: the output differs", workers)
				}
				if !reflect.DeepEqual(e.Stats, ref.Stats) {
					t.Errorf("workers %d: stats %+v, want %+v", workers, e.Stats, ref.Stats)
				}
			}
		})
	}
}

// 入力の数が、処理中のブロックの数より多くても止まらない。
func TestEngineManyInputs(t *testing.T) {
	inputs := make([]io.Reader, maxWorkers*blocksPerWorker*3)
	for i := range inputs {
		inputs[i] = strings.NewReader(fmt.Sprintf("u%d@example.com\n", i))
	}
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: 1}
	var out bytes.Buffer
	if err := e.Run(inputs, &out); err != nil {
		t.Fatal(err)
	}
	if e.Stats.Lines != len(inputs) {
		t.Errorf("lines = %d, want %d", e.Stats.Lines, len(inputs))
	}
}

// Inspect は、入力の順に、1 つの goroutine から呼ばれる。
func TestEngineInspectRunsInOrder(t *testing.T) {
	var in bytes.Buffer
	const lines = 200000
	for i := range lines {
		fmt.Fprintf(&in, "%d\n", i)
	}
	next := 0
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: 4, Inspect: func(out []byte) int {
		if string(out) != fmt.Sprint(next) {
			t.Fatalf("line %d: got %q", next, out)
		}
		next++
		return 0
	}}
	if err := e.Run([]io.Reader{&in}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if next != lines {
		t.Errorf("Inspect was called %d times", next)
	}
}

// 読み取りエラーの前の完全な行は処理し、読みかけの行と、後ろの入力は読まない。
func TestEngineReadError(t *testing.T) {
	boom := errors.New("boom")
	second := strings.NewReader("b@example.com\n")
	first := io.MultiReader(strings.NewReader("a@example.com\npartial@example.com"), iotest.ErrReader(boom))
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat)}
	if err := e.Run([]io.Reader{first, second}, io.Discard); err != boom {
		t.Fatalf("got %v", err)
	}
	if e.Stats.Lines != 1 {
		t.Errorf("lines = %d, want 1", e.Stats.Lines)
	}
	if second.Len() == 0 {
		t.Error("the next input was read")
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

type endless struct{ line []byte }

func (e endless) Read(p []byte) (int, error) {
	n := 0
	for len(p)-n >= len(e.line) {
		n += copy(p[n:], e.line)
	}
	return n, nil
}

func waitForGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines remain, had %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(time.Millisecond)
	}
}

// 書き込みエラー(`| head`)では、終わらない入力でも止まり、goroutine が残らない。
func TestEngineWriteErrorStopsEverything(t *testing.T) {
	boom := errors.New("boom")
	before := runtime.NumGoroutine()
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: 4}
	if err := e.Run([]io.Reader{endless{[]byte("a@example.com\n")}}, failingWriter{boom}); err != boom {
		t.Fatalf("got %v", err)
	}
	waitForGoroutines(t, before)
}

// blockingReader は、data を返したあと、blocked を閉じて、unblock が閉じるまで Read で止まる。
type blockingReader struct {
	data    []byte
	blocked chan struct{}
	unblock chan struct{}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	close(b.blocked)
	<-b.unblock
	return 0, io.EOF
}

// lateFailingWriter は、wait が閉じるのを待ってから、エラーを返す。
type lateFailingWriter struct {
	wait <-chan struct{}
	err  error
}

func (l lateFailingWriter) Write([]byte) (int, error) {
	<-l.wait
	return 0, l.err
}

// 読み取りが Read の中で止まっていても、書き込みエラーで戻る(`tail -f | logscrub | head`)。
func TestEngineWriteErrorDoesNotWaitForARead(t *testing.T) {
	boom := errors.New("boom")
	before := runtime.NumGoroutine()
	// 置換後も 64KB の書き込みのバッファを超える大きさで、1 回の Read に収まる大きさ。
	r := &blockingReader{data: bytes.Repeat([]byte("a@example.com\n"), 12000), blocked: make(chan struct{}), unblock: make(chan struct{})}
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: 2}
	errc := make(chan error)
	go func() { errc <- e.Run([]io.Reader{r}, lateFailingWriter{r.blocked, boom}) }()
	select {
	case err := <-errc:
		if err != boom {
			t.Fatalf("got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	close(r.unblock)
	waitForGoroutines(t, before)
}

// countingReader は、読まれたバイト数を数える。
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// gateWriter は、open が閉じるまで最初の Write で止まる。
type gateWriter struct {
	started chan struct{}
	open    chan struct{}
	once    atomic.Bool
}

func (g *gateWriter) Write(p []byte) (int, error) {
	if g.once.CompareAndSwap(false, true) {
		close(g.started)
	}
	<-g.open
	return len(p), nil
}

// 長い行が続く入力では、処理中の行が増えない(メモリを、長い行の程度に収める。仕様 7 章)。
func TestEngineDoesNotReadAheadOfLongLines(t *testing.T) {
	const lineLen = 4 << 20
	line := append(bytes.Repeat([]byte("x"), lineLen-1), '\n')
	in := &countingReader{r: bytes.NewReader(bytes.Repeat(line, 24))}
	w := &gateWriter{started: make(chan struct{}), open: make(chan struct{})}
	e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: 8}
	errc := make(chan error)
	go func() { errc <- e.Run([]io.Reader{in}, w) }()
	<-w.started
	time.Sleep(100 * time.Millisecond) // 読み取りが先へ進むなら、進む時間
	got := in.n.Load()
	close(w.open)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if want := int64(3 * lineLen); got > want {
		t.Errorf("read %d bytes while the first line was being written, want at most %d", got, want)
	}
}
