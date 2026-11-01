package transform

import (
	"bufio"
	"io"
	"runtime"
	"sync"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/stream"
)

const (
	// maxWorkers は、検出のワーカー数の上限(Q96)。
	maxWorkers = 8
	// blocksPerWorker は、処理中のブロックの数(ワーカーあたり)。使い回すので、メモリの上限になる。
	blocksPerWorker = 3
	// largeBlock は、長い行のブロックとして扱う大きさ。これより大きいバッファは、使い回さない。
	largeBlock = 1 << 20
)

// Engine は、入力を行の単位で読み、検出した範囲を Rep で置き換えて、w に書く。
//
// 行の、置換した範囲以外は、1 バイトも変えない(改行コード、末尾改行の有無、不正な UTF-8 を含む)。
// 置換のない行は、読んだバイト列をそのまま書く。
// mask、hash、restore が、同じ Engine を通ることで、検出と書き換えの規則が共通になる。
//
// 処理は 3 段に分かれる(DEVELOPMENT.md 3.3 節)。読み取りが入力を完全な行のブロックに分け、ワーカーが検出し、
// 書き換えが入力の順に Rep、Stats、Inspect を呼んで書く。連番は書き換えの段だけで振るので、ワーカー数によらず同じ結果になる。
type Engine struct {
	Det *detect.Detector
	Rep Replacer
	// Stats は、実行結果の集計。Run は、これに加算する。
	Stats Stats
	// Inspect は、任意。変換した 1 行(改行コードを含まない)を受け取り、その行で
	// 置換済みの形として数える文字列の数を返す。restore が、mask の出力を確かめるために使う。
	Inspect func(out []byte) int

	// workers は、検出のワーカー数。0 なら GOMAXPROCS から決める(上限は maxWorkers)。
	workers int
}

// lineResult は、ブロックの 1 行の検出の結果。
type lineResult struct {
	matchEnd int // block.matches の中の、この行の一致の終わり(始まりは前の行の matchEnd)
	kept     int
}

// block は、3 段の間で受け渡す、完全な行の並びと、その検出の結果。
type block struct {
	data     []byte
	lines    []lineResult
	matches  []detect.Match
	err      error         // 読み取りエラー。これを持つブロックは、データも検出の結果もない
	detected chan struct{} // 検出が終わると通知する
	released chan struct{} // 長い行のブロックだけ。書き換えが終わると閉じる
}

// Run は、inputs を順に読んで(行は入力ごとに区切る。Q22)、変換した結果を w に書く。
// 出力は、各入力の変換結果を、そのままつなげたもの。
//
// 書き込みエラーで戻るときは、読み取りが Read の中で止まっていても待たない(その Read が戻ると終わる)。
func (e *Engine) Run(inputs []io.Reader, w io.Writer) error {
	workers := e.workers
	if workers == 0 {
		workers = min(runtime.GOMAXPROCS(0), maxWorkers)
	}
	n := workers * blocksPerWorker
	free := make(chan *block, n)
	for range n {
		free <- &block{detected: make(chan struct{}, 1)}
	}
	// どちらも、ブロックの総数の容量があるので、送信で止まらない。
	work := make(chan *block, n)
	ordered := make(chan *block, n)
	done := make(chan struct{})

	go readBlocks(inputs, free, work, ordered, done)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detectBlocks(e.Det.Clone(), work, done)
		}()
	}
	err := e.writeBlocks(w, ordered, free)
	close(done)
	wg.Wait()
	return err
}

// readBlocks は、読み取りの段。入力を順にブロックに分けて、work と ordered に送る。
//
// 長い行のブロックは、書き換えが終わるまで次を読まない。ブロックの数だけでは、長い行が続く入力で、
// メモリが行の長さの何倍にもなるため(メモリは、処理中の最長の行の程度に収める。仕様 7 章)。
func readBlocks(inputs []io.Reader, free chan *block, work, ordered chan<- *block, done <-chan struct{}) {
	defer close(work)
	defer close(ordered)
	for _, in := range inputs {
		r := stream.NewBlockReader(in)
		for {
			var b *block
			select {
			case b = <-free:
			case <-done:
				return
			}
			var err error
			b.data, err = r.Next(b.data)
			if err == io.EOF {
				free <- b
				break
			}
			if err != nil {
				b.err = err
				ordered <- b
				return
			}
			var released chan struct{}
			if len(b.data) > largeBlock {
				released = make(chan struct{})
				b.released = released
			}
			ordered <- b
			work <- b
			if released != nil {
				select {
				case <-released:
				case <-done:
					return
				}
			}
		}
	}
}

// detectBlocks は、検出の段。d は、このワーカーだけが使う。
func detectBlocks(d *detect.Detector, work <-chan *block, done <-chan struct{}) {
	for {
		select {
		case b, ok := <-work:
			if !ok {
				return
			}
			b.lines, b.matches = b.lines[:0], b.matches[:0]
			for rest := b.data; len(rest) > 0; {
				var content []byte
				var kept int
				content, _, rest = stream.NextLine(rest)
				b.matches, kept = d.Find(content, b.matches)
				b.lines = append(b.lines, lineResult{len(b.matches), kept})
			}
			b.detected <- struct{}{}
		case <-done:
			return
		}
	}
}

// writeBlocks は、書き換えの段。ブロックを入力の順に受け取り、1 行ずつ置き換えて書く。
func (e *Engine) writeBlocks(w io.Writer, ordered <-chan *block, free chan<- *block) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	var out []byte
	for b := range ordered {
		if b.err != nil {
			return b.err
		}
		<-b.detected
		rest, first := b.data, 0
		for _, l := range b.lines {
			var content, eol []byte
			content, eol, rest = stream.NextLine(rest)
			if err := e.writeLine(bw, &out, content, eol, b.matches[first:l.matchEnd], l.kept); err != nil {
				return err
			}
			first = l.matchEnd
		}
		if b.released != nil {
			close(b.released)
			b.released = nil
		}
		if cap(b.data) > largeBlock {
			b.data, b.lines, b.matches = nil, nil, nil
		}
		free <- b
	}
	return bw.Flush()
}

// writeLine は、1 行を置き換えて書く。out は、置き換えた行の作業領域。
func (e *Engine) writeLine(bw *bufio.Writer, out *[]byte, content, eol []byte, matches []detect.Match, kept int) error {
	e.Stats.Lines++
	line := content
	if len(matches) > 0 {
		*out = (*out)[:0]
		last := 0
		for _, m := range matches {
			*out = append(*out, content[last:m.Start]...)
			*out = e.Rep.Append(*out, content, m)
			last = m.End
			e.Stats.add(m)
		}
		line = append(*out, content[last:]...)
		*out = line
	}
	if e.Inspect != nil {
		kept += e.Inspect(line)
	}
	if kept > 0 {
		e.Stats.addKept(kept, e.Stats.Lines)
	}
	if _, err := bw.Write(line); err != nil {
		return err
	}
	_, err := bw.Write(eol)
	return err
}
