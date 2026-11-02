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
	// largeBlock は、長い行のブロックとして扱う大きさ。行が Read をまたがないブロック(読みかけの部分と 1 回の Read)は、
	// これを超えない。これより大きいバッファは、プールに残さない。
	largeBlock = 512 * 1024
	// maxPooledMatches は、プールに残す一致の領域の要素数の上限(1 件 32 バイトなので、約 1MB)。
	maxPooledMatches = 1 << 15
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
	// Review は、任意。`--review` の表示にする(nil なら、通常の出力)。
	Review *Review

	// workers は、検出のワーカー数。0 なら GOMAXPROCS から決める(上限は maxWorkers)。
	workers int
}

// lineResult は、ブロックの 1 行の検出の結果。
type lineResult struct {
	matchEnd   int // block.matches の中の、この行の一致の終わり(始まりは前の行の matchEnd)
	kept       int
	contentEnd int // block.data の中の、行の中身の終わり(行の始まりは前の行の lineEnd)
	lineEnd    int // block.data の中の、改行コードまで含めた行の終わり
}

// block は、3 段の間で受け渡す、完全な行の並びと、その検出の結果。
type block struct {
	data     []byte
	lines    []lineResult
	matches  []detect.Match
	pem      []detect.PEMSpan // PEM の秘密鍵の範囲(読み取りの段が求める)
	err      error            // 読み取りエラー。これを持つブロックは、データも検出の結果もない
	detected chan struct{}    // 検出が終わると通知する
	released chan *block      // 長い行のブロックだけ。書き換えが終わると、このブロックを読み取りに返す(容量は 1)
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
	// ブロックは、読み取りが必要なときに、n 個まで作る(takeBlock)。
	free := make(chan *block, n)
	// どちらも、ブロックの総数の容量があるので、送信で止まらない。
	work := make(chan *block, n)
	ordered := make(chan *block, n)
	done := make(chan struct{})

	// 行をまたぐ状態は、読み取りの段だけに持つ(Q98)。ワーカーは、行ごとに独立に検出する。
	pem := e.Det.NewPEMScanner(e.Stats.Lines)
	go readBlocks(inputs, pem, free, work, ordered, done)
	// 長い行のブロックは同時に 1 つなので、長い行の作業領域を、ワーカーの数だけ持たないように 1 つの Detector で検出する。
	long := e.Det.Clone()
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detectBlocks(e.Det.Clone(), long, work, done)
		}()
	}
	err := e.writeBlocks(w, ordered, free)
	close(done)
	wg.Wait()
	if err == nil && pem != nil { // err が nil なら、読み取りは終わっている
		e.Stats.Unclosed += pem.Unclosed
		// Run は、入力ごとに続けて呼ばれることがある(`--out-dir`)。
		for _, line := range pem.UnclosedLines {
			e.Stats.UnclosedLines = appendLine(e.Stats.UnclosedLines, line)
		}
	}
	return err
}

// readBlocks は、読み取りの段。入力を順にブロックに分けて、work と ordered に送る。
//
// 長い行のブロックは、書き換えが終わるまで次を読まず、そのブロックを次に使う。ブロックの数だけでは、
// 長い行が続く入力で、メモリが行の長さの何倍にもなるため(メモリは、処理中の最長の行の程度に収める。仕様 7 章)。
func readBlocks(inputs []io.Reader, pem *detect.PEMScanner, free chan *block, work, ordered chan<- *block, done <-chan struct{}) {
	defer close(work)
	defer close(ordered)
	var long *block // 前の長い行のブロック
	created := 0
	for _, in := range inputs {
		r := stream.NewBlockReader(in)
		for {
			b := long
			long = nil
			if b == nil {
				if b = takeBlock(free, &created, done); b == nil {
					return
				}
			}
			var err error
			b.data, err = r.Next(b.data)
			if err == io.EOF {
				free <- b
				if pem != nil {
					pem.Finish()
				}
				break
			}
			if err != nil {
				b.err = err
				ordered <- b
				return
			}
			if pem != nil {
				b.pem = pem.Scan(b.data, b.pem[:0])
			}
			var released chan *block
			if len(b.data) > largeBlock {
				released = make(chan *block, 1)
				b.released = released
			}
			ordered <- b
			work <- b
			if released != nil {
				select {
				case long = <-released:
				case <-done:
					return
				}
			}
		}
	}
}

// takeBlock は、使うブロックを返す。空きを優先し、なければ cap(free) 個まで作り、それ以上は空くのを待つ。
// 処理が追いついている間は、少ないブロックを使い回す。done が閉じると nil を返す。
func takeBlock(free chan *block, created *int, done <-chan struct{}) *block {
	select {
	case b := <-free:
		return b
	default:
	}
	if *created < cap(free) {
		*created++
		return &block{detected: make(chan struct{}, 1)}
	}
	select {
	case b := <-free:
		return b
	case <-done:
		return nil
	}
}

// detectBlocks は、検出の段。d は、このワーカーだけが使う。long は、長い行のブロックだけに使う(ワーカーで共有するが、
// 長い行のブロックは、書き換えが終わるまで次を読まないので、同時に使われない)。
func detectBlocks(d, long *detect.Detector, work <-chan *block, done <-chan struct{}) {
	for {
		select {
		case b, ok := <-work:
			if !ok {
				return
			}
			det := d
			if b.released != nil {
				det = long
			}
			b.lines, b.matches = b.lines[:0], b.matches[:0]
			pem := b.pem
			for pos := 0; pos < len(b.data); {
				var kept int
				content, eol, _ := stream.NextLine(b.data[pos:])
				if len(pem) > 0 && pem[0].Pos == pos {
					n := 1
					for n < len(pem) && pem[n].Pos == pos {
						n++
					}
					b.matches, kept = det.FindSpans(content, pem[:n], b.matches)
					pem = pem[n:]
				} else {
					b.matches, kept = det.Find(content, b.matches)
				}
				contentEnd := pos + len(content)
				pos = contentEnd + len(eol)
				b.lines = append(b.lines, lineResult{len(b.matches), kept, contentEnd, pos})
			}
			b.detected <- struct{}{}
		case <-done:
			return
		}
	}
}

// writeBlocks は、書き換えの段。ブロックを入力の順に受け取り、1 行ずつ置き換えて書く。
// 読み取りエラーでは、エラーの前の完全な行を書き出してから、読み取りエラーを返す。
func (e *Engine) writeBlocks(w io.Writer, ordered <-chan *block, free chan<- *block) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	var out []byte
	for b := range ordered {
		if b.err != nil {
			bw.Flush()
			return b.err
		}
		<-b.detected
		start, first := 0, 0
		for _, l := range b.lines {
			content, eol := b.data[start:l.contentEnd], b.data[l.contentEnd:l.lineEnd]
			if err := e.writeLine(bw, &out, content, eol, b.matches[first:l.matchEnd], l.kept); err != nil {
				return err
			}
			start, first = l.lineEnd, l.matchEnd
		}
		if released := b.released; released != nil {
			b.released = nil
			released <- b
			continue
		}
		if cap(b.data) > largeBlock || cap(b.matches) > maxPooledMatches {
			b.data, b.lines, b.matches, b.pem = nil, nil, nil, nil
		}
		free <- b
	}
	return bw.Flush()
}

// reviewLine は、`--review` の表示の 1 行を作る。
func (e *Engine) reviewLine(out *[]byte, content []byte, matches []detect.Match) []byte {
	dst := (*out)[:0]
	last, suspects := 0, 0
	for _, m := range matches {
		var n int
		dst, n = e.Review.appendPlain(dst, content[last:m.Start])
		suspects += n
		dst = e.Review.appendValue(dst, e.Rep, content, m)
		last = m.End
		e.Stats.add(m)
	}
	dst, n := e.Review.appendPlain(dst, content[last:])
	if suspects += n; suspects > 0 {
		e.Stats.addSuspects(suspects, e.Stats.Lines)
	}
	*out = dst
	return dst
}

// writeLine は、1 行を置き換えて書く。out は、置き換えた行の作業領域。
func (e *Engine) writeLine(bw *bufio.Writer, out *[]byte, content, eol []byte, matches []detect.Match, kept int) error {
	e.Stats.Lines++
	line := content
	if e.Review != nil {
		line = e.reviewLine(out, content, matches)
	} else if len(matches) > 0 {
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
