package transform

import (
	"bufio"
	"io"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/stream"
)

// Engine は、入力を 1 行ずつ読み、検出した範囲を Rep で置き換えて、w に書く。
//
// 行の、置換した範囲以外は、1 バイトも変えない(改行コード、末尾改行の有無、不正な UTF-8 を含む)。
// 置換のない行は、読んだバイト列をそのまま書く。
// mask、hash、restore が、同じ Engine を通ることで、検出と書き換えの規則が共通になる。
type Engine struct {
	Det *detect.Detector
	Rep Replacer
	// Stats は、実行結果の集計。Run は、これに加算する。
	Stats Stats
}

// Run は、inputs を順に読んで(行は入力ごとに区切る。Q22)、変換した結果を w に書く。
// 出力は、各入力の変換結果を、そのままつなげたもの。
func (e *Engine) Run(inputs []io.Reader, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	var (
		matches []detect.Match
		out     []byte
	)
	err := stream.ForEachLine(inputs, func(content, eol []byte) error {
		e.Stats.Lines++
		var kept int
		matches, kept = e.Det.Find(content, matches[:0])
		if kept > 0 {
			e.Stats.addKept(kept, e.Stats.Lines)
		}
		if len(matches) == 0 {
			if _, err := bw.Write(content); err != nil {
				return err
			}
			_, err := bw.Write(eol)
			return err
		}
		out = out[:0]
		last := 0
		for _, m := range matches {
			out = append(out, content[last:m.Start]...)
			out = e.Rep.Append(out, content, m)
			last = m.End
			e.Stats.add(m)
		}
		out = append(out, content[last:]...)
		if _, err := bw.Write(out); err != nil {
			return err
		}
		_, err := bw.Write(eol)
		return err
	})
	if err != nil {
		return err
	}
	return bw.Flush()
}
