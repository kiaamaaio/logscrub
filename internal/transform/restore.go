package transform

import (
	"bufio"
	"io"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/stream"
)

// RestoreResult は、Restore の結果。値は、持たない(ラベルと件数だけ)。
type RestoreResult struct {
	// Missing は、対応が見つからず、そのまま残したラベル(回答に現れた順、重複なし。Q23)。
	// ラベルの文字列だけで、元の値は含まない。
	Missing []string
	// Restored は、元の値に戻したラベルの、出現回数。
	Restored int
	// Source は、--source の処理の集計。Kept と KeptLines は、元の入力に、ラベルと同じ形の文字列が
	// あること(正しく戻らない可能性)の通知に使う(Q31)。
	Source Stats
}

// Restore は、ラベルを元の値に戻す(仕様 5.3)。
//
// 対応表は、保存しない。sources(mask に渡したのと同じ入力、同じ順)を、mask と同じ Engine と Masker に
// 通して、連番を振り直す(出力は捨てる)。連番は、検出器の結果と入力の順だけで決まるので、
// det と f が、mask のときと同じなら、同じ対応になる。
// 次に、answer を 1 行ずつ読み、f のラベルを、元の値に置き換えて、w に書く。
// 対応が見つからないラベルは、そのまま残し、RestoreResult.Missing に記録する。
// ラベルの外は、1 バイトも変えない(改行コード、末尾改行の有無を含む)。
// 戻した値は、再度ラベルとして読まない。
func Restore(sources []io.Reader, answer io.Reader, w io.Writer, det *detect.Detector, f label.Format) (RestoreResult, error) {
	var res RestoreResult
	if f.IsZero() {
		f = label.DefaultFormat
	}

	table := NewMasker(f)
	eng := &Engine{Det: det, Rep: table}
	err := eng.Run(sources, io.Discard)
	res.Source = eng.Stats
	if err != nil {
		return res, err
	}

	bw := bufio.NewWriterSize(w, 64<<10)
	r := stream.NewReader(answer)
	var out []byte
	var missing map[string]struct{}
	for {
		content, eol, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, err
		}
		out = out[:0]
		last := 0
		f.Scan(content, func(start, end int, typ string, n int) {
			if v, ok := table.Value(typ, n); ok {
				out = append(out, content[last:start]...)
				out = append(out, v...)
				last = end
				res.Restored++
				return
			}
			name := string(content[start:end])
			if _, seen := missing[name]; !seen {
				if missing == nil {
					missing = make(map[string]struct{})
				}
				missing[name] = struct{}{}
				res.Missing = append(res.Missing, name)
			}
		})
		out = append(out, content[last:]...)
		if _, err := bw.Write(out); err != nil {
			return res, err
		}
		if _, err := bw.Write(eol); err != nil {
			return res, err
		}
	}
	return res, bw.Flush()
}
