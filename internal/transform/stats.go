package transform

import (
	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

// MaxKeptLines は、Stats.KeptLines に記録する行番号の最大数(仕様 6 章)。
const MaxKeptLines = 5

// TypeCount は、種別名と、その件数。
type TypeCount struct {
	Type  string
	Count int
}

// Stats は、Engine の実行結果の集計。生の値は、持たない。
//
// ゼロ値で使える。Engine.Run は、同じ Stats に加算する。
type Stats struct {
	// Lines は、読んだ行数(すべての入力の合計)。
	Lines int
	// Kept は、置換済みの形(ラベル・hash 出力形)のため、置換せずに残した文字列の数(Q31)。
	// --allow で残したもの、特殊アドレスなど、置換済みの形でないものは、含まない。
	Kept int
	// KeptLines は、Kept の文字列がある行の行番号(入力をまたいで通しで数える。1 始まり。
	// 重複なし、昇順、最初の MaxKeptLines 件まで)。
	KeptLines []int

	counts [label.NumTypes]int
}

// add は、置換した 1 件を数える。
func (s *Stats) add(m detect.Match) {
	if i := label.TypeIndex(m.LabelType()); i >= 0 {
		s.counts[i]++
	}
}

// addKept は、行番号 line の行で、置換せずに残した文字列を n 件数える(1 行につき 1 回呼ぶ)。
func (s *Stats) addKept(n, line int) {
	s.Kept += n
	if len(s.KeptLines) < MaxKeptLines {
		s.KeptLines = append(s.KeptLines, line)
	}
}

// Count は、種別名 typ(label.Types のいずれか)の、置換した出現回数を返す。
func (s *Stats) Count(typ string) int {
	if i := label.TypeIndex(typ); i >= 0 {
		return s.counts[i]
	}
	return 0
}

// Total は、置換した出現回数の合計を返す。`--fail-on-detect` の判定に使う。
func (s *Stats) Total() int {
	n := 0
	for _, c := range s.counts {
		n += c
	}
	return n
}

// Types は、置換した件数のある種別を、label.Types の順(固定)で返す(Q19)。
// 件数は、値の種類数でなく、出現回数。
func (s *Stats) Types() []TypeCount {
	var out []TypeCount
	for i, c := range s.counts {
		if c > 0 {
			out = append(out, TypeCount{Type: label.Types[i], Count: c})
		}
	}
	return out
}
