// Package transform は、検出した範囲を、ラベル(mask)やハッシュ(hash)に置き換える。
package transform

import (
	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

// Replacer は、検出した 1 件を、置換後のバイト列にする。
type Replacer interface {
	// Append は、line の中の範囲 m を置き換えたバイト列を、dst に追記して返す。
	Append(dst []byte, line []byte, m detect.Match) []byte
}

// Masker は、値を `<種別_連番>` のラベルに置き換える(仕様 5.1)。
//
// 連番は、種別名(IP アドレスは、グローバル/プライベートの区別を含む)ごとに、
// 入力の中で最初に現れた順に振る。同じ値(バイト列が完全に同じもの。Q3)には同じ番号を、
// 違う値には次の番号を振る。対応表は、メモリ上だけに持ち、ファイルには書かない。
//
// restore は、元の入力を、mask と同じ Engine と Masker に通して、対応を作り直す(仕様 5.3)。
// このため、番号の振り方は、検出器の結果と入力の順だけで決まる。Go の map の反復順には依存しない。
type Masker struct {
	format label.Format
	ids    [label.NumTypes]map[string]int // 種別名ごとの、値 → 連番
	values [label.NumTypes][]string       // 種別名ごとの、連番 - 1 → 値(restore の逆引き)
}

// NewMasker は、書式 f でラベルを作る Masker を返す。ゼロ値の書式は、既定(`<{type}_{n}>`)。
func NewMasker(f label.Format) *Masker {
	if f.IsZero() {
		f = label.DefaultFormat
	}
	return &Masker{format: f}
}

// Append は、m の値のラベルを、dst に追記して返す。
// ラベルの種別がない(置換しないはずの)範囲は、元のバイト列をそのまま追記する。
func (k *Masker) Append(dst []byte, line []byte, m detect.Match) []byte {
	v := line[m.Start:m.End]
	ti := label.TypeIndex(m.LabelType())
	if ti < 0 {
		return append(dst, v...)
	}
	ids := k.ids[ti]
	if ids == nil {
		ids = make(map[string]int)
		k.ids[ti] = ids
	}
	n, ok := ids[string(v)]
	if !ok {
		n = len(ids) + 1
		val := string(v)
		ids[val] = n
		k.values[ti] = append(k.values[ti], val)
	}
	return k.format.Append(dst, label.Types[ti], n)
}

// Value は、種別名 typ(label.Types のいずれか)の連番 n に振った値を返す。
// まだその番号を振っていなければ、ok は false。restore が、対応表として使う。
func (k *Masker) Value(typ string, n int) (value string, ok bool) {
	ti := label.TypeIndex(typ)
	if ti < 0 || n < 1 || n > len(k.values[ti]) {
		return "", false
	}
	return k.values[ti][n-1], true
}

func (k *Masker) total() int {
	n := 0
	for _, m := range k.ids {
		n += len(m)
	}
	return n
}
