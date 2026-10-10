package detect

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// finder は、1 つの種別の検出器。
//
// find は、line の中の候補を dst に追記して返す。この時点では、重なりも、置換しない値も気にしない。
// 候補の範囲は空でなく、line の内側でなければならない(空の範囲は無視する)。
// IP アドレスの検出器は、Class に区別(特殊アドレスを含む)を入れて返す。
type finder interface {
	kind() Kind
	find(line []byte, dst []Match) []Match
}

// Options は、Detector の設定。ゼロ値の項目は、既定値になる。
type Options struct {
	// Kinds は、検出する種別。ゼロ値は DefaultKinds。
	Kinds KindSet
	// UUIDVersions は、検出する UUID のバージョン(ビット i がバージョン i、1〜8)。
	// 0 以外を指定すると、Kinds に uuid が加わる(仕様 4.2)。
	UUIDVersions uint16
	// IPScope は、置換する IP アドレスの範囲。ゼロ値は ScopeAll。
	IPScope Scope
	// Allow は、置換しない値(完全一致)。
	Allow map[string]struct{}
	// Format は、置換済みのラベルとみなす書式。ゼロ値は label.DefaultFormat。
	Format label.Format
	// HashLen は、置換済みの hash 出力形とみなす 16 進数の桁数(8〜64)。ゼロ値は 12。
	// mask と restore では、常に既定の 12 を使う(Q10)。
	HashLen int
}

// Detector は、行の中の置換する範囲を決める。
//
// 内部に作業領域を持つため、複数の goroutine から同時に使ってはならない。
type Detector struct {
	finders []finder
	kinds   KindSet
	scope   Scope
	allow   map[string]struct{}
	format  label.Format
	hashLen int

	raw     []Match
	cands   []cand
	scratch []cand
	chosen  []cand
}

// source は、候補の由来。
type source uint8

const (
	srcFound       source = iota // 検出器が見つけた値
	srcAllow                     // 検出器が見つけたが、--allow で置換しない値
	srcPlaceholder               // 置換済みのラベル・hash 出力形(保護範囲)
)

type cand struct {
	Match
	src source
}

// priority は、範囲の長さが同じときの優先順位(小さいほうが優先)。
// 保護範囲が最優先で、そのあとは種別の優先順位。
func (c cand) priority() int {
	if c.src == srcPlaceholder {
		return 0
	}
	return kindPriority[c.Kind]
}

// New は、o に従う Detector を作る。
func New(o Options) (*Detector, error) {
	n, err := normalize(o)
	if err != nil {
		return nil, err
	}
	return newDetector(n, builtinFinders(n))
}

// builtinFinders は、種別ごとの検出器を返す。o は normalize 済みでなければならない。
// 検出器は、段階が進むごとに加わった(email は段階 3、ipv4 / ipv6 は段階 4、secret は段階 5、uuid は段階 6)。
func builtinFinders(o Options) []finder {
	var fs []finder
	if o.Kinds.Has(KindEmail) {
		fs = append(fs, emailFinder{hashLen: o.HashLen, format: o.Format})
	}
	if o.Kinds.Has(KindIPv4) {
		fs = append(fs, ipv4Finder{})
	}
	if o.Kinds.Has(KindIPv6) {
		fs = append(fs, ipv6Finder{})
	}
	if o.Kinds.Has(KindSecret) {
		fs = append(fs, secretFinder{})
	}
	if o.Kinds.Has(KindUUID) {
		fs = append(fs, uuidFinder{versions: o.UUIDVersions})
	}
	return fs
}

// normalize は、o を検証し、ゼロ値の項目を既定値にして返す。何度適用しても結果は同じ。
func normalize(o Options) (Options, error) {
	if o.UUIDVersions&^(0xFF<<1) != 0 {
		return o, errors.New("uuid versions must be between 1 and 8")
	}
	if o.IPScope > ScopePrivate {
		return o, fmt.Errorf("invalid ip scope %d", o.IPScope)
	}
	switch {
	case o.HashLen == 0:
		o.HashLen = label.DefaultHashLen
	case o.HashLen < label.MinHashLen || o.HashLen > label.MaxHashLen:
		return o, fmt.Errorf("hash length must be between %d and %d", label.MinHashLen, label.MaxHashLen)
	}
	if o.Kinds == 0 {
		o.Kinds = DefaultKinds
	}
	if o.UUIDVersions != 0 {
		o.Kinds = o.Kinds.With(KindUUID)
	}
	if o.Format.IsZero() {
		o.Format = label.DefaultFormat
	}
	return o, nil
}

// newDetector は、検出器を差し替えられるようにした New(テスト用)。
func newDetector(o Options, finders []finder) (*Detector, error) {
	o, err := normalize(o)
	if err != nil {
		return nil, err
	}
	d := &Detector{
		kinds:   o.Kinds,
		scope:   o.IPScope,
		allow:   o.Allow,
		format:  o.Format,
		hashLen: o.HashLen,
	}
	for _, f := range finders {
		if d.kinds.Has(f.kind()) {
			d.finders = append(d.finders, f)
		}
	}
	return d, nil
}

// Find は、line の中の置換する範囲を、開始位置の順に dst に追記して返す(重なりはない)。
// 2 つ目の戻り値は、置換済みの形(ラベル・hash 出力形)のため、置換せずに残した範囲の数(Q31)。
//
// 手順(PLAN 4.1):
//  1. 有効な種別の検出器が、候補を出す
//  2. 特殊アドレスと、--ip-scope の範囲外の IP アドレスを外す(Q11: 重なりの解決の前に外す。
//     他の種別が、その範囲を置換できるようにするため)
//  3. --allow の値と完全に一致する候補に印を付ける(外さない。重なりの解決に加えて、勝てばそのまま残す)
//  4. 置換済みのラベル・hash 出力形を、保護範囲として候補に加える(Q1)
//  5. 重なりを解決する。範囲が長いほうを優先し、同じ長さなら、保護範囲、種別の優先順位、
//     開始位置の順で決める。負けた候補は、重なっていない部分も含めて捨てる
func (d *Detector) Find(line []byte, dst []Match) ([]Match, int) {
	d.raw = d.raw[:0]
	for _, f := range d.finders {
		d.raw = f.find(line, d.raw)
	}

	d.cands = d.cands[:0]
	for _, m := range d.raw {
		if m.End <= m.Start {
			continue
		}
		if m.Kind == KindIPv4 || m.Kind == KindIPv6 {
			if m.Class == ClassSpecial || !d.scope.includes(m.Class) {
				continue
			}
		}
		c := cand{Match: m, src: srcFound}
		if len(d.allow) > 0 {
			if _, ok := d.allow[string(line[m.Start:m.End])]; ok {
				c.src = srcAllow
			}
		}
		d.cands = append(d.cands, c)
	}

	d.format.Scan(line, func(start, end int, _ string, _ int) {
		d.cands = append(d.cands, cand{Match: Match{Start: start, End: end}, src: srcPlaceholder})
	})
	label.ScanHashed(line, d.hashLen, func(start, end int) {
		d.cands = append(d.cands, cand{Match: Match{Start: start, End: end}, src: srcPlaceholder})
	})

	return d.resolve(dst)
}

// cmpStart は、開始位置の昇順(同じなら、終了位置の降順)。
// 同じ範囲の候補の順序も一意になるよう、残りの項目でも比較する。
func cmpStart(a, b cand) int {
	return cmp.Or(
		cmp.Compare(a.Start, b.Start),
		cmp.Compare(b.End, a.End),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Class, b.Class),
		cmp.Compare(a.src, b.src),
	)
}

// cmpPriority は、採用する順序。範囲が長い順、優先順位の順、開始位置の昇順。
func cmpPriority(a, b cand) int {
	return cmp.Or(
		cmp.Compare(b.End-b.Start, a.End-a.Start),
		cmp.Compare(a.priority(), b.priority()),
		cmp.Compare(a.Start, b.Start),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Class, b.Class),
		cmp.Compare(a.src, b.src),
	)
}

// resolve は、d.cands の重なりを解決して、置換する範囲を dst に追記する。
//
// 候補を開始位置の順に並べ、重なる候補の塊(推移的に重なるもの)ごとに解決する。
// 塊が違えば互いに重ならないので、塊ごとの解決は、全体に対する貪欲法と同じ結果になる。
// 1 行に多数の候補がある場合(1MB の JSON 1 行など)でも、重ならない候補は塊が 1 つなので、
// 候補の数の 2 乗の時間はかからない。
func (d *Detector) resolve(dst []Match) ([]Match, int) {
	cs := d.cands
	slices.SortFunc(cs, cmpStart)
	kept := 0
	for i := 0; i < len(cs); {
		end := cs[i].End
		j := i + 1
		for j < len(cs) && cs[j].Start < end {
			if cs[j].End > end {
				end = cs[j].End
			}
			j++
		}
		if j-i == 1 {
			dst, kept = emit(dst, kept, cs[i])
		} else {
			d.scratch = append(d.scratch[:0], cs[i:j]...)
			slices.SortFunc(d.scratch, cmpPriority)
			d.chosen = d.chosen[:0]
		pick:
			for _, c := range d.scratch {
				for _, w := range d.chosen {
					if c.Start < w.End && w.Start < c.End {
						continue pick
					}
				}
				d.chosen = append(d.chosen, c)
			}
			slices.SortFunc(d.chosen, cmpStart)
			for _, c := range d.chosen {
				dst, kept = emit(dst, kept, c)
			}
		}
		i = j
	}
	return dst, kept
}

// emit は、採用した候補 c を結果に反映する。置換するものだけを dst に追記し、
// 置換済みの形のため残したものは kept に数える。--allow で残したものは、どちらにも入れない。
func emit(dst []Match, kept int, c cand) ([]Match, int) {
	switch c.src {
	case srcFound:
		dst = append(dst, c.Match)
	case srcPlaceholder:
		kept++
	}
	return dst, kept
}
