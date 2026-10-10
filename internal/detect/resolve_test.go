package detect

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// refCand は、参照実装(単純な全体の貪欲法)が扱う候補。
type refCand struct {
	Match
	placeholder bool
}

func refPriority(c refCand) int {
	if c.placeholder {
		return 0
	}
	switch c.Kind {
	case KindEmail:
		return 1
	case KindIPv4, KindIPv6:
		return 2
	case KindSecret:
		return 3
	case KindUUID:
		return 4
	}
	panic("unknown kind")
}

// refResolve は、仕様と PLAN 4.1 の規則を、そのまま書いた参照実装。
// 「長さの降順 → 優先順位 → 開始位置の昇順」に並べ、すでに採用した範囲と重ならないものを採用する。
func refResolve(cands []refCand) (out []Match, kept int) {
	sorted := slices.Clone(cands)
	slices.SortStableFunc(sorted, func(a, b refCand) int {
		if la, lb := a.End-a.Start, b.End-b.Start; la != lb {
			return lb - la
		}
		if pa, pb := refPriority(a), refPriority(b); pa != pb {
			return pa - pb
		}
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Class) - int(b.Class)
	})
	var chosen []refCand
	for _, c := range sorted {
		ok := true
		for _, w := range chosen {
			if c.Start < w.End && w.Start < c.End {
				ok = false
				break
			}
		}
		if ok {
			chosen = append(chosen, c)
		}
	}
	slices.SortFunc(chosen, func(a, b refCand) int { return a.Start - b.Start })
	for _, c := range chosen {
		if c.placeholder {
			kept++
		} else {
			out = append(out, c.Match)
		}
	}
	return out, kept
}

// 乱数で作った候補と保護範囲について、実装の結果が参照実装と一致すること。
// 実装は、重なる候補の塊ごとに解決する(長い行で候補の数の 2 乗にならないため)。
// その結果が、全体に対する単純な貪欲法と同じであることを確かめる。
func TestResolveMatchesReferenceImplementation(t *testing.T) {
	kinds := []Kind{KindEmail, KindIPv4, KindIPv6, KindSecret, KindUUID}
	labels := []string{"<email_1>", "<secret_22>", "<ipv4_private_3>", "<uuid_4>"}
	rng := rand.New(rand.NewPCG(1, 2))

	for iter := 0; iter < 3000; iter++ {
		// 行を作る: 'x' の間に、保護範囲(ラベル)をいくつか置く。
		var sb strings.Builder
		var placeholders []refCand
		for sb.Len() < 70 {
			if rng.IntN(5) == 0 {
				s := sb.Len()
				lab := labels[rng.IntN(len(labels))]
				sb.WriteString(lab)
				placeholders = append(placeholders, refCand{Match: Match{Start: s, End: s + len(lab)}, placeholder: true})
			} else {
				sb.WriteByte('x')
			}
		}
		line := sb.String()

		// 種別ごとに、ランダムな候補を作る。
		finders := map[Kind]*fakeFinder{}
		var cands []refCand
		for i, n := 0, rng.IntN(10); i < n; i++ {
			k := kinds[rng.IntN(len(kinds))]
			s := rng.IntN(len(line) - 1)
			e := s + 1 + rng.IntN(min(25, len(line)-s))
			class := ClassNone
			if k == KindIPv4 || k == KindIPv6 {
				class = ClassGlobal
			}
			if finders[k] == nil {
				finders[k] = &fakeFinder{k: k}
			}
			finders[k].spans = append(finders[k].spans, span{start: s, end: e, class: class})
			cands = append(cands, refCand{Match: Match{Start: s, End: e, Kind: k, Class: class}})
		}
		var fs []finder
		for _, k := range kinds {
			if finders[k] != nil {
				fs = append(fs, finders[k])
			}
		}

		// 保護範囲は、ラベル同士の重なりはなく、実装も同じ範囲を見つけるはず。
		wantOut, wantKept := refResolve(append(cands, placeholders...))

		d := newTestDetector(t, Options{Format: label.DefaultFormat}, fs...)
		gotOut, gotKept := d.Find([]byte(line), nil)
		if !slices.Equal(gotOut, wantOut) || gotKept != wantKept {
			t.Fatalf("iter %d, line %q\ncands %+v\n got  %+v kept=%d\n want %+v kept=%d",
				iter, line, cands, gotOut, gotKept, wantOut, wantKept)
		}
		// 出力の性質: 開始位置の順で、重ならない。
		for i := 1; i < len(gotOut); i++ {
			if gotOut[i].Start < gotOut[i-1].End {
				t.Fatalf("iter %d: overlapping output %+v", iter, gotOut)
			}
		}
	}
}

// 多数の候補が連鎖して重なる行でも、結果は参照実装と一致する。
func TestResolveLongOverlapChainMatchesReference(t *testing.T) {
	const n = 400
	f1 := &fakeFinder{k: KindSecret}
	f2 := &fakeFinder{k: KindEmail}
	var cands []refCand
	for i := 0; i < n; i++ {
		// 長さ 7 の secret を 5 ずつずらして置き、その間に長さ 7 の email を置く。
		s := i * 5
		f1.spans = append(f1.spans, span{start: s, end: s + 7})
		cands = append(cands, refCand{Match: Match{Start: s, End: s + 7, Kind: KindSecret}})
		f2.spans = append(f2.spans, span{start: s + 2, end: s + 9})
		cands = append(cands, refCand{Match: Match{Start: s + 2, End: s + 9, Kind: KindEmail}})
	}
	line := strings.Repeat("x", n*5+20)
	wantOut, _ := refResolve(cands)
	d := newTestDetector(t, Options{}, f1, f2)
	gotOut, _ := d.Find([]byte(line), nil)
	if !slices.Equal(gotOut, wantOut) {
		t.Fatalf("got %d matches, want %d\n got  %v\n want %v", len(gotOut), len(wantOut), fmt.Sprint(gotOut[:min(5, len(gotOut))]), fmt.Sprint(wantOut[:min(5, len(wantOut))]))
	}
}
