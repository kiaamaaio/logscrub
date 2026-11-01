package detect

// literalMatcher は、多数の語を 1 回の走査で探す(Aho-Corasick)。`--deny` と `--domain` で共用する。
//
// ASCII の英字だけ、大文字・小文字を区別しない(Q72)。バイト列として照合し、非 ASCII は畳まない。
// 遷移は、語に現れるバイトの同値類を列とする表で持つ(語が多くても、表が 256 列にならないように)。
type literalMatcher struct {
	class  [256]uint16 // バイト → 同値類。0 は、どの語にも現れないバイト
	width  int         // 同値類の数
	next   []int32     // 状態 × 同値類 → 次の状態
	outPos []int32     // 状態 s の一致の長さは outLen[outPos[s]:outPos[s+1]]
	outLen []int32
}

func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// newLiteralMatcher は、words(空の語は含まない)を探す照合器を作る。
func newLiteralMatcher(words []string) *literalMatcher {
	m := &literalMatcher{width: 1}
	for _, w := range words {
		for i := 0; i < len(w); i++ {
			c := foldByte(w[i])
			if m.class[c] == 0 {
				m.class[c] = uint16(m.width)
				m.width++
			}
		}
	}
	for c := 'A'; c <= 'Z'; c++ {
		m.class[c] = m.class[foldByte(byte(c))]
	}

	// 語の木を作る。children は、状態 × 同値類 → 子の状態(0 は子なし)。
	children := make([]int32, m.width)
	var ends [][]int32 // 状態 → その状態で終わる語の長さ
	ends = append(ends, nil)
	for _, w := range words {
		s := int32(0)
		for i := 0; i < len(w); i++ {
			k := int(s)*m.width + int(m.class[w[i]])
			if children[k] == 0 {
				children[k] = int32(len(ends))
				ends = append(ends, nil)
				children = append(children, make([]int32, m.width)...)
			}
			s = children[k]
		}
		if !containsLen(ends[s], int32(len(w))) {
			ends[s] = append(ends[s], int32(len(w)))
		}
	}

	// 幅優先で、失敗の遷移を表に畳み込む。
	next := children
	fail := make([]int32, len(ends))
	queue := make([]int32, 0, len(ends))
	for c := 1; c < m.width; c++ {
		if s := next[c]; s != 0 {
			queue = append(queue, s)
		}
	}
	for head := 0; head < len(queue); head++ {
		s := queue[head]
		f := fail[s]
		for _, n := range ends[f] {
			if !containsLen(ends[s], n) {
				ends[s] = append(ends[s], n)
			}
		}
		for c := 1; c < m.width; c++ {
			k := int(s)*m.width + c
			alt := next[int(f)*m.width+c]
			if child := next[k]; child != 0 {
				fail[child] = alt
				queue = append(queue, child)
			} else {
				next[k] = alt
			}
		}
	}
	m.next = next

	m.outPos = make([]int32, len(ends)+1)
	for s, ns := range ends {
		m.outLen = append(m.outLen, ns...)
		m.outPos[s+1] = int32(len(m.outLen))
	}
	return m
}

func containsLen(ns []int32, n int32) bool {
	for _, v := range ns {
		if v == n {
			return true
		}
	}
	return false
}

// scan は、line の中の語の出現を、重なりも含めてすべて報告する(終わりの位置の順)。
func (m *literalMatcher) scan(line []byte, fn func(start, end int)) {
	s := int32(0)
	for i, c := range line {
		s = m.next[int(s)*m.width+int(m.class[c])]
		if lo, hi := m.outPos[s], m.outPos[s+1]; lo != hi {
			for _, n := range m.outLen[lo:hi] {
				fn(i+1-int(n), i+1)
			}
		}
	}
}
