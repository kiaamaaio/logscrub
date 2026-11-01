package detect

import "bytes"

// customFinder は、`--deny`・`--deny-file` の語の検出器(仕様 4.6)。
type customFinder struct{ m *literalMatcher }

func (customFinder) kind() Kind { return KindCustom }

func (f customFinder) find(line []byte, dst []Match) []Match {
	f.m.scan(line, func(s, e int) {
		if wordBounded(line, s, e) {
			dst = append(dst, Match{Start: s, End: e, Kind: KindCustom})
		}
	})
	return dst
}

// wordBounded は、語の範囲 line[s:e] の両端が、語の境目かを返す。
// 語の端が ASCII 英数字で、その外側の文字も ASCII 英数字なら、境目ではない(Q73)。
func wordBounded(line []byte, s, e int) bool {
	if s > 0 && isASCIIAlnum(line[s]) && isASCIIAlnum(line[s-1]) {
		return false
	}
	return e >= len(line) || !isASCIIAlnum(line[e-1]) || !isASCIIAlnum(line[e])
}

// hostFinder は、`--domain` のドメインとそのサブドメインのホスト名の検出器(仕様 4.7)。
type hostFinder struct{ m *literalMatcher }

func (hostFinder) kind() Kind { return KindHost }

func isHostNameChar(c byte) bool {
	return isASCIIAlnum(c) || c == '-' || c == '_' || c == '.'
}

// hostStart は、ホスト名の先頭を、手前へ遡って求める。rs・hi は、前回の結果(rs から hi までが同じ連なり)。
// 遡る長さの合計が行の長さ以内になるよう、前回の範囲に届いたら、その先頭を使う。
func hostStart(line []byte, s, rs, hi int) int {
	if rs <= s && s <= hi {
		return rs
	}
	i := s
	for i > 0 && isHostNameChar(line[i-1]) {
		i--
		if i == hi {
			return rs
		}
	}
	for i < s && line[i] == '.' {
		i++
	}
	return i
}

func (f hostFinder) find(line []byte, dst []Match) []Match {
	rs, hi, last := 0, -1, -1
	f.m.scan(line, func(s, e int) {
		if e == last || !isHostEnd(line, e) {
			return
		}
		if s > 0 && line[s-1] != '.' && isHostNameChar(line[s-1]) {
			return // notexample.co.jp
		}
		rs, hi = hostStart(line, s, rs, hi), e
		last = e
		dst = append(dst, Match{Start: rs, End: e, Kind: KindHost})
	})
	return dst
}

// validDomain は、`--domain` の値として正しいかを返す(英数字・`-` のラベルを `.` でつないだもの)。
func validDomain(d string) bool {
	for label := range bytes.SplitSeq([]byte(d), []byte{'.'}) {
		if len(label) == 0 {
			return false
		}
		for _, c := range label {
			if !isASCIIAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}
