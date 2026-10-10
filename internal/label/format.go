// Package label は、置換後のラベル(mask の `<email_1>` など)と、hash の出力形を扱う。
//
// ラベルの書式は、mask での生成、restore での読み取り、検出時の「置換済みの値」の除外の
// 3 か所で使うため、検出(detect)や変換(transform)から独立させている。
package label

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// Types は、置換後の種別名。IP アドレスは、グローバル/プライベートの区別を含む(仕様 4.3)。
// 並びは、`--stats` の出力順にも使う。
var Types = []string{"email", "ipv4_global", "ipv4_private", "ipv6_global", "ipv6_private", "secret", "uuid"}

// NumTypes は、len(Types)。統計や連番の表を、固定長の配列で持つための定数
// (TestTypesAreTheDocumentedSet で、len(Types) と一致することを確認している)。
const NumTypes = 7

var typeBytes = func() [][]byte {
	bs := make([][]byte, len(Types))
	for i, s := range Types {
		bs[i] = []byte(s)
	}
	return bs
}()

const (
	typePlaceholder = "{type}"
	numPlaceholder  = "{n}"

	// maxDigits は、ラベルの連番として読み取る最大の桁数(int64 に収まる桁数)。
	maxDigits = 18
)

// DefaultFormat は、`--mask-format` の既定値 `<{type}_{n}>`。
var DefaultFormat = func() Format {
	f, err := ParseFormat("<{type}_{n}>")
	if err != nil {
		panic(err)
	}
	return f
}()

// Format は、`--mask-format` の書式。`{type}` と `{n}` の前・間・後のリテラルに分解して持つ。
// ゼロ値は書式として無効(IsZero)。
type Format struct {
	pre, mid, post []byte
	typeFirst      bool
	ok             bool
	// first は、pre が空のとき、ラベルの先頭になりうるバイト。
	first [256]bool
}

// ParseFormat は書式を解析する(Q12)。
// `{type}` と `{n}` をちょうど 1 回ずつ含む必要がある。`\r` と `\n` は含められない。
// それ以外の文字(`{` `}` を含む)は、そのままのリテラルとして扱う。
func ParseFormat(s string) (Format, error) {
	if strings.ContainsAny(s, "\r\n") {
		return Format{}, errors.New("mask format must not contain a newline")
	}
	if strings.Count(s, typePlaceholder) != 1 || strings.Count(s, numPlaceholder) != 1 {
		return Format{}, errors.New("mask format must contain {type} and {n} exactly once each")
	}
	ti := strings.Index(s, typePlaceholder)
	ni := strings.Index(s, numPlaceholder)
	var f Format
	if ti < ni {
		f.typeFirst = true
		f.pre = []byte(s[:ti])
		f.mid = []byte(s[ti+len(typePlaceholder) : ni])
		f.post = []byte(s[ni+len(numPlaceholder):])
	} else {
		f.pre = []byte(s[:ni])
		f.mid = []byte(s[ni+len(numPlaceholder) : ti])
		f.post = []byte(s[ti+len(typePlaceholder):])
	}
	f.ok = true
	if len(f.pre) == 0 {
		if f.typeFirst {
			for _, t := range typeBytes {
				f.first[t[0]] = true
			}
		} else {
			for c := '1'; c <= '9'; c++ {
				f.first[c] = true
			}
		}
	}
	return f, nil
}

// IsZero は、f が ParseFormat で作られていない(ゼロ値である)かどうかを返す。
func (f Format) IsZero() bool { return !f.ok }

// Append は、種別名 typ と連番 n のラベルを dst に追記して返す。
func (f Format) Append(dst []byte, typ string, n int) []byte {
	dst = append(dst, f.pre...)
	if f.typeFirst {
		dst = append(dst, typ...)
		dst = append(dst, f.mid...)
		dst = strconv.AppendInt(dst, int64(n), 10)
	} else {
		dst = strconv.AppendInt(dst, int64(n), 10)
		dst = append(dst, f.mid...)
		dst = append(dst, typ...)
	}
	return append(dst, f.post...)
}

// Scan は、line の中のラベル(Types のいずれかの種別名と、先頭 0 のない 1 以上の整数)を
// 左から順に、重ならないように見つけ、fn を呼ぶ。
// restore でのラベルの読み取りと、検出時の置換済みの値の除外で共用する。
func (f Format) Scan(line []byte, fn func(start, end int, typ string, n int)) {
	if !f.ok {
		return
	}
	for i := 0; i < len(line); {
		if len(f.pre) > 0 {
			j := bytes.Index(line[i:], f.pre)
			if j < 0 {
				return
			}
			i += j
		} else if !f.first[line[i]] {
			i++
			continue
		}
		if end, typ, n, ok := f.matchAt(line, i); ok {
			fn(i, end, typ, n)
			i = end
		} else {
			i++
		}
	}
}

func (f Format) matchAt(line []byte, i int) (end int, typ string, n int, ok bool) {
	p := i
	if !bytes.HasPrefix(line[p:], f.pre) {
		return 0, "", 0, false
	}
	p += len(f.pre)
	if f.typeFirst {
		if typ, p, ok = matchType(line, p); !ok {
			return 0, "", 0, false
		}
		if !bytes.HasPrefix(line[p:], f.mid) {
			return 0, "", 0, false
		}
		p += len(f.mid)
		if n, p, ok = matchNumber(line, p); !ok {
			return 0, "", 0, false
		}
	} else {
		if n, p, ok = matchNumber(line, p); !ok {
			return 0, "", 0, false
		}
		if !bytes.HasPrefix(line[p:], f.mid) {
			return 0, "", 0, false
		}
		p += len(f.mid)
		if typ, p, ok = matchType(line, p); !ok {
			return 0, "", 0, false
		}
	}
	if !bytes.HasPrefix(line[p:], f.post) {
		return 0, "", 0, false
	}
	return p + len(f.post), typ, n, true
}

func matchType(line []byte, p int) (typ string, end int, ok bool) {
	for k, t := range typeBytes {
		if bytes.HasPrefix(line[p:], t) {
			return Types[k], p + len(t), true
		}
	}
	return "", p, false
}

// matchNumber は、先頭が 0 でない 1 以上の整数を、桁の続く限り(最大 maxDigits 桁)読む。
// それより長い数字列は、整数として読めないので、ラベルとはみなさない。
func matchNumber(line []byte, p int) (n int, end int, ok bool) {
	if p >= len(line) || line[p] < '1' || line[p] > '9' {
		return 0, p, false
	}
	end = p
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	if end-p > maxDigits {
		return 0, p, false
	}
	for _, c := range line[p:end] {
		n = n*10 + int(c-'0')
	}
	return n, end, true
}

// TypeIndex は、種別名 typ の、Types での位置を返す。Types にない名前では -1。
// 統計や連番の表を、Types の順(固定)の配列で持つために使う。
func TypeIndex(typ string) int {
	for i, t := range Types {
		if t == typ {
			return i
		}
	}
	return -1
}

// IsLabel は、b 全体が、ちょうど 1 つのラベル(現在の書式、既知の種別名、先頭 0 のない 1 以上の連番)かを返す。
func (f Format) IsLabel(b []byte) bool {
	found := false
	f.Scan(b, func(start, end int, _ string, _ int) {
		if start == 0 && end == len(b) {
			found = true
		}
	})
	return found
}
