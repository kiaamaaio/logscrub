package transform

import (
	"fmt"
	"unicode/utf8"

	"github.com/kiaamaaio/logscrub/internal/detect"
)

const (
	colorReplaced = "\x1b[36m"    // 置換した箇所
	colorSuspect  = "\x1b[30;43m" // 置換しなかった怪しい語
	colorReset    = "\x1b[0m"

	// minSuspectLen は、怪しい語の最小の長さ(仕様 6 章)。
	minSuspectLen = 20
)

// Review は、`--review` の表示の設定。確認専用の表示なので、入出力のバイト列の保持の対象にしない(仕様 6 章)。
type Review struct {
	// Color は、色の指定を出すか(NO_COLOR のときは false)。
	Color bool
}

func (r *Review) color(dst []byte, code string) []byte {
	if r.Color {
		return append(dst, code...)
	}
	return dst
}

// appendValue は、置換した 1 件を、色を付けて追記する。
func (r *Review) appendValue(dst []byte, rep Replacer, line []byte, m detect.Match) []byte {
	dst = r.color(dst, colorReplaced)
	dst = rep.Append(dst, line, m)
	return r.color(dst, colorReset)
}

// appendPlain は、置換しなかった部分 seg を、制御文字を見える形にし、怪しい語に色を付けて追記する。
// 2 つ目の戻り値は、怪しい語の数。
func (r *Review) appendPlain(dst, seg []byte) ([]byte, int) {
	n := 0
	for i := 0; i < len(seg); {
		c := seg[i]
		switch {
		case isSuspectByte(c):
			j := i + 1
			for j < len(seg) && isSuspectByte(seg[j]) {
				j++
			}
			run := seg[i:j]
			if isSuspect(run) {
				n++
				dst = r.color(dst, colorSuspect)
				dst = append(dst, run...)
				dst = r.color(dst, colorReset)
			} else {
				dst = append(dst, run...)
			}
			i = j
		case c == '\t' || c >= 0x20 && c < 0x7f:
			dst = append(dst, c)
			i++
		case c < 0x80:
			dst = append(dst, '^', c^0x40) // ESC は ^[、DEL は ^?
			i++
		default:
			var size int
			dst, size = appendRune(dst, seg[i:])
			i += size
		}
	}
	return dst, n
}

// appendRune は、b の先頭の非 ASCII の文字を追記する。表示を変える文字は、見える形にする。
//
// C1 制御文字(CSI の U+009B など)は、端末の制御になる。双方向テキストの制御文字は、表示の順を入れ替えて、値を読めなくできる。
// 不正なバイトは、UTF-8 でない端末では C1 制御文字として働くことがある。
func appendRune(dst, b []byte) ([]byte, int) {
	r, size := utf8.DecodeRune(b)
	switch {
	case r == utf8.RuneError && size == 1:
		return fmt.Appendf(dst, `\x%02x`, b[0]), 1
	case r >= 0x80 && r <= 0x9f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return fmt.Appendf(dst, `\u%04x`, r), size
	}
	return append(dst, b[:size]...), size
}

func isSuspectByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '+' || c == '=' || c == '_' || c == '-'
}

// isSuspect は、run(isSuspectByte の並び)が、怪しい語の条件(長さと、英字と数字の両方)を満たすかを返す。
func isSuspect(run []byte) bool {
	if len(run) < minSuspectLen {
		return false
	}
	letter, digit := false, false
	for _, c := range run {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letter = true
		}
	}
	return letter && digit
}
