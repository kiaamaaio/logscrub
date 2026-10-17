package label

import "bytes"

// hash 出力形の 16 進数の桁数(`--hash-length`、仕様 5.2)。
const (
	DefaultHashLen = 12 // 既定。mask と restore では、常にこの桁数で、hash 出力形を置換済みとみなす(Q10)
	MinHashLen     = 8
	MaxHashLen     = 64 // SHA-256 の 16 進数の全桁
)

// ScanHashed は、line の中の hash モードの出力形を、左から順に見つけ、fn を呼ぶ。
// 見つけるのは、次の 2 つの形(hexLen は 16 進数の桁数、16 進数は小文字のみ)。
//
//   - `<種別>_<16 進数>`(例: `email_3f9a1c0b7d2e`、`ipv4_global_a1b2c3d4e5f6`)。
//     前後が英数字でないものだけ
//   - `hash_<16 進数>@ドメイン`(例: `hash_3f9a1c0b7d2e@example.com`)。
//     ローカルパートが丸ごとこの形のものだけ。範囲はドメインの末尾まで(DomainEndBeforeHashed。Q69)
//
// 本物の値との区別のため、桁数・小文字・前後の文字・種別名のどれかが合わないものは見つけない(Q10)。
func ScanHashed(line []byte, hexLen int, fn func(start, end int)) {
	if hexLen <= 0 {
		return
	}
	for i := 0; i < len(line); {
		j := bytes.IndexByte(line[i:], '_')
		if j < 0 {
			return
		}
		p := i + j // '_' の位置
		i = p + 1
		h := p + 1
		e := h + hexLen
		if e > len(line) || !isLowerHex(line[h:e]) {
			continue
		}
		// <種別>_<16 進数>
		if typ := typeEndingAt(line, p); typ != "" {
			s := p - len(typ)
			if (s == 0 || !isAlnum(line[s-1])) && (e == len(line) || !isAlnum(line[e])) {
				fn(s, e)
				i = e
				continue
			}
		}
		// hash_<16 進数>@ドメイン
		if p >= 4 && string(line[p-4:p]) == "hash" && e < len(line) && line[e] == '@' {
			s := p - 4
			if s == 0 || !IsEmailLocalChar(line[s-1]) {
				if end := DomainEndBeforeHashed(line, e+1, EmailDomainEnd(line, e+1), hexLen); end > 0 {
					fn(s, end)
					i = end
					continue
				}
			}
		}
	}
}

func typeEndingAt(line []byte, p int) string {
	for k, t := range typeBytes {
		if p >= len(t) && bytes.Equal(line[p-len(t):p], t) {
			return Types[k]
		}
	}
	return ""
}

func isLowerHex(b []byte) bool {
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
