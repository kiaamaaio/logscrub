package detect

import (
	"bytes"
	"encoding/base64"
	"regexp"
)

// secretFinder は、トークン類(secret)の検出器(仕様 4.1、決定事項 15)。
//
// 次の 2 つの規則の候補をまとめて返す。重なりは、Detector が解決する。
//
//   - 固定形式: AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT(前後が英数字でないこと。Q14)
//   - キー名ベース: `password=<値>`、`"api_key": "<値>"`、`Authorization: Bearer <値>` などの値の部分
//     (Q15、Q16。JSON の文法を壊さない。決定事項 15)
type secretFinder struct{}

func (secretFinder) kind() Kind { return KindSecret }

func (f secretFinder) find(line []byte, dst []Match) []Match {
	dst = f.fixed(line, dst)
	return f.keyed(line, dst)
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ---- 固定形式 ----

// fixedRe は、固定形式の正規表現(仕様 4.1 の表)。位置は、fixedLiterals の接頭辞で絞る。
// 前後が英数字でないこと(Q14)は、呼び出し側で確認する。
var fixedRe = regexp.MustCompile(`^(?:` +
	`(?:AKIA|ASIA)[A-Z0-9]{16}` + // AWS アクセスキー ID
	`|gh[pousr]_[A-Za-z0-9]{36,}` + // GitHub
	`|github_pat_[A-Za-z0-9_]{22,}` + // GitHub(fine-grained)
	`|xox[bparso]-[A-Za-z0-9-]{10,}` + // Slack
	`|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}` + // Stripe
	`|AIza[A-Za-z0-9_-]{35}` + // Google API キー
	`|sk-[A-Za-z0-9_-]{20,}` + // sk- 形式
	`|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` + // JWT(署名部は空でもよい)
	`)`)

// fixedLiterals は、固定形式の接頭辞(の先頭部分)。どれかを含まない行は、正規表現を当てない。
var fixedLiterals = [...][]byte{
	[]byte("AKIA"), []byte("ASIA"), []byte("AIza"), []byte("gh"), []byte("github_pat_"),
	[]byte("xox"), []byte("sk"), []byte("rk"), []byte("eyJ"),
}

func (secretFinder) fixed(line []byte, dst []Match) []Match {
	n := len(line)
	var next [len(fixedLiterals)]int // 各接頭辞の次の出現位置。-1: 未計算、n: これ以上ない
	for i := range next {
		next[i] = -1
	}
	for pos := 0; pos < n; {
		best := n
		for i, lit := range fixedLiterals {
			if next[i] == n {
				continue
			}
			if next[i] < pos {
				j := bytes.Index(line[pos:], lit)
				if j < 0 {
					next[i] = n
					continue
				}
				next[i] = pos + j
			}
			if next[i] < best {
				best = next[i]
			}
		}
		if best >= n {
			break
		}
		p := best
		if p > 0 && isASCIIAlnum(line[p-1]) {
			pos = p + 1
			continue
		}
		loc := fixedRe.FindIndex(line[p:])
		if loc == nil || p+loc[1] < n && isASCIIAlnum(line[p+loc[1]]) {
			pos = p + 1
			continue
		}
		dst = append(dst, Match{Start: p, End: p + loc[1], Kind: KindSecret})
		pos = p + loc[1]
	}
	return dst
}

// ---- Authorization ヘッダ(Bearer / Basic) ----

// schemeCredentials は、line[p:] が `Bearer <値>` / `Basic <値>` で始まる場合に、値の範囲を返す(Q13、決定事項 15)。
//
// 方式名は、大文字・小文字を区別せず、後ろに空白(スペース・タブ)が 1 つ以上ある。
// 値は、RFC 7235 の token68(英数字と `-` `.` `_` `~` `+` `/`、末尾に `=` が続いてもよい)。
// Basic は、値が base64 として解読でき、結果に `:`(`user:pass` の形)を含む場合に限る。
func schemeCredentials(line []byte, p int) (start, end int, ok bool) {
	length := 0
	basic := false
	switch {
	case hasPrefixFold(line[p:], "bearer"):
		length = len("bearer")
	case hasPrefixFold(line[p:], "basic"):
		length, basic = len("basic"), true
	default:
		return 0, 0, false
	}
	q := p + length
	if q >= len(line) || line[q] != ' ' && line[q] != '\t' {
		return 0, 0, false
	}
	for q < len(line) && (line[q] == ' ' || line[q] == '\t') {
		q++
	}
	e := token68End(line, q)
	if e == q || basic && !basicCredentials(line[q:e]) {
		return 0, 0, false
	}
	return q, e, true
}

// hasPrefixFold は、b が、小文字の ASCII 文字列 lower で、大文字・小文字を区別せずに始まるかを返す。
func hasPrefixFold(b []byte, lower string) bool {
	if len(b) < len(lower) {
		return false
	}
	for i := 0; i < len(lower); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

func isToken68Char(c byte) bool {
	return isASCIIAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/'
}

// token68End は、line[q:] から始まる token68 の末尾の位置を返す。token68 でなければ q。
func token68End(line []byte, q int) int {
	e := q
	for e < len(line) && isToken68Char(line[e]) {
		e++
	}
	if e == q {
		return q
	}
	for e < len(line) && line[e] == '=' {
		e++
	}
	return e
}

// basicCredentials は、Basic の値が、base64 として解読でき、結果に ':' を含むかどうかを返す。
// 末尾の '.'(文末の句点)は、外して再度試す。
func basicCredentials(v []byte) bool {
	if base64HasColon(v) {
		return true
	}
	if t := bytes.TrimRight(v, "."); len(t) < len(v) && len(t) > 0 {
		return base64HasColon(t)
	}
	return false
}

func base64HasColon(v []byte) bool {
	buf := make([]byte, len(v)) // 解読結果は、入力より短い
	for _, enc := range [...]*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if n, err := enc.Decode(buf, v); err == nil && bytes.IndexByte(buf[:n], ':') >= 0 {
			return true
		}
	}
	return false
}

// ---- キー名ベース ----

// secretKeyNames は、対象のキー名(仕様 4.1)。照合は、キー名を小文字にし、区切りを '_' にそろえた形で行う。
var secretKeyNames = [...]string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key",
	"client_secret", "access_token", "refresh_token", "auth_token", "session_id",
}

// authorizationKeyName は、値が `Bearer <値>` / `Basic <値>` の形のときだけ対象になるキー名。
const authorizationKeyName = "authorization"

// keyWindow は、キー名の照合で見る、キー名の末尾のバイト数。最長の対象のキー名(13 バイト)より長ければよい。
const keyWindow = 15

func isKeyChar(c byte) bool {
	return isASCIIAlnum(c) || c == '_' || c == '-' || c == '.'
}

func isUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }

// normKeyChar は、キー名の文字を、照合用の形(小文字、'-' と '.' は '_')にする。
func normKeyChar(c byte) byte {
	switch {
	case isUpperASCII(c):
		return c + 'a' - 'A'
	case c == '-' || c == '.':
		return '_'
	}
	return c
}

// normalizeKeyTail は、キー名 k の末尾(最大 keyWindow バイト)を、照合用の形にして buf に書く。
// 小文字・数字から大文字への変わり目(`accessToken`)と、大文字の連なりの終わり(`APIKey` の `I` と `K` の間)に、
// '_' を入れる(camelCase、決定事項 15)。
func normalizeKeyTail(k []byte, buf *[2 * keyWindow]byte) []byte {
	w := k
	if len(w) > keyWindow {
		w = w[len(w)-keyWindow:]
	}
	n := 0
	for i, c := range w {
		if i > 0 && isUpperASCII(c) {
			p := w[i-1]
			if isLowerASCII(p) || isDigit(p) || isUpperASCII(p) && i+1 < len(w) && isLowerASCII(w[i+1]) {
				buf[n] = '_'
				n++
			}
		}
		buf[n] = normKeyChar(c)
		n++
	}
	return buf[:n]
}

// hasKeySuffix は、照合用に整えたキー名 t が、区切りの単位として、name で終わるかを返す。
func hasKeySuffix(t []byte, name string) bool {
	off := len(t) - len(name)
	if off < 0 || string(t[off:]) != name {
		return false
	}
	return off == 0 || t[off-1] == '_'
}

// classifyKey は、キー名 k(英数字と `_` `-` `.` の連なり)が、対象のキー名かを返す。
// 対象のキー名が、k の末尾の区切り単位として現れれば、対象になる
// (`X-Auth-Token`、`db.password`、`accessToken` は対象。`tokens`、`maxTokens`、`passwordless` は対象外)。
// authOnly は、Authorization のように、値が方式名で始まる場合だけ対象になるキー名。
func classifyKey(k []byte) (ok, authOnly bool) {
	// 対象のキー名は、どれも d、t、y、n のどれかで終わる。ほとんどのキー名を、ここで除く。
	switch normKeyChar(k[len(k)-1]) {
	case 'd', 't', 'y', 'n':
	default:
		return false, false
	}
	var buf [2 * keyWindow]byte
	t := normalizeKeyTail(k, &buf)
	for _, name := range secretKeyNames {
		if hasKeySuffix(t, name) {
			return true, false
		}
	}
	if hasKeySuffix(t, authorizationKeyName) {
		return true, true
	}
	return false, false
}

// isValueTerminator は、引用符なしの値を終える文字。
// 空白・& , ; } ] ) と、引用符 " '(文字列の中の `password=abc` の閉じ引用符を、巻き込まないため)。
func isValueTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '&', ',', ';', '}', ']', ')', '"', '\'':
		return true
	}
	return false
}

// bareValueEnd は、引用符なしの値(line[vs:] から始まる)の末尾の位置を返す。
//
// isValueTerminator の文字の手前で終わる。さらに、JSON の文字列の中のエスケープ
// (`\"` `\'` `\n` `\r` `\t` `\u0026`)の手前の `\` でも終わる。値に、閉じ引用符のためのエスケープや、
// 改行・& を表すエスケープを巻き込むと、JSON が壊れるため。`\\` は、1 つの文字として扱う。
func bareValueEnd(line []byte, vs int) int {
	n := len(line)
	e := vs
	for e < n {
		c := line[e]
		if c == '\\' && e+1 < n {
			switch line[e+1] {
			case '"', '\'', 'n', 'r', 't':
				return e
			case '\\':
				e += 2
				continue
			case 'u':
				if bytes.HasPrefix(line[e+2:], []byte("0026")) {
					return e
				}
				e += 2
				continue
			}
		} else if isValueTerminator(c) {
			return e
		}
		e++
	}
	return e
}

// keyed は、キー名ベースの値の範囲を追記する(仕様 4.1、決定事項 15)。
//
// '=' または ':' の手前が、対象のキー名(引用符、または `\"` で囲まれていてもよい)なら、その後ろの値が対象になる。
//   - 区切りの前後の空白(スペース・タブ)は、任意個を許す(Q15)
//   - 値が `Bearer ` / `Basic ` で始まる場合は、方式名の後ろの値だけが対象。
//     キー名が Authorization で、方式名がなければ対象でない
//   - 値が引用符(" または ')で始まる場合は、閉じ引用符の手前まで。`\` の次の文字は、値の一部。
//     `\"` で始まる場合は、次の `\"` の手前まで(ログに文字列として埋め込まれた JSON)。
//     閉じ引用符がなければ、行末まで(Q16)
//   - キー名が引用符で囲まれている場合(JSON、辞書)は、値が文字列のものだけが対象。
//     数値・true・false・null・{・[ は、JSON の文法を壊すので、対象にしない
//   - それ以外は、空白・& , ; } ] ) " ' と、JSON のエスケープの手前まで(bareValueEnd)。
//     { または [ で始まる値は、対象にしない
//   - 値が空なら、置換しない
//
// 値の範囲だけを返す(キー名・区切り・引用符は残す)。
func (secretFinder) keyed(line []byte, dst []Match) []Match {
	n := len(line)
	ne, nc := -1, -1 // 次の '='、':' の位置(-1: 未計算、n: これ以上ない)
	for pos := 0; pos < n; {
		if ne != n && ne < pos {
			if j := bytes.IndexByte(line[pos:], '='); j >= 0 {
				ne = pos + j
			} else {
				ne = n
			}
		}
		if nc != n && nc < pos {
			if j := bytes.IndexByte(line[pos:], ':'); j >= 0 {
				nc = pos + j
			} else {
				nc = n
			}
		}
		i := min(ne, nc)
		if i >= n {
			break
		}
		pos = i + 1

		// キー名: 区切りの手前の空白、閉じ引用符(`\"` を含む)を除いた、英数字と `_` `-` `.` の連なり
		j := i
		for j > 0 && (line[j-1] == ' ' || line[j-1] == '\t') {
			j--
		}
		quotedKey := false
		if j > 0 && (line[j-1] == '"' || line[j-1] == '\'') {
			quotedKey = true
			j--
			if j > 0 && line[j-1] == '\\' {
				j--
			}
		}
		k := j
		for k > 0 && isKeyChar(line[k-1]) {
			k--
		}
		if k == j {
			continue
		}
		ok, authOnly := classifyKey(line[k:j])
		if !ok {
			continue
		}

		// 値
		vs := i + 1
		for vs < n && (line[vs] == ' ' || line[vs] == '\t') {
			vs++
		}
		if vs >= n {
			continue
		}
		cs := vs // 値の内容の開始(引用符で始まる場合は、引用符の次)
		var quote byte
		escaped := false
		switch {
		case line[vs] == '"' || line[vs] == '\'':
			quote, cs = line[vs], vs+1
		case line[vs] == '\\' && vs+1 < n && line[vs+1] == '"':
			escaped, cs = true, vs+2
		}
		if s, e, ok := schemeCredentials(line, cs); ok {
			dst = append(dst, Match{Start: s, End: e, Kind: KindSecret})
			continue
		}
		if authOnly {
			continue
		}
		s, e := cs, n
		switch {
		case quote != 0:
			for x := s; x < n; {
				if line[x] == '\\' {
					x += 2
					continue
				}
				if line[x] == quote {
					e = x
					break
				}
				x++
			}
		case escaped:
			for x := s; x < n; {
				if line[x] == '\\' {
					if x+1 < n && line[x+1] == '"' {
						e = x
						break
					}
					x += 2
					continue
				}
				x++
			}
		case quotedKey || line[vs] == '{' || line[vs] == '[':
			continue
		default:
			e = bareValueEnd(line, vs)
		}
		if e > s {
			dst = append(dst, Match{Start: s, End: e, Kind: KindSecret})
		}
	}
	return dst
}
