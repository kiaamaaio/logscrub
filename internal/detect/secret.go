package detect

import (
	"bytes"
	"encoding/base64"
	"regexp"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// secretFinder は、トークン類(secret)の検出器(仕様 4.1、決定事項 15)。
//
// 次の 2 つの規則の候補をまとめて返す。重なりは、Detector が解決する。
//
//   - 固定形式: AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT(前後が英数字でないこと。Q14)
//   - AWS の署名(SigV4): `X-Amz-Signature=<値>`、`Signature=<値>` の値の部分(v1.1。Q32)
//   - URL のパスワード: `<スキーム>://<ユーザー>:<パスワード>@<ホスト>` のパスワード部分(v1.2。Q48)
//   - キー名ベース: `password=<値>`、`"api_key": "<値>"`、`Authorization: Bearer <値>` などの値の部分
//     (Q15、Q16。JSON の文法を壊さない。決定事項 15)
type secretFinder struct {
	// format は、置換済みのラベルの書式(ゼロ値は、ラベルを見ない)。キー名ベースの値が URL のパスワードの形で
	// 始まるかの判定で、置換済みのラベルを、ユーザー・パスワード・ホスト名の部分として読むために使う(Q65)
	format label.Format
}

func (secretFinder) kind() Kind { return KindSecret }

func (f secretFinder) find(line []byte, dst []Match) []Match {
	dst = f.fixed(line, dst)
	dst = f.signatures(line, dst)
	dst = f.urlPasswords(line, dst)
	return f.keyed(line, dst)
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ---- 固定形式 ----

// fixedRe は、固定形式の正規表現(仕様 4.1 の表)。位置は、fixedPrefixes の接頭辞で絞る。
// 前後が英数字でないこと(Q14)は、呼び出し側で確認する。
var fixedRe = regexp.MustCompile(`^(?:` +
	`(?:AKIA|ASIA)[A-Z0-9]{16}` + // AWS アクセスキー ID
	`|gh[pousr]_[A-Za-z0-9]{36,}` + // GitHub
	`|github_pat_[A-Za-z0-9_]{22,}` + // GitHub(fine-grained)
	`|xox[bpars]-[A-Za-z0-9-]{10,}` + // Slack
	`|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}` + // Stripe
	`|AIza[A-Za-z0-9_-]{35}` + // Google API キー
	`|sk-[A-Za-z0-9_-]{20,}` + // sk- 形式
	`|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` + // JWT(署名部は空でもよい)
	`)`)

// fixedPrefix は、固定形式の接頭辞(の先頭部分)のまとまり。lits は、どれも off の位置に同じバイト(手がかり)を持つ。
type fixedPrefix struct {
	lits [][]byte
	off  int
}

// fixedPrefixes は、固定形式の接頭辞を、手がかりのバイトごとにまとめたもの。どれも含まない行は、正規表現を当てない。
//
// 接頭辞を bytes.Index で探すと、先頭の文字が文中に多い場合(`sk` の `s`、`rk` の `r` など)に、遅い経路になる
// (DEVELOPMENT.md 3.4 節)。接頭辞の中の、文中に少ない 1 バイトを bytes.IndexByte で探してから、前後を照合する。
// 手がかりが同じ接頭辞は、1 回の走査でまとめて探す(plans/v1.2.0.md 段階 7 の実測)。
var fixedPrefixes = []fixedPrefix{
	{lits: [][]byte{[]byte("AKIA"), []byte("ASIA"), []byte("AIza")}, off: 0}, // `A`
	{lits: [][]byte{[]byte("gh"), []byte("github_pat_")}, off: 0},             // `g`
	{lits: [][]byte{[]byte("xox")}, off: 0},                                   // `x`
	{lits: [][]byte{[]byte("sk"), []byte("rk")}, off: 1},                      // `k`
	{lits: [][]byte{[]byte("eyJ")}, off: 2},                                   // `J`
}

// maxFixedPrefixes は、fixedPrefixes のまとまりの数の上限(fixed の作業領域を、配列で持つため)。
const maxFixedPrefixes = 8

func init() {
	if len(fixedPrefixes) > maxFixedPrefixes {
		panic("too many fixed prefix groups")
	}
	for _, g := range fixedPrefixes {
		for _, l := range g.lits {
			if g.off >= len(l) || l[g.off] != g.lits[0][g.off] {
				panic("fixed prefixes in a group must share the hint byte: " + string(l))
			}
		}
	}
}

// nextFixedPrefix は、line[pos:] の中で、g の接頭辞のどれかが始まる最初の位置を返す。なければ -1。
func nextFixedPrefix(line []byte, pos int, g *fixedPrefix) int {
	hint := g.lits[0][g.off]
	for q := pos + g.off; q < len(line); {
		j := bytes.IndexByte(line[q:], hint)
		if j < 0 {
			return -1
		}
		p := q + j - g.off // 接頭辞の先頭
		q += j + 1
		for _, l := range g.lits {
			if bytes.HasPrefix(line[p:], l) {
				return p
			}
		}
	}
	return -1
}

func (secretFinder) fixed(line []byte, dst []Match) []Match {
	n := len(line)
	var nextBuf [maxFixedPrefixes]int
	next := nextBuf[:len(fixedPrefixes)] // まとまりごとの、接頭辞の次の出現位置。-1: 未計算、n: これ以上ない
	for i := range next {
		next[i] = -1
	}
	for pos := 0; pos < n; {
		best := n
		for i := range fixedPrefixes {
			if next[i] == n {
				continue
			}
			if next[i] < pos {
				j := nextFixedPrefix(line, pos, &fixedPrefixes[i])
				if j < 0 {
					next[i] = n
					continue
				}
				next[i] = j
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

// ---- AWS の署名(SigV4) ----

const (
	// sigWord、sigAmzPrefix は、署名の語 `Signature`、`X-Amz-Signature` の部分(照合は、大文字・小文字を区別しない)。
	sigWord      = "signature"
	sigAmzPrefix = "x-amz-"
	// sigLen は、署名の値(SHA-256 の HMAC の 16 進数)の長さ。
	sigLen = 64
)

// signatures は、AWS の署名(SigV4)の値の範囲を追記する(仕様 4.1「AWS の署名」、Q32)。
//
// 語 `X-Amz-Signature` または `Signature`(大文字・小文字を区別しない。前が英数字・`-`・`_` でないこと)+ `=` +
// 小文字の 16 進数ちょうど 64 文字 + 後ろが英数字でないこと。`AWS4-HMAC-SHA256` などの前後の文脈は見ない。
// 語は大文字・小文字を区別しないため、固定の接頭辞では探せない。'=' を手がかりにし、手前の 9 バイトを照合する。
func (secretFinder) signatures(line []byte, dst []Match) []Match {
	n := len(line)
	if n < len(sigWord)+1+sigLen {
		return dst
	}
	for pos := len(sigWord); pos+sigLen < n; {
		j := bytes.IndexByte(line[pos:n-sigLen], '=')
		if j < 0 {
			break
		}
		i := pos + j // '=' の位置
		pos = i + 1
		w := i - len(sigWord) // 語の先頭
		if !hasPrefixFold(line[w:], sigWord) {
			continue
		}
		if w >= len(sigAmzPrefix) && hasPrefixFold(line[w-len(sigAmzPrefix):], sigAmzPrefix) {
			w -= len(sigAmzPrefix)
		}
		if w > 0 && (isASCIIAlnum(line[w-1]) || line[w-1] == '-' || line[w-1] == '_') {
			continue
		}
		s, e := i+1, i+1+sigLen
		if !isLowerHex(line[s:e]) || e < n && isASCIIAlnum(line[e]) {
			continue
		}
		dst = append(dst, Match{Start: s, End: e, Kind: KindSecret})
		pos = e
	}
	return dst
}

// isLowerHex は、b がすべて小文字の 16 進数(0-9、a-f)かを返す。
func isLowerHex(b []byte) bool {
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ---- URL のパスワード(v1.2。仕様 4.1、Q48) ----

// isURLSchemeChar は、URL のスキームに使える文字(英数字・`+`・`.`・`-`)。
func isURLSchemeChar(c byte) bool { return isASCIIAlnum(c) || c == '+' || c == '.' || c == '-' }

// isURLUserInfoStop は、URL のユーザー情報(ユーザーとパスワード)に含まれない文字(空白・`/`・`?`・`#`・`@`と、
// RFC 3986 で URL に使えない `"` `'` `` ` `` `<` `>` `\` `{` `}` `|` `^`)。後者は、JSON などで、パスのない URL の後ろの
// 別の値(`"https://example.com","email":"bob@example.com"`)を、ユーザー情報として読まないため(Q60)。
func isURLUserInfoStop(c byte) bool {
	switch c {
	case ' ', '\t', '/', '?', '#', '@', '"', '\'', '`', '<', '>', '\\', '{', '}', '|', '^':
		return true
	}
	return false
}

// isURLHostChar は、`@` の後ろのホスト名の文字(英数字・`.`・`-`・`[`)。
func isURLHostChar(c byte) bool { return isASCIIAlnum(c) || c == '.' || c == '-' || c == '[' }

// urlPasswordStart は、line[at] の `@` が、URL のユーザー情報の `@` なら、パスワードの先頭を返す(仕様 4.1)。
//
// `@` の手前を遡り、ユーザー情報(isURLUserInfoStop でない文字の続き)を求める。その中の最初の `:` より後ろ
// (1 文字以上)がパスワード、手前がユーザー(0 文字以上)。ユーザー情報の直前が `://` で、その前がスキーム
// (英数字・`+`・`.`・`-` の続きで、英字で始まり、直前が `_` でない。Q64)、`@` の後ろがホスト名の文字であること。
// 遡る範囲は、手前の `@`・`/` などで止まるので、`@` ごとに呼んでも、遡る長さの合計は行の長さ以内に収まる。
// secret のパスワードの検出と、email の検出器の「この `@` はメールアドレスとして扱わない」の判定が共用する。
func urlPasswordStart(line []byte, at int) (int, bool) {
	if at+1 >= len(line) || !isURLHostChar(line[at+1]) {
		return 0, false
	}
	p, colon := at, -1
	for p > 0 && !isURLUserInfoStop(line[p-1]) {
		p--
		if line[p] == ':' {
			colon = p
		}
	}
	if colon < 0 || colon+1 >= at || p < 3 || line[p-3] != ':' || line[p-2] != '/' || line[p-1] != '/' {
		return 0, false
	}
	q := p - 3
	for q > 0 && isURLSchemeChar(line[q-1]) {
		q--
	}
	if q == p-3 || !(line[q] >= 'a' && line[q] <= 'z' || line[q] >= 'A' && line[q] <= 'Z') {
		return 0, false
	}
	// スキームの直前が `_` なら対象にしない。hash の出力(`email_<16 進数>`)の 16 進数の部分を、スキームとして読まないため
	// (`email_fde789562e9a://:0@0` の `0` を再度置換しない。仕様 4.1。Q64)
	if q > 0 && line[q-1] == '_' {
		return 0, false
	}
	return colon + 1, true
}

// urlPasswords は、URL のユーザー情報のパスワードの範囲を追記する(仕様 4.1)。
//
// 前処理: `@` を bytes.IndexByte で探し(email も同じ手がかり。`@` のない行はここで終わる)、見つけた `@` ごとに
// urlPasswordStart で手前を調べる。`://` を手がかりにすると、`:` が文中に多く(時刻など)、探す回数が増える。
func (secretFinder) urlPasswords(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		j := bytes.IndexByte(line[pos:], '@')
		if j < 0 {
			return dst
		}
		at := pos + j
		pos = at + 1
		if s, ok := urlPasswordStart(line, at); ok {
			dst = append(dst, Match{Start: s, End: at, Kind: KindSecret})
		}
	}
}

// ---- Authorization ヘッダ(Bearer / Basic) ----

// schemeCredentials は、line[p:] が `Bearer <値>` / `Basic <値>` の形かを調べる(Q13、決定事項 15)。
//
// 方式名は、大文字・小文字を区別せず、後ろに空白(スペース・タブ)が 1 つ以上ある。この形のときは、
// isScheme が true になる(値が読めなくても)。値は、RFC 7235 の token68(英数字と `-` `.` `_` `~` `+` `/`、
// 末尾に `=` が続いてもよい)。Basic は、値が base64 として解読でき、結果に `:`(`user:pass` の形)を含む場合に限る。
// 値が読めたときは、その範囲を start、end に返し、ok が true になる。
//
// 方式名で始まるのに値が読めない場合(置換済みのラベルなど)に、方式名の語を値として置換しないよう、
// 呼び出し側は、isScheme が true のときは、ok でなくても、他の規則を適用しない。
func schemeCredentials(line []byte, p int) (start, end int, ok, isScheme bool) {
	length := 0
	basic := false
	switch {
	case hasPrefixFold(line[p:], "bearer"):
		length = len("bearer")
	case hasPrefixFold(line[p:], "basic"):
		length, basic = len("basic"), true
	default:
		return 0, 0, false, false
	}
	q := p + length
	if q >= len(line) || line[q] != ' ' && line[q] != '\t' {
		return 0, 0, false, false
	}
	for q < len(line) && (line[q] == ' ' || line[q] == '\t') {
		q++
	}
	e := token68End(line, q)
	if e == q || basic && !basicCredentials(line[q:e]) {
		return 0, 0, false, true
	}
	return q, e, true, true
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

// startsWithURLPassword は、line[s:] が URL のパスワードの形(`<スキーム>://<ユーザー>:<パスワード>@<ホスト名の文字>`)
// で始まるかを返す(キー名ベースの値の先頭の判定。仕様 4.1。Q65)。
//
// 置換していない形については、`@` に urlPasswordStart を当てた結果と同じ(スキームの先頭が s になるもの)。
// キー名ベースの値の先頭の手前は、区切り・空白・引用符で、スキームの文字でも `_` でもないので、スキームは s から始まる。
// 加えて、ユーザー・パスワードの部分が置換済みのラベル 1 つだけのもの、`@` の直後がラベルのものも、この形とする。
// 置換後の `https://u:<secret_1>@<aws_host_1>.…` を再度流したときに、キー名ベースの値として読まないため(冪等性)。
// hash の出力形(`secret_<16 進数>` など)は、もともとユーザー情報・ホスト名の文字だけでできている。
func (f secretFinder) startsWithURLPassword(line []byte, s int) bool {
	n := len(line)
	if s >= n || !(line[s] >= 'a' && line[s] <= 'z' || line[s] >= 'A' && line[s] <= 'Z') {
		return false
	}
	if s > 0 && (isURLSchemeChar(line[s-1]) || line[s-1] == '_') {
		return false
	}
	p := s + 1
	for p < n && isURLSchemeChar(line[p]) {
		p++
	}
	if !bytes.HasPrefix(line[p:], schemeSep) {
		return false
	}
	// ユーザー情報: 最初の `:` の前がユーザー(0 文字以上)、後ろがパスワード(1 文字以上)。
	// それぞれ、ユーザー情報の文字の続きか、ラベル 1 つだけ(ラベルは、部分の先頭から、部分の終わりまでのものだけ)
	colon, pwLen := -1, 0
	segStart := true // 今の位置が、ユーザーかパスワードの先頭か
	x := p + len(schemeSep)
	for {
		if x >= n {
			return false
		}
		if segStart {
			segStart = false
			if e, ok := f.format.MatchAt(line, x); ok && e < n && (line[e] == '@' || colon < 0 && line[e] == ':') {
				if colon >= 0 {
					pwLen++
				}
				x = e
				continue
			}
		}
		c := line[x]
		if c == '@' {
			break
		}
		if isURLUserInfoStop(c) {
			return false
		}
		switch {
		case c == ':' && colon < 0:
			colon, segStart = x, true
		case colon >= 0:
			pwLen++
		}
		x++
	}
	if colon < 0 || pwLen == 0 || x+1 >= n {
		return false
	}
	// `@` の後ろ: ホスト名の文字か、ラベル
	if isURLHostChar(line[x+1]) {
		return true
	}
	_, ok := f.format.MatchAt(line, x+1)
	return ok
}

// urlSchemeSlashes は、URL のスキームの `:` の後ろの `//`。
var urlSchemeSlashes = []byte("//")

// keyed は、キー名ベースの値の範囲を追記する(仕様 4.1、決定事項 15)。
//
// '=' または ':' の手前が、対象のキー名(引用符、または `\"` で囲まれていてもよい)なら、その後ろの値が対象になる。
//   - 区切りの前後の空白(スペース・タブ)は、任意個を許す(Q15)
//   - `:` の直後が `//` なら、区切りとして扱わない(`<キー名>://` は URL のスキーム。v1.2。Q63)。
//     キー名と値として読むと、URL のパスワードと置換の範囲が隣り合い、置換で値の区切り(`&` など)が消えて、
//     2 回目に置換済みのラベルごと再度置換されることがあった(`passwd://u:&x@host`)
//   - 値(引用符で始まる場合は、引用符の次)が URL のパスワードの形で始まるなら、対象にしない(v1.2。Q65)。
//     パスワードは urlPasswords が拾う。キー名ベースの値として読むと、値が `&` などで終わるため、
//     置換の範囲が隣り合って 2 回目に再度置換されたり、パスワードの残りが出力に残ったりした(`password=https://u:p&q@h`)
//   - 値が `Bearer ` / `Basic ` で始まる場合は、方式名の後ろの値だけが対象
//     (後ろが値として読めなければ、何も置換しない)。キー名が Authorization で、方式名がなければ対象でない
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
func (f secretFinder) keyed(line []byte, dst []Match) []Match {
	n := len(line)
	ne, nc := -1, -1 // 次の '='、':' の位置(-1: 未計算、n: これ以上ない)
	// 直前に求めた引用符なしの値の範囲 [bareStart, bareEnd)。この中から始まる値は、同じ位置で終わる
	// (値の開始位置の手前は '=' ':' 空白・タブのどれかで '\' ではないため、`\\` の組の区切り方が一致する)。
	// `token=token=…` のような行で、値ごとに行末まで走査し直さないため。
	bareStart, bareEnd := -1, -1
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
		if line[i] == ':' && bytes.HasPrefix(line[i+1:], urlSchemeSlashes) {
			continue // `<キー名>://` は、キーと値の組ではなく URL のスキーム(仕様 4.1。Q63)
		}

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
		if s, e, ok, isScheme := schemeCredentials(line, cs); isScheme {
			if ok {
				dst = append(dst, Match{Start: s, End: e, Kind: KindSecret})
			}
			continue
		}
		if authOnly {
			continue
		}
		if f.startsWithURLPassword(line, cs) {
			continue // パスワードは、URL のパスワードとして置換する(仕様 4.1。Q65)
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
			if bareStart <= vs && vs < bareEnd {
				e = bareEnd
			} else {
				e = bareValueEnd(line, vs)
				bareStart, bareEnd = vs, e
			}
		}
		if e > s {
			dst = append(dst, Match{Start: s, End: e, Kind: KindSecret})
		}
	}
	return dst
}
