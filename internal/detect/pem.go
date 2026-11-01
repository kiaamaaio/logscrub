package detect

import (
	"bytes"

	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/stream"
)

const (
	// pemKeyHint は、すべての印に含まれる語。これを含まないブロックは、行に分けずに読み飛ばす。
	pemKeyHint = "PRIVATE KEY"
	// pemMaxLabel は、印の語の長さの上限。不完全な印が続く長い行で、走査が 2 乗の時間にならないようにする。
	pemMaxLabel = 64
	// pemMinTail は、行の先頭に日時などが付いた本文の、行末の base64 の文字の最小の長さ(仕様 4.1)。
	pemMinTail = 40
	// pemMinSpaced は、BEGIN の印のあとに空白で続く、END のない本文の最小の長さ(仕様 4.1)。
	pemMinSpaced = 16

	// MaxUnclosedLines は、PEMScanner.UnclosedLines に記録する行番号の最大数(仕様 6 章)。
	MaxUnclosedLines = 5
)

// PEMSpan は、読み取りの段が見つけた、PEM の秘密鍵の範囲(仕様 4.1)。
type PEMSpan struct {
	Pos        int // ブロックの中の、行の始まりの位置
	Start, End int // 行の中の範囲。[Start, End)
	// Body は、行全体が鍵の本文であること。その行に、ほかの種別の検出を行わない。
	Body bool
}

// PEMScanner は、PEM の秘密鍵の範囲を求める(仕様 4.1)。
//
// 行をまたぐ状態を持つので、読み取りの段の 1 か所だけで使う(検出のワーカーでは使わない。DEVELOPMENT.md 3.3 節)。
type PEMScanner struct {
	format  label.Format
	hashLen int

	inBlock   bool
	bodySeen  bool
	line      int  // data[:counted] までの行数
	counted   int  // data の中の、行数を数え終えた位置
	beginLine int  // 開いているブロックの BEGIN の行番号
	column    int  // 開いているブロックの BEGIN の印の列。文字列で包まれた形では開き引用符の次から数える。手前が空白だけなら 0(行頭に日時などが付くログ。仕様 4.1)
	escaped   bool // 開いているブロックが、1 行ごとに文字列で包まれた形(`{"log":"…\n",…}`。仕様 4.1)

	// Unclosed は、END のないブロックの数。UnclosedLines は、その BEGIN の行番号(最初の MaxUnclosedLines 件まで)。
	Unclosed      int
	UnclosedLines []int
}

// NewPEMScanner は、d の設定の PEMScanner を返す。`secret` が無効なら nil。
// line は、これまでに読んだ行数(通知の行番号を、入力をまたいで通しで数えるため)。
func (d *Detector) NewPEMScanner(line int) *PEMScanner {
	if !d.kinds.Has(KindSecret) {
		return nil
	}
	return &PEMScanner{format: d.format, hashLen: d.hashLen, line: line}
}

// Scan は、完全な行だけを含むブロック data の中の範囲を、行の順に dst に追記して返す。
func (s *PEMScanner) Scan(data []byte, dst []PEMSpan) []PEMSpan {
	s.counted = 0
	for pos := 0; pos < len(data); {
		if !s.inBlock {
			i := bytes.Index(data[pos:], []byte(pemKeyHint))
			if i < 0 {
				break
			}
			pos = bytes.LastIndexByte(data[:pos+i], '\n') + 1
		}
		content, eol, _ := stream.NextLine(data[pos:])
		dst = s.scanLine(data, content, pos, dst)
		pos += len(content) + len(eol)
	}
	s.countLines(data, len(data))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		s.line++
	}
	return dst
}

// Finish は、1 つの入力の終わりで呼ぶ。行は入力ごとに区切るので、ブロックの状態も入力ごとに戻す。
func (s *PEMScanner) Finish() {
	if s.inBlock {
		s.closeUnfinished()
	}
}

// countLines は、data[:pos] までの行数を s.line に足す。数え終えた位置から続けて数えるので、BEGIN の行が続いても線形の時間で終わる。
func (s *PEMScanner) countLines(data []byte, pos int) {
	s.line += bytes.Count(data[s.counted:pos], []byte{'\n'})
	s.counted = pos
}

func (s *PEMScanner) closeUnfinished() {
	s.inBlock = false
	s.Unclosed++
	if len(s.UnclosedLines) < MaxUnclosedLines {
		s.UnclosedLines = append(s.UnclosedLines, s.beginLine)
	}
}

// scanLine は、位置 pos の 1 行を処理する。
func (s *PEMScanner) scanLine(data, line []byte, pos int, dst []PEMSpan) []PEMSpan {
	from := 0
	if s.inBlock {
		if ms, me, ok := findPEMMarker(line, 0, "-----END "); ok {
			s.inBlock = false
			from = me
			// 印から離れた語は、本文の長さのときだけ本文とする。`t=3 -----END …` の `t=3` は、本文ではない。
			if bs, be := trimBlank(line, 0, ms); bs < be && isBase64(line[bs:be]) && (be == ms || be-bs >= pemMinTail) {
				dst = append(dst, PEMSpan{Pos: pos, Start: bs, End: be})
			}
		} else {
			var body bool
			if dst, body = s.bodyLine(line, pos, dst); body {
				return dst
			}
			// 本文の範囲の末尾が置換済みなら、伏せた出力を再度流している。鍵の残りを知らせる理由がない。
			from, to := s.bodyRange(line)
			if bs, be := trimBlank(line, from, to); s.secretTail(line[bs:be]) >= 0 {
				s.inBlock = false
			} else {
				s.closeUnfinished()
			}
		}
	}
	for {
		ms, me, ok := findPEMMarker(line, from, "-----BEGIN ")
		if !ok {
			return dst
		}
		if es, ee, ok := findPEMMarker(line, me, "-----END "); ok {
			if me < es {
				dst = append(dst, PEMSpan{Pos: pos, Start: me, End: es})
			}
			from = ee
			continue
		}
		rest := line[me:]
		escaped := endsWithEscapedNewline(rest)
		if escaped || len(bytes.TrimRight(rest, " \t")) == 0 {
			s.inBlock, s.bodySeen, s.escaped = true, false, escaped
			base := 0
			if escaped {
				base = bytes.LastIndexAny(line[:ms], `"'`) + 1
			}
			s.column = 0
			if bs, be := trimBlank(line, base, ms); bs < be {
				s.column = ms - base
			}
			s.countLines(data, pos)
			s.beginLine = s.line + 1
			return dst
		}
		if inlinePEMBody(rest) {
			dst = append(dst, PEMSpan{Pos: pos, Start: me, End: me + inlinePEMEnd(rest)})
		}
		return dst
	}
}

// bodyLine は、ブロックの中の 1 行が本文の形かを返し、置換する範囲を dst に追記する(仕様 4.1)。
// BEGIN の印の列(列で語が切れる行は除く)、本文の範囲(bodyRange)、行全体の順に、狭い範囲から調べる。
func (s *PEMScanner) bodyLine(line []byte, pos int, dst []PEMSpan) ([]PEMSpan, bool) {
	from, to := s.bodyRange(line)
	if c := from + s.column; s.column > 0 && c <= to && !isBase64Byte(line[c-1]) {
		if d, body := s.bodyForm(line, c, to, pos, dst); body {
			return d, true
		}
	}
	if from > 0 || to < len(line) {
		if d, body := s.bodyForm(line, from, to, pos, dst); body {
			return d, true
		}
	}
	return s.bodyForm(line, 0, len(line), pos, dst)
}

// bodyRange は、行の中で本文が入る範囲を返す。文字列で包まれた形では、開き引用符から文字の `\n` まで。それ以外は行全体。
func (s *PEMScanner) bodyRange(line []byte) (from, to int) {
	if s.escaped {
		if i := bytes.Index(line, []byte(`\n`)); i >= 0 {
			if bytes.HasSuffix(line[:i], []byte(`\r`)) {
				i -= len(`\r`)
			}
			return bytes.LastIndexAny(line[:i], `"'`) + 1, i
		}
	}
	return 0, len(line)
}

// bodyForm は、line[from:to] が本文の形かを返し、置換する範囲を dst に追記する。
func (s *PEMScanner) bodyForm(line []byte, from, to, pos int, dst []PEMSpan) ([]PEMSpan, bool) {
	whole := from == 0 && to == len(line)
	bs, be := trimBlank(line, from, to)
	switch {
	case bs == be:
		return dst, true
	case isBase64(line[bs:be]):
		s.bodySeen = true
		return append(dst, PEMSpan{Pos: pos, Start: bs, End: be, Body: whole}), true
	case s.isReplacedSecret(line[bs:be]):
		s.bodySeen = true
		return dst, true // 通常の検出が、保護範囲として残す
	case !s.bodySeen && isPEMHeader(line[bs:be]):
		return append(dst, PEMSpan{Pos: pos, Start: bs, End: be, Body: whole}), true
	}
	t := be
	for t > bs && isBase64Byte(line[t-1]) {
		t--
	}
	if be-t >= pemMinTail {
		s.bodySeen = true
		// 行の前半は本文でないので、通常の検出も行う。
		return append(dst, PEMSpan{Pos: pos, Start: t, End: be}), true
	}
	return dst, false
}

// isReplacedSecret は、b の全体が、`secret` の置換済みの形かを返す。ほかの種別に限らないと、1 回目にブロックを終えた行
// (`<email_1>` になる行)が 2 回目にブロックを続け、後ろの行の結果が変わる。
func (s *PEMScanner) isReplacedSecret(b []byte) bool {
	return s.secretTail(b) == 0
}

// secretTail は、b の末尾にある `secret` の置換済みの形の開始位置を返す。なければ -1。
func (s *PEMScanner) secretTail(b []byte) int {
	at := -1
	s.format.Scan(b, func(start, end int, typ string, _ int) {
		if end == len(b) && typ == "secret" {
			at = start
		}
	})
	if at < 0 {
		label.ScanHashed(b, s.hashLen, func(start, end int) {
			if end == len(b) && bytes.HasPrefix(b[start:], []byte("secret_")) {
				at = start
			}
		})
	}
	return at
}

// findPEMMarker は、line[from:] の最初の印(prefix + 語 + `-----`)の範囲を返す。
// 語は、`PRIVATE KEY` で終わるか、`PGP PRIVATE KEY BLOCK` であること。
func findPEMMarker(line []byte, from int, prefix string) (start, end int, ok bool) {
	for i := from; ; {
		j := bytes.Index(line[i:], []byte(prefix))
		if j < 0 {
			return 0, 0, false
		}
		s := i + j
		i = s + 1
		k := s + len(prefix)
		e := k
		for e < len(line) && e-k < pemMaxLabel && (isASCIIAlnum(line[e]) || line[e] == ' ') {
			e++
		}
		if !bytes.HasPrefix(line[e:], []byte("-----")) {
			continue
		}
		if word := line[k:e]; bytes.HasSuffix(word, []byte(pemKeyHint)) || string(word) == "PGP PRIVATE KEY BLOCK" {
			return s, e + len("-----"), true
		}
	}
}

func isBase64Byte(c byte) bool { return isASCIIAlnum(c) || c == '+' || c == '/' || c == '=' }

func isBase64(b []byte) bool {
	for _, c := range b {
		if !isBase64Byte(c) {
			return false
		}
	}
	return true
}

// trimBlank は、line[s:e] の前後の空白を除いた範囲を返す。
func trimBlank(line []byte, s, e int) (int, int) {
	for s < e && (line[s] == ' ' || line[s] == '\t') {
		s++
	}
	for s < e && (line[e-1] == ' ' || line[e-1] == '\t') {
		e--
	}
	return s, e
}

// isPEMHeader は、b が `名前: 値` の形(`Proc-Type: 4,ENCRYPTED`)かを返す。
func isPEMHeader(b []byte) bool {
	i := bytes.Index(b, []byte(": "))
	if i <= 0 {
		return false
	}
	for _, c := range b[:i] {
		if !isASCIIAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}

// endsWithEscapedNewline は、BEGIN の印の後ろ rest が、文字の `\n`(`\r\n`)と閉じ引用符で始まるかを返す。
// 本文は次の行の文字列に続く(Docker の json-file など)。
func endsWithEscapedNewline(rest []byte) bool {
	rest, ok := bytes.CutPrefix(bytes.TrimPrefix(rest, []byte(`\r`)), []byte(`\n`))
	if !ok {
		return false
	}
	rest = bytes.TrimPrefix(rest, []byte(`\`))
	return len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'')
}

// inlinePEMBody は、END のない BEGIN の印の後ろ rest が、本文で始まるかを返す。
func inlinePEMBody(rest []byte) bool {
	if bytes.HasPrefix(rest, []byte(`\n`)) || bytes.HasPrefix(rest, []byte(`\r\n`)) || isBase64Byte(rest[0]) {
		return true
	}
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	n := i
	for n < len(rest) && isBase64Byte(rest[n]) {
		n++
	}
	return n-i >= pemMinSpaced
}

// inlinePEMEnd は、rest の本文の終わり(行末か、閉じ引用符の手前)を返す。`\"` の `\` も含めない。
func inlinePEMEnd(rest []byte) int {
	i := bytes.IndexAny(rest, `"'`)
	if i < 0 {
		return len(rest)
	}
	if i > 0 && rest[i-1] == '\\' {
		i--
	}
	return i
}
