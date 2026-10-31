package label

import "bytes"

// AnswerScanner は、AI の回答の中のラベルを読む。現在の書式のラベルに加えて、
// HTML と Markdown で崩れた形も、ラベルとして認める(仕様 5.3)。
//
// Format.Scan は、変えない(検出の保護範囲と連番に、崩れた形を混ぜないため)。
type AnswerScanner struct {
	f    Format
	html Format // リテラルを文字参照にした書式。リテラルに対象の文字がなければ、ゼロ値
	// start は、ラベル(崩れた形を含む)の先頭になりうるバイト。それ以外の位置は、照合せずに読み飛ばす。
	start [256]bool
}

// NewAnswerScanner は、書式 f の AnswerScanner を返す。
func NewAnswerScanner(f Format) *AnswerScanner {
	a := &AnswerScanner{f: f}
	pre, mid, post := escapeHTML(f.pre), escapeHTML(f.mid), escapeHTML(f.post)
	if !bytes.Equal(pre, f.pre) || !bytes.Equal(mid, f.mid) || !bytes.Equal(post, f.post) {
		a.html = Format{pre: pre, mid: mid, post: post, typeFirst: f.typeFirst, ok: true}
	}
	if len(f.pre) == 0 {
		a.start = f.first
		return a
	}
	a.start[f.pre[0]] = true
	a.start[pre[0]] = true
	if isASCIIPunct(f.pre[0]) {
		a.start['\\'] = true
	}
	return a
}

// escapeHTML は、b の `&` `<` `>` `"` を文字参照にしたものを返す。
func escapeHTML(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case '&':
			out = append(out, "&amp;"...)
		case '<':
			out = append(out, "&lt;"...)
		case '>':
			out = append(out, "&gt;"...)
		case '"':
			out = append(out, "&quot;"...)
		default:
			out = append(out, c)
		}
	}
	return out
}

func isASCIIPunct(c byte) bool {
	return c > ' ' && c < 0x7f && !isAlnum(c)
}

// matchEscaped は、line[p:] が、lit の記号の前に `\` を置いた形で始まるなら、その終わりの位置を返す。
// required が false なら、`\` はあってもなくてもよい。
func matchEscaped(line []byte, p int, lit []byte, required bool) (int, bool) {
	for _, c := range lit {
		if isASCIIPunct(c) {
			if p < len(line) && line[p] == '\\' && p+1 < len(line) && line[p+1] == c {
				p++
			} else if required {
				return p, false
			}
		}
		if p >= len(line) || line[p] != c {
			return p, false
		}
		p++
	}
	return p, true
}

// matchMarkdown は、line[i:] が Markdown で崩れたラベルで始まるなら、それを読む。
// 始めと終わりのリテラルの記号は `\` が必須で、間のリテラルと種別名の記号の `\` は任意(仕様 5.3)。
func (a *AnswerScanner) matchMarkdown(line []byte, i int) (end int, typ string, n int, ok bool) {
	f := &a.f
	p, ok := matchEscaped(line, i, f.pre, true)
	if !ok {
		return 0, "", 0, false
	}
	matchTyp := func() bool {
		for k, t := range typeBytes {
			if e, ok := matchEscaped(line, p, t, false); ok {
				typ, p = Types[k], e
				return true
			}
		}
		return false
	}
	matchNum := func() bool {
		var ok bool
		n, p, ok = matchNumber(line, p)
		return ok
	}
	first, second := matchTyp, matchNum
	if !f.typeFirst {
		first, second = matchNum, matchTyp
	}
	if !first() {
		return 0, "", 0, false
	}
	if p, ok = matchEscaped(line, p, f.mid, false); !ok || !second() {
		return 0, "", 0, false
	}
	if p, ok = matchEscaped(line, p, f.post, true); !ok {
		return 0, "", 0, false
	}
	return p, typ, n, true
}

// matchAnyAt は、line[i:] で始まるラベルを読む。escaped は、崩れた形かどうか。
func (a *AnswerScanner) matchAnyAt(line []byte, i int) (end int, typ string, n int, escaped, ok bool) {
	if end, typ, n, ok = a.f.matchAt(line, i); ok {
		return end, typ, n, false, true
	}
	if !a.html.IsZero() {
		if end, typ, n, ok = a.html.matchAt(line, i); ok {
			return end, typ, n, true, true
		}
	}
	if end, typ, n, ok = a.matchMarkdown(line, i); ok {
		return end, typ, n, true, true
	}
	return 0, "", 0, false, false
}

// Scan は、line の中のラベルを、崩れた形も含めて左から順に、重ならないように見つけ、fn を呼ぶ。
// skip にある崩れた形は、ラベルとして扱わない。
func (a *AnswerScanner) Scan(line []byte, skip map[string]struct{}, fn func(start, end int, typ string, n int)) {
	if !a.f.ok {
		return
	}
	for i := 0; i < len(line); {
		if !a.start[line[i]] {
			i++
			continue
		}
		end, typ, n, escaped, ok := a.matchAnyAt(line, i)
		if ok && escaped {
			_, skipped := skip[string(line[i:end])]
			ok = !skipped
		}
		if !ok {
			i++
			continue
		}
		fn(i, end, typ, n)
		i = end
	}
}

// ScanEscaped は、line の中の崩れた形だけを報告する。崩れた形には、必ず `\` か `&` が含まれる。
func (a *AnswerScanner) ScanEscaped(line []byte, fn func(form []byte)) {
	if !a.f.ok || bytes.IndexByte(line, '\\') < 0 && bytes.IndexByte(line, '&') < 0 {
		return
	}
	for i := 0; i < len(line); {
		if !a.start[line[i]] {
			i++
			continue
		}
		end, _, _, escaped, ok := a.matchAnyAt(line, i)
		if !ok {
			i++
			continue
		}
		if escaped {
			fn(line[i:end])
		}
		i = end
	}
}
