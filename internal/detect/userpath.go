package detect

import (
	"bytes"
	"slices"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// commonUserNames は、人名でないので対象にしないユーザー名(仕様 4.8。Q102)。
var commonUserNames = []string{
	"user", "ubuntu", "ec2-user", "debian", "centos", "admin", "runner", "node", "vagrant",
	"Administrator", "Public", "Default", "Default User", "All Users", "Shared", "Guest",
}

// userPathFinder は、ホームディレクトリのパスの中のユーザー名の検出器(仕様 4.8)。
//
// 既定で有効なので、`/` と `\` の位置だけを IndexByte で飛んで調べる(手がかりの語を照合器で探すより速い)。
// format が大きいので、行ごとに値を写さないよう、ポインタで持つ。
type userPathFinder struct {
	format label.Format // 置換済みのラベルの書式。形の前の条件で使う
	// labelEnd は、ラベルの末尾の文字。手がかりごとに EndsAt を呼ばないよう、先に比べる。末尾が連番や種別名の書式では
	// ラベルごとに変わるが、英数字なので、そのラベルの直後は文字の条件で対象外になる。
	labelEnd byte
}

func newUserPathFinder(format label.Format) *userPathFinder {
	l := format.Append(nil, label.Types[0], 1)
	return &userPathFinder{format: format, labelEnd: l[len(l)-1]}
}

func (*userPathFinder) kind() Kind { return KindUserPath }

func (f *userPathFinder) find(line []byte, dst []Match) []Match {
	for i := 0; ; {
		j := bytes.IndexByte(line[i:], '/')
		if j < 0 {
			break
		}
		p := i + j
		i = p + 1
		rest := line[i:]
		switch {
		case bytes.HasPrefix(rest, []byte("home/")):
			if f.unixPathStart(line, p) {
				dst = appendUserName(dst, line, i+len("home/"), false)
			}
		case hasPrefixFold(rest, `users\`):
			if p >= 2 && f.isDrive(line, p-1) {
				dst = appendUserName(dst, line, i+len(`users\`), true) // C:/Users\(区切りが混ざる形)
			}
		case hasPrefixFold(rest, "users/"):
			switch {
			case f.windowsSlashStart(line, p):
				dst = appendUserName(dst, line, i+len("users/"), true)
			case bytes.HasPrefix(rest, []byte("Users/")) && f.unixPathStart(line, p):
				dst = appendUserName(dst, line, i+len("users/"), false)
			}
		case bytes.HasPrefix(rest, []byte("/wsl")):
			// `https://wsl.localhost/…` は、ドメインのある URL なので対象にしない。
			if s := f.wslHomeStart(line, p); s >= 0 && (p == 0 || line[p-1] != ':') {
				dst = appendUserName(dst, line, s, false)
			}
		}
	}
	for i := 0; ; {
		j := bytes.IndexByte(line[i:], '\\')
		if j < 0 {
			return dst
		}
		p := i + j
		i = p + 1
		rest := line[i:]
		switch {
		case bytes.HasPrefix(rest, []byte(`/home\/`)) && f.pathBoundary(line, p):
			dst = appendUserName(dst, line, i+len(`/home\/`), false) // \/home\/(JSON の `/` のエスケープ)
		case hasPrefixFold(rest, `/users\/`) && p >= 2 && f.isDrive(line, p-1):
			dst = appendUserName(dst, line, i+len(`/users\/`), true) // C:\/Users\/(`:` は形の前の条件を満たすので、macOS の形より先に見る)
		case bytes.HasPrefix(rest, []byte(`/Users\/`)) && f.pathBoundary(line, p):
			dst = appendUserName(dst, line, i+len(`/Users\/`), false)
		case hasPrefixFold(rest, `users\\`) && p >= 3 && line[p-1] == '\\' && f.isDrive(line, p-2):
			dst = appendUserName(dst, line, i+len(`users\\`), true) // C:\\Users\\
		case hasPrefixFold(rest, `users\`) && p >= 2 && f.isDrive(line, p-1):
			dst = appendUserName(dst, line, i+len(`users\`), true)
		case hasPrefixFold(rest, "users/") && p >= 2 && f.isDrive(line, p-1):
			dst = appendUserName(dst, line, i+len("users/"), true) // C:\Users/(区切りが混ざる形)
		case bytes.HasPrefix(rest, []byte(`\`)):
			if s := f.wslHomeStart(line, p); s >= 0 {
				dst = appendUserName(dst, line, s, false)
			}
		}
	}
}

func isASCIILetter(c byte) bool { return isLowerASCII(c) || isUpperASCII(c) }

// isDrive は、line[colon] が `:` で、その手前がドライブ名(英字 1 文字)で、形の前の条件を満たすかを返す。
func (f *userPathFinder) isDrive(line []byte, colon int) bool {
	return line[colon] == ':' && colon >= 1 && isASCIILetter(line[colon-1]) && f.pathBoundary(line, colon-1)
}

// pathBoundary は、形の始まり s の前の条件(行頭か、パスの続きに見えない文字)を満たすかを返す(仕様 4.8)。
// 置換済みのラベルの直後は、満たさない(Q128)。`10.0.0.5/home/x` の 1 回目は末尾の英数字で対象にならないが、
// ラベルの終わりの文字で判定すると、2 回目に対象になるため。
func (f *userPathFinder) pathBoundary(line []byte, s int) bool {
	if s == 0 {
		return true
	}
	c := line[s-1]
	if c == f.labelEnd && f.format.EndsAt(line, s) {
		return false
	}
	if s >= 2 && line[s-2] == '\\' && (c == 'n' || c == 't' || c == 'r') {
		return true // 文字の `\n` など(JSON の文字列の中の改行)
	}
	if bytes.HasSuffix(line[:s], []byte(`?\`)) || bytes.HasSuffix(line[:s], []byte(`?\\`)) {
		return true // `\\?\C:\Users\`
	}
	return !isASCIIAlnum(c) && c != '-' && c != '_' && c != '.' && c != '/' && c != '\\'
}

// unixPathStart は、p の `/` から始まる `/home/`・`/Users/` が、形の前の条件を満たすかを返す。
func (f *userPathFinder) unixPathStart(line []byte, p int) bool {
	return f.pathBoundary(line, p) || f.fileURLStart(line, p, "file://")
}

// fileURLStart は、line[:s] が URL の始まり(prefix)で終わり、その前が形の前の条件を満たすかを返す。
func (f *userPathFinder) fileURLStart(line []byte, s int, prefix string) bool {
	return bytes.HasSuffix(line[:s], []byte(prefix)) && f.pathBoundary(line, s-len(prefix))
}

// wslForms は、WSL の形の、配布の名前の手前と、後ろの `home`。
var wslForms = []struct{ host, home string }{
	{`\\wsl$\`, `\home\`},
	{`\\wsl.localhost\`, `\home\`},
	{`\\\\wsl$\\`, `\\home\\`},
	{`\\\\wsl.localhost\\`, `\\home\\`},
	{`//wsl$/`, `/home/`},
	{`//wsl.localhost/`, `/home/`},
}

// wslHomeStart は、p の位置から wslForms のどれかの形が始まるなら、ユーザー名の開始位置を返す。そうでなければ -1。
func (f *userPathFinder) wslHomeStart(line []byte, p int) int {
	if !f.pathBoundary(line, p) {
		return -1
	}
	for _, f := range wslForms {
		rest, ok := bytes.CutPrefix(line[p:], []byte(f.host))
		if !ok {
			continue
		}
		n := 0
		for n < len(rest) && isUserNameByte(rest[n]) {
			n++
		}
		if n > 0 && bytes.HasPrefix(rest[n:], []byte(f.home)) {
			return len(line) - len(rest) + n + len(f.home)
		}
	}
	return -1
}

// windowsSlashStart は、p の `/` の手前が、`C:`、`/C:`、`/c`、`/mnt/c`、`/cygdrive/c`、`file:///C:` のどれかかを返す。
func (f *userPathFinder) windowsSlashStart(line []byte, p int) bool {
	if p < 2 {
		return false
	}
	if line[p-1] == ':' {
		if !isASCIILetter(line[p-2]) {
			return false
		}
		return f.pathBoundary(line, p-2) || f.fileURLStart(line, p-2, "file:///") || p >= 3 && line[p-3] == '/' && f.pathBoundary(line, p-3)
	}
	if line[p-2] != '/' || !isASCIILetter(line[p-1]) {
		return false
	}
	if f.pathBoundary(line, p-2) || bytes.HasSuffix(line[:p-2], []byte("/mnt")) && f.pathBoundary(line, p-len("/mnt/c")) {
		return true
	}
	s := p - len("/cygdrive/c")
	return s >= 0 && hasPrefixFold(line[s:], "/cygdrive/") && f.pathBoundary(line, s)
}

func isUserNameByte(c byte) bool {
	return isASCIIAlnum(c) || c == '.' || c == '_' || c == '-' || c == '@' || c == '+' || c >= 0x80
}

// spacedNameEnd は、e の空白から先が、区切り(`\`、`/`)の手前まで名前として読めるなら、その区切りの位置を返す。
// 読めなければ -1。
func spacedNameEnd(line []byte, e int) int {
	for i := e; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' || c == '/':
			return i
		case c != ' ' && !isUserNameByte(c):
			return -1
		}
	}
	return -1
}

// appendUserName は、start から始まるユーザー名が対象なら、dst に追記する。
// windows は、Windows の形か(空白を含めてよく、大文字・小文字を区別しない)。
func appendUserName(dst []Match, line []byte, start int, windows bool) []Match {
	e := start
	for e < len(line) && isUserNameByte(line[e]) {
		e++
	}
	if windows && e > start && e < len(line) && line[e] == ' ' {
		if end := spacedNameEnd(line, e); end >= 0 {
			e = end
			for line[e-1] == ' ' {
				e--
			}
		}
	}
	for e > start && line[e-1] == '.' {
		e--
	}
	if e == start {
		return dst
	}
	name := line[start:e]
	common := slices.ContainsFunc(commonUserNames, func(s string) bool {
		if windows {
			return bytes.EqualFold(name, []byte(s))
		}
		return string(name) == s
	})
	if common {
		return dst
	}
	return append(dst, Match{Start: start, End: e, Kind: KindUserPath})
}
