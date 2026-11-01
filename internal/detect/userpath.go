package detect

import (
	"bytes"
	"slices"
)

// commonUserNames は、人名でないので対象にしないユーザー名(仕様 4.8。Q102)。
var commonUserNames = []string{
	"user", "ubuntu", "ec2-user", "debian", "centos", "admin", "runner", "node", "vagrant",
	"Administrator", "Public", "Default", "Default User", "All Users", "Shared", "Guest",
}

// userPathFinder は、ホームディレクトリのパスの中のユーザー名の検出器(仕様 4.8)。
//
// 既定で有効なので、`/` と `\` の位置だけを IndexByte で飛んで調べる(手がかりの語を照合器で探すより速い)。
type userPathFinder struct{}

func (userPathFinder) kind() Kind { return KindUserPath }

func (userPathFinder) find(line []byte, dst []Match) []Match {
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
			if unixPathStart(line, p) {
				dst = appendUserName(dst, line, i+len("home/"), false)
			}
		case hasPrefixFold(rest, "users/"):
			switch {
			case windowsSlashStart(line, p):
				dst = appendUserName(dst, line, i+len("users/"), true)
			case bytes.HasPrefix(rest, []byte("Users/")) && unixPathStart(line, p):
				dst = appendUserName(dst, line, i+len("users/"), false)
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
		case bytes.HasPrefix(rest, []byte(`/home\/`)) && pathBoundary(line, p):
			dst = appendUserName(dst, line, i+len(`/home\/`), false) // \/home\/(JSON の `/` のエスケープ)
		case bytes.HasPrefix(rest, []byte(`/Users\/`)) && pathBoundary(line, p):
			dst = appendUserName(dst, line, i+len(`/Users\/`), false)
		case hasPrefixFold(rest, `/users\/`) && p >= 2 && isDrive(line, p-1):
			dst = appendUserName(dst, line, i+len(`/users\/`), true) // C:\/Users\/
		case hasPrefixFold(rest, `users\\`) && p >= 3 && line[p-1] == '\\' && isDrive(line, p-2):
			dst = appendUserName(dst, line, i+len(`users\\`), true) // C:\\Users\\
		case hasPrefixFold(rest, `users\`) && p >= 2 && isDrive(line, p-1):
			dst = appendUserName(dst, line, i+len(`users\`), true)
		}
	}
}

func isASCIILetter(c byte) bool { return isLowerASCII(c) || isUpperASCII(c) }

// isDrive は、line[colon] が `:` で、その手前がドライブ名(英字 1 文字)で、形の前の条件を満たすかを返す。
func isDrive(line []byte, colon int) bool {
	return line[colon] == ':' && colon >= 1 && isASCIILetter(line[colon-1]) && pathBoundary(line, colon-1)
}

// pathBoundary は、形の始まり s の前の条件(行頭か、パスの続きに見えない文字)を満たすかを返す(仕様 4.8)。
func pathBoundary(line []byte, s int) bool {
	if s == 0 {
		return true
	}
	c := line[s-1]
	if s >= 2 && line[s-2] == '\\' && (c == 'n' || c == 't' || c == 'r') {
		return true // 文字の `\n` など(JSON の文字列の中の改行)
	}
	if bytes.HasSuffix(line[:s], []byte(`?\`)) || bytes.HasSuffix(line[:s], []byte(`?\\`)) {
		return true // `\\?\C:\Users\`
	}
	return !isASCIIAlnum(c) && c != '-' && c != '_' && c != '.' && c != '/' && c != '\\'
}

// unixPathStart は、p の `/` から始まる `/home/`・`/Users/` が、形の前の条件を満たすかを返す。
func unixPathStart(line []byte, p int) bool {
	return pathBoundary(line, p) || fileURLStart(line, p, "file://")
}

// fileURLStart は、line[:s] が URL の始まり(prefix)で終わり、その前が形の前の条件を満たすかを返す。
func fileURLStart(line []byte, s int, prefix string) bool {
	return bytes.HasSuffix(line[:s], []byte(prefix)) && pathBoundary(line, s-len(prefix))
}

// windowsSlashStart は、p の `/` の手前が、`C:`、`/c`、`/mnt/c`、`file:///C:` のどれかかを返す。
func windowsSlashStart(line []byte, p int) bool {
	if p < 2 {
		return false
	}
	if line[p-1] == ':' {
		return isASCIILetter(line[p-2]) && (pathBoundary(line, p-2) || fileURLStart(line, p-2, "file:///"))
	}
	if line[p-2] != '/' || !isASCIILetter(line[p-1]) {
		return false
	}
	return pathBoundary(line, p-2) || bytes.HasSuffix(line[:p-2], []byte("/mnt")) && pathBoundary(line, p-len("/mnt/c"))
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
