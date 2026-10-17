package detect

import (
	"bytes"
	"regexp"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// emailRe は、メールアドレスの正規表現(仕様 4 章、plans/v1.0.0.md の Q5)。
//
//   - ローカルパート: `[A-Za-z0-9._%+-]+`(非 ASCII は英数字でない扱い)
//   - ドメイン: `([A-Za-z0-9-]+\.)+[A-Za-z]{2,}`。TLD は英字 2 文字以上(`pass@10.0.0.1` は対象外)
//   - 後ろに `[A-Za-z0-9-]` が続かないこと(末尾の `(?:[^A-Za-z0-9-]|$)`。終端は範囲に含めない)
//
// 大文字・小文字は、文字クラスの指定で区別しない。
// ドメインの終わり方は、label.EmailDomainEnd(hash 出力形の保護範囲が使う)と一致する。
var emailRe = regexp.MustCompile(`([A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?:[^A-Za-z0-9-]|$)`)

// emailFinder は、メールアドレスの検出器。
//
// URL のユーザー情報の `@`(`<スキーム>://<ユーザー>:<パスワード>@<ホスト>`。urlPasswordStart)は、候補にしない。
//
// ローカルパート全体が、`hash_<hex>` の形、hash の出力形(`<種別>_<hex>`)、現在の書式のラベルのいずれか、
// またはそれらが区切りなしで続いたものであるものは、検出の対象外(仕様 5.2、決定事項 11。連なりは v1.2。Q69)。
// ドメインの末尾は、後ろの `hash_<hex>@` の `hash` に食い込ませない(label.DomainEndBeforeHashed。Q69)。
//
// 前処理(DEVELOPMENT.md 3.4): '@' のない行は、IndexByte 1 回で終わる。'@' のある行は、最初の '@' の
// ローカルパートの先頭から正規表現を当て、一致のたびに、その終端から次の '@' を探す。
// 1 行が長くても、'@' のない区間に正規表現を当てない。
type emailFinder struct {
	hashLen int          // hash_<hex> の 16 進数の桁数
	format  label.Format // 置換済みのラベルの書式(ゼロ値は、ラベルを見ない)
}

func (emailFinder) kind() Kind { return KindEmail }

func (f emailFinder) find(line []byte, dst []Match) []Match {
	return f.scan(line, dst, true)
}

// scan は、line の中のメールアドレスを、左から順に dst に追記する。
// excludeHashed が false のときは、置換済みの形のローカルパートを持つものも含める(テスト用)。
func (f emailFinder) scan(line []byte, dst []Match, excludeHashed bool) []Match {
	pos := 0 // 前の一致の終端。ローカルパートは、これより前に伸ばさない
	for {
		at := bytes.IndexByte(line[pos:], '@')
		if at < 0 {
			return dst
		}
		start := pos + at
		for start > pos && label.IsEmailLocalChar(line[start-1]) {
			start--
		}
		loc := emailRe.FindSubmatchIndex(line[start:])
		if loc == nil {
			return dst
		}
		s, e := start+loc[2], start+loc[3]
		matchAt := s + bytes.IndexByte(line[s:e], '@')
		// ドメインの末尾を、後ろの `hash_<hex>@` の `hash` に食い込ませない(仕様 5.2。Q69)
		if e = label.DomainEndBeforeHashed(line, matchAt+1, e, f.hashLen); e < 0 {
			pos = matchAt + 1
			continue
		}
		if _, ok := urlPasswordStart(line, matchAt); ok {
			// URL のユーザー情報の `@`(`postgres://app:s3cret@db-host/`)は、メールアドレスとして扱わない
			// (v1.2。secret が無効でも同じ。仕様 4.1、Q54)。重なりの解決の規則には、例外を設けない。
			pos = matchAt + 1
			continue
		}
		if !excludeHashed || !f.replacedLocal(line[s:matchAt]) {
			dst = append(dst, Match{Start: s, End: e, Kind: KindEmail})
		}
		pos = e
	}
}

// replacedLocal は、ローカルパート local の全体が、置換済みの形(`hash_<hex>`・`<種別>_<hex>`・現在の書式のラベル)の
// 1 つ、またはそれらが区切りなしで続いたものかを返す(仕様 5.2)。続いたものは、区切りなしで続くメールアドレスの
// 置換の結果(`email_<hex>email_<hex>@d.example.com`)で、1 回目の境目(前の一致の終端)が消えて、全体を 1 つの
// メールアドレスとして再度置換しないため(Q69)。置換済みの形でない部分を含むもの(桁数の違う `hash_<hex>` など)は、
// 本物の値として扱う(Q10)。
func (f emailFinder) replacedLocal(local []byte) bool {
	for p := 0; p < len(local); {
		if e := label.HashedAt(local, p, f.hashLen); e > 0 {
			p = e
			continue
		}
		if e, ok := f.format.MatchAt(local, p); ok {
			p = e
			continue
		}
		return false
	}
	return len(local) > 0
}
