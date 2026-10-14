package detect

import (
	"bytes"
	"regexp"
)

// uuidLen は、UUID(8-4-4-4-12 の 16 進数とハイフン)の長さ。
const uuidLen = 36

// uuidRe は、UUID の正規表現(仕様 4.2)。大文字・小文字どちらも可。
// 3 つ目のグループの先頭桁がバージョン(1〜8)、4 つ目のグループの先頭桁がバリアント(8 9 a b)。
// ハイフン無し(32 桁)は対象外。前後が英数字でないことは、呼び出し側で確認する。
var uuidRe = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}`)

// allUUIDVersions は、バージョン 1〜8 のすべて(ビット i がバージョン i)。
const allUUIDVersions uint16 = 0xFF << 1

// uuidFinder は、UUID の検出器(仕様 4.2)。
//
// 範囲は、UUID の 36 バイトだけ。`{...}` で囲まれた形や `urn:uuid:` 付きでも、括弧や接頭辞は含めない
// (Q9。`{<uuid_1>}`、`urn:uuid:<uuid_1>` になる)。これらは `{` `:` が英数字でないので、
// 前後が英数字でないこと(`req-<uuid>` のように、ハイフンの場合は検出する)の条件で、そのまま一致する。
//
// 前処理(DEVELOPMENT.md 3.4): UUID は、4 つのハイフンが、8、13、18、23 バイト目に並ぶ。
// ハイフンを `IndexByte` で探し、その位置を最初のハイフンとして、残りの 3 つが並ぶ位置にだけ、
// 正規表現を当てる。タイムスタンプなどの日付のハイフンでは、正規表現を当てない。
type uuidFinder struct {
	// versions は、検出するバージョン(ビット i がバージョン i)。0 は、1〜8 のすべて。
	versions uint16
}

func (uuidFinder) kind() Kind { return KindUUID }

func (f uuidFinder) find(line []byte, dst []Match) []Match {
	versions := f.versions
	if versions == 0 {
		versions = allUUIDVersions
	}
	n := len(line)
	end := 0 // 前の一致の終端
	for pos := 0; pos < n; {
		j := bytes.IndexByte(line[pos:], '-')
		if j < 0 {
			break
		}
		h := pos + j // 最初のハイフンの位置の候補
		pos = h + 1
		s := h - 8
		if s < end {
			continue
		}
		if s+uuidLen > n {
			break // これ以降のハイフンでも、収まらない
		}
		if line[s+13] != '-' || line[s+18] != '-' || line[s+23] != '-' {
			continue
		}
		if s > 0 && isASCIIAlnum(line[s-1]) {
			continue
		}
		if e := s + uuidLen; e < n && isASCIIAlnum(line[e]) {
			continue
		}
		if !uuidRe.Match(line[s : s+uuidLen]) {
			continue
		}
		if versions&(1<<(line[s+14]-'0')) == 0 {
			continue
		}
		dst = append(dst, Match{Start: s, End: s + uuidLen, Kind: KindUUID})
		end = s + uuidLen
		pos = end
	}
	return dst
}
