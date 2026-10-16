// Package detect は、行の中から置換対象(メールアドレス、IP アドレス、トークン類、UUID、クラウド固有の値)を見つける。
//
// 種別ごとの検出器が候補を出し、Detector が、除外と範囲の重なりの解決を行って、
// 置換する範囲を決める(DEVELOPMENT.md 3.1、3.2)。
package detect

import (
	"fmt"
	"slices"
	"strings"
)

// Kind は、検出する種別。IP アドレスのグローバル/プライベートの区別は Class で持つ。
type Kind uint8

const (
	// KindEmail などの並びは、範囲の長さが同じときの優先順位の目安(仕様 4 章)。
	// 実際の優先順位は kindPriority による(ipv4 と ipv6 は同順位)。
	KindEmail Kind = iota + 1
	KindIPv4
	KindIPv6
	KindSecret
	KindUUID
	KindAWSAccount
	KindAWSS3Bucket
)

var kindNames = [...]string{
	KindEmail:       "email",
	KindIPv4:        "ipv4",
	KindIPv6:        "ipv6",
	KindSecret:      "secret",
	KindUUID:        "uuid",
	KindAWSAccount:  "aws_account",
	KindAWSS3Bucket: "aws_s3_bucket",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// kindPriority は、範囲の長さが同じときの優先順位(小さいほうが優先)。
// 仕様: email → ipv4 / ipv6 → secret → uuid → aws_account → aws_s3_bucket。
var kindPriority = [...]int{
	KindEmail:       1,
	KindIPv4:        2,
	KindIPv6:        2,
	KindSecret:      3,
	KindUUID:        4,
	KindAWSAccount:  5,
	KindAWSS3Bucket: 6,
}

// KindSet は、Kind の集合。ビット k が Kind k。
type KindSet uint32

// With は、k を加えた集合を返す。
func (s KindSet) With(k Kind) KindSet { return s | 1<<k }

// Has は、k が集合に含まれるかを返す。
func (s KindSet) Has(k Kind) bool { return s&(1<<k) != 0 }

// TypeInfo は、`--types` に書ける種別 1 つの情報(仕様 4 章の種別の表)。
type TypeInfo struct {
	Kind Kind
	// Default は、既定で有効か(`--types` を省略したときの対象か)。
	Default bool
	// Cloud は、クラウド固有の種別のクラウド名(種別名の `<クラウド>_` の部分)。共通の種別では空。
	Cloud string
}

// Name は、種別名(`--types` に書く名前)を返す。
func (t TypeInfo) Name() string { return t.Kind.String() }

// Types は、`--types` に書ける種別の一覧。並びは、`logscrub types` とエラーメッセージの順
// (共通の種別のあとに、クラウドごとにまとめる。仕様 6 章)。
var Types = []TypeInfo{
	{Kind: KindEmail, Default: true},
	{Kind: KindIPv4, Default: true},
	{Kind: KindIPv6, Default: true},
	{Kind: KindSecret, Default: true},
	{Kind: KindUUID},
	{Kind: KindAWSAccount, Cloud: "aws"},
	{Kind: KindAWSS3Bucket, Cloud: "aws"},
}

// DefaultKinds は、`--types` を省略したときの対象(既定で有効の種別)。uuid と aws_* は含まない。
var DefaultKinds = func() KindSet {
	var s KindSet
	for _, t := range Types {
		if t.Default {
			s = s.With(t.Kind)
		}
	}
	return s
}()

// Group は、`--types` に種別名と同じ場所に書ける、種別のまとまり(仕様 4 章「対象種別の指定」)。
type Group struct {
	Name  string
	Kinds KindSet
}

// Groups は、種別のまとまり。中身は Types から求める(種別を足したとき、ここを書き換えなくて済むように)。
//   - default: 既定で有効の種別
//   - クラウド名(aws など): そのクラウドの種別(`<クラウド>_` で始まる種別)
//   - cloud: すべてのクラウドの種別
var Groups = func() []Group {
	gs := []Group{{Name: "default", Kinds: DefaultKinds}}
	var all KindSet
	for _, t := range Types {
		if t.Cloud == "" {
			continue
		}
		all = all.With(t.Kind)
		i := slices.IndexFunc(gs, func(g Group) bool { return g.Name == t.Cloud })
		if i < 0 {
			gs = append(gs, Group{Name: t.Cloud})
			i = len(gs) - 1
		}
		gs[i].Kinds = gs[i].Kinds.With(t.Kind)
	}
	return append(gs, Group{Name: "cloud", Kinds: all})
}()

// validTypeNames は、ParseTypes のエラーメッセージに出す、指定できる名前の一覧(まとまり、種別の順)。
var validTypeNames = func() string {
	var names []string
	for _, g := range Groups {
		names = append(names, g.Name)
	}
	for _, t := range Types {
		names = append(names, t.Name())
	}
	return strings.Join(names, ", ")
}()

// ParseTypes は、`--types` の値(カンマ区切り)を解析する。
//
// 指定できる名前は、Groups のまとまりと、Types の種別名だけで、完全一致で照合する。
// それ以外(大文字、前後の空白、空の要素を含む)は、存在しない種別名としてエラーにする。
func ParseTypes(spec string) (KindSet, error) {
	var set KindSet
	for _, name := range strings.Split(spec, ",") {
		if s, ok := lookupType(name); ok {
			set |= s
			continue
		}
		return 0, fmt.Errorf("unknown type %q (valid: %s)", name, validTypeNames)
	}
	return set, nil
}

// lookupType は、まとまりまたは種別の名前 name が表す集合を返す。
func lookupType(name string) (KindSet, bool) {
	for _, g := range Groups {
		if g.Name == name {
			return g.Kinds, true
		}
	}
	for _, t := range Types {
		if t.Name() == name {
			return KindSet(0).With(t.Kind), true
		}
	}
	return 0, false
}

// Class は、IP アドレスの区別(仕様 4.3)。IP アドレス以外の種別では ClassNone。
type Class uint8

const (
	ClassNone Class = iota
	ClassGlobal
	ClassPrivate
	// ClassSpecial は、置換しない特殊アドレス(0.0.0.0、255.255.255.255、::、マルチキャスト)。
	ClassSpecial
)

// Scope は、`--ip-scope` の値。置換する IP アドレスの範囲。
type Scope uint8

const (
	ScopeAll Scope = iota
	ScopeGlobal
	ScopePrivate
)

// includes は、区別 c の IP アドレスが、範囲 s で置換の対象になるかを返す。
func (s Scope) includes(c Class) bool {
	switch s {
	case ScopeGlobal:
		return c != ClassPrivate
	case ScopePrivate:
		return c != ClassGlobal
	}
	return true
}

// Match は、置換する範囲。
type Match struct {
	Start, End int // 行内のバイト位置。[Start, End)
	Kind       Kind
	Class      Class // IP アドレスのときだけ使う
}

// LabelType は、置換後のラベルの種別名(label.Types のいずれか)を返す。
// 置換しないもの(特殊アドレス、区別のない IP アドレス)では空文字列を返す。
func (m Match) LabelType() string {
	switch m.Kind {
	case KindEmail:
		return "email"
	case KindSecret:
		return "secret"
	case KindUUID:
		return "uuid"
	case KindAWSAccount:
		return "aws_account"
	case KindAWSS3Bucket:
		return "aws_s3_bucket"
	case KindIPv4:
		switch m.Class {
		case ClassGlobal:
			return "ipv4_global"
		case ClassPrivate:
			return "ipv4_private"
		}
	case KindIPv6:
		switch m.Class {
		case ClassGlobal:
			return "ipv6_global"
		case ClassPrivate:
			return "ipv6_private"
		}
	}
	return ""
}

// ParseUUIDVersions は、`--uuid-versions` の値(カンマ区切りの 1〜8)を、ビット i がバージョン i の集合にする(仕様 4.2)。
// 1〜8 以外、空の要素、空白、数字以外は、エラー。
func ParseUUIDVersions(spec string) (uint16, error) {
	var set uint16
	for _, v := range strings.Split(spec, ",") {
		if len(v) != 1 || v[0] < '1' || v[0] > '8' {
			return 0, fmt.Errorf("invalid uuid version %q (valid: 1 to 8, comma separated)", v)
		}
		set |= 1 << (v[0] - '0')
	}
	return set, nil
}

// ParseScope は、`--ip-scope` の値(all、global、private)を解析する(仕様 4.3)。
func ParseScope(s string) (Scope, error) {
	switch s {
	case "all":
		return ScopeAll, nil
	case "global":
		return ScopeGlobal, nil
	case "private":
		return ScopePrivate, nil
	}
	return 0, fmt.Errorf("invalid ip scope %q (valid: all, global, private)", s)
}
