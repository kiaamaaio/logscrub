// Package detect は、行の中から置換対象(メールアドレス、IP アドレス、トークン類、UUID)を見つける。
//
// 種別ごとの検出器が候補を出し、Detector が、除外と範囲の重なりの解決を行って、
// 置換する範囲を決める(PLAN 4.1、4.2)。
package detect

import (
	"fmt"
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
)

var kindNames = [...]string{
	KindEmail:  "email",
	KindIPv4:   "ipv4",
	KindIPv6:   "ipv6",
	KindSecret: "secret",
	KindUUID:   "uuid",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// kindPriority は、範囲の長さが同じときの優先順位(小さいほうが優先)。
// 仕様: email → ipv4 / ipv6 → secret → uuid。
var kindPriority = [...]int{
	KindEmail:  1,
	KindIPv4:   2,
	KindIPv6:   2,
	KindSecret: 3,
	KindUUID:   4,
}

// KindSet は、Kind の集合。
type KindSet uint8

// With は、k を加えた集合を返す。
func (s KindSet) With(k Kind) KindSet { return s | 1<<k }

// Has は、k が集合に含まれるかを返す。
func (s KindSet) Has(k Kind) bool { return s&(1<<k) != 0 }

// DefaultKinds は、`--types` を省略したときの対象(既定で有効の種別)。uuid は含まない。
var DefaultKinds = KindSet(0).With(KindEmail).With(KindIPv4).With(KindIPv6).With(KindSecret)

// ParseTypes は、`--types` の値(カンマ区切り)を解析する。
//
// 指定できる名前は default、email、ipv4、ipv6、secret、uuid だけで、完全一致で照合する。
// それ以外(大文字、前後の空白、空の要素を含む)は、存在しない種別名としてエラーにする。
func ParseTypes(spec string) (KindSet, error) {
	var set KindSet
	for _, name := range strings.Split(spec, ",") {
		switch name {
		case "default":
			set |= DefaultKinds
		case "email":
			set = set.With(KindEmail)
		case "ipv4":
			set = set.With(KindIPv4)
		case "ipv6":
			set = set.With(KindIPv6)
		case "secret":
			set = set.With(KindSecret)
		case "uuid":
			set = set.With(KindUUID)
		default:
			return 0, fmt.Errorf("unknown type %q (valid: default, email, ipv4, ipv6, secret, uuid)", name)
		}
	}
	return set, nil
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
