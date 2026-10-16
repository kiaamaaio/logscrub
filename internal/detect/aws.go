package detect

import (
	"regexp"
	"strings"
)

// AWS の値の形の定義(仕様 4.3「ホスト名に埋め込まれた IPv4」、4.4)。
//
// パーティション・ドメイン・エンドポイントなどの形は、表(スライスと正規表現の部品)として持つ。
// 将来のクラウドの追加や、v1.2 の aws_host のホストの表も、同じ形で書き足す(plans/v1.1.0.md 2.2)。

// awsDomains は、対象のドメイン(仕様 4.4)。長いほうから並べる
// (amazonaws.com.cn を、amazonaws.com + `.cn` と読まないため。Q41)。
var awsDomains = []string{"amazonaws.com.cn", "amazonaws.com", "amazonaws.eu"}

// awsRegionRe は、ホスト名の中のリージョン(英小文字・数字・`-` の 1 文字以上。Q40)。
const awsRegionRe = `[a-z0-9-]+`

// awsDomainRe は、awsDomains のどれかに一致する正規表現の部品(並びの順に試す)。
var awsDomainRe = func() string {
	qs := make([]string, len(awsDomains))
	for i, d := range awsDomains {
		qs[i] = regexp.QuoteMeta(d)
	}
	return `(?:` + strings.Join(qs, "|") + `)`
}()

// isHostPrefixChar は、ホスト名の一部になる文字(英数字・`-`・`_`・`.`)。
// 決まった形(`ec2-`、`ip-` など)の前に、この文字があれば、別の名前の一部とみなす。
func isHostPrefixChar(c byte) bool {
	return isASCIIAlnum(c) || c == '-' || c == '_' || c == '.'
}

// isHostEnd は、line[e:] が、ホスト名の末尾の後ろとして読めるかを返す(Q41)。
// 後ろが英数字・`-`・`_` でなく、「`.` + 英数字」でもないこと(行末は可。文末の `.` と、FQDN の末尾の `.` は許す)。
func isHostEnd(line []byte, e int) bool {
	if e >= len(line) {
		return true
	}
	c := line[e]
	if isASCIIAlnum(c) || c == '-' || c == '_' {
		return false
	}
	return !(c == '.' && e+1 < len(line) && isASCIIAlnum(line[e+1]))
}
