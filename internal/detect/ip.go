package detect

import (
	"bytes"
	"net/netip"
	"regexp"
)

// sharedAddressSpace は、共有アドレス空間(RFC 6598)。仕様 4.3 で private に含める。
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// classify は、アドレスの区別を返す(仕様 4.3)。
//
//   - 特殊アドレス(置換しない): 0.0.0.0、255.255.255.255、::、マルチキャスト
//   - private: RFC1918、ループバック、リンクローカル、共有アドレス空間、IPv6 の ULA
//   - global: 上記以外
//
// IPv4-mapped(::ffff:a.b.c.d)は、埋め込まれた IPv4 で判定する(Q8)。
// それ以外の埋め込み(::a.b.c.d、64:ff9b::/96 など)は、IPv6 のアドレスとして判定する。
// ゾーンは、判定に使わない。
func classify(a netip.Addr) Class {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	switch {
	case a.IsUnspecified(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return ClassSpecial
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.Is4() && sharedAddressSpace.Contains(a):
		return ClassPrivate
	}
	return ClassGlobal
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ipv4Re は、IPv4 アドレスの候補。0〜255 の確認と、先頭 0 の除外は、netip.ParseAddr が行う(Q7)。
var ipv4Re = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)

// ipv4Finder は、IPv4 アドレスの検出器(仕様 4.3)。
//
// 次の 2 つの規則の候補をまとめて返す。
//
//   - ドット区切り(dotted): 10.0.0.1 など
//   - ホスト名に埋め込まれた IPv4(hosts): EC2 のホスト名の `ec2-54-250-1-2.…`、`ip-10-0-1-23` など(v1.1)
type ipv4Finder struct{}

func (ipv4Finder) kind() Kind { return KindIPv4 }

func (f ipv4Finder) find(line []byte, dst []Match) []Match {
	dst = f.dotted(line, dst)
	return f.hosts(line, dst)
}

// dotted は、ドット区切りの IPv4 アドレスの候補を追記する。
//
// 前後の文字の条件: 前が数字・ドットでないこと。後ろが数字でなく、「ドット + 数字」でもないこと。
// ポート付き(10.0.0.1:8080)や CIDR(10.0.0.0/8)は、アドレス部分だけが範囲になる。
//
// 前処理(DEVELOPMENT.md 3.4): 候補は、数字に挟まれた '.' が 3 つ連続する箇所にしか現れない。
// そのような箇所(ipv4WindowStart)の手前から、正規表現を当てる。
// ほぼ全ての行にあるタイムスタンプの '.' では、正規表現を当てない。
func (ipv4Finder) dotted(line []byte, dst []Match) []Match {
	pos := 0
	for pos < len(line) {
		from := ipv4WindowStart(line, pos)
		if from < 0 {
			break
		}
		loc := ipv4Re.FindIndex(line[from:])
		if loc == nil {
			break
		}
		s, e := from+loc[0], from+loc[1]
		pos = e
		if s > 0 && (isDigit(line[s-1]) || line[s-1] == '.') {
			continue
		}
		if e < len(line) && (isDigit(line[e]) || line[e] == '.' && e+1 < len(line) && isDigit(line[e+1])) {
			continue
		}
		addr, err := netip.ParseAddr(string(line[s:e]))
		if err != nil {
			continue
		}
		dst = append(dst, Match{Start: s, End: e, Kind: KindIPv4, Class: classify(addr)})
	}
	return dst
}

// hostIPv4Re は、ホスト名の中の、`-` 区切りの 4 つの数値(0〜255 の確認と、先頭 0 の除外は netip.ParseAddr)。
const hostIPv4Re = `([0-9]{1,3}(?:-[0-9]{1,3}){3})`

// hostForm は、IPv4 を埋め込んだホスト名の形の 1 つ(仕様 4.3「ホスト名に埋め込まれた IPv4」)。
type hostForm struct {
	// name は、形の先頭の `-` より前の部分(`ec2`、`ip`)。
	name []byte
	// re は、形の先頭(`ec2-`、`ip-`)の位置に当てる正規表現。1 つ目のグループが、4 つの数値。
	// 数値の後ろの部分(ドメイン)があれば、一致の末尾まで含める。
	re *regexp.Regexp
	// bare は、ドメインのない形(数値で終わる形)を許すか。
	bare bool
}

// hostForms は、IPv4 を埋め込んだホスト名の形(仕様 4.3、Q33、Q40〜Q42)。
//
//   - パブリック DNS: `ec2-a-b-c-d.compute-1.amazonaws.com`(us-east-1)、`ec2-a-b-c-d.<リージョン>.compute.<ドメイン>`
//   - プライベート DNS: `ip-a-b-c-d.ec2.internal`(us-east-1)、`ip-a-b-c-d.<リージョン>.compute.internal`
//   - ドメインのない IP 名: `ip-a-b-c-d`(後ろが、英数字・`-`・`_`・`.` でないこと)
var hostForms = []hostForm{
	{
		name: []byte("ec2"),
		re: regexp.MustCompile(`^ec2-` + hostIPv4Re +
			`\.(?:compute-1\.amazonaws\.com|` + awsRegionRe + `\.compute\.` + awsDomainRe + `)`),
	},
	{
		name: []byte("ip"),
		re:   regexp.MustCompile(`^ip-` + hostIPv4Re + `(?:\.ec2\.internal|\.` + awsRegionRe + `\.compute\.internal)?`),
		bare: true,
	},
}

// hosts は、ホスト名に埋め込まれた IPv4 の候補を追記する(仕様 4.3)。
//
// 範囲は、`-` 区切りの 4 つの数値の部分だけ(`ec2-`・`ip-` とドメインは残す)。値のバイト列は `-` 区切りのまま
// (`54-250-1-2` と `54.250.1.2` は別の値。Q34)。区別は、`.` 区切りに直したアドレスで決める。
//
// 前処理: 形の先頭(`ec2-`、`ip-`)を手がかりにする。`-` を bytes.IndexByte で探し、手前が `ec2` / `ip`、
// 後ろが数字のときだけ、その位置に正規表現を当てる。`ec2-`・`ip-` を bytes.Index で探すと、
// 先頭の文字(`e`、`i`)が文中に多く、速い IndexByte の経路を外れて、約 5 倍遅かったため(段階 3 の測定)。
func (ipv4Finder) hosts(line []byte, dst []Match) []Match {
	n := len(line)
	for pos := 0; pos < n; {
		j := bytes.IndexByte(line[pos:], '-')
		if j < 0 {
			break
		}
		i := pos + j // '-' の位置
		pos = i + 1
		if i+1 >= n || !isDigit(line[i+1]) {
			continue
		}
		for _, h := range hostForms {
			p := i - len(h.name) // 形の先頭
			if p < 0 || !bytes.Equal(line[p:i], h.name) || p > 0 && isHostPrefixChar(line[p-1]) {
				continue
			}
			loc := h.re.FindSubmatchIndex(line[p:])
			if loc == nil {
				break
			}
			s, e, end := p+loc[2], p+loc[3], p+loc[1]
			if end > e {
				if !isHostEnd(line, end) {
					break
				}
			} else if !h.bare || end < n && isHostPrefixChar(line[end]) {
				break
			}
			addr, ok := hostIPv4(line[s:e])
			if !ok {
				break
			}
			dst = append(dst, Match{Start: s, End: e, Kind: KindIPv4, Class: classify(addr)})
			pos = end
			break
		}
	}
	return dst
}

// hostIPv4 は、`-` 区切りの 4 つの数値 b を、`.` 区切りに直して、netip.ParseAddr で確認する。
func hostIPv4(b []byte) (netip.Addr, bool) {
	var buf [15]byte // 255-255-255-255 の長さ
	if len(b) > len(buf) {
		return netip.Addr{}, false
	}
	n := copy(buf[:], b)
	for i := range n {
		if buf[i] == '-' {
			buf[i] = '.'
		}
	}
	addr, err := netip.ParseAddr(string(buf[:n]))
	return addr, err == nil && addr.Is4()
}

// ipv4WindowStart は、line[from:] の中で、IPv4 アドレスの候補が始まりうる最初の位置を返す。
// なければ -1。必要条件だけを見る: 両側が数字の '.' が、前の '.' から 4 バイト以内
// (数字 1〜3 桁と '.')で 3 つ連続する箇所の、最初の '.' の手前(数字は最大 3 桁まで、from まで)。
func ipv4WindowStart(line []byte, from int) int {
	chain, first, last := 0, 0, 0
	for i := from; ; {
		j := bytes.IndexByte(line[i:], '.')
		if j < 0 {
			return -1
		}
		d := i + j
		i = d + 1
		if d == 0 || !isDigit(line[d-1]) || d+1 >= len(line) || !isDigit(line[d+1]) {
			chain = 0
			continue
		}
		if chain > 0 && d-last <= 4 {
			chain++
		} else {
			chain, first = 1, d
		}
		last = d
		if chain == 3 {
			s := first
			for s > from && first-s < 3 && isDigit(line[s-1]) {
				s--
			}
			return s
		}
	}
}

// maxIPv6Len は、ゾーンを除く IPv6 アドレスの最長の表記
// (ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255)の長さ。
const maxIPv6Len = 45

func isIPv6RunChar(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.'
}

// isZoneChar は、ゾーン(%eth0 の eth0)の文字。'.' は、ゾーンの文字の間だけ(下の zoneEnd)。
func isZoneChar(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-'
}

// zoneEnd は、line[i:] から始まるゾーンの末尾の位置を返す。ゾーンがなければ i。
func zoneEnd(line []byte, i int) int {
	j := i
	for j < len(line) {
		switch c := line[j]; {
		case isZoneChar(c):
			j++
		case c == '.' && j > i && j+1 < len(line) && isZoneChar(line[j+1]):
			j++
		default:
			return j
		}
	}
	return j
}

// assignedPrefixes は、IPv6 のうち、検出する範囲(仕様 4.3、決定事項 14)。
// 割り当てのない範囲は、アドレスではないもの(C++ や Rust の記号 `d::`、`::E` など)が
// 偶然一致することが多いので、検出しない。
var assignedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("2000::/3"),     // グローバルユニキャスト
	netip.MustParsePrefix("fc00::/7"),     // ULA
	netip.MustParsePrefix("fe80::/10"),    // リンクローカル
	netip.MustParsePrefix("ff00::/8"),     // マルチキャスト(置換しない特殊アドレス)
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64
}

// assignedIPv6 は、IPv6 アドレス a が、検出する範囲(割り当て済み)にあるかを返す。
// ::1(ループバック)、::(未指定)、IPv4-mapped(::ffff:0:0/96)も含む。
func assignedIPv6(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() || a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	for _, p := range assignedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isLetterOrUnderscore(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// stripColons は、[s,e) の先頭・末尾の単独の ':'(`::` の一部でないもの)を、1 つずつ外す。
// `src:2001:db8::1` の `:` や、`2001:db8::1: refused` の末尾の `:` は、区切りであってアドレスの一部ではない。
// 単独かどうかは、元の行で判断する(範囲の外の隣の ':' も見る)。端のグループを切り離したあとの `::1:`
// (`::1::x` の `x` の手前で切ったもの)の末尾の ':' は、`::` の一部なので外さない(v1.2。仕様 4.3。Q67)。
func stripColons(line []byte, s, e int) (int, int) {
	if e-s >= 2 && line[s] == ':' && line[s+1] != ':' && (s == 0 || line[s-1] != ':') {
		s++
	}
	if e-s >= 2 && line[e-1] == ':' && line[e-2] != ':' && (e == len(line) || line[e] != ':') {
		e--
	}
	return s, e
}

// trimIPv6Run は、16 進数・':'・'.' の連なり line[s:e] を、候補の範囲に整える(仕様 4.3)。
//
//  1. 前後の '.' を外す
//  2. 先頭・末尾の単独の ':' を外す
//  3. 前(後ろ)が英字・'_' なら、その端の 16 進数のグループを、最初(最後)の ':' まで切り離す。
//     端が英字・'_' と接しなくなるまで繰り返す(`tcp6:fe80::1` の `6`、`std::string` の `d`)
func trimIPv6Run(line []byte, s, e int) (int, int) {
	for s < e && line[s] == '.' {
		s++
	}
	for e > s && line[e-1] == '.' {
		e--
	}
	s, e = stripColons(line, s, e)
	for s > 0 && s < e && isLetterOrUnderscore(line[s-1]) {
		k := bytes.IndexByte(line[s:e], ':')
		if k < 0 {
			return e, e
		}
		s += k + 1
		s, e = stripColons(line, s, e)
	}
	for e < len(line) && e > s && isLetterOrUnderscore(line[e]) {
		k := bytes.LastIndexByte(line[s:e], ':')
		if k < 0 {
			return s, s
		}
		e = s + k
		s, e = stripColons(line, s, e)
	}
	return s, e
}

// ipv6Finder は、IPv6 アドレスの検出器(仕様 4.3)。
//
// 16 進数・':'・'.' の連なりを、':' を手がかりに伸ばせるだけ伸ばし、trimIPv6Run で整えて候補とする。
// ':' を 2 つ以上含むものを netip.ParseAddr で確認し、割り当て済みの範囲(assignedIPv6)だけを検出する。
// 直後が '%' + ゾーンなら、ゾーンまで範囲に含める(Q6)。
// ポート付き([::1]:8080)や CIDR(2001:db8::/32)は、アドレス部分だけが範囲になる。
type ipv6Finder struct{}

func (ipv6Finder) kind() Kind { return KindIPv6 }

func (ipv6Finder) find(line []byte, dst []Match) []Match {
	i := bytes.IndexByte(line, ':')
	for i >= 0 {
		s := i
		for s > 0 && isIPv6RunChar(line[s-1]) {
			s--
		}
		e := i + 1
		for e < len(line) && isIPv6RunChar(line[e]) {
			e++
		}
		dst = ipv6Run(line, s, e, dst)
		j := bytes.IndexByte(line[e:], ':')
		if j < 0 {
			break
		}
		i = e + j
	}
	return dst
}

// ipv6Run は、連なり line[s:e] が IPv6 アドレスなら、dst に追記する。
func ipv6Run(line []byte, s, e int, dst []Match) []Match {
	cs, ce := trimIPv6Run(line, s, e)
	cand := line[cs:ce]
	if len(cand) < 2 || len(cand) > maxIPv6Len {
		return dst
	}
	// 形式として成り立つ最低条件(':' が 7 つ、'::' を含む、または IPv4 埋め込みで 6 つ)。
	// 時刻(12:34:56)や MAC アドレスで、ParseAddr を呼ばないための前処理。
	colons := bytes.Count(cand, []byte{':'})
	double := bytes.Contains(cand, []byte("::"))
	if colons < 2 || !double && colons != 7 && !(colons == 6 && bytes.IndexByte(cand, '.') >= 0) {
		return dst
	}
	if ce == e && e < len(line) && line[e] == '%' {
		if z := zoneEnd(line, e+1); z > e+1 {
			if addr, err := netip.ParseAddr(string(line[cs:z])); err == nil {
				if !assignedIPv6(addr) {
					return dst
				}
				return append(dst, Match{Start: cs, End: z, Kind: KindIPv6, Class: classify(addr)})
			}
		}
	}
	addr, err := netip.ParseAddr(string(cand))
	if err != nil || !addr.Is6() || !assignedIPv6(addr) {
		return dst
	}
	return append(dst, Match{Start: cs, End: ce, Kind: KindIPv6, Class: classify(addr)})
}
