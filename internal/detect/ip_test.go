package detect

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var ipKinds = KindSet(0).With(KindIPv4).With(KindIPv6)

// ipLabels は、Detector を通して(特殊アドレスと --ip-scope 外を除いて)検出した結果を、
// 「ラベルの種別名=置換される文字列」の列で返す。
func ipLabels(t *testing.T, line string, scope Scope) []string {
	t.Helper()
	d, err := New(Options{Kinds: ipKinds, IPScope: scope})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := d.Find([]byte(line), nil)
	var out []string
	for _, m := range got {
		out = append(out, m.LabelType()+"="+line[m.Start:m.End])
	}
	return out
}

// ---- 区別(仕様 4.3) ----

func TestClassifyIPv4(t *testing.T) {
	tests := []struct {
		addr string
		want Class
	}{
		// private: RFC1918、ループバック、リンクローカル、共有アドレス空間
		{"10.0.0.0", ClassPrivate}, {"10.255.255.255", ClassPrivate}, {"192.168.0.1", ClassPrivate},
		{"192.168.255.254", ClassPrivate}, {"172.16.0.1", ClassPrivate}, {"172.31.255.254", ClassPrivate},
		{"127.0.0.1", ClassPrivate}, {"127.255.255.254", ClassPrivate}, {"169.254.0.1", ClassPrivate},
		{"169.254.255.254", ClassPrivate}, {"100.64.0.0", ClassPrivate}, {"100.64.0.1", ClassPrivate}, {"100.127.255.255", ClassPrivate},
		// global: 上記以外
		{"203.0.113.5", ClassGlobal}, {"8.8.8.8", ClassGlobal}, {"1.1.1.1", ClassGlobal},
		{"172.15.255.255", ClassGlobal}, {"172.32.0.0", ClassGlobal}, {"100.63.255.255", ClassGlobal},
		{"100.128.0.0", ClassGlobal}, {"11.0.0.1", ClassGlobal}, {"192.169.0.1", ClassGlobal},
		{"169.253.1.1", ClassGlobal}, {"126.255.255.255", ClassGlobal}, {"0.1.2.3", ClassGlobal},
		{"240.0.0.1", ClassGlobal}, {"223.255.255.255", ClassGlobal},
		// 特殊アドレス: 置換しない
		{"0.0.0.0", ClassSpecial}, {"255.255.255.255", ClassSpecial},
		{"224.0.0.0", ClassSpecial}, {"224.0.0.1", ClassSpecial}, {"239.255.255.250", ClassSpecial},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := classify(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("classify(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestClassifyIPv6(t *testing.T) {
	tests := []struct {
		addr string
		want Class
	}{
		{"::1", ClassPrivate}, {"fe80::1", ClassPrivate}, {"fe80::1%eth0", ClassPrivate}, {"febf::1", ClassPrivate},
		{"fc00::1", ClassPrivate}, {"fd00::1", ClassPrivate}, {"fdff:ffff::1", ClassPrivate},
		{"2001:4860:4860::8888", ClassGlobal}, {"2001:db8::1", ClassGlobal}, {"2606:4700::1111", ClassGlobal},
		{"fec0::1", ClassGlobal}, {"fbff::1", ClassGlobal}, {"::2", ClassGlobal},
		{"::", ClassSpecial}, {"ff00::", ClassSpecial}, {"ff02::1", ClassSpecial}, {"ff0e::1234", ClassSpecial},
		// IPv4-mapped は、埋め込まれた IPv4 で区別を判定する(Q8)
		{"::ffff:10.0.0.1", ClassPrivate}, {"::ffff:192.168.0.1", ClassPrivate}, {"::ffff:127.0.0.1", ClassPrivate},
		{"::ffff:203.0.113.5", ClassGlobal}, {"::ffff:8.8.8.8", ClassGlobal},
		{"::ffff:0.0.0.0", ClassSpecial}, {"::ffff:255.255.255.255", ClassSpecial}, {"::ffff:224.0.0.1", ClassSpecial},
		// IPv4-mapped 以外は、埋め込みとして扱わない(Q8)
		{"::10.0.0.1", ClassGlobal}, {"64:ff9b::10.0.0.1", ClassGlobal}, {"2002:a00:1::", ClassGlobal},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := classify(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("classify(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// ---- IPv4 の検出 ----

func TestIPv4Detection(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"private", "10.0.0.1", []string{"ipv4_private=10.0.0.1"}},
		{"global", "203.0.113.5", []string{"ipv4_global=203.0.113.5"}},
		{"in text", "from 192.168.0.1 to 203.0.113.5 ok", []string{"ipv4_private=192.168.0.1", "ipv4_global=203.0.113.5"}},
		// 受け入れ基準: 文末の connected to 10.0.0.1. は検出する
		{"sentence end", "connected to 10.0.0.1.", []string{"ipv4_private=10.0.0.1"}},
		{"followed by dot and letter", "10.0.0.1.a", []string{"ipv4_private=10.0.0.1"}},
		// ポート付き・CIDR は、アドレス部分だけ
		{"with port", "10.0.0.1:8080", []string{"ipv4_private=10.0.0.1"}},
		{"in url", "http://203.0.113.5:8080/path?x=1", []string{"ipv4_global=203.0.113.5"}},
		{"cidr", "10.0.0.0/8", []string{"ipv4_private=10.0.0.0"}},
		{"range", "10.0.0.1-10.0.0.2", []string{"ipv4_private=10.0.0.1", "ipv4_private=10.0.0.2"}},
		{"parentheses", "(10.0.0.1)", []string{"ipv4_private=10.0.0.1"}},
		{"key value", "ip=10.0.0.1,port=80", []string{"ipv4_private=10.0.0.1"}},
		{"json", `{"ip":"203.0.113.5"}`, []string{"ipv4_global=203.0.113.5"}},
		{"japanese around", "接続元10.0.0.1から", []string{"ipv4_private=10.0.0.1"}},
		{"letter before", "a10.0.0.1", []string{"ipv4_private=10.0.0.1"}},
		{"tab separated", "10.0.0.1\t203.0.113.5", []string{"ipv4_private=10.0.0.1", "ipv4_global=203.0.113.5"}},
		{"leading dot", "...10.0.0.1", nil},
		// 仕様の限界: 4 つ組のバージョン番号は、IP アドレスとして検出される
		{"version number", "version 1.2.3.4", []string{"ipv4_global=1.2.3.4"}},

		// 検出しない: 不正な形式
		{"octet over 255", "999.1.1.1", nil},
		{"last octet 256", "1.2.3.256", nil},
		{"three octets", "1.2.3", nil},
		{"two octets", "1.2", nil},
		{"leading zero (Q7)", "192.168.001.001", nil},
		{"leading zero first", "01.2.3.4", nil},
		{"leading zero last", "10.0.0.01", nil},
		{"empty octet", "1..2.3", nil},
		// 検出しない: 前後の文字の条件
		{"five octets", "1.2.3.4.5", nil},
		{"six octets", "10.0.0.1.2.3", nil},
		{"digit before", "110.0.0.1.5", nil},
		{"four digit octet", "1.2.3.4567", nil},
		{"dot before", "x.1.2.3.4", nil},
		{"digit before octet", "1234.5.6.7", nil},
		// 特殊アドレスは置換しない
		{"unspecified", "0.0.0.0", nil},
		{"broadcast", "255.255.255.255", nil},
		{"multicast", "224.0.0.1", nil},
		{"multicast upper", "239.255.255.250", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipLabels(t, tt.line, ScopeAll); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestIPv4FinderReportsSpecialClass(t *testing.T) {
	line := []byte("0.0.0.0 255.255.255.255 224.0.0.1 10.0.0.1 203.0.113.5")
	got := (ipv4Finder{}).find(line, nil)
	want := []Class{ClassSpecial, ClassSpecial, ClassSpecial, ClassPrivate, ClassGlobal}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, m := range got {
		if m.Kind != KindIPv4 || m.Class != want[i] {
			t.Errorf("match %d = %+v, want class %v", i, m, want[i])
		}
	}
}

// ---- ホスト名に埋め込まれた IPv4(仕様 4.3、Q33・Q34・Q40〜Q42) ----

func TestIPv4HostNames(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		// 受け入れ基準(仕様 9 章「AWS」)
		{"public dns", "ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com", []string{"ipv4_global=54-250-1-2"}},
		{"public dns us-east-1", "ec2-54-250-1-2.compute-1.amazonaws.com", []string{"ipv4_global=54-250-1-2"}},
		{"private dns", "ip-10-0-1-23.ap-northeast-1.compute.internal", []string{"ipv4_private=10-0-1-23"}},
		{"private dns us-east-1", "ip-10-0-1-23.ec2.internal", []string{"ipv4_private=10-0-1-23"}},
		{"bare ip name", "ip-10-0-1-23", []string{"ipv4_private=10-0-1-23"}},
		// 中国リージョン・aws-eusc のドメイン、新しい形のリージョン(Q40)
		{"china", "ec2-52-80-1-2.cn-north-1.compute.amazonaws.com.cn", []string{"ipv4_global=52-80-1-2"}},
		{"eusc", "ec2-52-80-1-2.eusc-de-east-1.compute.amazonaws.eu", []string{"ipv4_global=52-80-1-2"}},
		{"gov cloud", "ec2-52-80-1-2.us-gov-west-1.compute.amazonaws.com", []string{"ipv4_global=52-80-1-2"}},
		// 前後の文字
		{"shell prompt", "[ec2-user@ip-10-0-1-23 ~]$ ls", []string{"ipv4_private=10-0-1-23"}},
		{"node name in json", `{"node":"ip-10-0-1-23.ap-northeast-1.compute.internal"}`, []string{"ipv4_private=10-0-1-23"}},
		{"bare in json", `{"node":"ip-10-0-1-23"}`, []string{"ipv4_private=10-0-1-23"}},
		{"bare with port", "ip-10-0-1-23:8080", []string{"ipv4_private=10-0-1-23"}},
		{"bare then slash", "node/ip-10-0-1-23/pods", []string{"ipv4_private=10-0-1-23"}},
		{"in url", "http://ec2-54-250-1-2.compute-1.amazonaws.com:8080/x", []string{"ipv4_global=54-250-1-2"}},
		{"sentence end", "connected to ip-10-0-1-23.ec2.internal.", []string{"ipv4_private=10-0-1-23"}},
		{"fqdn trailing dot", "ec2-54-250-1-2.compute-1.amazonaws.com. 300 IN A", []string{"ipv4_global=54-250-1-2"}},
		{"bare sentence end", "host is ip-10-0-1-23 now", []string{"ipv4_private=10-0-1-23"}},
		{"japanese around", "ノードip-10-0-1-23です", []string{"ipv4_private=10-0-1-23"}},
		{"with dotted address", "ip-10-0-1-23 (10.0.1.23)", []string{"ipv4_private=10-0-1-23", "ipv4_private=10.0.1.23"}},
		{"two hosts", "ip-10-0-1-23 -> ec2-54-250-1-2.compute-1.amazonaws.com",
			[]string{"ipv4_private=10-0-1-23", "ipv4_global=54-250-1-2"}},
		{"shared address space", "ip-100-64-0-1", []string{"ipv4_private=100-64-0-1"}},

		// 置換しない(受け入れ基準)
		{"ship", "ship-10-0-1-23", nil},
		{"octet over 255", "ip-10-0-1-256", nil},
		{"five numbers", "ip-10-0-1-23-4", nil},
		{"ec2 other domain", "ec2-54-250-1-2.example.com", nil},
		// 置換しない: 数値の形
		{"leading zero", "ip-10-0-01-23", nil},
		{"three numbers", "ip-10-0-1", nil},
		{"four digit number", "ip-10-0-1-2345", nil},
		{"empty number", "ip-10--1-23", nil},
		// 置換しない: 前の文字
		{"after letter", "zip-10-0-1-23", nil},
		{"after hyphen", "my-ip-10-0-1-23", nil},
		{"after underscore", "x_ip-10-0-1-23", nil},
		{"after dot", "a.ip-10-0-1-23", nil},
		{"ec2 after letter", "xec2-54-250-1-2.compute-1.amazonaws.com", nil},
		// 置換しない: 後ろの文字・ドメイン(Q41)
		{"bare then letter", "ip-10-0-1-23a", nil},
		{"bare then underscore", "ip-10-0-1-23_x", nil},
		{"bare then other domain", "ip-10-0-1-23.example.com", nil},
		{"bare then dot", "ip-10-0-1-23.", nil},
		{"internal then letter", "ip-10-0-1-23.ec2.internalx", nil},
		{"internal then domain", "ip-10-0-1-23.ec2.internal.example.com", nil},
		{"compute internal without region", "ip-10-0-1-23.compute.internal", nil},
		{"ec2 without domain", "ec2-54-250-1-2", nil},
		{"ec2 without region", "ec2-54-250-1-2.compute.amazonaws.com", nil},
		{"ec2 then other domain", "ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com.example.net", nil},
		{"ec2 then letter", "ec2-54-250-1-2.compute-1.amazonaws.comx", nil},
		{"ec2 then hyphen", "ec2-54-250-1-2.compute-1.amazonaws.com-x", nil},
		{"ec2 cn then letter", "ec2-52-80-1-2.cn-north-1.compute.amazonaws.com.cnx", nil},
		{"ec2 internal domain", "ec2-54-250-1-2.ec2.internal", nil},
		{"ec2 iso domain", "ec2-54-250-1-2.us-iso-east-1.compute.c2s.ic.gov", nil},
		{"region with uppercase", "ec2-54-250-1-2.AP-northeast-1.compute.amazonaws.com", nil},
		// 置換しない: 大文字(Q42)
		{"uppercase ip", "IP-10-0-1-23", nil},
		{"uppercase ec2", "EC2-54-250-1-2.compute-1.amazonaws.com", nil},
		{"uppercase domain", "ip-10-0-1-23.EC2.INTERNAL", nil},
		// 特殊アドレスは置換しない(受け入れ基準)
		{"unspecified", "ec2-0-0-0-0.compute-1.amazonaws.com", nil},
		{"broadcast", "ip-255-255-255-255", nil},
		{"multicast", "ip-224-0-0-1.ec2.internal", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipLabels(t, tt.line, ScopeAll); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// --ip-scope は、通常の IPv4 と同じに扱う(受け入れ基準: ip-10-0-1-23 は --ip-scope global で置換されない)。
func TestIPv4HostNamesWithScope(t *testing.T) {
	line := "ip-10-0-1-23 ec2-54-250-1-2.compute-1.amazonaws.com"
	if got := ipLabels(t, line, ScopeGlobal); !slices.Equal(got, []string{"ipv4_global=54-250-1-2"}) {
		t.Errorf("global: %q", got)
	}
	if got := ipLabels(t, line, ScopePrivate); !slices.Equal(got, []string{"ipv4_private=10-0-1-23"}) {
		t.Errorf("private: %q", got)
	}
}

// 置換済みの形は、再度検出しない。mask のラベルと、hash の出力(`ec2-ipv4_global_<hex>.…`。
// `-` の後ろの hash の出力が保護範囲として見つかること。plans/v1.1.0.md 2.4)。
func TestIPv4HostNamesAlreadyReplaced(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com",
		"ip-<ipv4_private_1>.ec2.internal",
		"[ec2-user@ip-<ipv4_private_1> ~]$",
		"ec2-ipv4_global_a1b2c3d4e5f6.ap-northeast-1.compute.amazonaws.com",
		"ip-ipv4_private_a1b2c3d4e5f6.ec2.internal",
		"ip-ipv4_private_a1b2c3d4e5f6",
	} {
		got, kept := d.Find([]byte(line), nil)
		if len(got) != 0 || kept != 1 {
			t.Errorf("Find(%q) = %+v kept=%d, want nothing and 1 kept", line, got, kept)
		}
	}
}

// 他の種別との重なり: メールアドレスのドメインがホスト名なら、長いメールアドレスが勝つ(仕様 4 章)。
func TestIPv4HostNamesWithOtherKinds(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	line := "ec2-user@ip-10-0-1-23.ec2.internal"
	got, _ := d.Find([]byte(line), nil)
	if len(got) != 1 || got[0].Kind != KindEmail || got[0].Start != 0 || got[0].End != len(line) {
		t.Errorf("Find(%q) = %+v", line, got)
	}
	line = "[ec2-user@ip-10-0-1-23 ~]$"
	got, _ = d.Find([]byte(line), nil)
	if len(got) != 1 || got[0].Kind != KindIPv4 || line[got[0].Start:got[0].End] != "10-0-1-23" {
		t.Errorf("Find(%q) = %+v", line, got)
	}
}

func TestHostIPv4(t *testing.T) {
	for in, want := range map[string]string{"10-0-1-23": "10.0.1.23", "255-255-255-255": "255.255.255.255", "0-0-0-0": "0.0.0.0"} {
		if a, ok := hostIPv4([]byte(in)); !ok || a.String() != want {
			t.Errorf("hostIPv4(%q) = %v, %v", in, a, ok)
		}
	}
	for _, in := range []string{"", "10-0-1", "10-0-01-23", "256-0-0-1", "1-2-3-4-5", "1000-0-0-0-0-0", "a-b-c-d"} {
		if a, ok := hostIPv4([]byte(in)); ok {
			t.Errorf("hostIPv4(%q) = %v, want error", in, a)
		}
	}
}

// ---- IPv6 の検出 ----

func TestIPv6Detection(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		// 受け入れ基準: ::1、fe80::1、fd00::1 は private、2001:4860:4860::8888 は global
		{"loopback", "::1", []string{"ipv6_private=::1"}},
		{"link local", "fe80::1", []string{"ipv6_private=fe80::1"}},
		{"ula", "fd00::1", []string{"ipv6_private=fd00::1"}},
		{"global", "2001:4860:4860::8888", []string{"ipv6_global=2001:4860:4860::8888"}},
		{"documentation", "2001:db8::1", []string{"ipv6_global=2001:db8::1"}},
		{"full form", "2001:0db8:0000:0000:0000:ff00:0042:8329", []string{"ipv6_global=2001:0db8:0000:0000:0000:ff00:0042:8329"}},
		{"uppercase", "2001:DB8::A", []string{"ipv6_global=2001:DB8::A"}},
		{"trailing double colon", "2001:db8::", []string{"ipv6_global=2001:db8::"}},
		{"eight groups", "2001:1:2:3:4:5:6:7", []string{"ipv6_global=2001:1:2:3:4:5:6:7"}},
		{"in text", "from fe80::1 to 2001:db8::2 ok", []string{"ipv6_private=fe80::1", "ipv6_global=2001:db8::2"}},
		// 受け入れ基準: ::ffff:10.0.0.1 は、全体で 1 つの ipv6_private(IPv4 部分だけにならない)
		{"ipv4 mapped private", "::ffff:10.0.0.1", []string{"ipv6_private=::ffff:10.0.0.1"}},
		{"ipv4 mapped global", "::ffff:203.0.113.5", []string{"ipv6_global=::ffff:203.0.113.5"}},
		{"ipv4 mapped in text", "peer ::ffff:192.168.0.1 up", []string{"ipv6_private=::ffff:192.168.0.1"}},
		{"ipv4 mapped sentence end", "peer ::ffff:10.0.0.1.", []string{"ipv6_private=::ffff:10.0.0.1"}},
		// IPv4-compatible は、割り当てのない範囲(::/8)なので IPv6 としては検出しない。IPv4 部分は IPv4 として検出する。
		{"ipv4 compatible is unassigned", "::10.0.0.1", []string{"ipv4_private=10.0.0.1"}},
		{"nat64", "64:ff9b::10.0.0.1", []string{"ipv6_global=64:ff9b::10.0.0.1"}},
		// ゾーンは範囲に含める(Q6)
		{"zone", "fe80::1%eth0", []string{"ipv6_private=fe80::1%eth0"}},
		{"zone in text", "bind fe80::1%eth0 ok", []string{"ipv6_private=fe80::1%eth0"}},
		{"zone numeric", "fe80::1%2", []string{"ipv6_private=fe80::1%2"}},
		{"zone with hyphen and dot", "fe80::1%br-lan.100,", []string{"ipv6_private=fe80::1%br-lan.100"}},
		{"zone then period", "up on fe80::1%eth0.", []string{"ipv6_private=fe80::1%eth0"}},
		{"empty zone", "fe80::1%", []string{"ipv6_private=fe80::1"}},
		{"zone then space", "fe80::1%eth0 and ::1", []string{"ipv6_private=fe80::1%eth0", "ipv6_private=::1"}},
		// ポート付き・CIDR は、アドレス部分だけ
		{"bracket with port", "[::1]:8080", []string{"ipv6_private=::1"}},
		{"bracket global with port", "[2001:db8::1]:443", []string{"ipv6_global=2001:db8::1"}},
		{"in url", "http://[2001:db8::1]/path", []string{"ipv6_global=2001:db8::1"}},
		{"cidr", "2001:db8::/32", []string{"ipv6_global=2001:db8::"}},
		{"cidr host", "2001:db8::1/64", []string{"ipv6_global=2001:db8::1"}},
		{"key value", "ip=fe80::1,port=80", []string{"ipv6_private=fe80::1"}},
		{"japanese around", "接続元::1から", []string{"ipv6_private=::1"}},
		{"sentence end", "connected to 2001:db8::1.", []string{"ipv6_global=2001:db8::1"}},
		{"two in a row", "::1 ::1", []string{"ipv6_private=::1", "ipv6_private=::1"}},
		// 前後の整理(仕様 4.3): 単独の ':' は区切り、英字・'_' と癒着した端のグループは切り離す
		{"label colon", "src:2001:db8::1", []string{"ipv6_global=2001:db8::1"}},
		{"label colon long", "ipv6addr:2001:db8::5", []string{"ipv6_global=2001:db8::5"}},
		{"label with digit", "tcp6:fe80::1", []string{"ipv6_private=fe80::1"}},
		{"label colon loopback", "ip6:::1", []string{"ipv6_private=::1"}},
		{"trailing colon", "from 2001:db8::1: refused", []string{"ipv6_global=2001:db8::1"}},
		{"bracket colon port", "client:[2001:db8::2]:5000", []string{"ipv6_global=2001:db8::2"}},
		{"hex letters after", "addr=2001:db8::1abc", []string{"ipv6_global=2001:db8::1abc"}},
		{"parentheses", "(2001:db8:0:0:0:0:0:1)", []string{"ipv6_global=2001:db8:0:0:0:0:0:1"}},
		{"quoted", `"ip":"2001:db8::1"`, []string{"ipv6_global=2001:db8::1"}},
		{"zone then text", "peer=fe80::a00:27ff:fe4e:66a1%enp0s3 up", []string{"ipv6_private=fe80::a00:27ff:fe4e:66a1%enp0s3"}},

		// 検出しない: 形式として不正
		{"time", "12:34:56", nil},
		{"time with millis", "2026-10-11T03:25:56.789Z", nil},
		{"mac", "aa:bb:cc:dd:ee:ff", nil},
		{"nine groups", "1:2:3:4:5:6:7:8:9", nil},
		{"two double colons", "1::2::3", nil},
		{"triple colon", ":::", nil},
		{"group too long", "12345::1", nil},
		{"single colon", "a:b", nil},
		{"colon only", ":", nil},
		{"key colon value", "key: value", nil},
		// 割り当てのない範囲は検出しない(仕様 4.3、決定事項 14)
		{"unassigned low", "::2", nil},
		{"unassigned one", "1::2", nil},
		{"unassigned 64", "64::1", nil},
		{"unassigned 100", "100::1", nil},
		{"unassigned 4000", "4000::1", nil},
		{"unassigned site local", "fec0::1", nil},
		{"hex words", "dead::beef", nil},
		{"hex words upper", "FACE::CAFE", nil},
		{"unassigned with zone", "1::1%eth0", nil},
		{"hex words with zone", "dead::beef%eth0", nil},
		// 後ろが英字・'_' と癒着したものは、アドレスとして扱わない(仕様 4.3)
		{"glued letters after", "2001:db8::1xyz", nil},
		{"glued underscore after", "fe80::1_suffix", nil},
		// 特殊アドレスは置換しない
		{"unspecified", "::", nil},
		{"multicast", "ff02::1", nil},
		{"multicast all", "ff00::", nil},
		{"mapped unspecified", "::ffff:0.0.0.0", nil},
		{"mapped broadcast", "::ffff:255.255.255.255", nil},
		{"mapped multicast", "::ffff:224.0.0.1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipLabels(t, tt.line, ScopeAll); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// コードの記号(C++ の std::string、Rust の fmt::Error など)や、時刻・MAC アドレスは、
// IPv6 として検出されない(仕様 4.3、受け入れ基準)。
func TestIPv6CodeSymbolsAreNotAddresses(t *testing.T) {
	for _, line := range []string{
		"std::string", "std::bad_alloc", "std::vector<int>", "std::io::Error", "fmt::Error", "anyhow::Error: failed",
		"core::fmt::Debug", "boost::asio::ip", "namespace::add", "Foo::a()", "log::debug!", "PHP Foo::BAR",
		"Ruby: Net::HTTPError", "A::B", "BAD::CAFE", "Face::cafe", "dead::beef()", "feed::Bad", "a::b::c",
		"12:34:56", "aa:bb:cc:dd:ee:ff", "2026-10-11T03:25:56.789Z", "http://example.com:8080/", "key:value",
	} {
		if got := ipLabels(t, line, ScopeAll); len(got) != 0 {
			t.Errorf("Find(%q) = %q, want none", line, got)
		}
	}
}

// 割り当て済みの範囲(仕様 4.3 の表、決定事項 14)。
func TestAssignedIPv6(t *testing.T) {
	assigned := []string{
		"2001:db8::1", "2000::", "3fff:ffff::1", "fc00::1", "fdff::1", "fe80::1", "febf::1", "fe80::1%eth0",
		"ff02::1", "ff00::", "::1", "::", "::ffff:10.0.0.1", "::ffff:0.0.0.0", "64:ff9b::1", "64:ff9b::10.0.0.1",
	}
	for _, s := range assigned {
		if !assignedIPv6(netip.MustParseAddr(s)) {
			t.Errorf("assignedIPv6(%s) = false, want true", s)
		}
	}
	unassigned := []string{
		"::2", "::10.0.0.1", "1::", "d::", "::e", "dead::beef", "100::1", "4000::1", "fbff::1", "fec0::1",
		"64:ff9a::1", "64:ff9c::1", "64:ff9b:1::1", "::1:ffff:0:1", "1fff::1",
	}
	for _, s := range unassigned {
		if assignedIPv6(netip.MustParseAddr(s)) {
			t.Errorf("assignedIPv6(%s) = true, want false", s)
		}
	}
}

func TestIPv6FinderReportsSpecialClass(t *testing.T) {
	line := []byte(":: ff02::1 ::ffff:224.0.0.1 ::1 2001:db8::1")
	got := (ipv6Finder{}).find(line, nil)
	want := []Class{ClassSpecial, ClassSpecial, ClassSpecial, ClassPrivate, ClassGlobal}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, m := range got {
		if m.Kind != KindIPv6 || m.Class != want[i] {
			t.Errorf("match %d = %+v, want class %v", i, m, want[i])
		}
	}
}

// ---- 範囲の重なりと他の種別との組み合わせ ----

// 受け入れ基準: ::ffff:10.0.0.1 は、IPv4 部分だけでなく、全体で 1 つの <ipv6_private_1> になる。
func TestIPv4MappedIsOneIPv6Match(t *testing.T) {
	d, err := New(Options{Kinds: ipKinds})
	if err != nil {
		t.Fatal(err)
	}
	line := "::ffff:10.0.0.1"
	got, _ := d.Find([]byte(line), nil)
	want := []Match{{Start: 0, End: 15, Kind: KindIPv6, Class: ClassPrivate}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// 受け入れ基準: https://user:pass@10.0.0.1/ が https://user:<secret_1>@<ipv4_private_1>/ になる(v1.2 で変更。
// v1.1 まではパスワードがそのまま残っていた)。pass@10.0.0.1 はメールアドレスとして扱わない。
func TestUserinfoWithIPv4(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	line := "https://user:pass@10.0.0.1/"
	got, _ := d.Find([]byte(line), nil)
	want := []Match{{Start: 13, End: 17, Kind: KindSecret}, {Start: 18, End: 26, Kind: KindIPv4, Class: ClassPrivate}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestIPv4AloneWhenIPv6IsDisabled(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindIPv4)})
	if err != nil {
		t.Fatal(err)
	}
	line := "::ffff:10.0.0.1 and fe80::1"
	got, _ := d.Find([]byte(line), nil)
	want := []Match{{Start: 7, End: 15, Kind: KindIPv4, Class: ClassPrivate}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestIPv6AloneWhenIPv4IsDisabled(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindIPv6)})
	if err != nil {
		t.Fatal(err)
	}
	line := "10.0.0.1 and fe80::1"
	got, _ := d.Find([]byte(line), nil)
	want := []Match{{Start: 13, End: 20, Kind: KindIPv6, Class: ClassPrivate}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// ---- --ip-scope(受け入れ基準) ----

func TestIPScopeEndToEnd(t *testing.T) {
	line := "10.0.0.1 203.0.113.5 fe80::1 2001:db8::1 ::ffff:192.168.0.1 ::ffff:8.8.8.8"
	tests := []struct {
		scope Scope
		want  []string
	}{
		{ScopeAll, []string{
			"ipv4_private=10.0.0.1", "ipv4_global=203.0.113.5", "ipv6_private=fe80::1", "ipv6_global=2001:db8::1",
			"ipv6_private=::ffff:192.168.0.1", "ipv6_global=::ffff:8.8.8.8",
		}},
		{ScopeGlobal, []string{"ipv4_global=203.0.113.5", "ipv6_global=2001:db8::1", "ipv6_global=::ffff:8.8.8.8"}},
		{ScopePrivate, []string{"ipv4_private=10.0.0.1", "ipv6_private=fe80::1", "ipv6_private=::ffff:192.168.0.1"}},
	}
	for _, tt := range tests {
		if got := ipLabels(t, line, tt.scope); !slices.Equal(got, tt.want) {
			t.Errorf("scope %d:\n got  %q\n want %q", tt.scope, got, tt.want)
		}
	}
}

// ---- 前処理と長い行 ----

func TestIPFindersIgnoreLinesWithoutClues(t *testing.T) {
	for _, line := range []string{"", "plain text only", "no dots or colons here 12345", "abc def"} {
		if got := (ipv4Finder{}).find([]byte(line), nil); len(got) != 0 {
			t.Errorf("ipv4 %q: %+v", line, got)
		}
		if got := (ipv6Finder{}).find([]byte(line), nil); len(got) != 0 {
			t.Errorf("ipv6 %q: %+v", line, got)
		}
	}
}

func TestIPFindersOnLongLines(t *testing.T) {
	// 数字とドットだけ、16 進数とコロンだけの長い連なり
	long4 := strings.Repeat("1.", 100000)
	long6 := strings.Repeat("a:", 100000)
	for _, line := range []string{long4, long6, long4 + "10.0.0.1", long6 + " fe80::1"} {
		_ = (ipv4Finder{}).find([]byte(line), nil)
		_ = (ipv6Finder{}).find([]byte(line), nil)
	}
	// ホスト名の先頭だけが並ぶ行、ホスト名が多数並ぶ行
	for _, line := range []string{strings.Repeat("ip-", 300000), strings.Repeat("ec2-1-2-3-4.", 100000), strings.Repeat(" ip-1-1-1-1.a", 100000)} {
		_ = (ipv4Finder{}).find([]byte(line), nil)
	}
	if got := (ipv4Finder{}).find([]byte(strings.Repeat("ip-10-0-1-23 ", 50000)), nil); len(got) != 50000 {
		t.Errorf("many host names: got %d matches, want 50000", len(got))
	}
	// 多数のアドレス
	var many []byte
	for i := 0; i < 20000; i++ {
		many = append(many, "10.0.0.1 fe80::1 "...)
	}
	d, err := New(Options{Kinds: ipKinds})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := d.Find(many, nil)
	if len(got) != 40000 {
		t.Errorf("got %d matches, want 40000", len(got))
	}
}

// ---- ベンチマーク ----

func BenchmarkIPv4Finder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (ipv4Finder{}).find(line, dst[:0])
		}
	}
}

func BenchmarkIPv6Finder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (ipv6Finder{}).find(line, dst[:0])
		}
	}
}

// ---- 前処理・別実装との一致(Q2) ----

// refIPv4 は、前処理(ipv4WindowStart)を使わず、正規表現を行全体に当てる IPv4 検出器。
// 前処理は、候補になりえない区間を飛ばすだけで、結果を変えてはならない。
func refIPv4(line []byte) []Match {
	var out []Match
	pos := 0
	for pos < len(line) {
		loc := ipv4Re.FindIndex(line[pos:])
		if loc == nil {
			break
		}
		s, e := pos+loc[0], pos+loc[1]
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
		out = append(out, Match{Start: s, End: e, Kind: KindIPv4, Class: classify(addr)})
	}
	return out
}

func TestIPv4FinderMatchesUnfilteredRegexp(t *testing.T) {
	alphabet := []string{
		"1", "2", "9", "0", "01", "25", "255", "256", "999", "1234", ".", ".", ".", "..", " ", ":", "/", "a", "-",
		"10.0.0.1", "192.168.0.1", "1.2.3.4", "0.0.0.0", "1.2.3", "v", "あ", "\xff",
	}
	rng := rand.New(rand.NewPCG(11, 12))
	for iter := 0; iter < 40000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(16); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		want := refIPv4(line)
		got := (ipv4Finder{}).dotted(line, nil)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %+v\n want %+v", iter, line, got, want)
		}
	}
}

// ホスト名に埋め込まれた IPv4 の参照実装(仕様 4.3、Q40〜Q42)。前処理(bytes.Index)を使わず、
// 行のすべての位置で、形ごとに別の正規表現を試す。ドメインの選択肢も 1 つずつ試す
// (実装の、ドメインを長いほうから 1 つに決める方法と、結果が変わらないことの確認)。
var (
	refHostNums  = `([0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3})`
	refHostForms = []struct {
		re   *regexp.Regexp
		bare bool
	}{
		{re: regexp.MustCompile(`^ec2-` + refHostNums + `\.compute-1\.amazonaws\.com`)},
		{re: regexp.MustCompile(`^ec2-` + refHostNums + `\.[a-z0-9-]+\.compute\.amazonaws\.com`)},
		{re: regexp.MustCompile(`^ec2-` + refHostNums + `\.[a-z0-9-]+\.compute\.amazonaws\.com\.cn`)},
		{re: regexp.MustCompile(`^ec2-` + refHostNums + `\.[a-z0-9-]+\.compute\.amazonaws\.eu`)},
		{re: regexp.MustCompile(`^ip-` + refHostNums + `\.ec2\.internal`)},
		{re: regexp.MustCompile(`^ip-` + refHostNums + `\.[a-z0-9-]+\.compute\.internal`)},
		{re: regexp.MustCompile(`^ip-` + refHostNums), bare: true},
	}
	refHostBefore  = regexp.MustCompile(`[A-Za-z0-9_.-]$`)
	refHostEnd     = regexp.MustCompile(`^(?:$|[^A-Za-z0-9_.-]|\.(?:$|[^A-Za-z0-9]))`)
	refHostBareEnd = regexp.MustCompile(`^(?:$|[^A-Za-z0-9_.-])`)
)

func refHostIPv4(line []byte) []Match {
	var out []Match
	for p := 0; p < len(line); p++ {
		if p > 0 && refHostBefore.Match(line[p-1:p]) {
			continue
		}
		for _, f := range refHostForms {
			loc := f.re.FindSubmatchIndex(line[p:])
			if loc == nil {
				continue
			}
			end := p + loc[1]
			if f.bare && !refHostBareEnd.Match(line[end:]) || !f.bare && !refHostEnd.Match(line[end:]) {
				continue
			}
			s, e := p+loc[2], p+loc[3]
			addr, err := netip.ParseAddr(strings.ReplaceAll(string(line[s:e]), "-", "."))
			if err != nil {
				continue
			}
			out = append(out, Match{Start: s, End: e, Kind: KindIPv4, Class: classify(addr)})
			break
		}
	}
	return out
}

// 乱数で作った行で、ホスト名の検出が、参照実装と一致すること。
// 行は「前の文字 + 先頭(ec2- / ip- など)+ 数値(の変形)+ ドメイン(の変形)+ 後ろの文字」の組を並べて作る。
func TestIPv4HostNamesMatchRegexpReference(t *testing.T) {
	around := []string{"", "", " ", "@", "[", "/", ":", "\"", ".", "-", "_", "s", "x", "0", "あ", "\xff"}
	prefixes := []string{"ec2-", "ip-", "ip-", "EC2-", "IP-", "ship-", "ec2-ip-", ""}
	nums := []string{"54-250-1-2", "10-0-1-23", "10-0-1-23", "0-0-0-0", "224-0-0-1", "10-0-1-256", "10-0-01-23",
		"10-0-1-23-4", "1-2-3", "255-255-255-255", "10-0-1-2345", "10.0.1.23"}
	suffixes := []string{"", "", ".ec2.internal", ".ap-northeast-1.compute.internal", ".compute-1.amazonaws.com",
		".ap-northeast-1.compute.amazonaws.com", ".cn-north-1.compute.amazonaws.com.cn", ".eusc-de-east-1.compute.amazonaws.eu",
		".example.com", ".compute.internal", ".EC2.INTERNAL", ".ap-northeast-1.compute.amazonaws.com.example.net",
		".ec2.internalx", ".", ".compute.amazonaws.com", "..compute.internal", ".a.compute.amazonaws.com.", ".compute-1.amazonaws.comx"}
	rng := rand.New(rand.NewPCG(41, 42))
	found := 0
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			sb.WriteString(around[rng.IntN(len(around))])
			sb.WriteString(prefixes[rng.IntN(len(prefixes))])
			sb.WriteString(nums[rng.IntN(len(nums))])
			sb.WriteString(suffixes[rng.IntN(len(suffixes))])
			sb.WriteString(around[rng.IntN(len(around))])
		}
		line := []byte(sb.String())
		want := refHostIPv4(line)
		got := (ipv4Finder{}).hosts(line, nil)
		slices.SortFunc(got, func(a, b Match) int { return a.Start - b.Start })
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %+v\n want %+v", iter, line, got, want)
		}
		found += len(got)
	}
	if found < 1500 {
		t.Errorf("only %d host names were found; the generator does not exercise the rules", found)
	}
}

// refIPv6 は、IPv6 検出器の別実装。16 進数・':'・'.' の連なりを正規表現で拾い、
// 前処理(':' の数、長さ)を使わずに、netip.ParseAddr で確認する。
// 整理の規則(仕様 4.3)と、割り当て済みの範囲(決定事項 14)は、プレフィックスの一覧で書く。
var (
	refIPv6Run  = regexp.MustCompile(`[0-9A-Fa-f:.]+`)
	refIPv6Zone = regexp.MustCompile(`^%[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*`)
	refAssigned = []netip.Prefix{
		netip.MustParsePrefix("2000::/3"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::ffff:0:0/96"), netip.MustParsePrefix("64:ff9b::/96"),
	}
)

func refLetterOrUnderscore(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// refStrip は、[s,e) の先頭・末尾の単独の ':'(「::」の一部でないもの)を 1 つずつ外す。
func refStrip(line []byte, s, e int) (int, int) {
	if e-s >= 2 && line[s] == ':' && line[s+1] != ':' {
		s++
	}
	if e-s >= 2 && line[e-1] == ':' && line[e-2] != ':' {
		e--
	}
	return s, e
}

func refIPv6(line []byte) []Match {
	var out []Match
	for _, loc := range refIPv6Run.FindAllIndex(line, -1) {
		s, e := loc[0], loc[1]
		for s < e && line[s] == '.' {
			s++
		}
		for e > s && line[e-1] == '.' {
			e--
		}
		s, e = refStrip(line, s, e)
		for s > 0 && s < e && refLetterOrUnderscore(line[s-1]) {
			k := bytes.IndexByte(line[s:e], ':')
			if k < 0 {
				s = e
				break
			}
			s += k + 1
			s, e = refStrip(line, s, e)
		}
		for e < len(line) && e > s && refLetterOrUnderscore(line[e]) {
			k := bytes.LastIndexByte(line[s:e], ':')
			if k < 0 {
				e = s
				break
			}
			e = s + k
			s, e = refStrip(line, s, e)
		}
		if bytes.Count(line[s:e], []byte(":")) < 2 {
			continue
		}
		end := e
		if e == loc[1] {
			if z := refIPv6Zone.FindIndex(line[e:]); z != nil {
				if addr, err := netip.ParseAddr(string(line[s : e+z[1]])); err == nil && addr.Is6() {
					end = e + z[1]
				}
			}
		}
		addr, err := netip.ParseAddr(string(line[s:end]))
		if err != nil || !addr.Is6() {
			continue
		}
		plain := addr.WithZone("")
		ok := false
		for _, p := range refAssigned {
			if p.Contains(plain) {
				ok = true
			}
		}
		if !ok && !plain.Is4In6() {
			continue
		}
		out = append(out, Match{Start: s, End: end, Kind: KindIPv6, Class: classify(addr)})
	}
	return out
}

func TestIPv6FinderMatchesRegexpReference(t *testing.T) {
	alphabet := []string{
		":", ":", "::", ":::", "1", "a", "F", "0", "ffff", "db8", "2001", "fe80", "fd00", "12345", "g", "x", "_", ".", "..",
		"%", "%eth0", "%1", "%", "10.0.0.1", "1.2.3.4", "::1", "::ffff:", "ffff:", " ", "/", "[", "]", "-", "あ", "\xff",
		"std", "Error", "src", "tcp6", "ip6",
	}
	rng := rand.New(rand.NewPCG(13, 14))
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(14); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		want := refIPv6(line)
		got := (ipv6Finder{}).find(line, nil)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %+v\n want %+v", iter, line, got, want)
		}
	}
}

// 実装(前処理つき)と、前処理なしの正規表現の速度。plans/v1.0.0.md の Q2 の記録用。
func BenchmarkIPv4Unfiltered(b *testing.B) {
	lines, size := benchCorpus(b)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			_ = refIPv4(line)
		}
	}
}

// ipv4WindowStart は、候補になりえない区間を飛ばす(必要条件だけを見る)。
func TestIPv4WindowStart(t *testing.T) {
	tests := []struct {
		line string
		from int
		want int
	}{
		{"", 0, -1},
		{"no dots", 0, -1},
		{"2026-10-11T03:25:56.789Z", 0, -1},
		{"took=12.5ms 3.4", 0, -1},
		{"1.2.3", 0, -1},
		{"1.2.3.4", 0, 0},
		{"ip 10.0.0.1 ok", 0, 3},
		{"ip 10.0.0.1 ok", 4, 4}, // from より前には戻らない
		{"x 12345.6.7.8", 0, 4},  // 先頭の数字は、最大 3 桁まで戻る
		{"a.b.1.2.3.4", 0, 4},
		{"1.2..3.4.5", 0, -1},
		{"1.2.x3.4.5", 0, -1},
	}
	for _, tt := range tests {
		if got := ipv4WindowStart([]byte(tt.line), tt.from); got != tt.want {
			t.Errorf("ipv4WindowStart(%q, %d) = %d, want %d", tt.line, tt.from, got, tt.want)
		}
	}
}
