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
		{"eight groups", "1:2:3:4:5:6:7:8", []string{"ipv6_global=1:2:3:4:5:6:7:8"}},
		{"in text", "from fe80::1 to 2001:db8::2 ok", []string{"ipv6_private=fe80::1", "ipv6_global=2001:db8::2"}},
		// 受け入れ基準: ::ffff:10.0.0.1 は、全体で 1 つの ipv6_private(IPv4 部分だけにならない)
		{"ipv4 mapped private", "::ffff:10.0.0.1", []string{"ipv6_private=::ffff:10.0.0.1"}},
		{"ipv4 mapped global", "::ffff:203.0.113.5", []string{"ipv6_global=::ffff:203.0.113.5"}},
		{"ipv4 mapped in text", "peer ::ffff:192.168.0.1 up", []string{"ipv6_private=::ffff:192.168.0.1"}},
		{"ipv4 mapped sentence end", "peer ::ffff:10.0.0.1.", []string{"ipv6_private=::ffff:10.0.0.1"}},
		{"ipv4 embedded not mapped", "::10.0.0.1", []string{"ipv6_global=::10.0.0.1"}},
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

// 仕様の前後の文字の条件(IPv6: 前後が 16 進数・コロンでないこと)を、そのまま適用した結果。
// 次の動作は、仕様どおりだが、見落としや誤検出につながる。仕様の見直しがあれば、ここを直す。
func TestIPv6SpecLiteralBehaviors(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
		why  string
	}{
		// 16 進数の文字が、前後に続くと、それも候補の一部になる(前が 16 進数でないことを満たすため)。
		{"c++ std::string", "std::string", []string{"ipv6_global=d::"}, "'d' は 16 進数なので、`d::` が IPv6 になる"},
		{"c++ std::bad_alloc", "std::bad_alloc", []string{"ipv6_global=d::bad"}, "'d' と 'bad' が 16 進数"},
		{"rust fmt::Error", "fmt::Error", []string{"ipv6_global=::E"}, "'r' は 16 進数でなく、`::E` が IPv6 になる"},
		// 後ろがコロンのときは、候補に含まれ、形式として不正になる。
		{"trailing colon", "from 2001:db8::1: refused", nil, "後ろがコロンなので、アドレスとして検出されない"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipLabels(t, tt.line, ScopeAll); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q (%s)", tt.line, got, tt.want, tt.why)
			}
		})
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

// 受け入れ基準: https://user:pass@10.0.0.1/ が https://user:pass@<ipv4_private_1>/ になる。
// pass@10.0.0.1 はメールアドレスとして扱わない。
func TestUserinfoWithIPv4(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	line := "https://user:pass@10.0.0.1/"
	got, _ := d.Find([]byte(line), nil)
	want := []Match{{Start: 18, End: 26, Kind: KindIPv4, Class: ClassPrivate}}
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
		got := (ipv4Finder{}).find(line, nil)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %+v\n want %+v", iter, line, got, want)
		}
	}
}

// refIPv6 は、IPv6 検出器の別実装。16 進数・':'・'.' の連なりを正規表現で拾い、
// 前処理(':' の数、長さ)を使わずに、netip.ParseAddr で確認する。
var (
	refIPv6Run  = regexp.MustCompile(`[0-9A-Fa-f:.]+`)
	refIPv6Zone = regexp.MustCompile(`^%[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*`)
)

func refIPv6(line []byte) []Match {
	var out []Match
	for _, loc := range refIPv6Run.FindAllIndex(line, -1) {
		s, e := loc[0], loc[1]
		trimmedEnd := false
		for s < e && line[s] == '.' {
			s++
		}
		for e > s && line[e-1] == '.' {
			e--
			trimmedEnd = true
		}
		if bytes.Count(line[s:e], []byte(":")) < 2 {
			continue
		}
		if !trimmedEnd {
			if z := refIPv6Zone.FindIndex(line[loc[1]:]); z != nil {
				if addr, err := netip.ParseAddr(string(line[s : loc[1]+z[1]])); err == nil && addr.Is6() {
					out = append(out, Match{Start: s, End: loc[1] + z[1], Kind: KindIPv6, Class: classify(addr)})
					continue
				}
			}
		}
		if addr, err := netip.ParseAddr(string(line[s:e])); err == nil && addr.Is6() {
			out = append(out, Match{Start: s, End: e, Kind: KindIPv6, Class: classify(addr)})
		}
	}
	return out
}

func TestIPv6FinderMatchesRegexpReference(t *testing.T) {
	alphabet := []string{
		":", ":", "::", ":::", "1", "a", "F", "0", "ffff", "db8", "2001", "fe80", "12345", "g", ".", "..", "%", "%eth0", "%1", "%",
		"10.0.0.1", "1.2.3.4", "::1", "::ffff:", "ffff:", " ", "/", "[", "]", "-", "_", "あ", "\xff", "std", "Error",
	}
	rng := rand.New(rand.NewPCG(13, 14))
	for iter := 0; iter < 40000; iter++ {
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

// 実装(前処理つき)と、前処理なしの正規表現の速度。PLAN の Q2 の記録用。
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
