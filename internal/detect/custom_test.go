package detect

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

func findStrings(t *testing.T, o Options, line string) []string {
	t.Helper()
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := d.Find([]byte(line), nil)
	out := []string{}
	for _, m := range ms {
		out = append(out, m.LabelType()+":"+line[m.Start:m.End])
	}
	return out
}

func TestDenyBoundaries(t *testing.T) {
	tests := []struct {
		deny []string
		line string
		want []string
	}{
		{[]string{"acme"}, "acmerica AcmeCorp xacme acme1", nil},
		{[]string{"acme"}, "acme-prod", []string{"custom:acme"}},
		{[]string{"acme"}, "acme_prod", []string{"custom:acme"}},
		{[]string{"acme"}, "x.acme.internal", []string{"custom:acme"}},
		{[]string{"acme"}, "Acmeの", []string{"custom:Acme"}},
		{[]string{"acme"}, "ACME acme", []string{"custom:ACME", "custom:acme"}},
		{[]string{"アクメ"}, "株式会社アクメの", []string{"custom:アクメ"}},
		{[]string{"Acme Corp"}, "by acme  corp, ACME CORP.", []string{"custom:ACME CORP"}},
		{[]string{"--"}, "a--b", []string{"custom:--"}},
		{[]string{"ab", "abc"}, "abc", []string{"custom:abc"}},
		{[]string{"foo bar", "bar baz"}, "foo bar baz", []string{"custom:foo bar"}},
	}
	for _, tt := range tests {
		got := findStrings(t, Options{Deny: tt.deny, Kinds: KindSet(0).With(KindCustom)}, tt.line)
		if !slices.Equal(got, append([]string{}, tt.want...)) {
			t.Errorf("deny %q, line %q: got %q, want %q", tt.deny, tt.line, got, tt.want)
		}
	}
}

func TestDenyWithOtherTypes(t *testing.T) {
	// 語より長い値に含まれる場合は、その値全体が置換される(Q74)。
	got := findStrings(t, Options{Deny: []string{"acme"}}, "taro@acme.co.jp")
	if !slices.Equal(got, []string{"email:taro@acme.co.jp"}) {
		t.Errorf("got %q", got)
	}
	// 同じ長さなら、種別の優先順位。
	got = findStrings(t, Options{Deny: []string{"10.0.0.1"}}, "10.0.0.1")
	if !slices.Equal(got, []string{"ipv4_private:10.0.0.1"}) {
		t.Errorf("got %q", got)
	}
	// 置換済みの形は、再置換されない。
	for _, line := range []string{"<email_1>", "<custom_1>", "email_3f9a1c0b7d2e"} {
		if got := findStrings(t, Options{Deny: []string{"email", "custom", "1"}}, line); len(got) != 0 {
			t.Errorf("%q: got %q", line, got)
		}
	}
}

func TestDenyAllow(t *testing.T) {
	o := Options{Deny: []string{"acme", "acme-public"}, Allow: map[string]struct{}{"Acme": {}}}
	if got := findStrings(t, o, "Acme ACME"); !slices.Equal(got, []string{"custom:ACME"}) {
		t.Errorf("got %q", got)
	}
}

func TestOptionsAddKinds(t *testing.T) {
	n, err := normalize(Options{Kinds: KindSet(0).With(KindEmail), Deny: []string{"x"}, Domains: []string{"example.jp"}})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Kinds.Has(KindCustom) || !n.Kinds.Has(KindHost) || !n.Kinds.Has(KindEmail) || n.Kinds.Has(KindSecret) {
		t.Errorf("kinds = %b", n.Kinds)
	}
	if DefaultKinds.Has(KindCustom) || DefaultKinds.Has(KindHost) {
		t.Error("custom and host must not be default")
	}
}

func TestOptionsRejectValues(t *testing.T) {
	for _, o := range []Options{
		{Deny: []string{""}}, {Deny: []string{"a\nb"}}, {Deny: []string{"a\rb"}},
		{Domains: []string{""}}, {Domains: []string{"https://example.jp"}}, {Domains: []string{"*.example.jp"}},
		{Domains: []string{".example.jp"}}, {Domains: []string{"example.jp."}}, {Domains: []string{"a..b"}}, {Domains: []string{"例え.jp"}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%+v: want error", o)
		}
		if _, err := New(Options{Deny: []string{"secretword\n"}}); err == nil || strings.Contains(err.Error(), "secretword") {
			t.Errorf("error %v must not contain the word", err)
		}
	}
	if _, err := New(Options{Domains: []string{"internal", "xn--wgv71a.jp", "EXAMPLE.jp"}}); err != nil {
		t.Error(err)
	}
}

func TestDomain(t *testing.T) {
	dom := []string{"example.co.jp", "mycompany.internal"}
	onlyHost := Options{Domains: dom, Kinds: KindSet(0).With(KindHost)}
	tests := []struct {
		line string
		want []string
	}{
		{"curl https://internal.corp.example.co.jp/api", []string{"host:internal.corp.example.co.jp"}},
		{"connecting to db.mycompany.internal", []string{"host:db.mycompany.internal"}},
		{"example.co.jp", []string{"host:example.co.jp"}},
		{"see db.example.co.jp.", []string{"host:db.example.co.jp"}},
		{"db.example.co.jp.\tok", []string{"host:db.example.co.jp"}},
		{"db.example.co.jp:8080", []string{"host:db.example.co.jp"}},
		{"DB.Example.CO.JP", []string{"host:DB.Example.CO.JP"}},
		{"接続先はdb.example.co.jpです", []string{"host:db.example.co.jp"}},
		{".example.co.jp", []string{"host:example.co.jp"}},
		{"_dmarc.example.co.jp", []string{"host:_dmarc.example.co.jp"}},
		{"taro@example.co.jp", []string{"host:example.co.jp"}},
		{"notexample.co.jp", nil},
		{"not-example.co.jp", nil},
		{"example.co.jp.evil.org", nil},
		{"example.co.jp-access.log", nil},
		{"api.example.co.jp.log", nil},
		{"a.example.co.jp b.example.co.jp a.example.co.jp", []string{"host:a.example.co.jp", "host:b.example.co.jp", "host:a.example.co.jp"}},
	}
	for _, tt := range tests {
		if got := findStrings(t, onlyHost, tt.line); !slices.Equal(got, append([]string{}, tt.want...)) {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestDomainNestedDomainsGiveOneMatch(t *testing.T) {
	o := Options{Domains: []string{"example.jp", "corp.example.jp"}, Kinds: KindSet(0).With(KindHost)}
	if got := findStrings(t, o, "db.corp.example.jp"); !slices.Equal(got, []string{"host:db.corp.example.jp"}) {
		t.Errorf("got %q", got)
	}
}

func TestDomainWithOtherTypes(t *testing.T) {
	o := Options{Domains: []string{"example.co.jp"}, Kinds: KindSet(0).With(KindEmail).With(KindSecret).With(KindIPv4)}
	tests := []struct {
		line string
		want []string
	}{
		{"taro@example.co.jp", []string{"email:taro@example.co.jp"}},
		{"postgres://app:s3cret@db.example.co.jp/", []string{"secret:s3cret", "host:db.example.co.jp"}},
		{"ip-10-0-1-23.corp.example.co.jp", []string{"host:ip-10-0-1-23.corp.example.co.jp"}},
	}
	for _, tt := range tests {
		if got := findStrings(t, o, tt.line); !slices.Equal(got, tt.want) {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestHideDomain(t *testing.T) {
	tests := []struct {
		o    Options
		line string
		want bool
	}{
		{Options{Deny: []string{"acme"}}, "taro@acme.co.jp", true},
		{Options{Deny: []string{"acme"}}, "taro@mail.ACME.co.jp", true},
		{Options{Deny: []string{"acme"}}, "taro@acmerica.co.jp", false},
		{Options{Deny: []string{"acme"}}, "acme@example.org", false},
		{Options{Deny: []string{"@acme.co.jp"}}, "taro@acme.co.jp", true},
		{Options{Deny: []string{"taro@acme.co.jp"}}, "taro@acme.co.jp", true},
		{Options{Deny: []string{"taro@"}}, "taro@acme.co.jp", false},
		{Options{Domains: []string{"example.co.jp"}}, "example.co.jp@example.org", false},
		{Options{Domains: []string{"example.co.jp"}}, "taro@mail.example.co.jp", true},
		{Options{Domains: []string{"example.co.jp"}}, "taro@notexample.co.jp", false},
		{Options{}, "taro@example.org", false},
	}
	for _, tt := range tests {
		d, err := New(tt.o)
		if err != nil {
			t.Fatal(err)
		}
		ms, _ := d.Find([]byte(tt.line), nil)
		if len(ms) != 1 || ms[0].Kind != KindEmail || ms[0].HideDomain != tt.want {
			t.Errorf("%q: %+v, want HideDomain %v", tt.line, ms, tt.want)
		}
	}
}

// refHosts は、hostFinder と同じ条件を、遡りの範囲を覚えずに、全位置で確かめる参照実装。
func refHosts(domains []string, line []byte) []string {
	lower := strings.ToLower(string(line))
	seen := map[int]bool{}
	type rng struct{ s, e int }
	var out []rng
	for e := 0; e <= len(line); e++ {
		for _, d := range domains {
			s := e - len(d)
			if s < 0 || lower[s:e] != strings.ToLower(d) || seen[e] || !isHostEnd(line, e) {
				continue
			}
			if s > 0 && line[s-1] != '.' && isHostNameChar(line[s-1]) {
				continue
			}
			i := s
			for i > 0 && isHostNameChar(line[i-1]) {
				i--
			}
			for i < s && line[i] == '.' {
				i++
			}
			seen[e] = true
			out = append(out, rng{i, e})
		}
	}
	strs := []string{}
	for _, r := range out {
		strs = append(strs, string(line[r.s:r.e]))
	}
	return strs
}

func TestHostFinderAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	parts := []string{"a.jp", "b.a.jp", "A.JP", ".", "..", "-", "_", "x", "/", " ", "a", "jp", "@"}
	domains := []string{"a.jp", "b.a.jp"}
	f := hostFinder{m: newLiteralMatcher(domains)}
	for range 50000 {
		var sb strings.Builder
		for n := rng.IntN(12); n > 0; n-- {
			sb.WriteString(parts[rng.IntN(len(parts))])
		}
		line := []byte(sb.String())
		got := []string{}
		for _, m := range f.find(line, nil) {
			got = append(got, string(line[m.Start:m.End]))
		}
		if want := refHosts(domains, line); !slices.Equal(got, want) {
			t.Fatalf("line %q: got %q, want %q", line, got, want)
		}
	}
}

// 1 行の長い連なりでも、遡りが 2 乗の時間にならない。
func TestDomainLongRunIsLinear(t *testing.T) {
	line := []byte(strings.Repeat("a.example.jp..", 1<<17))
	f := hostFinder{m: newLiteralMatcher([]string{"example.jp"})}
	start := time.Now()
	if got := f.find(line, nil); len(got) != 1<<17 {
		t.Fatalf("got %d matches", len(got))
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v", el)
	}
}
