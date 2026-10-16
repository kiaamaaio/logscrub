package detect

import (
	"slices"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// span は偽の検出器が返す範囲。
type span struct {
	start, end int
	class      Class
}

// fakeFinder は、行の内容を見ずに、決まった範囲を候補として返す検出器。
type fakeFinder struct {
	k     Kind
	spans []span
	calls int
}

func (f *fakeFinder) kind() Kind { return f.k }

func (f *fakeFinder) find(line []byte, dst []Match) []Match {
	f.calls++
	for _, s := range f.spans {
		dst = append(dst, Match{Start: s.start, End: s.end, Kind: f.k, Class: s.class})
	}
	return dst
}

func fake(k Kind, spans ...[2]int) *fakeFinder {
	f := &fakeFinder{k: k}
	for _, s := range spans {
		f.spans = append(f.spans, span{start: s[0], end: s[1]})
	}
	return f
}

func fakeIP(k Kind, class Class, start, end int) *fakeFinder {
	return &fakeFinder{k: k, spans: []span{{start, end, class}}}
}

func newTestDetector(t *testing.T, o Options, fs ...finder) *Detector {
	t.Helper()
	if o.Kinds == 0 {
		for _, ti := range Types {
			o.Kinds = o.Kinds.With(ti.Kind)
		}
	}
	d, err := newDetector(o, fs)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// pad は、ラベルや hash 出力形を含まない、長さ n の行を返す。
func pad(n int) string { return strings.Repeat("x", n) }

func m(k Kind, start, end int) Match { return Match{Start: start, End: end, Kind: k} }

func check(t *testing.T, d *Detector, line string, want []Match, wantKept int) {
	t.Helper()
	got, kept := d.Find([]byte(line), nil)
	if !slices.Equal(got, want) {
		t.Errorf("Find(%q)\n got  %+v\n want %+v", line, got, want)
	}
	if kept != wantKept {
		t.Errorf("Find(%q) kept = %d, want %d", line, kept, wantKept)
	}
}

// ---- 範囲の重なりの解決(仕様 4 章「範囲が重なった場合」、DEVELOPMENT.md 3.1) ----

func TestResolveLongerWins(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 5}),
		fake(KindSecret, [2]int{2, 12}),
	)
	check(t, d, pad(20), []Match{m(KindSecret, 2, 12)}, 0)
}

func TestResolveLongerWinsRegardlessOfPriority(t *testing.T) {
	// email の優先順位が高くても、短ければ負ける。
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{4, 8}),
		fake(KindUUID, [2]int{0, 20}),
	)
	check(t, d, pad(30), []Match{m(KindUUID, 0, 20)}, 0)
}

// ::ffff:10.0.0.1 は IPv6 全体(長い)が、末尾の IPv4 部分(短い)に勝つ。
func TestResolveIPv4MappedIPv6(t *testing.T) {
	d := newTestDetector(t, Options{},
		fakeIP(KindIPv6, ClassPrivate, 0, 15),
		fakeIP(KindIPv4, ClassPrivate, 7, 15),
	)
	check(t, d, pad(15), []Match{{Start: 0, End: 15, Kind: KindIPv6, Class: ClassPrivate}}, 0)
}

func TestResolveSameLengthUsesKindPriority(t *testing.T) {
	// 優先順位: email → ipv4 / ipv6 → secret → uuid → aws_account → aws_s3_bucket
	order := []Kind{KindEmail, KindIPv4, KindSecret, KindUUID, KindAWSAccount, KindAWSS3Bucket}
	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			hi, lo := order[i], order[j]
			// 追加する順序に依らないこと
			for _, fs := range [][]finder{
				{fakeIP(hi, ClassGlobal, 0, 10), fakeIP(lo, ClassGlobal, 0, 10)},
				{fakeIP(lo, ClassGlobal, 0, 10), fakeIP(hi, ClassGlobal, 0, 10)},
			} {
				d := newTestDetector(t, Options{}, fs...)
				got, _ := d.Find([]byte(pad(10)), nil)
				if len(got) != 1 || got[0].Kind != hi {
					t.Errorf("%v vs %v: got %+v, want %v to win", hi, lo, got, hi)
				}
			}
		}
	}
}

func TestResolveSameLengthPartialOverlapUsesKindPriority(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindSecret, [2]int{0, 10}),
		fake(KindEmail, [2]int{5, 15}),
	)
	check(t, d, pad(20), []Match{m(KindEmail, 5, 15)}, 0)
}

func TestResolveSameKindSameLengthEarlierStartWins(t *testing.T) {
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{5, 15}, [2]int{0, 10}))
	check(t, d, pad(20), []Match{m(KindSecret, 0, 10)}, 0)
}

func TestResolveLosersAreDroppedEvenWhereTheyDoNotOverlap(t *testing.T) {
	// [0,10) が [8,30) に負けたあと、[0,8) の部分を別の候補として拾い直さない。
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 10}),
		fake(KindSecret, [2]int{8, 30}),
	)
	check(t, d, pad(40), []Match{m(KindSecret, 8, 30)}, 0)
}

func TestResolveChainOfOverlaps(t *testing.T) {
	// A[0,10) B[8,22) C[20,26): B が最長で勝ち、A と C は B と重なるので捨てる。
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 10}),
		fake(KindSecret, [2]int{8, 22}),
		fake(KindUUID, [2]int{20, 26}),
	)
	check(t, d, pad(30), []Match{m(KindSecret, 8, 22)}, 0)
}

func TestResolveChainWhereEndsSurvive(t *testing.T) {
	// A[0,12) B[10,16) C[14,26): A と C は長く、互いに重ならない。B は両方と重なり、短いので負ける。
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 12}),
		fake(KindSecret, [2]int{10, 16}),
		fake(KindUUID, [2]int{14, 26}),
	)
	check(t, d, pad(30), []Match{m(KindEmail, 0, 12), m(KindUUID, 14, 26)}, 0)
}

func TestResolveNestedKeepsOnlyTheOuter(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindIPv4, [2]int{10, 15}),
		fake(KindSecret, [2]int{0, 30}),
		fake(KindEmail, [2]int{12, 20}),
	)
	check(t, d, pad(40), []Match{m(KindSecret, 0, 30)}, 0)
}

func TestResolveIdenticalRangesProduceOneMatch(t *testing.T) {
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{3, 9}, [2]int{3, 9}, [2]int{3, 9}))
	check(t, d, pad(20), []Match{m(KindSecret, 3, 9)}, 0)
}

func TestResolveTouchingRangesDoNotOverlap(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 5}),
		fake(KindSecret, [2]int{5, 9}),
	)
	check(t, d, pad(20), []Match{m(KindEmail, 0, 5), m(KindSecret, 5, 9)}, 0)
}

func TestResolveOutputIsSortedByStart(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindUUID, [2]int{50, 60}),
		fake(KindEmail, [2]int{30, 40}, [2]int{0, 5}),
		fake(KindSecret, [2]int{10, 20}),
	)
	check(t, d, pad(70), []Match{m(KindEmail, 0, 5), m(KindSecret, 10, 20), m(KindEmail, 30, 40), m(KindUUID, 50, 60)}, 0)
}

func TestResolveIgnoresEmptyAndInvertedRanges(t *testing.T) {
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{5, 5}, [2]int{9, 3}, [2]int{1, 4}))
	check(t, d, pad(20), []Match{m(KindSecret, 1, 4)}, 0)
}

func TestFindAppendsToDst(t *testing.T) {
	d := newTestDetector(t, Options{}, fake(KindEmail, [2]int{0, 5}))
	prev := Match{Start: 100, End: 200, Kind: KindUUID}
	got, _ := d.Find([]byte(pad(10)), []Match{prev})
	want := []Match{prev, m(KindEmail, 0, 5)}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestFindIsRepeatable(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 10}, [2]int{30, 40}),
		fake(KindSecret, [2]int{8, 22}),
	)
	first, k1 := d.Find([]byte(pad(50)), nil)
	second, k2 := d.Find([]byte(pad(50)), nil)
	if !slices.Equal(first, second) || k1 != k2 {
		t.Errorf("results differ: %+v / %+v", first, second)
	}
}

func TestOnlyEnabledKindsAreRun(t *testing.T) {
	email := fake(KindEmail, [2]int{0, 5})
	secret := fake(KindSecret, [2]int{6, 10})
	uuid := fake(KindUUID, [2]int{11, 15})
	d := newTestDetector(t, Options{Kinds: KindSet(0).With(KindEmail)}, email, secret, uuid)
	check(t, d, pad(20), []Match{m(KindEmail, 0, 5)}, 0)
	if secret.calls != 0 || uuid.calls != 0 {
		t.Errorf("disabled finders were called: secret=%d uuid=%d", secret.calls, uuid.calls)
	}
}

// ---- 置換済みの値の除外(仕様 4 章「置換済みの値は検出しない」、DEVELOPMENT.md 3.2、Q1) ----

// password=<secret_1> の値部分 <secret_1> は、候補と保護範囲が同じ範囲なので、保護範囲が勝つ。
func TestPlaceholderBeatsEqualCandidate(t *testing.T) {
	line := "password=<secret_1>&user=x"
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{9, 19}))
	check(t, d, line, nil, 1)
}

func TestPlaceholderBearer(t *testing.T) {
	line := "Authorization: Bearer <secret_1>"
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{22, 32}))
	check(t, d, line, nil, 1)
}

func TestPlaceholderWithoutAnyCandidateIsCounted(t *testing.T) {
	d := newTestDetector(t, Options{})
	check(t, d, "from <email_1> to <ipv4_private_2>", nil, 2)
}

// 置換済みの形を含んでいても、より長い候補があれば、その候補が勝って全体が置換される(Q1)。
func TestLongerCandidateBeatsPlaceholder(t *testing.T) {
	line := `"password": "<secret_1> real value"`
	start := strings.Index(line, "<secret_1>")
	end := len(line) - 1
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{start, end}))
	check(t, d, line, []Match{m(KindSecret, start, end)}, 0)
}

func TestShorterCandidateInsidePlaceholderLoses(t *testing.T) {
	line := "<ipv4_private_1>"
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{1, 5}))
	check(t, d, line, nil, 1)
}

func TestPlaceholdersAreCountedOnlyWhenTheyRemain(t *testing.T) {
	line := "<email_1> and <email_2> and tail"
	// 2 つ目の保護範囲を含む、より長い候補
	start := strings.Index(line, "<email_2>") - 1
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{start, len(line)}))
	check(t, d, line, []Match{m(KindSecret, start, len(line))}, 1)
}

// --mask-format '[{type}-{n}]' の出力は、同じ書式で再度流しても変わらない(受け入れ基準)。
func TestPlaceholderWithCustomFormat(t *testing.T) {
	f, err := label.ParseFormat("[{type}-{n}]")
	if err != nil {
		t.Fatal(err)
	}
	line := "password=[secret-1]&x"
	// キー名ベースのクォートなしの値は ']' の直前で切れるため、値は "[secret-1" になる。
	d := newTestDetector(t, Options{Format: f}, fake(KindSecret, [2]int{9, 18}))
	check(t, d, line, nil, 1)
	// 既定の書式のラベルは、この書式では置換済みとみなさない(候補がそのまま残る)。
	check(t, d, "password=<secret_1>", []Match{m(KindSecret, 9, 18)}, 0)
}

func TestDefaultFormatIsNotProtectedUnderCustomFormat(t *testing.T) {
	f, _ := label.ParseFormat("[{type}-{n}]")
	d := newTestDetector(t, Options{Format: f}, fake(KindSecret, [2]int{9, 19}))
	check(t, d, "password=<secret_1>", []Match{m(KindSecret, 9, 19)}, 0)
}

func TestHashOutputsArePlaceholders(t *testing.T) {
	// hash モードの出力(受け入れ基準: password=secret_3f9a1c0b7d2e が再ハッシュされない)
	line := "password=secret_3f9a1c0b7d2e&user=x"
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{9, 28}))
	check(t, d, line, nil, 1)
}

func TestHashedEmailLocalPartIsPlaceholder(t *testing.T) {
	line := "to hash_3f9a1c0b7d2e@example.com ok"
	d := newTestDetector(t, Options{}, fake(KindEmail, [2]int{3, 32}))
	check(t, d, line, nil, 1)
}

func TestHashLengthIsConfigurable(t *testing.T) {
	line := "secret_3f9a1c0b7d2e4455"
	// 既定(12 桁)では桁数が合わないので、保護されない。
	d12 := newTestDetector(t, Options{}, fake(KindSecret, [2]int{0, 23}))
	check(t, d12, line, []Match{m(KindSecret, 0, 23)}, 0)
	// 16 桁を指定すると、保護される。
	d16 := newTestDetector(t, Options{HashLen: 16}, fake(KindSecret, [2]int{0, 23}))
	check(t, d16, line, nil, 1)
}

func TestLookalikeOfHashOutputWithWrongLengthIsNotProtected(t *testing.T) {
	// 本物の値 secret_abc123 は 16 進数でも 12 桁ではないので、保護されない(Q10)。
	line := "password=secret_abc123"
	d := newTestDetector(t, Options{}, fake(KindSecret, [2]int{9, 22}))
	check(t, d, line, []Match{m(KindSecret, 9, 22)}, 0)
}

// ---- --allow(Q11) ----

func allowSet(vs ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, v := range vs {
		m[v] = struct{}{}
	}
	return m
}

func TestAllowKeepsExactMatch(t *testing.T) {
	line := "contact support@example.com or taro@example.com"
	a := strings.Index(line, "support@example.com")
	b := strings.Index(line, "taro@example.com")
	d := newTestDetector(t, Options{Allow: allowSet("support@example.com")},
		fake(KindEmail, [2]int{a, a + len("support@example.com")}, [2]int{b, b + len("taro@example.com")}))
	// 置換済みの形ではないので、kept には数えない。
	check(t, d, line, []Match{m(KindEmail, b, b+len("taro@example.com"))}, 0)
}

func TestAllowIsExactNotPrefix(t *testing.T) {
	line := "support@example.com.au"
	d := newTestDetector(t, Options{Allow: allowSet("support@example.com")}, fake(KindEmail, [2]int{0, len(line)}))
	check(t, d, line, []Match{m(KindEmail, 0, len(line))}, 0)
}

func TestAllowIsCaseSensitive(t *testing.T) {
	line := "Support@example.com"
	d := newTestDetector(t, Options{Allow: allowSet("support@example.com")}, fake(KindEmail, [2]int{0, len(line)}))
	check(t, d, line, []Match{m(KindEmail, 0, len(line))}, 0)
}

// --allow ::ffff:10.0.0.1 では、全体を残す。末尾の 10.0.0.1 だけが置換されることはない。
func TestAllowWholeIPv4MappedKeepsInnerIPv4(t *testing.T) {
	line := "::ffff:10.0.0.1"
	d := newTestDetector(t, Options{Allow: allowSet("::ffff:10.0.0.1")},
		fakeIP(KindIPv6, ClassPrivate, 0, 15),
		fakeIP(KindIPv4, ClassPrivate, 7, 15),
	)
	check(t, d, line, nil, 0)
}

// 許可した値でも、より長い候補に含まれる場合は、長い候補が勝って置換される。
func TestAllowLosesToLongerCandidate(t *testing.T) {
	line := "api_key=10.0.0.1:8080"
	d := newTestDetector(t, Options{Allow: allowSet("10.0.0.1")},
		fakeIP(KindIPv4, ClassPrivate, 8, 16),
		fake(KindSecret, [2]int{8, 21}),
	)
	check(t, d, line, []Match{m(KindSecret, 8, 21)}, 0)
}

func TestAllowAppliesToAnyKindWithTheSameText(t *testing.T) {
	line := "token=10.0.0.1"
	d := newTestDetector(t, Options{Allow: allowSet("10.0.0.1")},
		fakeIP(KindIPv4, ClassPrivate, 6, 14),
		fake(KindSecret, [2]int{6, 14}),
	)
	check(t, d, line, nil, 0)
}

// ---- IP の区別と --ip-scope(Q11: 重なりの解決の前に外す) ----

func TestSpecialAddressesAreNeverReported(t *testing.T) {
	d := newTestDetector(t, Options{}, fakeIP(KindIPv4, ClassSpecial, 0, 7), fakeIP(KindIPv6, ClassSpecial, 10, 12))
	check(t, d, pad(20), nil, 0)
}

// token=0.0.0.0 は、IP としては置換しないが、キー名ベースの secret としては置換する。
func TestSpecialAddressDoesNotShadowSecret(t *testing.T) {
	d := newTestDetector(t, Options{},
		fakeIP(KindIPv4, ClassSpecial, 6, 13),
		fake(KindSecret, [2]int{6, 13}),
	)
	check(t, d, "token=0.0.0.0", []Match{m(KindSecret, 6, 13)}, 0)
}

func TestIPScope(t *testing.T) {
	priv := Match{Start: 0, End: 8, Kind: KindIPv4, Class: ClassPrivate}
	glob := Match{Start: 10, End: 21, Kind: KindIPv4, Class: ClassGlobal}
	build := func(scope Scope) *Detector {
		return newTestDetector(t, Options{IPScope: scope},
			fakeIP(KindIPv4, ClassPrivate, 0, 8),
			fakeIP(KindIPv4, ClassGlobal, 10, 21),
		)
	}
	check(t, build(ScopeAll), pad(30), []Match{priv, glob}, 0)
	check(t, build(ScopeGlobal), pad(30), []Match{glob}, 0)
	check(t, build(ScopePrivate), pad(30), []Match{priv}, 0)
}

func TestIPScopeDoesNotAffectOtherKinds(t *testing.T) {
	for _, scope := range []Scope{ScopeAll, ScopeGlobal, ScopePrivate} {
		d := newTestDetector(t, Options{IPScope: scope},
			fake(KindEmail, [2]int{0, 5}),
			fake(KindSecret, [2]int{10, 15}),
			fake(KindUUID, [2]int{20, 25}),
		)
		check(t, d, pad(30), []Match{m(KindEmail, 0, 5), m(KindSecret, 10, 15), m(KindUUID, 20, 25)}, 0)
	}
}

// --ip-scope global のとき、api_key=<プライベート IP> は secret として置換される(Q11)。
func TestOutOfScopeIPDoesNotShadowSecret(t *testing.T) {
	d := newTestDetector(t, Options{IPScope: ScopeGlobal},
		fakeIP(KindIPv4, ClassPrivate, 8, 16),
		fake(KindSecret, [2]int{8, 16}),
	)
	check(t, d, "api_key=10.0.0.1", []Match{m(KindSecret, 8, 16)}, 0)
}

func TestInScopeIPBeatsEqualSecret(t *testing.T) {
	d := newTestDetector(t, Options{IPScope: ScopeAll},
		fake(KindSecret, [2]int{8, 16}),
		fakeIP(KindIPv4, ClassPrivate, 8, 16),
	)
	check(t, d, "api_key=10.0.0.1", []Match{{Start: 8, End: 16, Kind: KindIPv4, Class: ClassPrivate}}, 0)
}

// ---- New のオプション検証 ----

func TestNewDefaults(t *testing.T) {
	d, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d.kinds != DefaultKinds {
		t.Errorf("kinds = %b, want %b", d.kinds, DefaultKinds)
	}
	if d.hashLen != 12 {
		t.Errorf("hashLen = %d, want 12", d.hashLen)
	}
	// 書式の既定は <{type}_{n}>
	got, kept := d.Find([]byte("<email_1>"), nil)
	if len(got) != 0 || kept != 1 {
		t.Errorf("Find(<email_1>) = %+v, %d", got, kept)
	}
}

func TestNewUUIDVersionsEnablesUUID(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindEmail), UUIDVersions: 1<<4 | 1<<7})
	if err != nil {
		t.Fatal(err)
	}
	if !d.kinds.Has(KindUUID) || !d.kinds.Has(KindEmail) || d.kinds.Has(KindSecret) {
		t.Errorf("kinds = %b", d.kinds)
	}
}

func TestNewRejectsInvalidUUIDVersions(t *testing.T) {
	for _, v := range []uint16{1 << 0, 1 << 9, 1 << 15, 1<<4 | 1<<9} {
		if _, err := New(Options{UUIDVersions: v}); err == nil {
			t.Errorf("UUIDVersions=%b: want error", v)
		}
	}
	for v := 1; v <= 8; v++ {
		if _, err := New(Options{UUIDVersions: 1 << v}); err != nil {
			t.Errorf("UUIDVersions=1<<%d: %v", v, err)
		}
	}
}

func TestNewRejectsInvalidHashLength(t *testing.T) {
	for _, n := range []int{-1, 1, 7, 65, 1000} {
		if _, err := New(Options{HashLen: n}); err == nil {
			t.Errorf("HashLen=%d: want error", n)
		}
	}
	for _, n := range []int{0, 8, 12, 16, 64} {
		if _, err := New(Options{HashLen: n}); err != nil {
			t.Errorf("HashLen=%d: %v", n, err)
		}
	}
}

func TestNewRejectsInvalidScope(t *testing.T) {
	if _, err := New(Options{IPScope: Scope(99)}); err == nil {
		t.Error("want error")
	}
}

// ---- 性能の前提 ----

// 候補が多い 1 行(1MB の JSON 1 行など)でも、候補の数の 2 乗の時間をかけない。
func TestManyDisjointCandidates(t *testing.T) {
	const n = 100000
	f := &fakeFinder{k: KindEmail}
	for i := 0; i < n; i++ {
		f.spans = append(f.spans, span{start: i * 4, end: i*4 + 3})
	}
	d := newTestDetector(t, Options{}, f)
	line := make([]byte, n*4)
	for i := range line {
		line[i] = 'x'
	}
	got, kept := d.Find(line, nil)
	if len(got) != n || kept != 0 {
		t.Fatalf("len=%d kept=%d, want %d, 0", len(got), kept, n)
	}
}

func TestFindDoesNotAllocateInSteadyState(t *testing.T) {
	d := newTestDetector(t, Options{},
		fake(KindEmail, [2]int{0, 10}, [2]int{30, 40}),
		fake(KindSecret, [2]int{8, 22}),
	)
	line := []byte("password=<secret_1> from hash_3f9a1c0b7d2e@example.com and <email_2> x")
	var dst []Match
	dst, _ = d.Find(line, dst[:0]) // 作業領域を確保する
	allocs := testing.AllocsPerRun(1000, func() {
		dst, _ = d.Find(line, dst[:0])
	})
	if allocs != 0 {
		t.Errorf("allocs per Find = %v, want 0", allocs)
	}
}
