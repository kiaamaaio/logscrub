package detect

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/label"
)

// emailsIn は、email 検出器だけを直接動かし、候補の文字列を返す。
func emailsIn(line string) []string {
	var got []string
	for _, m := range (emailFinder{hashLen: 12}).find([]byte(line), nil) {
		got = append(got, line[m.Start:m.End])
	}
	return got
}

func TestEmailFinderKind(t *testing.T) {
	if k := (emailFinder{}).kind(); k != KindEmail {
		t.Errorf("kind = %v", k)
	}
	for _, m := range (emailFinder{hashLen: 12}).find([]byte("a@example.com"), nil) {
		if m.Kind != KindEmail || m.Class != ClassNone {
			t.Errorf("match = %+v", m)
		}
	}
}

func TestEmailFinderMatches(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"plain", "taro@example.com", []string{"taro@example.com"}},
		{"with ip", "taro@example.com 192.168.0.1", []string{"taro@example.com"}},
		{"mixed case", "From: <Taro.Yamada+tag@Mail.Example.CO.JP>,", []string{"Taro.Yamada+tag@Mail.Example.CO.JP"}},
		{"special local chars", "a_b%c-d@x-y.example.org", []string{"a_b%c-d@x-y.example.org"}},
		{"two letter tld", "a@b.co", []string{"a@b.co"}},
		{"upper", "X@Y.COM", []string{"X@Y.COM"}},
		{"subdomains", "user@sub.example.co.jp", []string{"user@sub.example.co.jp"}},
		{"trailing period", "sent to user@example.com.", []string{"user@example.com"}},
		{"trailing periods", "user@example.com...", []string{"user@example.com"}},
		{"parentheses", "(user@example.com)", []string{"user@example.com"}},
		{"quotes", `"user@example.com"`, []string{"user@example.com"}},
		{"mailto", "mailto:user@example.com?subject=hi", []string{"user@example.com"}},
		{"with port", "user@example.com:587", []string{"user@example.com"}},
		{"with path", "user@example.com/inbox", []string{"user@example.com"}},
		{"json", `{"email":"user@example.com","n":1}`, []string{"user@example.com"}},
		{"comma separated", "a@x.com,b@y.org", []string{"a@x.com", "b@y.org"}},
		{"space separated", "a@x.com b@y.org  c@z.net", []string{"a@x.com", "b@y.org", "c@z.net"}},
		// ユーザーだけの URL のユーザー情報は、メールアドレスのまま(v1.1 と同じ。仕様 4.1)
		{"url userinfo, user only", "https://taro@example.com/", []string{"taro@example.com"}},
		{"url userinfo, no password", "ftp://taro@example.com:21/", []string{"taro@example.com"}},
		{"japanese around", "ユーザーtaro@example.comです", []string{"taro@example.com"}},
		{"fullwidth space", "　taro@example.com　", []string{"taro@example.com"}},
		{"invalid utf8 around", "\xff\xfetaro@example.com\x80", []string{"taro@example.com"}},
		{"long local part", strings.Repeat("a", 300) + "@example.com", []string{strings.Repeat("a", 300) + "@example.com"}},
		// Q5 のとおり、ローカルパートの文字は `[A-Za-z0-9._%+-]`。先頭の '.' も含む。
		{"leading dot is part of the local part", ".user@example.com", []string{".user@example.com"}},
		// 前の一致の終端より前には、ローカルパートを伸ばさない。
		{"second at sign right after a match", "user@example.com@evil.example.org", []string{"user@example.com"}},
		{"two at signs", "a@b@example.com", []string{"b@example.com"}},
		// ドメインは、最後の英字だけのラベル(2 文字以上)で終える。
		{"label with digit after tld", "user@a.bc.d1", []string{"user@a.bc"}},
		{"single letter label after tld", "user@a.bc.d", []string{"user@a.bc"}},
		{"hyphen label after tld", "user@a.bc.com-x", []string{"user@a.bc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := emailsIn(tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("emails(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestEmailFinderIgnores(t *testing.T) {
	for _, line := range []string{
		"", "no at sign here", "@", "@@@", "@example.com", "user@", "user @example.com", "user@ example.com",
		// TLD は英字 2 文字以上(受け入れ基準: pass@10.0.0.1 はメールアドレスとして扱わない)
		"pass@10.0.0.1", "https://user:pass@10.0.0.1/", "user@10.0.0.1:8080",
		// URL のユーザー情報の `@`(`<スキーム>://<ユーザー>:<パスワード>@<ホスト>`)は、メールアドレスとして扱わない(v1.2。仕様 4.1)
		"https://user:pass@example.com/", "postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app",
		"redis://:s3cret@cache.example.com:6379", "ftp://u:a:b@host.example.org", "git+ssh://git:tok@github.com/x/y.git",
		"user@localhost", "user@example", "user@example.c", "user@example.c0m", "user@example.123", "user@[10.0.0.1]",
		"user@.com", "user@example..com", "user@example.com-", "user@-",
		// 非 ASCII は英数字でない扱い。ローカルパートが空になる。
		"名前@example.com", "user@例え.jp", "user@\xff.com",
		// 検出対象外: ローカルパートが hash_<hex> の形(仕様 5.2、決定事項 11)
		"hash_3f9a1c0b7d2e@example.com", "to <hash_000000000000@example.org>.",
		// 検出対象外: ローカルパートが、hash の出力形(<種別>_<hex>)。`user@example.com@bastion.example.org` の、
		// 先頭だけがハッシュされた結果を、全体で 1 つのメールアドレスとして、再度検出しない。
		"email_3f9a1c0b7d2e@bastion.example.org", "ipv4_private_3f9a1c0b7d2e@example.com", "secret_000000000000@example.com",
	} {
		if got := emailsIn(line); len(got) != 0 {
			t.Errorf("emails(%q) = %q, want none", line, got)
		}
	}
}

// ローカルパートが hash_<hex> の形でないものは、似ていても検出する。
func TestEmailFinderDetectsLookalikesOfHashedLocalPart(t *testing.T) {
	for _, line := range []string{
		"hash_3f9a1c0b7d2@example.com",      // 11 桁
		"hash_3f9a1c0b7d2e1@example.com",    // 13 桁
		"hash_3F9A1C0B7D2E@example.com",     // 大文字
		"xhash_3f9a1c0b7d2e@example.com",    // 前に文字がある
		"x.hash_3f9a1c0b7d2e@example.com",   // ローカルパートの一部
		"hash_3f9a1c0b7d2e.x@example.com",   // 後ろに文字がある
		"hash-3f9a1c0b7d2e@example.com",     // 区切りが違う
		"foo_3f9a1c0b7d2e@example.com",      // 知らない種別名
		"email_3F9A1C0B7D2E@example.com",    // 大文字
		"email_3f9a1c0b7d2@example.com",     // 11 桁
		"xemail_3f9a1c0b7d2e@example.com",   // 前に文字がある
		"hash_3f9a1c0b7d2e4455@example.com", // 16 桁(桁数が合わない)
	} {
		got := emailsIn(line)
		if len(got) != 1 || got[0] != line {
			t.Errorf("emails(%q) = %q, want the whole address", line, got)
		}
	}
}

func TestEmailFinderHashLengthFollowsOption(t *testing.T) {
	line := "hash_3f9a1c0b7d2e4455@example.com"
	if got := (emailFinder{hashLen: 16}).find([]byte(line), nil); len(got) != 0 {
		t.Errorf("hashLen 16: got %+v, want none", got)
	}
	if got := (emailFinder{hashLen: 12}).find([]byte(line), nil); len(got) != 1 {
		t.Errorf("hashLen 12: got %+v, want 1", got)
	}
}

func TestEmailFinderIsRepeatableAndAppends(t *testing.T) {
	f := emailFinder{hashLen: 12}
	line := []byte("a@x.com and b@y.org")
	first := f.find(line, nil)
	prev := Match{Start: 99, End: 100, Kind: KindUUID}
	second := f.find(line, []Match{prev})
	if !slices.Equal(first, second[1:]) || second[0] != prev {
		t.Errorf("first=%+v second=%+v", first, second)
	}
}

// 長い行でも、極端に時間がかからない('@' のない区間に正規表現を当てない)。
func TestEmailFinderLongLines(t *testing.T) {
	// ローカルパートの文字だけの 1MB と、ドメインの文字だけの 1MB の間の '@'
	line := strings.Repeat("a", 1<<20) + "@" + strings.Repeat("b", 1<<20)
	if got := emailsIn(line); len(got) != 0 {
		t.Errorf("got %d matches, want none", len(got))
	}
	// '@' が多数
	line = strings.Repeat("a@b.co ", 50000)
	if got := emailsIn(line); len(got) != 50000 {
		t.Errorf("got %d matches, want 50000", len(got))
	}
	line = strings.Repeat("a@", 200000)
	if got := emailsIn(line); len(got) != 0 {
		t.Errorf("got %d matches, want none", len(got))
	}
}

// ---- Detector を通した動作(受け入れ基準) ----

func newEmailDetector(t *testing.T, o Options) *Detector {
	t.Helper()
	if o.Kinds == 0 {
		o.Kinds = KindSet(0).With(KindEmail)
	}
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDetectorFindsEmail(t *testing.T) {
	d := newEmailDetector(t, Options{})
	check(t, d, "taro@example.com 192.168.0.1", []Match{m(KindEmail, 0, 16)}, 0)
	check(t, d, "from taro@example.com to hanako@example.com", []Match{m(KindEmail, 5, 21), m(KindEmail, 25, 43)}, 0)
}

// 受け入れ基準: https://user:pass@10.0.0.1/ の pass@10.0.0.1 は、メールアドレスとして扱わない。
// (既定の種別すべてでの結果は、IP 検出器と合わせて TestUserinfoWithIPv4 で確認する。)
func TestDetectorDoesNotTreatUserinfoAtIPAsEmail(t *testing.T) {
	d := newEmailDetector(t, Options{})
	check(t, d, "https://user:pass@10.0.0.1/", nil, 0)
}

func TestDetectorEmailAllow(t *testing.T) {
	d := newEmailDetector(t, Options{Allow: allowSet("support@example.com")})
	line := "contact support@example.com or taro@example.com"
	check(t, d, line, []Match{m(KindEmail, 31, 47)}, 0)
}

func TestDetectorDoesNotRedetectPlaceholders(t *testing.T) {
	d := newEmailDetector(t, Options{})
	check(t, d, "from <email_1> to <email_2>", nil, 2)
	check(t, d, "to email_3f9a1c0b7d2e ok", nil, 1)
}

// 受け入れ基準: --email-hash local の出力は、再度流しても変わらない。
// ローカルパートが hash_<hex> の形のアドレスは、検出の対象外で、置換済みの形として数える。
func TestDetectorHashedLocalPartIsLeftAlone(t *testing.T) {
	d := newEmailDetector(t, Options{})
	check(t, d, "to hash_3f9a1c0b7d2e@example.com ok", nil, 1)
	check(t, d, "hash_3f9a1c0b7d2e@example.com,hash_000000000000@example.org", nil, 2)
	// ローカルパートが hash_<hex> でないものは、通常どおり置換する。
	check(t, d, "hash_3f9a1c0b7d2@example.com", []Match{m(KindEmail, 0, 28)}, 0)
}

// ローカルパートが hash_<hex> の形のアドレスについて、検出器側の除外と、
// label.ScanHashed の保護範囲が、同じ範囲を指す。
// 検出器が保護範囲より長い範囲を出すと、保護範囲が負けて再ハッシュされてしまう。
func TestHashedLocalPartRangesAgreeWithScanHashed(t *testing.T) {
	lines := []string{
		"hash_3f9a1c0b7d2e@example.com",
		"to hash_3f9a1c0b7d2e@example.com.",
		"<hash_3f9a1c0b7d2e@mail.example.co.jp>,",
		"hash_3f9a1c0b7d2e@a.bc.d1",
		"hash_3f9a1c0b7d2e@a.bc.com-x",
		"mailto:hash_3f9a1c0b7d2e@example.com?x=1",
		"hash_3f9a1c0b7d2e@example.com@evil.org",
		"a@b.co hash_000000000000@example.org c@d.net",
	}
	f := emailFinder{hashLen: 12}
	for _, line := range lines {
		b := []byte(line)
		var want [][2]int
		label.ScanHashed(b, 12, func(s, e int) {
			if bytes.Contains(b[s:e], []byte("@")) {
				want = append(want, [2]int{s, e})
			}
		})
		if len(want) == 0 {
			t.Fatalf("%q: ScanHashed found nothing", line)
		}

		// 除外しない場合の候補のうち、ローカルパートが hash_<hex> の形のもの
		var got [][2]int
		var rest []Match
		for _, m := range f.scan(b, nil, false) {
			local := b[m.Start : m.Start+bytes.IndexByte(b[m.Start:], '@')]
			if label.IsHashedLocalPart(local, 12) {
				got = append(got, [2]int{m.Start, m.End})
			} else {
				rest = append(rest, m)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: hashed-local candidates %v, ScanHashed %v", line, got, want)
		}
		// find は、それらを除いた候補だけを返す。
		if gotFind := f.find(b, nil); !slices.Equal(gotFind, rest) {
			t.Errorf("%q: find = %+v, want %+v", line, gotFind, rest)
		}
	}
}

// ---- 手書きの走査(置き換え候補)との一致(Q2) ----

// anchorScan は、'@' を手がかりにした手書きの走査による、email 検出器の別実装。
// 本番の実装(正規表現)と同じ結果にならなければならない。
//
// Q2 のとおり、まず正規表現のままで性能を測り、50MB/s に届かない場合にだけ、
// この実装に置き換える。置き換えたあとも、元の正規表現版を参照としてテストに残す。
// label.EmailDomainEnd(hash 出力形の保護範囲と共有する、ドメインの終端の判定)を使う。
func anchorScan(line []byte, dst []Match) []Match {
	at := bytes.IndexByte(line, '@')
	lo := 0
	for at >= 0 {
		next := at + 1
		s := at
		for s > lo && label.IsEmailLocalChar(line[s-1]) {
			s--
		}
		if s < at {
			if e := label.EmailDomainEnd(line, at+1); e > 0 {
				if slices.ContainsFunc(refURLPasswords(line), func(r [2]int) bool { return r[1] == at }) {
					// URL のユーザー情報の `@`(v1.2)は、候補にしない
					lo = at + 1
					next = at + 1
				} else {
					dst = append(dst, Match{Start: s, End: e, Kind: KindEmail})
					lo = e
					next = e
				}
			}
		}
		j := bytes.IndexByte(line[next:], '@')
		if j < 0 {
			break
		}
		at = next + j
	}
	return dst
}

func TestEmailFinderMatchesAnchorScan(t *testing.T) {
	alphabet := []string{
		"a", "b", "Z", "1", "9", ".", "-", "_", "%", "+", "@", "@", " ", ",", "/", ":", "<", ">",
		"com", ".com", "co", ".jp", "あ", "\xff", "hash_", "3f9a1c0b7d2e",
		"http", "://", "://", "u", "p", "[", "?", "#", "\t", `"`, `","k":"`, "'", "{", "|",
	}
	rng := rand.New(rand.NewPCG(5, 6))
	f := emailFinder{hashLen: 12}
	for iter := 0; iter < 30000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(14); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		want := anchorScan(line, nil)
		got := f.scan(line, nil, false)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
	}
}

// 実装(正規表現)と、置き換え候補(手書きの走査)の速度。plans/v1.0.0.md の Q2 の判断材料として記録する。
// 合成ログの全行を処理する('@' を含まない行は、どちらも IndexByte 1 回で終わる)。
func BenchmarkEmailFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	f := emailFinder{hashLen: 12}
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = f.find(line, dst[:0])
		}
	}
}

func BenchmarkEmailAnchorScan(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = anchorScan(line, dst[:0])
		}
	}
}

// ローカルパートが、現在の書式のラベルそのものなら、検出対象外(ラベルの後ろに `@` が続く入力を、再度置換しない)。
func TestEmailFinderIgnoresLabelAsLocalPart(t *testing.T) {
	f, err := label.ParseFormat("{type}_{n}")
	if err != nil {
		t.Fatal(err)
	}
	finder := emailFinder{hashLen: 12, format: f}
	for _, line := range []string{"email_1@bastion.example.org", "to secret_12@example.com"} {
		if got := finder.find([]byte(line), nil); len(got) != 0 {
			t.Errorf("%q: got %+v, want none", line, got)
		}
	}
	// 既定の書式のラベルは、ローカルパートの文字でないので、そもそも一致しない。別の書式では、検出する。
	if got := (emailFinder{hashLen: 12}).find([]byte("email_1@bastion.example.org"), nil); len(got) != 1 {
		t.Errorf("default format: got %+v, want 1 match", got)
	}
}

// Detector を通すと、置換済みの形として残した数に数えられる。
func TestDetectorKeepsHashedFormFollowedByAtSign(t *testing.T) {
	d := newEmailDetector(t, Options{})
	check(t, d, "ssh email_3f9a1c0b7d2e@bastion.example.org", nil, 1)
	f, _ := label.ParseFormat("{type}_{n}")
	d2 := newEmailDetector(t, Options{Format: f})
	check(t, d2, "ssh email_1@bastion.example.org", nil, 1)
}
