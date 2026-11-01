package detect

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// refLiteralScan は、全位置ですべての語を比べる参照実装。
func refLiteralScan(words []string, line []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range words {
		for s := 0; s+len(w) <= len(line); s++ {
			if bytes.Equal(asciiOnlyFold(line[s:s+len(w)]), asciiOnlyFold([]byte(w))) {
				k := fmt.Sprint(s, "-", s+len(w))
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// asciiOnlyFold は、ASCII だけを小文字にする。
func asciiOnlyFold(b []byte) []byte {
	c := bytes.Clone(b)
	for i := range c {
		c[i] = foldByte(c[i])
	}
	return c
}

func literalScan(m *literalMatcher, line []byte) []string {
	var out []string
	m.scan(line, func(s, e int) { out = append(out, fmt.Sprint(s, "-", e)) })
	slices.Sort(out)
	return out
}

func TestLiteralMatcherExamples(t *testing.T) {
	m := newLiteralMatcher([]string{"he", "she", "hers", "HIS", "アクメ"})
	got := literalScan(m, []byte("ushers His アクメ"))
	want := []string{"1-4", "11-20", "2-4", "2-6", "7-10"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLiteralMatcherFoldsOnlyASCII(t *testing.T) {
	m := newLiteralMatcher([]string{"Ä", "k"})
	if got := literalScan(m, []byte("ä K \xe2\x84\xaa")); !slices.Equal(got, []string{"3-4"}) { // ä は畳まず、K は一致し、KELVIN SIGN は一致しない
		t.Errorf("got %q", got)
	}
}

func TestLiteralMatcherDuplicateWords(t *testing.T) {
	m := newLiteralMatcher([]string{"abc", "ABC", "abc"})
	if got := literalScan(m, []byte("abc")); !slices.Equal(got, []string{"0-3"}) {
		t.Errorf("got %q", got)
	}
}

func TestLiteralMatcherAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := "abAB-\xe3\x82"
	word := func(minLen, maxLen int) string {
		var sb strings.Builder
		for n := minLen + rng.Intn(maxLen-minLen+1); n > 0; n-- {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return sb.String()
	}
	// minLen が 1 なら 1 バイトの語が混ざるので root で、2 なら pair で読み飛ばす。
	for _, minLen := range []int{1, 2} {
		for range 20000 {
			words := make([]string, 1+rng.Intn(6))
			for i := range words {
				words[i] = word(minLen, 4)
			}
			m := newLiteralMatcher(words)
			if minLen == 2 && m.pair == nil {
				t.Fatalf("words %q: no pair table", words)
			}
			line := []byte(word(0, 40))
			if got, want := literalScan(m, line), refLiteralScan(words, line); !slices.Equal(got, want) {
				t.Fatalf("words %q, line %q: got %q, want %q", words, line, got, want)
			}
		}
	}
}

// 語が行の端にある場合と、読み飛ばしのあとの連続する一致。
func TestLiteralMatcherSkipEdges(t *testing.T) {
	tests := []struct {
		words []string
		line  string
		want  []string
	}{
		{[]string{"ab"}, "ab", []string{"0-2"}},
		{[]string{"ab"}, "xxab", []string{"2-4"}},
		{[]string{"ab"}, "xxa", nil},
		{[]string{"ab"}, "a", nil},
		{[]string{"ab"}, "", nil},
		{[]string{"AB"}, "xaBx", []string{"1-3"}},
		{[]string{"ab", "bc"}, "abc", []string{"0-2", "1-3"}},
		{[]string{"aab"}, "aaab", []string{"1-4"}},
		{[]string{"a"}, "xxa", []string{"2-3"}},
		{[]string{"a", "bc"}, "bbc a", []string{"1-3", "4-5"}},
	}
	for _, tt := range tests {
		if got := literalScan(newLiteralMatcher(tt.words), []byte(tt.line)); !slices.Equal(got, tt.want) {
			t.Errorf("words %q, line %q: got %q, want %q", tt.words, tt.line, got, tt.want)
		}
	}
}

func BenchmarkLiteralMatcher(b *testing.B) {
	line := bytes.Repeat([]byte("2026-10-24T12:00:00Z INFO request served by node-17 in 12ms status=200 path=/api/v1/items\n"), 1000)
	project := func(n int) []string {
		words := make([]string, n)
		for i := range words {
			words[i] = fmt.Sprintf("project-%d-name", i)
		}
		return words
	}
	// varied は、子音と母音の綴りの語。dense は、先頭の 2 バイトの組が、英小文字の組をほぼ覆う語。
	varied, dense := make([]string, 1000), make([]string, 1000)
	rng := rand.New(rand.NewSource(1))
	for i := range varied {
		var sb strings.Builder
		for range 3 {
			sb.WriteByte("bdfghjkmnprstwyz"[rng.Intn(16)])
			sb.WriteByte("aeiou"[rng.Intn(5)])
		}
		varied[i] = sb.String()
		dense[i] = fmt.Sprintf("%c%cword%d", 'a'+i%26, 'a'+(i/26)%26, i)
	}
	for _, tc := range []struct {
		name  string
		words []string
	}{
		{"1", project(1)},
		{"10", project(10)},
		{"1000", project(1000)},
		{"domain", []string{"example.com"}},
		{"varied1000", varied},
		{"dense1000", dense},
	} {
		words := tc.words
		b.Run(tc.name, func(b *testing.B) {
			m := newLiteralMatcher(words)
			b.SetBytes(int64(len(line)))
			for b.Loop() {
				m.scan(line, func(int, int) {})
			}
		})
	}
}
