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
	word := func(maxLen int) string {
		var sb strings.Builder
		for n := 1 + rng.Intn(maxLen); n > 0; n-- {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return sb.String()
	}
	for range 20000 {
		words := make([]string, 1+rng.Intn(6))
		for i := range words {
			words[i] = word(4)
		}
		m := newLiteralMatcher(words)
		line := []byte(word(40))
		if got, want := literalScan(m, line), refLiteralScan(words, line); !slices.Equal(got, want) {
			t.Fatalf("words %q, line %q: got %q, want %q", words, line, got, want)
		}
	}
}

func BenchmarkLiteralMatcher(b *testing.B) {
	line := bytes.Repeat([]byte("2026-10-24T12:00:00Z INFO request served by node-17 in 12ms status=200 path=/api/v1/items\n"), 1000)
	for _, n := range []int{1, 10, 1000} {
		words := make([]string, n)
		for i := range words {
			words[i] = fmt.Sprintf("project-%d-name", i)
		}
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			m := newLiteralMatcher(words)
			b.SetBytes(int64(len(line)))
			for b.Loop() {
				m.scan(line, func(int, int) {})
			}
		})
	}
}
