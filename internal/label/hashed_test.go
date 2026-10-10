package label

import (
	"fmt"
	"testing"
)

func scanHashed(line string, hexLen int) []string {
	var got []string
	ScanHashed([]byte(line), hexLen, func(start, end int) {
		got = append(got, line[start:end])
	})
	return got
}

// hash モードの出力形(<種別>_<hex>、hash_<hex>@ドメイン)を、置換済みの値として見つける。
func TestScanHashedFindsHashOutputs(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		hexLen int
		want   []string
	}{
		{"email full", "email_3f9a1c0b7d2e", 12, []string{"email_3f9a1c0b7d2e"}},
		{"ipv4 global", "ipv4_global_a1b2c3d4e5f6", 12, []string{"ipv4_global_a1b2c3d4e5f6"}},
		{"ipv4 private", "ipv4_private_a1b2c3d4e5f6", 12, []string{"ipv4_private_a1b2c3d4e5f6"}},
		{"ipv6 global", "ipv6_global_a1b2c3d4e5f6", 12, []string{"ipv6_global_a1b2c3d4e5f6"}},
		{"ipv6 private", "ipv6_private_a1b2c3d4e5f6", 12, []string{"ipv6_private_a1b2c3d4e5f6"}},
		{"secret", "secret_3f9a1c0b7d2e", 12, []string{"secret_3f9a1c0b7d2e"}},
		{"uuid", "uuid_3f9a1c0b7d2e", 12, []string{"uuid_3f9a1c0b7d2e"}},
		{"in key value", "password=secret_3f9a1c0b7d2e&user=x", 12, []string{"secret_3f9a1c0b7d2e"}},
		{"in json", `{"api_key": "secret_3f9a1c0b7d2e"}`, 12, []string{"secret_3f9a1c0b7d2e"}},
		{"in parentheses", "(email_3f9a1c0b7d2e)", 12, []string{"email_3f9a1c0b7d2e"}},
		{"trailing period", "sent to email_3f9a1c0b7d2e.", 12, []string{"email_3f9a1c0b7d2e"}},
		{"after underscore", "my_email_3f9a1c0b7d2e", 12, []string{"email_3f9a1c0b7d2e"}},
		{"between japanese", "値email_3f9a1c0b7d2e値", 12, []string{"email_3f9a1c0b7d2e"}},
		{"two", "email_3f9a1c0b7d2e -> ipv4_global_000000000000", 12, []string{"email_3f9a1c0b7d2e", "ipv4_global_000000000000"}},
		{"hash length 16", "email_3f9a1c0b7d2e4455", 16, []string{"email_3f9a1c0b7d2e4455"}},
		{"hash length 8", "email_3f9a1c0b", 8, []string{"email_3f9a1c0b"}},

		{"email local", "hash_3f9a1c0b7d2e@example.com", 12, []string{"hash_3f9a1c0b7d2e@example.com"}},
		{"email local in text", "from <hash_3f9a1c0b7d2e@example.com> ok", 12, []string{"hash_3f9a1c0b7d2e@example.com"}},
		{"email local after colon", "mailto:hash_3f9a1c0b7d2e@example.com", 12, []string{"hash_3f9a1c0b7d2e@example.com"}},
		{"email local subdomain", "hash_3f9a1c0b7d2e@mail.example.co.jp", 12, []string{"hash_3f9a1c0b7d2e@mail.example.co.jp"}},
		{"email local trailing period", "to hash_3f9a1c0b7d2e@example.com.", 12, []string{"hash_3f9a1c0b7d2e@example.com"}},
		{"email local trailing comma", "hash_3f9a1c0b7d2e@example.com,x", 12, []string{"hash_3f9a1c0b7d2e@example.com"}},
		{"email local length 16", "hash_3f9a1c0b7d2e4455@example.com", 16, []string{"hash_3f9a1c0b7d2e4455@example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanHashed(tt.line, tt.hexLen); !equal(got, tt.want) {
				t.Errorf("ScanHashed(%q, %d) = %q, want %q", tt.line, tt.hexLen, got, tt.want)
			}
		})
	}
}

// 本物の値と区別するため、桁数・小文字・前後の文字・種別名が合うものだけを置換済みとみなす(Q10)。
func TestScanHashedIgnoresLookalikes(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		hexLen int
	}{
		{"11 digits", "email_3f9a1c0b7d2", 12},
		{"13 digits", "email_3f9a1c0b7d2e1", 12},
		{"13 digits then letter", "secret_3f9a1c0b7d2ez", 12},
		{"uppercase hex", "email_3F9A1C0B7D2E", 12},
		{"not hex", "email_3f9a1c0b7d2g", 12},
		{"alnum before", "xemail_3f9a1c0b7d2e", 12},
		{"digit before", "1secret_3f9a1c0b7d2e", 12},
		{"unknown type", "foo_3f9a1c0b7d2e", 12},
		{"type without distinction", "ipv4_3f9a1c0b7d2e", 12},
		{"hash length mismatch", "email_3f9a1c0b7d2e", 16},
		{"plain", "just some text with_underscore and 3f9a1c0b7d2e", 12},
		{"hash local without domain", "hash_3f9a1c0b7d2e", 12},
		{"hash local with ip", "hash_3f9a1c0b7d2e@10.0.0.1", 12},
		{"hash local without tld", "hash_3f9a1c0b7d2e@localhost", 12},
		{"hash local single letter tld", "hash_3f9a1c0b7d2e@a.b", 12},
		{"hash local other local part", "x.hash_3f9a1c0b7d2e@example.com", 12},
		{"hash local alnum before", "xhash_3f9a1c0b7d2e@example.com", 12},
		{"hash local uppercase", "hash_3F9A1C0B7D2E@example.com", 12},
		{"hash local short", "hash_3f9a1c0b7d2@example.com", 12},
		{"other prefix", "mash_3f9a1c0b7d2e@example.com", 12},
		{"zero length", "email_", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanHashed(tt.line, tt.hexLen); len(got) != 0 {
				t.Errorf("ScanHashed(%q, %d) = %q, want none", tt.line, tt.hexLen, got)
			}
		})
	}
}

// 不正な UTF-8 や長い行でも、見つける位置は変わらない。
func TestScanHashedWithInvalidUTF8(t *testing.T) {
	line := "\xff\xfe email_3f9a1c0b7d2e \x80"
	if got, want := scanHashed(line, 12), []string{"email_3f9a1c0b7d2e"}; !equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestScanHashedPositions(t *testing.T) {
	line := "aa email_3f9a1c0b7d2e bb hash_000000000000@example.org cc"
	var got [][2]int
	ScanHashed([]byte(line), 12, func(start, end int) { got = append(got, [2]int{start, end}) })
	want := [][2]int{{3, 21}, {25, 54}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
