package label

import "testing"

func TestEmailDomainEnd(t *testing.T) {
	tests := []struct {
		in   string
		from int
		want int // -1 はドメインではない
	}{
		{"example.com", 0, 11},
		{"example.com.", 0, 11},
		{"example.com,x", 0, 11},
		{"example.com:8080", 0, 11},
		{"example.com/path", 0, 11},
		{"sub.example.co.jp", 0, 17},
		{"a-b.example.org", 0, 15},
		{"EXAMPLE.COM", 0, 11},
		{"example.comです", 0, 11},
		{"@example.com", 1, 12},
		// TLD は英字 2 文字以上、ドメインには '.' が必要
		{"example", 0, -1},
		{"localhost", 0, -1},
		{"example.c", 0, -1},
		{"example.c0m", 0, -1},
		{"example.123", 0, -1},
		{"10.0.0.1", 0, -1},
		{"example..com", 0, -1},
		{".com", 0, -1},
		{"", 0, -1},
		// ラベルが英字だけでない場合は、そこまでの最後の英字だけのラベルで終える
		{"a.bc.d", 0, 4},
		{"a.bc.d1", 0, 4},
		{"a.bc.com-x", 0, 4},
		{"a.b-c.com", 0, 9},
		{"example.com-", 0, -1},
	}
	for _, tt := range tests {
		if got := EmailDomainEnd([]byte(tt.in), tt.from); got != tt.want {
			t.Errorf("EmailDomainEnd(%q, %d) = %d, want %d", tt.in, tt.from, got, tt.want)
		}
	}
}

func TestIsEmailLocalChar(t *testing.T) {
	for _, c := range []byte("azAZ09._%+-") {
		if !IsEmailLocalChar(c) {
			t.Errorf("IsEmailLocalChar(%q) = false", c)
		}
	}
	for _, c := range []byte("@ ,;:/\\<>()[]\"'!#$&*=?^`{|}~\x00\x7f\x80\xff") {
		if IsEmailLocalChar(c) {
			t.Errorf("IsEmailLocalChar(%q) = true", c)
		}
	}
}

func TestIsHashedLocalPart(t *testing.T) {
	tests := []struct {
		local  string
		hexLen int
		want   bool
	}{
		{"hash_3f9a1c0b7d2e", 12, true},
		{"hash_000000000000", 12, true},
		{"hash_3f9a1c0b7d2e4455", 16, true},
		{"hash_3f9a1c0b7d2e", 16, false},
		{"hash_3f9a1c0b7d2e4455", 12, false},
		{"hash_3F9A1C0B7D2E", 12, false},
		{"hash_3f9a1c0b7d2g", 12, false},
		{"hash_3f9a1c0b7d2", 12, false},
		{"xhash_3f9a1c0b7d2e", 12, false},
		{"hash-3f9a1c0b7d2e", 12, false},
		{"Hash_3f9a1c0b7d2e", 12, false},
		{"hash_", 12, false},
		{"", 12, false},
		{"hash_3f9a1c0b7d2e", 0, false},
	}
	for _, tt := range tests {
		if got := IsHashedLocalPart([]byte(tt.local), tt.hexLen); got != tt.want {
			t.Errorf("IsHashedLocalPart(%q, %d) = %v, want %v", tt.local, tt.hexLen, got, tt.want)
		}
	}
}
