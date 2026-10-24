package label

import (
	"strings"
	"testing"
)

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
		// hash の出力形(<種別>_<hex>)も、同じく、置換済みの形
		{"email_3f9a1c0b7d2e", 12, true},
		{"ipv4_global_3f9a1c0b7d2e", 12, true},
		{"ipv4_private_3f9a1c0b7d2e", 12, true},
		{"ipv6_global_3f9a1c0b7d2e", 12, true},
		{"ipv6_private_3f9a1c0b7d2e", 12, true},
		{"secret_3f9a1c0b7d2e", 12, true},
		{"uuid_3f9a1c0b7d2e", 12, true},
		{"email_3f9a1c0b7d2e4455", 16, true},
		{"email_3f9a1c0b7d2e4455", 12, false},
		{"foo_3f9a1c0b7d2e", 12, false},
		{"ipv4_3f9a1c0b7d2e", 12, false},
		{"email_3F9A1C0B7D2E", 12, false},
		{"xemail_3f9a1c0b7d2e", 12, false},
		{"email-3f9a1c0b7d2e", 12, false},
		{"email_", 12, false},
	}
	for _, tt := range tests {
		if got := IsHashedLocalPart([]byte(tt.local), tt.hexLen); got != tt.want {
			t.Errorf("IsHashedLocalPart(%q, %d) = %v, want %v", tt.local, tt.hexLen, got, tt.want)
		}
	}
}

func TestHashedAt(t *testing.T) {
	tests := []struct {
		in     string
		i      int
		hexLen int
		want   int
	}{
		{"hash_3f9a1c0b7d2e", 0, 12, 17},
		{"email_3f9a1c0b7d2eemail_2ec9724db863", 0, 12, 18},
		{"email_3f9a1c0b7d2eemail_2ec9724db863", 18, 12, 36},
		{"xhash_3f9a1c0b7d2e@", 1, 12, 18}, // 前後の文字は見ない
		{"ipv4_global_3f9a1c0b7d2e", 0, 12, 24},
		{"email_3f9a1c0b7d2", 0, 12, -1},
		{"email_3F9A1C0B7D2E", 0, 12, -1},
		{"foo_3f9a1c0b7d2e", 0, 12, -1},
		{"hash_3f9a1c0b7d2e", 0, 0, -1},
		{"hash_3f9a1c0b7d2e", 17, 12, -1},
		{"hash_3f9a1c0b7d2e", 18, 12, -1},
	}
	for _, tt := range tests {
		if got := HashedAt([]byte(tt.in), tt.i, tt.hexLen); got != tt.want {
			t.Errorf("HashedAt(%q, %d, %d) = %d, want %d", tt.in, tt.i, tt.hexLen, got, tt.want)
		}
	}
}

// ドメインの末尾が、後ろの `hash_<hex>@` の `hash` に食い込むなら、その手前で終える(Q69)。
func TestDomainEndBeforeHashed(t *testing.T) {
	tests := []struct {
		in   string
		want int // b[2:] のドメインの末尾
	}{
		{"x@0.AAhash_387ee2c18c54@0.AA", 6},
		{"x@a.example.comhash_387ee2c18c54@0.AA", 15},
		{"x@a.bhash_387ee2c18c54@0.AA", -1},   // 手前で終えるとドメインにならない
		{"x@a.co.bhash_387ee2c18c54@0.AA", 6}, // 手前の英字だけのラベルで終える
		{"x@0.AAhash_387ee2c18c54x@0.AA", 10}, // `@` が続かない
		{"x@0.AAhash_387ee2c18c5@0.AA", 10},   // 桁数が違う
		{"x@0.AAhash_387EE2C18C54@0.AA", 10},  // 大文字
		{"x@0.AAhash_387ee2c18c54", 10},       // 行末
		{"x@0.AAxhash_387ee2c18c54@0.AA", 7},  // 食い込んだ `hash` の手前
		{"x@0.AAemail_387ee2c18c54@0.AA", 11}, // `hash_` でない
		{"x@0.hash_387ee2c18c54@0.AA", -1},    // TLD が `hash` だけ
	}
	for _, tt := range tests {
		b := []byte(tt.in)
		if got := DomainEndBeforeHashed(b, 2, EmailDomainEnd(b, 2), 12); got != tt.want {
			t.Errorf("DomainEndBeforeHashed(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestFormatIsLabel(t *testing.T) {
	for _, tt := range []struct {
		format string
		in     string
		want   bool
	}{
		{"<{type}_{n}>", "<email_1>", true},
		{"<{type}_{n}>", "email_1", false},
		{"<{type}_{n}>", "<email_1>x", false},
		{"<{type}_{n}>", "x<email_1>", false},
		{"<{type}_{n}>", "<email_01>", false},
		{"{type}_{n}", "email_1", true},
		{"{type}_{n}", "email_12", true},
		{"{type}_{n}", "email_1x", false},
		{"{type}_{n}", "xemail_1", false},
		{"{type}_{n}", "email_0", false},
		{"[{type}-{n}]", "[secret-3]", true},
		{"{n}-{type}", "7-uuid", true},
		{"{type}_{n}", "", false},
	} {
		f, err := ParseFormat(tt.format)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.IsLabel([]byte(tt.in)); got != tt.want {
			t.Errorf("%q.IsLabel(%q) = %v, want %v", tt.format, tt.in, got, tt.want)
		}
	}
	if (Format{}).IsLabel([]byte("<email_1>")) {
		t.Error("the zero Format matched")
	}
}

func TestFormatEndsAt(t *testing.T) {
	for _, tt := range []struct {
		format string
		line   string
		e      int
		want   bool
	}{
		{"<{type}_{n}>", "<email_1>passwd", 9, true},
		{"<{type}_{n}>", "x<ipv4_global_12>y", 17, true},
		{"<{type}_{n}>", "<aws_s3_bucket_" + strings.Repeat("9", 18) + ">", 34, true}, // 最も長い種別名と連番
		{"<{type}_{n}>", "<email_1>passwd", 8, false},
		{"<{type}_{n}>", "<email_1>passwd", 10, false},
		{"<{type}_{n}>", "email_1>", 8, false},
		{"<{type}_{n}>", "<email_0>", 9, false},
		{"<{type}_{n}>", "<email_1>", 0, false},
		{"<{type}_{n}>", "<email_1>", 10, false},
		{"{type}_{n}", "email_12", 8, true},
		{"{type}_{n}", "email_12", 7, false}, // 連番の途中
		{"{type}_{n}", "xemail_1", 8, true},  // 前の文字は見ない(Scan と違い、e で終わるものを探す)
		{"[{type}-{n}]", "a[secret-3]b", 11, true},
		{"{n}-{type}", "7-uuid", 6, true},
	} {
		f, err := ParseFormat(tt.format)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.EndsAt([]byte(tt.line), tt.e); got != tt.want {
			t.Errorf("%q.EndsAt(%q, %d) = %v, want %v", tt.format, tt.line, tt.e, got, tt.want)
		}
	}
	if (Format{}).EndsAt([]byte("<email_1>"), 9) {
		t.Error("the zero Format matched")
	}
}
