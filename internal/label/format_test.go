package label

import (
	"fmt"
	"strings"
	"testing"
)

func scan(f Format, line string) []string {
	var got []string
	f.Scan([]byte(line), func(start, end int, typ string, n int) {
		got = append(got, fmt.Sprintf("%s|%d|%s", typ, n, line[start:end]))
	})
	return got
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Q12: {type} と {n} をちょうど 1 回ずつ含み、改行を含まない書式だけを受け付ける。
func TestParseFormatAccepts(t *testing.T) {
	tests := []struct {
		format string
		typ    string
		n      int
		want   string
	}{
		{"<{type}_{n}>", "email", 1, "<email_1>"},
		{"[{type}-{n}]", "secret", 12, "[secret-12]"},
		{"{type}{n}", "uuid", 3, "uuid3"},
		{"{type}_{n}", "ipv4_global", 7, "ipv4_global_7"},
		{"{n}:{type}", "ipv6_private", 7, "7:ipv6_private"},
		{"#{type}#{n}#", "email", 2, "#email#2#"},
		{"{{type}_{n}}", "email", 1, "{email_1}"}, // { } はそのままの文字として扱う
		{"《{type}・{n}》", "email", 5, "《email・5》"},
		{"日本語{type}の{n}です", "email", 2, "日本語emailの2です"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			f, err := ParseFormat(tt.format)
			if err != nil {
				t.Fatalf("ParseFormat(%q): %v", tt.format, err)
			}
			got := string(f.Append(nil, tt.typ, tt.n))
			if got != tt.want {
				t.Errorf("Append = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFormatRejects(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"empty", ""},
		{"no placeholders", "<label>"},
		{"type only", "<{type}>"},
		{"n only", "<{n}>"},
		{"type twice", "<{type}_{type}_{n}>"},
		{"n twice", "<{type}_{n}_{n}>"},
		{"lf", "<{type}_{n}>\n"},
		{"cr", "<{type}\r_{n}>"},
		{"crlf in prefix", "\r\n{type}{n}"},
		{"wrong braces", "<type_n>"},
		{"wrong case", "<{Type}_{N}>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseFormat(tt.format); err == nil {
				t.Errorf("ParseFormat(%q) succeeded, want error", tt.format)
			}
		})
	}
}

func TestDefaultFormat(t *testing.T) {
	if got := string(DefaultFormat.Append(nil, "email", 1)); got != "<email_1>" {
		t.Errorf("DefaultFormat.Append = %q, want <email_1>", got)
	}
	if DefaultFormat.IsZero() {
		t.Error("DefaultFormat.IsZero() = true")
	}
	if !(Format{}).IsZero() {
		t.Error("Format{}.IsZero() = false")
	}
}

func TestAppendKeepsExistingBytes(t *testing.T) {
	got := string(DefaultFormat.Append([]byte("x="), "uuid", 42))
	if got != "x=<uuid_42>" {
		t.Errorf("got %q", got)
	}
}

func TestTypesAreTheDocumentedSet(t *testing.T) {
	want := []string{"email", "ipv4_global", "ipv4_private", "ipv6_global", "ipv6_private", "secret", "uuid"}
	if !equal(Types, want) {
		t.Errorf("Types = %q, want %q", Types, want)
	}
	if len(Types) != NumTypes {
		t.Errorf("len(Types) = %d, NumTypes = %d", len(Types), NumTypes)
	}
}

func TestScanDefaultFormat(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"empty line", "", nil},
		{"no label", "plain text 123", nil},
		{"one", "<email_1>", []string{"email|1|<email_1>"}},
		{"in text", "a <email_1> b <ipv4_private_12> c", []string{"email|1|<email_1>", "ipv4_private|12|<ipv4_private_12>"}},
		{"all types", "<email_1><ipv4_global_2><ipv4_private_3><ipv6_global_4><ipv6_private_5><secret_6><uuid_7>", []string{
			"email|1|<email_1>", "ipv4_global|2|<ipv4_global_2>", "ipv4_private|3|<ipv4_private_3>",
			"ipv6_global|4|<ipv6_global_4>", "ipv6_private|5|<ipv6_private_5>", "secret|6|<secret_6>", "uuid|7|<uuid_7>",
		}},
		{"adjacent", "<email_1><email_2>", []string{"email|1|<email_1>", "email|2|<email_2>"}},
		{"surrounded by text", "x<secret_3>y", []string{"secret|3|<secret_3>"}},
		{"nested opening", "<<email_1>>", []string{"email|1|<email_1>"}},
		{"key value", "password=<secret_1>&user=x", []string{"secret|1|<secret_1>"}},
		{"japanese around", "ログ<uuid_5>です", []string{"uuid|5|<uuid_5>"}},
		{"same label twice", "<email_1> and <email_1>", []string{"email|1|<email_1>", "email|1|<email_1>"}},
		{"18 digits", "<email_999999999999999999>", []string{"email|999999999999999999|<email_999999999999999999>"}},

		// ラベルとみなさないもの(Q23: 既知の種別名 + 先頭 0 なしの 1 以上の整数)
		{"zero", "<email_0>", nil},
		{"leading zero", "<email_01>", nil},
		{"no number", "<email_>", nil},
		{"no closing", "<email_1", nil},
		{"no opening", "email_1>", nil},
		{"uppercase", "<Email_1>", nil},
		{"unknown type", "<unknown_1>", nil},
		{"bare ipv4 type", "<ipv4_1>", nil},
		{"type without distinction", "<ipv4_global>", nil},
		{"wrong separator", "<email-1>", nil},
		{"spaces", "< email_1 >", nil},
		{"trailing space", "<email_1 >", nil},
		{"19 digits", "<email_1000000000000000000>", nil},
		{"non digit suffix", "<email_1a>", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scan(DefaultFormat, tt.line); !equal(got, tt.want) {
				t.Errorf("Scan(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestScanCustomFormats(t *testing.T) {
	mustParse := func(s string) Format {
		f, err := ParseFormat(s)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	tests := []struct {
		name   string
		format string
		line   string
		want   []string
	}{
		{"brackets", "[{type}-{n}]", "x [email-1] [secret-10] <email_1>", []string{"email|1|[email-1]", "secret|10|[secret-10]"}},
		{"no prefix", "{type}_{n}", "email_1 uuid_22 secret_x email_01", []string{"email|1|email_1", "uuid|22|uuid_22"}},
		{"no delimiters", "{type}{n}", "see email1 and uuid22 or uuid0", []string{"email|1|email1", "uuid|22|uuid22"}},
		{"number first", "{n}-{type}", "1-email 22-ipv6_global 0-email 1-ema", []string{"email|1|1-email", "ipv6_global|22|22-ipv6_global"}},
		{"japanese literals", "《{type}・{n}》", "値は《email・3》です", []string{"email|3|《email・3》"}},
		{"braces as literals", "{{type}_{n}}", "{email_1} {email_x}", []string{"email|1|{email_1}"}},
		{"default format does not match", "[{type}-{n}]", "<email_1>", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scan(mustParse(tt.format), tt.line); !equal(got, tt.want) {
				t.Errorf("Scan(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestScanPassesInvalidUTF8(t *testing.T) {
	line := "\xff\xfe<email_1>\x80\xc0"
	got := scan(DefaultFormat, line)
	if want := []string{"email|1|<email_1>"}; !equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Append で作ったラベルは、同じ書式の Scan でそのまま見つかる(往復)。
func TestAppendThenScanRoundTrip(t *testing.T) {
	formats := []string{"<{type}_{n}>", "[{type}-{n}]", "{type}_{n}", "{type}{n}", "{n}:{type}", "{{type}_{n}}", "《{type}・{n}》", "<{n}|{type}>"}
	numbers := []int{1, 2, 9, 10, 99, 100, 12345, 999999999999999999}
	for _, fs := range formats {
		f, err := ParseFormat(fs)
		if err != nil {
			t.Fatal(err)
		}
		for _, typ := range Types {
			for _, n := range numbers {
				lab := string(f.Append(nil, typ, n))
				line := "xx " + lab + " yy"
				want := []string{fmt.Sprintf("%s|%d|%s", typ, n, lab)}
				if got := scan(f, line); !equal(got, want) {
					t.Errorf("format %q type %q n=%d: Scan(%q) = %q, want %q", fs, typ, n, line, got, want)
				}
			}
		}
	}
}

func TestScanReportsPositionsInOrder(t *testing.T) {
	line := strings.Repeat("a", 1000) + "<email_1>" + strings.Repeat("b", 1000) + "<uuid_2>"
	var starts []int
	DefaultFormat.Scan([]byte(line), func(start, end int, typ string, n int) {
		if line[start:end] != fmt.Sprintf("<%s_%d>", typ, n) {
			t.Errorf("range %d..%d = %q", start, end, line[start:end])
		}
		starts = append(starts, start)
	})
	if len(starts) != 2 || starts[0] != 1000 || starts[1] != 2009 {
		t.Errorf("starts = %v, want [1000 2009]", starts)
	}
}
