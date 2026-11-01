package label

import (
	"fmt"
	"slices"
	"testing"
)

func scanAnswer(t *testing.T, format, line string, skip map[string]struct{}) []string {
	t.Helper()
	f, err := ParseFormat(format)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	NewAnswerScanner(f).Scan([]byte(line), skip, func(s, e int, typ string, n int) {
		out = append(out, fmt.Sprintf("%s=%s_%d", line[s:e], typ, n))
	})
	return out
}

func TestAnswerScanForms(t *testing.T) {
	const def = "<{type}_{n}>"
	tests := []struct {
		format, line string
		want         []string
	}{
		{def, "<email_1>", []string{"<email_1>=email_1"}},
		{def, "x &lt;email_1&gt; y", []string{"&lt;email_1&gt;=email_1"}},
		{def, `x \<email_1\> y`, []string{`\<email_1\>=email_1`}},
		{def, `\<email\_1\>`, []string{`\<email\_1\>=email_1`}},
		{def, `\<ipv4\_private\_12\>`, []string{`\<ipv4\_private\_12\>=ipv4_private_12`}},
		{def, `\<aws_s3\_bucket_3\>`, []string{`\<aws_s3\_bucket_3\>=aws_s3_bucket_3`}},
		// 片方だけ、方式の混在、括りなしは認めない(\<email_1> の中の <email_1> は、普通のラベル)。
		{def, `\<email_1>`, []string{`<email_1>=email_1`}},
		{def, `<email_1\>`, []string{}},
		{def, `&lt;email_1>`, []string{}},
		{def, `<email_1&gt;`, []string{}},
		{def, `&lt;email_1\>`, []string{}},
		{def, `\<email_1&gt;`, []string{}},
		{def, `email_1 email\_1`, []string{}},
		{def, `<email\_1>`, []string{}},
		{def, `&#60;email_1&#62; %3Cemail_1%3E \u003cemail_1\u003e`, []string{}},
		{def, `\<email_0\> &lt;email_01&gt; \<unknown_1\>`, []string{}},
		{"[{type}-{n}]", `\[email-1\]`, []string{`\[email-1\]=email_1`}},
		{"[{type}-{n}]", `\[email\-1\]`, []string{`\[email\-1\]=email_1`}},
		{"[{type}-{n}]", `&lt;email-1&gt;`, []string{}},
		{"<{type}:{n}>", `&lt;email:1&gt;`, []string{`&lt;email:1&gt;=email_1`}},
		{"{{n}:{type}}", `\{3:uuid\}`, []string{`\{3:uuid\}=uuid_3`}},
		{"{type}_{n}", `email\_1 ipv4\_global\_2 email_3`, []string{`email\_1=email_1`, `ipv4\_global\_2=ipv4_global_2`, `email_3=email_3`}},
		{`"{type}#{n}"`, `&quot;email#1&quot;`, []string{`&quot;email#1&quot;=email_1`}},
	}
	for _, tt := range tests {
		if got := scanAnswer(t, tt.format, tt.line, nil); !slices.Equal(got, tt.want) {
			t.Errorf("format %q, line %q: got %q, want %q", tt.format, tt.line, got, tt.want)
		}
	}
}

func TestAnswerScanSkip(t *testing.T) {
	skip := map[string]struct{}{"&lt;email_1&gt;": {}}
	got := scanAnswer(t, "<{type}_{n}>", `&lt;email_1&gt; &lt;email_2&gt;`, skip)
	if !slices.Equal(got, []string{"&lt;email_2&gt;=email_2"}) {
		t.Errorf("got %q", got)
	}
}

func TestScanEscapedReportsOnlyEscapedForms(t *testing.T) {
	line := `<email_1> &lt;email_2&gt; \<uuid_3\> x&y\z`
	var got []string
	NewAnswerScanner(DefaultFormat).ScanEscaped([]byte(line), func(form []byte) { got = append(got, string(form)) })
	if want := []string{"&lt;email_2&gt;", `\<uuid_3\>`}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestScanEscapedWithoutBrackets(t *testing.T) {
	f, _ := ParseFormat("{type}_{n}")
	var got []string
	NewAnswerScanner(f).ScanEscaped([]byte(`email_1 & email\_2`), func(form []byte) { got = append(got, string(form)) })
	if want := []string{`email\_2`}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Format.Scan は、崩れた形を読まない(検出の保護範囲と連番を変えないため)。
func TestFormatScanIgnoresEscapedForms(t *testing.T) {
	DefaultFormat.Scan([]byte(`&lt;email_1&gt; \<email_1\>`), func(s, e int, _ string, _ int) {
		t.Errorf("unexpected label at %d-%d", s, e)
	})
}
