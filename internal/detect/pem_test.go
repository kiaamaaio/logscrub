package detect

import (
	"strings"
	"testing"
)

const pemTestBody = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpamts"

func scanPEM(t *testing.T, text string) ([]string, *PEMScanner) {
	t.Helper()
	d, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := d.NewPEMScanner(0)
	spans := s.Scan([]byte(text), nil)
	s.Finish()
	var got []string
	for _, sp := range spans {
		end := strings.IndexByte(text[sp.Pos:], '\n')
		line := text[sp.Pos:]
		if end >= 0 {
			line = line[:end]
		}
		got = append(got, line[sp.Start:sp.End])
	}
	return got, s
}

func TestPEMScanner(t *testing.T) {
	const b, e = "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"
	tail := strings.Repeat("A", 40)
	cases := []struct {
		name     string
		text     string
		want     []string
		unclosed int
	}{
		{"multiple lines", b + "\nAAAA\nBBBB==\n" + e + "\nafter\n", []string{"AAAA", "BBBB=="}, 0},
		{"no marker word", "-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n", nil, 0},
		{"certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", nil, 0},
		{"public key", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", nil, 0},
		{"no word", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", []string{"AAAA"}, 0},
		{"openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", []string{"AAAA"}, 0},
		{"encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", []string{"AAAA"}, 0},
		{"pgp", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n",
			[]string{"Version: GnuPG v2", "AAAA"}, 0},
		{"headers", b + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123\n\nAAAA\n" + e + "\n",
			[]string{"Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0123", "AAAA"}, 0},
		{"indented", "  " + b + "\n  AAAA  \n  " + e + "\n", []string{"AAAA"}, 0},
		{"key on the END line", b + "\nAAAA\nBBBB" + e + "\n", []string{"AAAA", "BBBB"}, 0},
		{"a time stamp on each line", "t=1 " + b + "\nt=2 " + tail + "\nt=3 " + e + "\n", []string{tail}, 0},
		{"no END: the log goes on", b + "\nAAAA\nerror: connection closed\nBBBB\n", []string{"AAAA"}, 1},
		{"no END at the end of the input", b + "\nAAAA\n", []string{"AAAA"}, 1},
		{"a header after the body ends the block", b + "\nAAAA\nINFO: done\nBBBB\n", []string{"AAAA"}, 1},
		{"only the marker in a string", `"` + b + `"` + "\nnext line here\n", nil, 0},
		{"the marker in a sentence", "expected " + b + " got foo\nnext\n", nil, 0},
		{"the marker before a log line", b + "\nnext line here\nAAAA\n", nil, 1},
		{"a new BEGIN ends the block", b + "\nAAAA\n" + b + "\nBBBB\n" + e + "\n", []string{"AAAA", "BBBB"}, 1},
		{"one line with \\n", `{"pem":"` + b + `\nAAAA\nBBBB\n` + e + `\n"}` + "\n", []string{`\nAAAA\nBBBB\n`}, 0},
		{"one line with spaces", "KEY=" + b + " AAAA BBBB " + e + "\n", []string{" AAAA BBBB "}, 0},
		{"two keys on one line", b + "AAAA" + e + " " + b + "BBBB" + e + "\n", []string{"AAAA", "BBBB"}, 0},
		{"one line without END", `{"pem":"` + b + `\nAAAA...` + `"}` + "\n", []string{`\nAAAA...`}, 0},
		{"one line without END, escaped quote", `{\"pem\":\"` + b + `\nAAAA\"}` + "\n", []string{`\nAAAA`}, 0},
		{"one line without END after a space", b + " " + strings.Repeat("A", 16) + " x\n", []string{" " + strings.Repeat("A", 16) + " x"}, 0},
		{"replaced lines keep the block", b + "\n<secret_1>\nsecret_3f9a1c0b7d2e\nAAAA\n" + e + "\n", []string{"AAAA"}, 0},
		{"other labels end the block", b + "\n<email_1>\nAAAA\n", nil, 1},
		{"an incomplete marker", "-----BEGIN RSA PRIVATE KEY\nAAAA\n", nil, 0},
	}
	for _, c := range cases {
		got, s := scanPEM(t, c.text)
		if strings.Join(got, "|") != strings.Join(c.want, "|") || s.Unclosed != c.unclosed {
			t.Errorf("%s: got %q (unclosed %d), want %q (%d)", c.name, got, s.Unclosed, c.want, c.unclosed)
		}
	}
}

// 行番号は、ブロックと入力をまたいで通しで数える(仕様 6 章)。
func TestPEMScannerLineNumbers(t *testing.T) {
	d, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	const b = "-----BEGIN PRIVATE KEY-----\n"
	s := d.NewPEMScanner(10)
	s.Scan([]byte("a\nb\n"), nil)         // 11、12 行目
	s.Scan([]byte("c\n"+b+"AAAA\n"), nil) // 13〜15 行目
	s.Finish()
	s.Scan([]byte("last"), nil) // 16 行目。改行なしで入力が終わる
	s.Finish()
	s.Scan([]byte(b), nil) // 17 行目
	s.Finish()
	if s.Unclosed != 2 || len(s.UnclosedLines) != 2 || s.UnclosedLines[0] != 14 || s.UnclosedLines[1] != 17 {
		t.Errorf("%d %v", s.Unclosed, s.UnclosedLines)
	}
}

func TestPEMScannerUnclosedLinesAreLimited(t *testing.T) {
	var sb strings.Builder
	for range MaxUnclosedLines + 2 {
		sb.WriteString("-----BEGIN PRIVATE KEY-----\nnot a body line\n")
	}
	if _, s := scanPEM(t, sb.String()); s.Unclosed != MaxUnclosedLines+2 || len(s.UnclosedLines) != MaxUnclosedLines {
		t.Errorf("%d %v", s.Unclosed, s.UnclosedLines)
	}
}

func TestNewPEMScannerNeedsSecret(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindEmail)})
	if err != nil {
		t.Fatal(err)
	}
	if d.NewPEMScanner(0) != nil {
		t.Error("secret is off, but a scanner was made")
	}
}

// 不完全な印が続く長い行でも、線形の時間で終わる。
func TestFindPEMMarkerLongLine(t *testing.T) {
	line := []byte(strings.Repeat("-----BEGIN ", 200000))
	if _, _, ok := findPEMMarker(line, 0, "-----BEGIN "); ok {
		t.Error("found a marker")
	}
}

// 本文の行は、--allow と保護範囲の規則に従い、ほかの種別の検出を行わない。
func TestFindSpansBody(t *testing.T) {
	d, err := New(Options{Allow: map[string]struct{}{"allowed": {}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		line string
		want []Match
		kept int
	}{
		{pemTestBody, []Match{{Start: 0, End: len(pemTestBody), Kind: KindSecret}}, 0},
		{"allowed", nil, 0},
		{"<secret_1>", nil, 1},
	} {
		got, kept := d.FindSpans([]byte(c.line), []PEMSpan{{Start: 0, End: len(c.line), Body: true}}, nil)
		if kept != c.kept || len(got) != len(c.want) || len(got) > 0 && got[0] != c.want[0] {
			t.Errorf("%q: %+v, kept %d", c.line, got, kept)
		}
	}
	line := "a@example.com -----END PRIVATE KEY-----"
	got, _ := d.FindSpans([]byte(line), []PEMSpan{{Start: 0, End: 1}}, nil)
	if len(got) != 1 || got[0].Kind != KindEmail {
		t.Errorf("a span without Body must keep the other detectors: %+v", got)
	}
}
