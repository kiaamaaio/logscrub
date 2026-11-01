package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPEMUnclosedNotice(t *testing.T) {
	const b = "-----BEGIN PRIVATE KEY-----\n"
	in := "x\n" + b + "AAAA\nnot a body line\n"
	src := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(src, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	const want = "logscrub: 1 private key block had no END line (line 2). Check the lines after it before sharing.\n"
	r := run(t, "", nil, "mask", src)
	if r.code != 0 || r.stdout != "x\n"+b+"<secret_1>\nnot a body line\n" || r.stderr != want {
		t.Fatalf("%+v", r)
	}
	back := run(t, r.stdout, nil, "restore", "--source", src)
	if back.code != 0 || back.stdout != in || !strings.Contains(back.stderr, want) {
		t.Errorf("%+v", back)
	}
	two := run(t, b+"line one here\n"+b+"line two here\n", nil, "mask")
	if two.stderr != "logscrub: 2 private key blocks had no END line (lines 1, 3). Check the lines after them before sharing.\n" {
		t.Errorf("%q", two.stderr)
	}
	var sb strings.Builder
	for range 7 {
		sb.WriteString(b + "line here\n")
	}
	many := run(t, sb.String(), nil, "mask")
	if !strings.Contains(many.stderr, "7 private key blocks had no END line (lines 1, 3, 5, 7, 9, ...)") {
		t.Errorf("%q", many.stderr)
	}
}

func TestPEMStatsAndFail(t *testing.T) {
	in := "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
	r := run(t, in, nil, "mask", "--stats", "--fail-on-detect")
	if r.code != exitDetected || r.stderr != "logscrub: secret=2\n" {
		t.Errorf("%+v", r)
	}
	if h := run(t, "", nil, "types", "--verbose"); !strings.Contains(h.stdout, "PEM private key") {
		t.Error("types --verbose lacks PEM")
	}
}
