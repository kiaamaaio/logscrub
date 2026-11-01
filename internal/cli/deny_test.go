package cli

import (
	"strings"
	"testing"
)

const testKey = "k"

func hashEnv() map[string]string { return map[string]string{"LOGSCRUB_KEY": testKey} }

func TestDenyMaskAndRestore(t *testing.T) {
	dir := t.TempDir()
	in := "Acme and ACME and acme-prod\nacmerica\n"
	src := writeFile(t, dir, "in.log", in)
	m := run(t, "", nil, "mask", src, "--deny", "acme")
	want := "<custom_1> and <custom_2> and <custom_3>-prod\nacmerica\n"
	if m.code != 0 || m.stdout != want {
		t.Fatalf("code %d, stdout %q", m.code, m.stdout)
	}
	r := run(t, m.stdout, nil, "restore", "--source", src, "--deny", "acme")
	if r.code != 0 || r.stdout != in {
		t.Errorf("restore: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	again := run(t, m.stdout, nil, "mask", "--deny", "acme")
	if again.stdout != m.stdout {
		t.Errorf("not idempotent: %q", again.stdout)
	}
}

func TestDenyWithTypes(t *testing.T) {
	line := "acme taro@example.com 10.0.0.1\n"
	r := run(t, line, nil, "mask", "--types", "email", "--deny", "acme")
	if r.stdout != "<custom_1> <email_1> 10.0.0.1\n" {
		t.Errorf("got %q", r.stdout)
	}
	r = run(t, line, nil, "mask", "--types", "custom", "--deny", "acme")
	if r.stdout != "<custom_1> taro@example.com 10.0.0.1\n" {
		t.Errorf("got %q", r.stdout)
	}
	for _, args := range [][]string{{"--types", "custom"}, {"--types", "default,custom"}, {"--types", "host"}} {
		r := run(t, line, nil, append([]string{"mask"}, args...)...)
		if r.code != exitError {
			t.Errorf("%v: code %d", args, r.code)
		}
	}
}

func TestDenyFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "words", "\xef\xbb\xbfAcme\r\n\r\n# comment\n  Foo Bar\t\n#x\nlast")
	r := run(t, "acme x foo bar LAST # comment comment\n", nil, "mask", "--deny-file", p, "--stats")
	if r.stdout != "<custom_1> x <custom_2> <custom_3> # comment comment\n" {
		t.Errorf("got %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "custom=3") {
		t.Errorf("stderr %q", r.stderr)
	}
}

func TestDenyFileEmptyIsAllowed(t *testing.T) {
	p := writeFile(t, t.TempDir(), "words", "# nothing yet\n\n")
	r := run(t, "taro@example.com\n", nil, "mask", "--deny-file", p)
	if r.code != 0 || r.stdout != "<email_1>\n" {
		t.Errorf("code %d, stdout %q", r.code, r.stdout)
	}
	r = run(t, "taro@example.com\n", nil, "mask", "--types", "custom", "--deny-file", p)
	if r.code != 0 || r.stdout != "taro@example.com\n" {
		t.Errorf("code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestDenyErrorsHideTheWords(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "words", "ok\nsecret\rword\n")
	r := run(t, "x\n", nil, "mask", "--deny-file", p)
	if r.code != exitError || !strings.Contains(r.stderr, "line 2") {
		t.Errorf("code %d, stderr %q", r.code, r.stderr)
	}
	noLeak(t, r, "secret", "word\n")
	r = run(t, "x\n", nil, "mask", "--deny", "secret\nword")
	if r.code != exitError {
		t.Errorf("code %d", r.code)
	}
	noLeak(t, r, "secret")
	if r := run(t, "x\n", nil, "mask", "--deny", ""); r.code != exitError {
		t.Errorf("empty --deny: code %d", r.code)
	}
	if r := run(t, "x\n", nil, "mask", "--deny-file", dir+"/none"); r.code != exitError {
		t.Errorf("missing file: code %d", r.code)
	}
}

func TestDenyFileIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	content := "acme\n"
	p := writeFile(t, dir, "words", content)
	in := writeFile(t, dir, "in", "acme\n")
	for _, args := range [][]string{
		{"mask", in, "--deny-file", p, "-o", p},
		{"restore", "--source", in, in, "--deny-file", p, "-o", p},
	} {
		r := run(t, "", nil, args...)
		if r.code != exitError || !strings.Contains(r.stderr, "also an input file") {
			t.Errorf("%v: code %d, stderr %q", args, r.code, r.stderr)
		}
		if got := readFile(t, p); got != content {
			t.Errorf("%v: the file was changed: %q", args, got)
		}
	}
}

func TestDomainMaskAndRestore(t *testing.T) {
	dir := t.TempDir()
	in := "curl https://internal.corp.example.co.jp/api\npostgres://app:s3cret@db.example.co.jp/ taro@example.co.jp\n"
	src := writeFile(t, dir, "in.log", in)
	args := []string{"--domain", "example.co.jp"}
	m := run(t, "", nil, append([]string{"mask", src}, args...)...)
	want := "curl https://<host_1>/api\npostgres://app:<secret_1>@<host_2>/ <email_1>\n"
	if m.stdout != want {
		t.Fatalf("got %q", m.stdout)
	}
	r := run(t, m.stdout, nil, append([]string{"restore", "--source", src}, args...)...)
	if r.stdout != in {
		t.Errorf("restore: %q", r.stdout)
	}
	if again := run(t, m.stdout, nil, append([]string{"mask"}, args...)...); again.stdout != m.stdout {
		t.Errorf("not idempotent: %q", again.stdout)
	}
	h := run(t, in, hashEnv(), append([]string{"mask", "--mode", "hash"}, args...)...)
	if again := run(t, h.stdout, hashEnv(), append([]string{"mask", "--mode", "hash"}, args...)...); again.stdout != h.stdout {
		t.Errorf("hash not idempotent:\n%q\n%q", h.stdout, again.stdout)
	}
}

func TestDomainWithoutEmail(t *testing.T) {
	r := run(t, "taro@example.co.jp\n", nil, "mask", "--types", "host", "--domain", "example.co.jp")
	if r.stdout != "taro@<host_1>\n" {
		t.Errorf("got %q", r.stdout)
	}
}

func TestEmailHashLocalHidesGivenValues(t *testing.T) {
	line := "taro@acme.co.jp taro@corp.example.co.jp taro@example.org\n"
	args := []string{"mask", "--mode", "hash", "--email-hash", "local", "--deny", "acme", "--domain", "example.co.jp"}
	r := run(t, line, hashEnv(), args...)
	f := strings.Fields(r.stdout)
	if len(f) != 3 || !strings.HasPrefix(f[0], "email_") || !strings.HasPrefix(f[1], "email_") ||
		!strings.HasPrefix(f[2], "hash_") || !strings.HasSuffix(f[2], "@example.org") {
		t.Fatalf("got %q", r.stdout)
	}
	if strings.Contains(r.stdout, "acme") || strings.Contains(r.stdout, "example.co.jp") {
		t.Errorf("the given value remains: %q", r.stdout)
	}
	if again := run(t, r.stdout, hashEnv(), args...); again.stdout != r.stdout {
		t.Errorf("not idempotent: %q", again.stdout)
	}
}

func TestDomainInvalid(t *testing.T) {
	for _, d := range []string{"https://example.jp", "*.example.jp", ".example.jp", ""} {
		if r := run(t, "x\n", nil, "mask", "--domain", d); r.code != exitError {
			t.Errorf("%q: code %d", d, r.code)
		}
	}
}

func TestStatsOrderOfNewTypes(t *testing.T) {
	r := run(t, "acme db.example.jp x@y.org\n", nil, "mask", "--stats", "--deny", "acme", "--domain", "example.jp")
	if !strings.HasSuffix(r.stderr, "logscrub: host=1\nlogscrub: custom=1\n") {
		t.Errorf("stderr %q", r.stderr)
	}
}

func TestFailOnDetectCountsDeny(t *testing.T) {
	if r := run(t, "acme\n", nil, "mask", "--fail-on-detect", "--deny", "acme"); r.code != exitDetected {
		t.Errorf("code %d", r.code)
	}
}
