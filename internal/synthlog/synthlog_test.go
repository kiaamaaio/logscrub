package synthlog

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func generate(t *testing.T, c Config) ([]byte, Stats) {
	t.Helper()
	var buf bytes.Buffer
	st, err := Generate(&buf, c)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), st
}

// 同じ設定なら、出力は 1 バイトも変わらない(ベンチマークの再現性)。
func TestGenerateIsDeterministic(t *testing.T) {
	c := Config{Size: 2 << 20, Seed: 7, LongLineEvery: 1 << 20}
	a, sa := generate(t, c)
	b, sb := generate(t, c)
	if !bytes.Equal(a, b) || sa != sb {
		t.Error("same config produced different output")
	}
	c.Seed = 8
	other, _ := generate(t, c)
	if bytes.Equal(a, other) {
		t.Error("different seeds produced the same output")
	}
}

func TestGenerateSize(t *testing.T) {
	const size = 3 << 20
	out, st := generate(t, Config{Size: size, Seed: 1})
	if len(out) < size || len(out) > size+4096 {
		t.Errorf("len = %d, want in [%d, %d]", len(out), size, size+4096)
	}
	if st.Bytes != len(out) {
		t.Errorf("Stats.Bytes = %d, want %d", st.Bytes, len(out))
	}
	if out[len(out)-1] != '\n' {
		t.Error("output does not end with a newline")
	}
	if bytes.Contains(out, []byte("\r")) {
		t.Error("output contains CR")
	}
}

// Q29: 1 行 200 バイト前後、約 30% の行に何らかの検出対象がある。
func TestGenerateLineShape(t *testing.T) {
	out, st := generate(t, Config{Size: 4 << 20, Seed: 3})
	if st.LongLines != 0 {
		t.Errorf("LongLines = %d, want 0 when LongLineEvery is 0", st.LongLines)
	}
	avg := float64(st.Bytes) / float64(st.Lines)
	if avg < 150 || avg > 260 {
		t.Errorf("average line length = %.1f, want about 200", avg)
	}
	ratio := float64(st.TargetLines) / float64(st.Lines)
	if ratio < 0.25 || ratio > 0.35 {
		t.Errorf("target line ratio = %.3f, want about 0.30", ratio)
	}
	if got := bytes.Count(out, []byte("\n")); got != st.Lines {
		t.Errorf("newline count = %d, Stats.Lines = %d", got, st.Lines)
	}
}

// Q29: 1MB の JSON 行を少し混ぜる。
func TestGenerateLongJSONLines(t *testing.T) {
	out, st := generate(t, Config{Size: 5 << 20, Seed: 1, LongLineEvery: 2 << 20})
	if st.LongLines < 2 {
		t.Fatalf("LongLines = %d, want at least 2", st.LongLines)
	}
	found := 0
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(line) < 1<<20 {
			continue
		}
		found++
		if !json.Valid(line) {
			t.Errorf("long line (%d bytes) is not valid JSON", len(line))
		}
	}
	if found != st.LongLines {
		t.Errorf("found %d long lines, Stats.LongLines = %d", found, st.LongLines)
	}
}

// 検出対象の行には、仕様の各種別に当たる値が含まれる。
func TestGenerateContainsEveryKindOfTarget(t *testing.T) {
	out, _ := generate(t, Config{Size: 4 << 20, Seed: 1})
	for _, marker := range []string{"@example.", "AKIA", "ghp_", "Bearer ", "password=", "10.", "203.0.113.", "::", "-4"} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("output lacks marker %q", marker)
		}
	}
}

func TestGenerateWithoutTargetsHasNoAt(t *testing.T) {
	// 検出対象でない行には、'@' が含まれない(email の前処理の効果を測れるように)。
	out, _ := generate(t, Config{Size: 1 << 20, Seed: 5})
	for _, line := range bytes.Split(out, []byte("\n")) {
		if bytes.Contains(line, []byte("@")) && !bytes.Contains(line, []byte("@example.")) {
			t.Fatalf("unexpected '@' in line: %q", line)
		}
	}
}

// ValuePool を指定すると、検出対象の値の種類数が、その数以下に抑えられる(メモリ測定用)。
func TestGenerateValuePoolBoundsDistinctValues(t *testing.T) {
	const pool = 40
	out, st := generate(t, Config{Size: 3 << 20, Seed: 2, LongLineEvery: 1 << 20, ValuePool: pool})
	if st.TargetLines == 0 || st.LongLines == 0 {
		t.Fatalf("stats = %+v", st)
	}
	re := regexp.MustCompile(strings.Join([]string{
		`[a-z0-9]+@example\.[a-z.]+`,
		`\b\d+\.\d+\.\d+\.\d+\b`,
		`AKIA[A-Z0-9]{16}`,
		`ghp_[A-Za-z0-9]{36}`,
		`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`,
		`Bearer [A-Za-z0-9_-]{40}`,
		`(?:password|api_key|db_password)=[A-Za-z0-9]+`,
		`(?:2001:db8|fe80|fd00)::[0-9a-f:]+`,
	}, "|"))
	distinct := map[string]struct{}{}
	for _, m := range re.FindAll(out, -1) {
		distinct[string(m)] = struct{}{}
	}
	if len(distinct) == 0 || len(distinct) > pool {
		t.Errorf("distinct values = %d, want 1..%d", len(distinct), pool)
	}
	// ValuePool なしでは、値の種類数が、大きく増える(この確認が、上の確認の意味を保つ)
	free, _ := generate(t, Config{Size: 3 << 20, Seed: 2, LongLineEvery: 1 << 20})
	freeDistinct := map[string]struct{}{}
	for _, m := range re.FindAll(free, -1) {
		freeDistinct[string(m)] = struct{}{}
	}
	if len(freeDistinct) < 20*pool {
		t.Errorf("without a pool: distinct values = %d, want many more than %d", len(freeDistinct), pool)
	}
}

func TestGenerateValuePoolIsDeterministicAndValid(t *testing.T) {
	c := Config{Size: 2 << 20, Seed: 4, LongLineEvery: 1 << 20, ValuePool: 25}
	a, _ := generate(t, c)
	b, _ := generate(t, c)
	if !bytes.Equal(a, b) {
		t.Error("same config produced different output")
	}
	for _, line := range bytes.Split(a, []byte("\n")) {
		if len(line) >= 1<<20 && !json.Valid(line) {
			t.Fatal("a long line is not valid JSON")
		}
	}
}
