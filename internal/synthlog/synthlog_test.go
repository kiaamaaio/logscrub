package synthlog

import (
	"bytes"
	"encoding/json"
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
