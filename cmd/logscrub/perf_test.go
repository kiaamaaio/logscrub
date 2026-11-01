package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// 性能とメモリの測定(仕様 7 章、plans/v1.0.0/README.md の段階 11、Q29)。時間がかかるので、-perf を付けたときだけ実行する。
//
//	./scripts/go test -run Perf -v ./cmd/logscrub -perf [-perf-size 100]
//
// ビルドしたバイナリを、子プロセスとして、合成ログに対して実行し、実時間と最大メモリ使用量(Maxrss)を測る。
var (
	perf     = flag.Bool("perf", false, "run the performance and memory measurements (slow)")
	perfSize = flag.Int("perf-size", 100, "size of the synthetic log in MB")
)

const targetMBps = 50.0 // 仕様 7 章の目標

// buildBinary は、logscrub をビルドして、そのパスを返す。
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "logscrub")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// genLog は、合成ログを、一時ファイルに作る(リポジトリの外)。
func genLog(t *testing.T, dir, name string, mb int, pool int) string {
	return genLogWith(t, dir, name, mb, pool, false)
}

// genLogWith は、genLog に、AWS の値を含めるか(synthlog.Config.AWS。plans/v1.1.0/README.md の Q39)を加えたもの。
func genLogWith(t *testing.T, dir, name string, mb int, pool int, aws bool) string {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := synthlog.Generate(f, synthlog.Config{
		Size:          mb << 20,
		Seed:          1,
		LongLineEvery: synthlog.DefaultLongLineEvery,
		ValuePool:     pool,
		AWS:           aws,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("generated %s: %d MB, %d lines, %d target lines, %d long lines", name, st.Bytes>>20, st.Lines, st.TargetLines, st.LongLines)
	return p
}

type measurement struct {
	seconds float64
	maxRSSM float64 // MB
}

// runMask は、`logscrub mask < log > /dev/null`(viaPipe なら `cat log | logscrub mask > /dev/null`)を実行して測る。
func runMask(t *testing.T, bin, logPath string, viaPipe bool, args ...string) measurement {
	t.Helper()
	return runBin(t, bin, logPath, viaPipe, nil, append([]string{"mask"}, args...)...)
}

// runBin は、`env logscrub args... < stdin > /dev/null` を実行して測る。viaPipe なら、stdin をパイプで渡す。
func runBin(t *testing.T, bin, stdin string, viaPipe bool, env []string, args ...string) measurement {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	f, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var pw *os.File
	if viaPipe {
		pr, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		pw = w
		cmd.Stdin = pr
		defer pr.Close()
	} else {
		cmd.Stdin = f
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if viaPipe {
		go func() {
			io.Copy(pw, f)
			pw.Close()
		}()
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("logscrub: %v", err)
	}
	elapsed := time.Since(start).Seconds()
	return measurement{seconds: elapsed, maxRSSM: maxRSSMB(t, cmd.ProcessState)}
}

// maskToFile は、log の mask の結果を path に書く(restore の測定の回答に使う)。
func maskToFile(t *testing.T, bin, log, path string) {
	t.Helper()
	in, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd := exec.Command(bin, "mask")
	cmd.Stdin, cmd.Stdout = in, out
	if err := cmd.Run(); err != nil {
		t.Fatalf("logscrub mask: %v", err)
	}
}

// variedWords は、子音と母音の綴りの語を n 個返す。語の先頭のバイトが多様で、文中の語に近い形(plans/v1.4.0 の Q99)。
func variedWords(n int) []string {
	const consonants, vowels = "bdfghjkmnprstwyz", "aeiou"
	rng := rand.New(rand.NewPCG(1, 2))
	ws := make([]string, n)
	for i := range ws {
		var sb strings.Builder
		for range 3 {
			sb.WriteByte(consonants[rng.IntN(len(consonants))])
			sb.WriteByte(vowels[rng.IntN(len(vowels))])
		}
		ws[i] = sb.String()
	}
	return ws
}

func TestPerfThroughput(t *testing.T) {
	if !*perf {
		t.Skip("run with -perf")
	}
	bin := buildBinary(t)
	dir := t.TempDir()
	log := genLog(t, dir, "big.log", *perfSize, 0)
	awsLog := genLogWith(t, dir, "big-aws.log", *perfSize, 0, true)
	writeWords := func(name string, ws []string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strings.Join(ws, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	words := func(n int) string {
		ws := make([]string, n)
		for i := range ws {
			ws[i] = fmt.Sprintf("project-%d-name", i)
		}
		return writeWords(fmt.Sprintf("words-%d", n), ws)
	}
	masked := filepath.Join(dir, "big.masked")
	maskToFile(t, bin, log, masked)
	for _, tc := range []struct {
		name string
		log  string // stdin
		pipe bool
		env  []string
		args []string
	}{
		{"mask, stdin from a file", log, false, nil, []string{"mask"}},
		{"mask, stdin from a pipe", log, true, nil, []string{"mask"}},
		{"mask, GOMAXPROCS=1", log, false, []string{"GOMAXPROCS=1"}, []string{"mask"}},
		{"mask, GOMAXPROCS=2", log, false, []string{"GOMAXPROCS=2"}, []string{"mask"}},
		{"mask, GOMAXPROCS=8", log, false, []string{"GOMAXPROCS=8"}, []string{"mask"}},
		{"mask with uuid", log, false, nil, []string{"mask", "--types", "default,uuid"}},
		{"aws log, default types", awsLog, false, nil, []string{"mask"}},
		{"aws log, default,aws", awsLog, false, nil, []string{"mask", "--types", "default,aws"}},
		{"aws log, without aws_host", awsLog, false, nil, []string{"mask", "--types", "default,aws_account,aws_s3_bucket"}},
		{"10 words", log, false, nil, []string{"mask", "--deny-file", words(10)}},
		{"1000 words", log, false, nil, []string{"mask", "--deny-file", words(1000)}},
		{"1000 varied words", log, false, nil, []string{"mask", "--deny-file", writeWords("words-varied", variedWords(1000))}},
		{"--domain", log, false, nil, []string{"mask", "--domain", "example.com"}},
		{"hash", log, false, []string{"LOGSCRUB_KEY=perf-key"}, []string{"mask", "--mode", "hash"}},
		// MB/s は、元の入力の大きさ。回答は、mask の結果そのもの。
		{"restore", masked, false, nil, []string{"restore", "--source", log}},
	} {
		best := measurement{seconds: 1e9}
		for i := 0; i < 3; i++ {
			m := runBin(t, bin, tc.log, tc.pipe, tc.env, tc.args...)
			if m.seconds < best.seconds {
				best = m
			}
		}
		mbps := float64(*perfSize) / best.seconds
		t.Logf("%-28s %6.1f MB/s (%.2f s for %d MB, best of 3), max RSS %.0f MB", tc.name, mbps, best.seconds, *perfSize, best.maxRSSM)
		if mbps < targetMBps {
			t.Errorf("%s: %.1f MB/s is below the target of %.0f MB/s", tc.name, mbps, targetMBps)
		}
	}
}

// 長い行が続く入力でも、最大メモリ使用量は、処理中の行の数倍に収まる(仕様 7 章)。
func TestPerfMemoryWithLongLines(t *testing.T) {
	if !*perf {
		t.Skip("run with -perf")
	}
	if !canMeasureRSS {
		t.Skip("the maximum memory usage cannot be measured on this OS")
	}
	bin := buildBinary(t)
	const lineMB = 10
	line := append([]byte(strings.Repeat("0123456789", lineMB<<20/10-1)), "012345678\n"...)
	p := filepath.Join(t.TempDir(), "long-lines.log")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	for range *perfSize / lineMB {
		if _, err := f.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, procs := range []string{"GOMAXPROCS=1", "GOMAXPROCS=2", "GOMAXPROCS=8"} {
		m := runBin(t, bin, p, false, []string{procs}, "mask")
		t.Logf("%s, %d MB lines: max RSS %.1f MB (%.1f MB/s)", procs, lineMB, m.maxRSSM, float64(*perfSize)/m.seconds)
		if limit := float64(8 * lineMB); m.maxRSSM > limit {
			t.Errorf("%s: max RSS %.1f MB is over %.0f MB", procs, m.maxRSSM, limit)
		}
	}
}

// 値の種類数が一定なら、最大メモリ使用量は、入力の大きさに比例して増えない(受け入れ基準)。
func TestPerfMemoryDoesNotGrowWithInputSize(t *testing.T) {
	if !*perf {
		t.Skip("run with -perf")
	}
	if !canMeasureRSS {
		t.Skip("the maximum memory usage cannot be measured on this OS")
	}
	bin := buildBinary(t)
	dir := t.TempDir()
	const pool = 1000
	sizes := []int{*perfSize / 5, *perfSize / 2, *perfSize}
	var rss []float64
	for _, mb := range sizes {
		log := genLog(t, dir, fmt.Sprintf("pool-%d.log", mb), mb, pool)
		m := runMask(t, bin, log, true)
		t.Logf("%4d MB log, %d distinct values: max RSS %.1f MB (%.1f MB/s)", mb, pool, m.maxRSSM, float64(mb)/m.seconds)
		rss = append(rss, m.maxRSSM)
		os.Remove(log)
	}
	// 入力が 5 倍でも、最大メモリ使用量は、ほぼ同じ(実行環境の揺れの範囲)
	if grown := rss[len(rss)-1] - rss[0]; grown > 16 {
		t.Errorf("max RSS grew by %.1f MB (%.1f MB -> %.1f MB) when the input grew %dx", grown, rss[0], rss[len(rss)-1], sizes[len(sizes)-1]/sizes[0])
	}

	// 参考: 値が、行ごとにほぼ異なる場合は、対応表(値の種類数に比例)のぶん、増える。
	log := genLog(t, dir, "unique.log", *perfSize, 0)
	m := runMask(t, bin, log, true)
	t.Logf("%4d MB log, nearly every value distinct: max RSS %.1f MB (the table grows with the number of distinct values)", *perfSize, m.maxRSSM)
}
