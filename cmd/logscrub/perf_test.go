package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// 性能とメモリの測定(仕様 7 章、plans/v1.0.0.md の段階 11、Q29)。時間がかかるので、-perf を付けたときだけ実行する。
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
	cmd := exec.Command(bin, append([]string{"mask"}, args...)...)
	f, err := os.Open(logPath)
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
	ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		t.Fatal("no rusage")
	}
	return measurement{seconds: elapsed, maxRSSM: float64(ru.Maxrss) / 1024} // Linux: Maxrss は KB
}

func TestPerfThroughput(t *testing.T) {
	if !*perf {
		t.Skip("run with -perf")
	}
	bin := buildBinary(t)
	dir := t.TempDir()
	log := genLog(t, dir, "big.log", *perfSize, 0)
	for _, tc := range []struct {
		name string
		pipe bool
		args []string
	}{
		{"mask, stdin from a file", false, nil},
		{"mask, stdin from a pipe", true, nil},
		{"mask with uuid", false, []string{"--types", "default,uuid"}},
	} {
		best := measurement{seconds: 1e9}
		for i := 0; i < 3; i++ {
			m := runMask(t, bin, log, tc.pipe, tc.args...)
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

// 値の種類数が一定なら、最大メモリ使用量は、入力の大きさに比例して増えない(受け入れ基準)。
func TestPerfMemoryDoesNotGrowWithInputSize(t *testing.T) {
	if !*perf {
		t.Skip("run with -perf")
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
