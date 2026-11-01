//go:build unix

package main

import (
	"os"
	"runtime"
	"syscall"
	"testing"
)

const canMeasureRSS = true

// maxRSSMB は、終了した子プロセスの最大メモリ使用量を MB で返す。
func maxRSSMB(t *testing.T, st *os.ProcessState) float64 {
	t.Helper()
	ru, ok := st.SysUsage().(*syscall.Rusage)
	if !ok {
		t.Fatal("no rusage")
	}
	if runtime.GOOS == "darwin" {
		return float64(ru.Maxrss) / (1 << 20) // macOS: Maxrss はバイト
	}
	return float64(ru.Maxrss) / (1 << 10) // Linux: Maxrss は KB
}
