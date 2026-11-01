//go:build !unix

package main

import (
	"os"
	"testing"
)

const canMeasureRSS = false

// maxRSSMB は、最大メモリ使用量を測れない環境では、0 を返す。
func maxRSSMB(*testing.T, *os.ProcessState) float64 { return 0 }
