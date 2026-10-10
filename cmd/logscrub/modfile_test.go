package main

import (
	"os"
	"strings"
	"testing"
)

// 受け入れ基準: go.mod に外部の依存がない(標準ライブラリのみ)。
func TestGoModHasNoDependencies(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "require", "replace", "tool", "godebug", "toolchain":
			t.Errorf("go.mod:%d: unexpected directive %q (外部の依存は使わない)", i+1, f[0])
		}
	}
	if _, err := os.Stat("../../go.sum"); err == nil {
		t.Error("go.sum exists; 外部の依存は使わない")
	}
}
