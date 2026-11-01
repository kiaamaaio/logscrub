package cli

import (
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
)

func TestVersion(t *testing.T) {
	want := "logscrub " + version() + "\n"
	for _, args := range [][]string{{"version"}, {"--version"}, {"-version"}} {
		r := run(t, "", nil, args...)
		if r.code != exitOK || r.stdout != want || r.stderr != "" {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, r.code, r.stdout, r.stderr)
		}
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	r := run(t, "", nil, "version", "x")
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "takes no arguments") {
		t.Errorf("code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestVersionHelp(t *testing.T) {
	r := run(t, "", nil, "version", "--help")
	if r.code != exitOK || !strings.Contains(r.stdout, "Usage: logscrub version") {
		t.Errorf("code %d, stdout %q", r.code, r.stdout)
	}
}

// 受け入れ基準: すべての種別名が `mask --help` に載っている(ヘルプが種別の追加に遅れないように)。
func TestMaskHelpListsAllTypes(t *testing.T) {
	r := run(t, "", nil, "mask", "--help")
	for _, ti := range detect.Types {
		if !strings.Contains(r.stdout, ti.Name()) {
			t.Errorf("mask --help does not mention %q", ti.Name())
		}
	}
}

// 全体のヘルプは、種別を列挙せず `logscrub types` へ案内する。URL のパスワードと `version` には触れる。
func TestTopHelp(t *testing.T) {
	r := run(t, "", nil, "--help")
	for _, want := range []string{"logscrub types", "logscrub version", "in URLs"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("help does not mention %q", want)
		}
	}
}
