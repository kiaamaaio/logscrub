package cli

import (
	"fmt"
	"runtime/debug"
)

// develVersion は、版が取れないときの表示。
const develVersion = "(devel)"

// version は、ビルドの情報にある版を返す(Q79)。
// `go install …@v1.3.0` とタグの位置のビルドでは、タグの版になる。開発用のビルドは、疑似版のまま出す。
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return develVersion
}

func runVersion(e *env, args []string) int {
	fs := newFlagSet("version")
	positional, code, done := e.parseFlags("version", usageVersion, fs, args)
	if done {
		return code
	}
	if len(positional) > 0 {
		fmt.Fprintf(e.stderr, "logscrub: version takes no arguments (got %q)\nRun \"logscrub version --help\" for usage.\n", positional[0])
		return exitError
	}
	fmt.Fprintf(e.stdout, "logscrub %s\n", version())
	return exitOK
}
