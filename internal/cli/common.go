package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/transform"
)

// detectFlags は、mask と restore が共有する、検出のオプション。
// restore では、mask のときと同じものを指定する必要がある(仕様 5.3)。
type detectFlags struct {
	types        string
	uuidVersions string
	ipScope      string
	maskFormat   string
	allow        stringList
}

func (d *detectFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&d.types, "types", "", "types to replace")
	fs.StringVar(&d.uuidVersions, "uuid-versions", "", "uuid versions to replace")
	fs.StringVar(&d.ipScope, "ip-scope", "all", "ip addresses to replace")
	fs.StringVar(&d.maskFormat, "mask-format", "<{type}_{n}>", "label format")
	fs.Var(&d.allow, "allow", "value that is never replaced")
}

// options は、検出のオプションを、detect.Options と、ラベルの書式にする。
// set は、コマンドラインで指定されたオプションの名前の集合。
func (d *detectFlags) options(set map[string]bool) (detect.Options, label.Format, error) {
	var o detect.Options
	if set["types"] {
		kinds, err := detect.ParseTypes(d.types)
		if err != nil {
			return o, label.Format{}, fmt.Errorf("--types: %w", err)
		}
		o.Kinds = kinds
	}
	if set["uuid-versions"] {
		v, err := detect.ParseUUIDVersions(d.uuidVersions)
		if err != nil {
			return o, label.Format{}, fmt.Errorf("--uuid-versions: %w", err)
		}
		o.UUIDVersions = v
	}
	scope, err := detect.ParseScope(d.ipScope)
	if err != nil {
		return o, label.Format{}, fmt.Errorf("--ip-scope: %w", err)
	}
	o.IPScope = scope
	f, err := label.ParseFormat(d.maskFormat)
	if err != nil {
		return o, label.Format{}, fmt.Errorf("--mask-format: %w", err)
	}
	o.Format = f
	if len(d.allow) > 0 {
		o.Allow = make(map[string]struct{}, len(d.allow))
		for _, v := range d.allow {
			o.Allow[v] = struct{}{}
		}
	}
	return o, f, nil
}

// ---- stderr への出力(値は出さない) ----

// printStats は、種別ごとの置換した件数を、label.Types の順に、1 行ずつ出す(Q19)。0 件の種別は出さない。
func printStats(e *env, st *transform.Stats) {
	for _, tc := range st.Types() {
		fmt.Fprintf(e.stderr, "logscrub: %s=%d\n", tc.Type, tc.Count)
	}
}

// printUnchanged は、置換済みの形のため置換せずに残した文字列の、件数と行番号を通知する(Q31)。
func printUnchanged(e *env, kept, keptLineCount int, keptLines []int) {
	if kept == 0 {
		return
	}
	what := fmt.Sprintf("%d strings were left unchanged because they look", kept)
	if kept == 1 {
		what = "1 string was left unchanged because it looks"
	}
	nums := make([]string, len(keptLines))
	for i, n := range keptLines {
		nums[i] = fmt.Sprint(n)
	}
	lines := "lines " + strings.Join(nums, ", ")
	if len(keptLines) == 1 && keptLineCount == 1 {
		lines = "line " + nums[0]
	}
	if keptLineCount > len(keptLines) {
		lines += ", ..."
	}
	fmt.Fprintf(e.stderr, "logscrub: %s already replaced (%s). Check them before sharing.\n", what, lines)
}

// maxMissingListed は、戻せなかったラベルを、stderr に並べる最大の数(件数は、全体を出す)。
const maxMissingListed = 50

// printMissing は、戻せなかったラベルの件数とラベル名を出す(仕様 5.3)。元の値は出さない。
func printMissing(e *env, missing []string) {
	if len(missing) == 0 {
		return
	}
	what := fmt.Sprintf("%d labels", len(missing))
	if len(missing) == 1 {
		what = "1 label"
	}
	listed := missing
	more := ""
	if len(listed) > maxMissingListed {
		listed, more = listed[:maxMissingListed], ", ..."
	}
	fmt.Fprintf(e.stderr, "logscrub: %s could not be restored: %s%s (check that --source and options match the mask run)\n",
		what, strings.Join(listed, ", "), more)
}
