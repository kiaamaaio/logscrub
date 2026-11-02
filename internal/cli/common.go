package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
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
	deny         stringList
	denyFiles    stringList
	domains      stringList
}

func (d *detectFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&d.types, "types", "", "types to replace")
	fs.StringVar(&d.uuidVersions, "uuid-versions", "", "uuid versions to replace")
	fs.StringVar(&d.ipScope, "ip-scope", "all", "ip addresses to replace")
	fs.StringVar(&d.maskFormat, "mask-format", "<{type}_{n}>", "label format")
	fs.Var(&d.allow, "allow", "value that is never replaced")
	fs.Var(&d.deny, "deny", "word to replace")
	fs.Var(&d.denyFiles, "deny-file", "file with words to replace, one per line")
	fs.Var(&d.domains, "domain", "domain whose host names are replaced")
}

// inputFiles は、検出のオプションが読むファイル。出力先と同じファイルを拒むために使う(仕様 4.6)。
func (d *detectFlags) inputFiles() []string { return d.denyFiles }

// options は、検出のオプションを、detect.Options と、ラベルの書式にする。
// set は、コマンドラインで指定されたオプションの名前の集合。
func (d *detectFlags) options(set map[string]bool) (detect.Options, label.Format, error) {
	var o detect.Options
	if set["types"] {
		kinds, err := detect.ParseTypes(d.types)
		if err != nil {
			return o, label.Format{}, fmt.Errorf("--types: %w", err)
		}
		// 語の指定がなければ、何も置換されないことに気づけないので、エラーにする(Q75)。
		if kinds.Has(detect.KindCustom) && !set["deny"] && !set["deny-file"] {
			return o, label.Format{}, errors.New("--types: custom needs --deny or --deny-file")
		}
		if kinds.Has(detect.KindHost) && !set["domain"] {
			return o, label.Format{}, errors.New("--types: host needs --domain")
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
	o.Deny = d.deny
	for _, p := range d.denyFiles {
		words, err := readDenyFile(p)
		if err != nil {
			return o, label.Format{}, fmt.Errorf("--deny-file: %w", err)
		}
		o.Deny = append(o.Deny, words...)
	}
	o.Domains = d.domains
	return o, f, nil
}

// readDenyFile は、語の一覧のファイルを読む(仕様 4.6)。エラーに、語の内容は含めない。
func readDenyFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var words []string
	n := 0
	for line := range bytes.SplitSeq(b, []byte{'\n'}) {
		n++
		line = bytes.Trim(bytes.TrimSuffix(line, []byte{'\r'}), " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if bytes.IndexByte(line, '\r') >= 0 {
			return nil, fmt.Errorf("%s: line %d: a word must not contain a carriage return", path, n)
		}
		words = append(words, string(line))
	}
	return words, nil
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
	fmt.Fprintf(e.stderr, "logscrub: %s already replaced (%s). Check them before sharing.\n", what, lineList(keptLines, keptLineCount))
}

// lineList は、通知の行番号の並びを作る。listed は最初の数件で、count は全体の数。
func lineList(listed []int, count int) string {
	nums := make([]string, len(listed))
	for i, n := range listed {
		nums[i] = fmt.Sprint(n)
	}
	if count == 1 {
		return "line " + nums[0]
	}
	lines := "lines " + strings.Join(nums, ", ")
	if count > len(listed) {
		lines += ", ..."
	}
	return lines
}

// printSuspects は、`--review` の怪しい語の、件数と行番号を通知する(仕様 6 章)。値は出さない。
func printSuspects(e *env, st *transform.Stats) {
	switch st.Suspects {
	case 0:
	case 1:
		fmt.Fprintf(e.stderr, "logscrub: 1 string looks like an unreplaced value (%s).\n", lineList(st.SuspectLines, st.SuspectLineCount))
	default:
		fmt.Fprintf(e.stderr, "logscrub: %d strings look like unreplaced values (%s).\n", st.Suspects, lineList(st.SuspectLines, st.SuspectLineCount))
	}
}

// printUnclosed は、END のない PEM のブロックと、END のない 1 行の形の、件数と行番号を通知する(仕様 6 章)。
func printUnclosed(e *env, st *transform.Stats) {
	if st.Unclosed == 0 {
		return
	}
	what, pron := fmt.Sprintf("%d private key blocks", st.Unclosed), "them"
	if st.Unclosed == 1 {
		what, pron = "1 private key block", "it"
	}
	fmt.Fprintf(e.stderr, "logscrub: %s had no END line (%s). Check the lines after %s before sharing.\n", what, lineList(st.UnclosedLines, st.Unclosed), pron)
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
