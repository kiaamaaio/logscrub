package cli

import (
	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/transform"
)

func runRestore(e *env, args []string) int {
	fs := newFlagSet("restore")
	var df detectFlags
	df.register(fs)
	var sources stringList
	fs.Var(&sources, "source", "input that was given to mask (repeatable)")
	var output string
	fs.StringVar(&output, "output", "", "output file")
	fs.StringVar(&output, "o", "", "output file (short)")

	positional, code, done := e.parseFlags("restore", usageRestore, fs, args)
	if done {
		return code
	}
	set := visited(fs)

	if len(sources) == 0 {
		return e.fail("--source is required (the input that was given to \"logscrub mask\")")
	}
	if len(positional) > 1 {
		return e.fail("only one ANSWER_FILE can be given (got %d)", len(positional))
	}
	answer := stdinPath
	if len(positional) == 1 {
		answer = positional[0]
	}
	// --source - (stdin) は、ANSWER_FILE を指定した場合だけ使える(仕様 5.3)。
	if answer == stdinPath {
		for _, s := range sources {
			if s == stdinPath {
				return e.fail("--source - reads stdin; give the answer as ANSWER_FILE (both cannot come from stdin)")
			}
		}
	}

	opts, format, err := df.options(set)
	if err != nil {
		return e.fail("%v", err)
	}
	det, err := detect.New(opts)
	if err != nil {
		return e.fail("%v", err)
	}

	paths := append(append([]string{}, sources...), answer)
	in, err := e.openInputs(paths)
	if err != nil {
		return e.fail("%v", err)
	}
	defer in.Close()
	w, closeOut, err := e.openOutput(output, paths)
	if err != nil {
		return e.fail("%v", err)
	}

	n := len(sources)
	res, runErr := transform.Restore(in.readers[:n], in.readers[n], w, det, format)
	closeErr := closeOut()
	if runErr == nil {
		runErr = closeErr
	}
	if runErr != nil {
		return e.fail("%v", runErr)
	}

	// 戻せなかったラベルは、警告(終了コードは 0)。
	printMissing(e, res.Missing)
	printUnchanged(e, res.Source.Kept, res.Source.KeptLineCount, res.Source.KeptLines)
	return exitOK
}
