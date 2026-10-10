// Package cli は、logscrub のコマンドラインの処理(サブコマンドの振り分け、オプションの解析、
// 入出力、終了コード)。標準の flag だけを使う(仕様 6.1)。
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// 終了コード(仕様 6 章)。
const (
	exitOK       = 0
	exitError    = 1
	exitDetected = 2
)

// env は、実行環境(入出力と環境変数)。テストで差し替えられるようにまとめている。
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
}

// Run は、logscrub を実行し、終了コードを返す。args は、プログラム名を除いた引数。
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv}
	if len(args) == 0 {
		fmt.Fprint(stderr, usageTop)
		return exitError
	}
	switch args[0] {
	case "mask":
		return runMask(e, args[1:])
	case "restore":
		return runRestore(e, args[1:])
	case "types":
		return runTypes(e, args[1:])
	case "-h", "--help", "-help", "help":
		fmt.Fprint(stdout, usageTop)
		return exitOK
	}
	fmt.Fprintf(stderr, "logscrub: unknown command %q\n\n%s", args[0], usageTop)
	return exitError
}

// fail は、エラーを stderr に出して、終了コード 1 を返す。メッセージに、置換対象の値は含めない。
func (e *env) fail(format string, a ...any) int {
	fmt.Fprintf(e.stderr, "logscrub: "+format+"\n", a...)
	return exitError
}

// parseFlags は、サブコマンドの引数を読む。--help は、usage を stdout に出して、done を true にする。
// オプションのエラーは、メッセージと、--help の案内を stderr に出す。
func (e *env) parseFlags(name, usage string, fs *flag.FlagSet, args []string) (positional []string, code int, done bool) {
	positional, err := parseArgs(fs, args)
	switch {
	case err == nil:
		return positional, exitOK, false
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(e.stdout, usage)
		return nil, exitOK, true
	}
	fmt.Fprintf(e.stderr, "logscrub: %v\nRun \"logscrub %s --help\" for usage.\n", err, name)
	return nil, exitError, true
}

// stdinPath は、標準入力を表す、ファイル名の `-`。
const stdinPath = "-"

// openedInputs は、開いた入力。Close で、開いたファイルを閉じる(標準入力は閉じない)。
type openedInputs struct {
	readers []io.Reader
	files   []*os.File
}

func (o *openedInputs) Close() {
	for _, f := range o.files {
		f.Close()
	}
}

// openInputs は、paths を、すべて開く(処理を始める前に、開けないものを見つけるため)。
// `-` は標準入力で、1 回だけ使える。
func (e *env) openInputs(paths []string) (*openedInputs, error) {
	o := &openedInputs{}
	stdinUsed := false
	for _, p := range paths {
		if p == stdinPath {
			if stdinUsed {
				o.Close()
				return nil, errors.New("stdin (-) can be used only once")
			}
			stdinUsed = true
			o.readers = append(o.readers, e.stdin)
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			o.Close()
			return nil, err
		}
		o.files = append(o.files, f)
		o.readers = append(o.readers, f)
	}
	return o, nil
}

// openOutput は、出力先を開く。path が空、または `-` なら、標準出力。
// 出力先が、入力のどれかと同じファイルなら、開かずにエラーにする(入力を消さないため。Q26)。
func (e *env) openOutput(path string, inputs []string) (w io.Writer, closeFn func() error, err error) {
	if path == "" || path == stdinPath {
		return e.stdout, func() error { return nil }, nil
	}
	if st, err := os.Stat(path); err == nil {
		for _, in := range inputs {
			if in == stdinPath {
				continue
			}
			if ist, err := os.Stat(in); err == nil && os.SameFile(st, ist) {
				return nil, nil, fmt.Errorf("the output file %q is also an input file", path)
			}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
