package cli

import (
	"flag"
	"io"
	"strings"
)

// stringList は、複数回指定できるオプション(--allow、--source)の値を、蓄積する。
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// newFlagSet は、サブコマンド name の FlagSet を作る。エラーと使い方は、flag に出力させず、
// 呼び出し側が、終了コードと出力先を決めて出す。
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("logscrub "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseArgs は、オプションと、ファイル名(位置引数)を、順序を問わずに読む(仕様 6.1)。
//
// 「Parse でオプションを読む → 残りの先頭を、ファイル名として 1 つ取り出す → 残りを、また読む」を、
// 引数がなくなるまで繰り返す。`--` の後ろは、`-` で始まっていても、すべてファイル名。
// 単独の `-` は、ファイル名(stdin)として返す。
func parseArgs(fs *flag.FlagSet, args []string) (positional []string, err error) {
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if endedWithTerminator(fs, args, len(args)-len(rest)) {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// endedWithTerminator は、fs.Parse が args の先頭 consumed 個を読み終えたのが、終端の `--` によるかを返す。
// `--` は、オプションの値(`--allow --`)として読まれることもあるので、flag の読み方を、そのとおりにたどる。
func endedWithTerminator(fs *flag.FlagSet, args []string, consumed int) bool {
	for i := 0; i < consumed; {
		tok := args[i]
		if tok == "--" {
			return i == consumed-1
		}
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		name := strings.TrimLeft(tok, "-")
		if strings.Contains(name, "=") {
			i++
			continue
		}
		if f := fs.Lookup(name); f != nil {
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				i++
				continue
			}
		}
		i += 2 // 値を取るオプション: 次の引数が値
	}
	return false
}

// visited は、コマンドラインで指定された(Parse が読んだ)オプションの名前の集合を返す。
func visited(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}
