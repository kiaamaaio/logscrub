package cli

import (
	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/transform"
)

func runMask(e *env, args []string) int {
	fs := newFlagSet("mask")
	var df detectFlags
	df.register(fs)
	mode := fs.String("mode", "mask", "mask or hash")
	emailHash := fs.String("email-hash", "full", "full or local")
	hashLen := fs.Int("hash-length", label.DefaultHashLen, "hex digits of a hash")
	keyFile := fs.String("key-file", "", "file with the hash key")
	showStats := fs.Bool("stats", false, "print counts to stderr")
	failOnDetect := fs.Bool("fail-on-detect", false, "exit 2 when something was replaced")
	var output string
	fs.StringVar(&output, "output", "", "output file")
	fs.StringVar(&output, "o", "", "output file (short)")

	files, code, done := e.parseFlags("mask", usageMask, fs, args)
	if done {
		return code
	}
	set := visited(fs)

	// オプションの値を、すべて確認する(入力を開く前に)。
	if *mode != "mask" && *mode != "hash" {
		return e.fail("--mode: invalid mode %q (valid: mask, hash)", *mode)
	}
	hashing := *mode == "hash"
	if !hashing {
		// Q25: hash 専用のオプションは、mask モードで指定するとエラー
		for _, name := range []string{"hash-length", "email-hash", "key-file"} {
			if set[name] {
				return e.fail("--%s can be used only with --mode hash", name)
			}
		}
	}
	opts, format, err := df.options(set)
	if err != nil {
		return e.fail("%v", err)
	}
	var rep transform.Replacer
	if hashing {
		var emailMode transform.EmailHash
		switch *emailHash {
		case "full":
			emailMode = transform.EmailHashFull
		case "local":
			emailMode = transform.EmailHashLocal
		default:
			return e.fail("--email-hash: invalid value %q (valid: full, local)", *emailHash)
		}
		if *hashLen < label.MinHashLen || *hashLen > label.MaxHashLen {
			return e.fail("--hash-length must be between %d and %d", label.MinHashLen, label.MaxHashLen)
		}
		key, err := transform.LoadKey(e.getenv, *keyFile)
		if err != nil {
			return e.fail("%v", err)
		}
		h, err := transform.NewHasher(key, *hashLen, emailMode)
		if err != nil {
			return e.fail("%v", err)
		}
		opts.HashLen = *hashLen
		rep = h
	} else {
		rep = transform.NewMasker(format)
	}
	det, err := detect.New(opts)
	if err != nil {
		return e.fail("%v", err)
	}

	// 入力と出力を、すべて開く(開けないものがあれば、何も書かずにエラー)。
	if len(files) == 0 {
		files = []string{stdinPath}
	}
	in, err := e.openInputs(files)
	if err != nil {
		return e.fail("%v", err)
	}
	defer in.Close()
	w, closeOut, err := e.openOutput(output, files)
	if err != nil {
		return e.fail("%v", err)
	}

	eng := &transform.Engine{Det: det, Rep: rep}
	runErr := eng.Run(in.readers, w)
	closeErr := closeOut()
	if runErr == nil {
		runErr = closeErr
	}
	if runErr != nil {
		// Q28: エラー(1)は、終了コード 2 より優先する。
		return e.fail("%v", runErr)
	}

	if *showStats {
		printStats(e, &eng.Stats)
	}
	printUnchanged(e, eng.Stats.Kept, eng.Stats.KeptLineCount, eng.Stats.KeptLines)
	if *failOnDetect && eng.Stats.Total() > 0 {
		return exitDetected
	}
	return exitOK
}
