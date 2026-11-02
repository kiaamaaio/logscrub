package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kiaamaaio/logscrub/internal/transform"
)

// outFile は、`--out-dir` の入力 1 つと、その書き出し先。
type outFile struct {
	src, dst string
}

// planOutDir は、files の書き出し先を求めて、何も書かずに確かめる(仕様 6 章)。
// 書き出し先は、すべての入力の共通の親ディレクトリからの相対パスを、dir につなげたもの。
//
// 入力は開いて確かめるだけで、開いたままにしない(ファイルが多いと、開ける数の上限に当たるため)。
// 通常のファイルだけを受け付ける。FIFO は、確かめるために開くと、中身が失われる。
func planOutDir(dir string, files []string) ([]outFile, error) {
	if len(files) == 0 {
		return nil, errors.New("--out-dir needs at least one FILE")
	}
	abs := make([]string, len(files))
	seen := make(map[string]bool, len(files))
	var parent string
	for i, f := range files {
		if f == stdinPath {
			return nil, errors.New("--out-dir cannot be used with stdin (-)")
		}
		st, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("--out-dir needs regular files: %q is not one", f)
		}
		in, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		in.Close()
		if abs[i], err = filepath.Abs(f); err != nil {
			return nil, err
		}
		if seen[abs[i]] {
			return nil, fmt.Errorf("--out-dir: %q is given twice", f)
		}
		seen[abs[i]] = true
		if i == 0 {
			parent = filepath.Dir(abs[i])
		}
		if parent, err = commonDir(parent, filepath.Dir(abs[i])); err != nil {
			return nil, err
		}
	}
	plan := make([]outFile, len(files))
	for i, a := range abs {
		rel, err := filepath.Rel(parent, a)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(dir, rel)
		switch _, err := os.Lstat(dst); {
		case err == nil:
			return nil, fmt.Errorf("--out-dir: %q already exists (remove it and run again)", dst)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, err
		}
		plan[i] = outFile{files[i], dst}
	}
	return plan, nil
}

// commonDir は、絶対パスのディレクトリ a と b の共通の親を返す。
func commonDir(a, b string) (string, error) {
	for {
		rel, err := filepath.Rel(a, b)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return a, nil
		}
		up := filepath.Dir(a)
		if up == a { // Windows の別のドライブ
			return "", fmt.Errorf("--out-dir: %q and %q have no common parent", a, b)
		}
		a = up
	}
}

// writeOutDir は、plan の順に、ファイルごとに変換して書き出す。eng の Rep と Stats を引き継ぐので、連番は通しになる。
// エラーでは、今回書いたファイルを消す(作ったディレクトリは残す)。再実行が、既存のファイルで止まらないように。
func writeOutDir(eng *transform.Engine, plan []outFile) error {
	var written []string
	for _, f := range plan {
		err := writeOne(eng, f, &written)
		if err != nil {
			for _, p := range written {
				os.Remove(p)
			}
			return err
		}
	}
	return nil
}

func writeOne(eng *transform.Engine, f outFile, written *[]string) error {
	in, err := os.Open(f.src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(f.dst), 0o700); err != nil {
		return err
	}
	// O_EXCL: 確かめたあとに作られたファイルも、上書きしない。
	out, err := os.OpenFile(f.dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	*written = append(*written, f.dst)
	err = eng.Run([]io.Reader{in}, out)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
