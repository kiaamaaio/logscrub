package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/transform"
)

func putFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func getFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// listFiles は、dir の下のファイルの、dir からの相対パスを返す。
func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var got []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			got = append(got, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return got
}

func TestOutDirLayout(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "logs", "a", "app.log")
	b := filepath.Join(root, "logs", "b", "app.log")
	c := filepath.Join(root, "logs", "c.log")
	for _, p := range []string{a, b, c} {
		putFile(t, p, "x\n")
	}
	for _, tt := range []struct {
		name  string
		files []string
		want  []string
	}{
		{"one file", []string{a}, []string{"app.log"}},
		{"same directory", []string{a, a + "2"}, []string{"app.log", "app.log2"}},
		{"different directories", []string{a, b}, []string{"a/app.log", "b/app.log"}},
		{"different depths", []string{a, c}, []string{"a/app.log", "c.log"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range tt.files {
				putFile(t, f, "x\n")
			}
			out := filepath.Join(t.TempDir(), "new", "dir")
			r := run(t, "", nil, append([]string{"mask", "--out-dir", out}, tt.files...)...)
			if r.code != 0 || r.stdout != "" || r.stderr != "" {
				t.Fatalf("%+v", r)
			}
			if got := listFiles(t, out); strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOutDirRelativePaths(t *testing.T) {
	root := t.TempDir()
	putFile(t, filepath.Join(root, "work", "a.log"), "x\n")
	putFile(t, filepath.Join(root, "other", "b.log"), "y\n")
	t.Chdir(filepath.Join(root, "work"))
	r := run(t, "", nil, "mask", "--out-dir", "out", "a.log", "../other/b.log")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if got := listFiles(t, "out"); strings.Join(got, ",") != "other/b.log,work/a.log" {
		t.Errorf("got %q", got)
	}
}

// 連結した内容が、`mask a b` の出力と同じで、--source を同じ順に指定した restore で戻る(仕様 6 章)。
func TestOutDirMatchesConcatenatedMask(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.log")
	b := filepath.Join(root, "b.log")
	inA := "taro@example.com /home/yamada/x\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	inB := "taro@example.com hanako@example.com password=abc\nno newline at the end 10.0.0.1"
	putFile(t, a, inA)
	putFile(t, b, inB)
	out := filepath.Join(root, "out")
	r := run(t, "", nil, "mask", "--out-dir", out, a, b, "--stats")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	whole := run(t, "", nil, "mask", a, b, "--stats")
	gotA, gotB := getFile(t, filepath.Join(out, "a.log")), getFile(t, filepath.Join(out, "b.log"))
	if gotA+gotB != whole.stdout || r.stderr != whole.stderr {
		t.Errorf("got %q + %q, want %q; stderr %q, want %q", gotA, gotB, whole.stdout, r.stderr, whole.stderr)
	}
	if !strings.Contains(gotB, "<email_1> <email_2>") {
		t.Errorf("the numbers do not continue across files: %q", gotB)
	}
	back := run(t, gotA+gotB, nil, "restore", "--source", a, "--source", b)
	if back.code != 0 || back.stdout != inA+inB {
		t.Errorf("%+v", back)
	}
}

func TestOutDirWithOtherOptions(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.log")
	putFile(t, a, "taro@example.com\n")
	r := run(t, "", nil, "mask", "--out-dir", filepath.Join(root, "o1"), a, "--fail-on-detect")
	if r.code != exitDetected {
		t.Errorf("%+v", r)
	}
	h := run(t, "", hashEnv(), "mask", "--mode", "hash", "--out-dir", filepath.Join(root, "o2"), a)
	if h.code != 0 || !strings.HasPrefix(getFile(t, filepath.Join(root, "o2", "a.log")), "email_") {
		t.Errorf("%+v", h)
	}
}

// 通知は全ファイルの合計で、行番号は通し(END のない PEM のブロックの行番号は 5 件まで)。
func TestOutDirNotices(t *testing.T) {
	root := t.TempDir()
	var files []string
	for _, name := range strings.Fields("a b c d e f g") {
		p := filepath.Join(root, name+".log")
		putFile(t, p, "-----BEGIN PRIVATE KEY-----\n")
		files = append(files, p)
	}
	r := run(t, "", nil, append([]string{"mask", "--out-dir", filepath.Join(root, "out")}, files...)...)
	if !strings.Contains(r.stderr, "7 private key blocks had no END line (lines 1, 2, 3, 4, 5, ...)") {
		t.Errorf("%q", r.stderr)
	}
}

func TestOutDirNewFilesAreNotReadableByOthers(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "x", "a.log")
	b := filepath.Join(root, "y", "b.log")
	putFile(t, a, "x\n")
	putFile(t, b, "y\n")
	out := filepath.Join(root, "out")
	if r := run(t, "", nil, "mask", "--out-dir", out, a, b); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	for p, want := range map[string]os.FileMode{out: 0o700, filepath.Join(out, "x"): 0o700, filepath.Join(out, "x", "a.log"): 0o600} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", p, st.Mode().Perm(), want)
		}
	}
}

// エラーの場合は、何も書かない(終了コード 1)。
func TestOutDirErrorsWriteNothing(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "in", "a.log")
	b := filepath.Join(root, "in", "b.log")
	putFile(t, a, "taro@example.com\n")
	putFile(t, b, "taro@example.com\n")
	exists := filepath.Join(root, "exists")
	putFile(t, filepath.Join(exists, "b.log"), "keep\n")
	blocked := filepath.Join(root, "blocked")
	putFile(t, blocked, "a file\n")
	out := filepath.Join(root, "out")

	for _, tt := range []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"no FILE", "x\n", []string{"--out-dir", out}, "at least one FILE"},
		{"stdin", "x\n", []string{"--out-dir", out, a, "-"}, "stdin"},
		{"directory", "", []string{"--out-dir", out, a, root}, "regular files"},
		{"missing file", "", []string{"--out-dir", out, a, filepath.Join(root, "none")}, "no such file"},
		{"given twice", "", []string{"--out-dir", out, a, filepath.Join(root, "in", ".", "a.log")}, "given twice"},
		{"existing file", "", []string{"--out-dir", exists, a, b}, "already exists"},
		{"same as the input", "", []string{"--out-dir", filepath.Join(root, "in"), a}, "already exists"},
		{"the directory is a file", "", []string{"--out-dir", blocked, a}, ""},
		{"with --output", "", []string{"--out-dir", out, "-o", filepath.Join(root, "o"), a}, "cannot be used with"},
		{"empty", "", []string{"--out-dir", "", a}, "needs a directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.stdin, nil, append([]string{"mask"}, tt.args...)...)
			if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("%+v", r)
			}
			if got := listFiles(t, out); len(got) != 0 {
				t.Errorf("wrote %q", got)
			}
			if _, err := os.Stat(filepath.Join(root, "o")); err == nil {
				t.Error("wrote the --output file")
			}
		})
	}
	if getFile(t, a) != "taro@example.com\n" || getFile(t, filepath.Join(exists, "b.log")) != "keep\n" {
		t.Error("a file was changed")
	}
	if got := listFiles(t, exists); len(got) != 1 {
		t.Errorf("wrote %q", got)
	}
}

// 途中のエラーでは、今回書いたファイルを消す。やり直しが、既存のファイルで止まらない。
func TestOutDirRemovesFilesOnFailure(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.log")
	b := filepath.Join(root, "b.log")
	putFile(t, a, "x\n")
	putFile(t, b, "y\n")
	out := filepath.Join(root, "out")
	plan, err := planOutDir(out, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b); err != nil { // 確かめたあとに消えた
		t.Fatal(err)
	}
	det, err := detect.New(detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	eng := &transform.Engine{Det: det, Rep: transform.NewMasker(label.DefaultFormat)}
	if err := writeOutDir(eng, plan); err == nil {
		t.Fatal("no error")
	}
	if got := listFiles(t, out); len(got) != 0 {
		t.Errorf("left %q", got)
	}
}

// 既存のファイルと同じ名前が、確かめたあとに作られても、上書きしない。
func TestOutDirDoesNotOverwriteALateFile(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.log")
	putFile(t, a, "x\n")
	out := filepath.Join(root, "out")
	plan, err := planOutDir(out, []string{a})
	if err != nil {
		t.Fatal(err)
	}
	putFile(t, filepath.Join(out, "a.log"), "keep\n")
	det, err := detect.New(detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	eng := &transform.Engine{Det: det, Rep: transform.NewMasker(label.DefaultFormat)}
	if err := writeOutDir(eng, plan); err == nil {
		t.Fatal("no error")
	}
	if got := getFile(t, filepath.Join(out, "a.log")); got != "keep\n" {
		t.Errorf("got %q", got)
	}
}
