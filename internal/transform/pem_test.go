package transform

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

const (
	pemBegin = "-----BEGIN RSA PRIVATE KEY-----"
	pemEnd   = "-----END RSA PRIVATE KEY-----"
)

// fakeKey は、n 行の架空の鍵の本文を返す。
func fakeKey(seed, n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("%s%04d%04d", strings.Repeat("QUJD", 14), seed, i)
	}
	return lines
}

func TestPEMKeepsLinesAndNewlines(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		key := fakeKey(1, 3)
		in := strings.Join(append(append([]string{"start", pemBegin}, key...), pemEnd, "end"), eol) // 最後は改行なし
		want := strings.Join([]string{"start", pemBegin, "<secret_1>", "<secret_2>", "<secret_3>", pemEnd, "end"}, eol)
		masked, restored, _ := roundTrip(t, detect.Options{}, in)
		if masked != want {
			t.Errorf("%q: got %q", eol, masked)
		}
		if restored != in {
			t.Errorf("%q: restored %q", eol, restored)
		}
	}
}

// 鍵がブロックの境目(行のブロックは最大 256KB)をまたいでも、ワーカー数によらず同じ結果になる。
func TestPEMAcrossBlocks(t *testing.T) {
	var in, want strings.Builder
	n := 0
	for k := range 200 {
		for i := range 60 {
			fmt.Fprintf(&in, "line %d of %d, nothing to replace here\n", i, k)
			fmt.Fprintf(&want, "line %d of %d, nothing to replace here\n", i, k)
		}
		fmt.Fprintln(&in, pemBegin)
		fmt.Fprintln(&want, pemBegin)
		for _, l := range fakeKey(k, 40) {
			n++
			fmt.Fprintln(&in, l)
			fmt.Fprintf(&want, "<secret_%d>\n", n)
		}
		fmt.Fprintln(&in, pemEnd)
		fmt.Fprintln(&want, pemEnd)
	}
	for _, workers := range []int{1, 2, 4, 8} {
		// 読み取りの大きさを変えて、ブロックの切れ目をずらす。
		for _, size := range []int{1000, 4096, 70000} {
			var out strings.Builder
			e := &Engine{Det: newDet(t, detect.Options{}), Rep: NewMasker(label.DefaultFormat), workers: workers}
			r := &chunkReader{r: strings.NewReader(in.String()), n: size}
			if err := e.Run([]io.Reader{r}, &out); err != nil {
				t.Fatal(err)
			}
			if out.String() != want.String() {
				t.Fatalf("workers %d, reads of %d bytes: the output differs", workers, size)
			}
			if e.Stats.Count("secret") != n || e.Stats.Unclosed != 0 {
				t.Errorf("workers %d: stats %+v", workers, e.Stats)
			}
		}
	}
}

type chunkReader struct {
	r io.Reader
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	return c.r.Read(p[:min(len(p), c.n)])
}

// ブロックの状態は、入力ごとに戻す。連結して 1 つの入力にしたときと違い、次の入力の行は本文にならない(Q106)。
func TestPEMStateIsPerInput(t *testing.T) {
	key := fakeKey(2, 1)[0]
	got, st := mask(t, detect.Options{}, pemBegin+"\n"+key+"\n", "next\n")
	if got != pemBegin+"\n<secret_1>\nnext\n" {
		t.Errorf("got %q", got)
	}
	if st.Unclosed != 1 || len(st.UnclosedLines) != 1 || st.UnclosedLines[0] != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestPEMSecretOff(t *testing.T) {
	in := pemBegin + "\nAAAA\n" + pemEnd + "\n"
	got, st := mask(t, detect.Options{Kinds: detect.KindSet(0).With(detect.KindEmail)}, in)
	if got != in || st.Unclosed != 0 {
		t.Errorf("got %q", got)
	}
}

// 2 回流しても変わらない。mask(既定の書式、ラベルが base64 の文字でない書式)と hash。
func TestPEMIsStable(t *testing.T) {
	key := fakeKey(3, 2)
	in := "taro@example.com\n" + pemBegin + "\nProc-Type: 4,ENCRYPTED\n\n" + strings.Join(key, "\n") + "\n" + pemEnd + "\n" +
		"t=1 " + pemBegin + "\nt=2 " + key[0] + "\nt=3 " + pemEnd + "\n" +
		`{"pem":"` + pemBegin + `\nAAAA\n` + pemEnd + `\n"}` + "\n" +
		`{"log":"t=1 ` + pemBegin + `\n"}` + "\n" + `{"log":"t=2 Proc-Type: 4,ENCRYPTED\n"}` + "\n" + `{"log":"t=3 ` + key[1] + `\n"}` + "\n" + `{"log":"t=4 ` + pemEnd + `\n"}` + "\n" +
		"key=" + pemBegin + `\n` + "\n" + key[0] + `\n` + "\n" + pemEnd + `\n` + "\n" +
		`KEY="` + pemBegin + `\n\` + "\n" + key[1] + `\n\` + "\n" + pemEnd + `\n"` + "\n"
	optsList, dets := fuzzOptions(t)
	checkMaskStable(t, optsList, dets, in)
	checkHashStable(t, optsList, dets, in)
	if _, restored, _ := roundTrip(t, detect.Options{}, in); restored != in {
		t.Errorf("restored %q", restored)
	}
}

// 文字列で包まれた形でブロックが閉じたとき、伏せた出力を再度流しても、END なしの通知は 1 回目より増えない(仕様 4.1)。
func TestPEMReplacedTailInAString(t *testing.T) {
	in := `{"log":"` + pemBegin + `\n"}` + "\n" + `{"log":"AAAA\n"}` + "\n" + `{"log":"password: abc\n","t":"1"}` + "\n"
	masked, st := mask(t, detect.Options{}, in)
	if st.Unclosed != 1 {
		t.Errorf("first pass: %+v", st)
	}
	if twice, st := mask(t, detect.Options{}, masked); twice != masked || st.Unclosed != 0 {
		t.Errorf("second pass %q: %+v", twice, st)
	}
}

// END のない 1 行の形は、通知する。伏せた出力を再度流しても、通知しない。hash の出力と `{type}_{n}` のラベルは、
// base64 の文字で始まるので、1 行の形として読まれる(Q123)。
func TestPEMOneLineNotice(t *testing.T) {
	f, err := label.ParseFormat("{type}_{n}")
	if err != nil {
		t.Fatal(err)
	}
	bare := detect.Options{Format: f}
	for _, in := range []string{
		`{"log":"` + pemBegin + `\nAAAA\n","stream":"stderr"}` + "\n" + `{"log":"BBBB\n"}` + "\n",
		`{\"pem\":\"` + pemBegin + `\nAAAA\"}` + "\n",
		`KEY="` + pemBegin + `\nAAAA\n\` + "\nBBBB\n",
		"key=" + pemBegin + `\nAAAA\n` + "\nBBBB\n",
		pemBegin + " " + strings.Repeat("A", 16) + "\nBBBB\n",
		"key=" + pemBegin + `\n ` + "\nBBBB\n",
		`KEY="` + pemBegin + `\n \` + "\nBBBB\n",
		`KEY="` + pemBegin + `\n\ ` + "\nBBBB\n",
		"key=" + pemBegin + `\n\n` + "\nBBBB\n",
	} {
		masked, st := mask(t, detect.Options{}, in)
		if st.Unclosed != 1 {
			t.Errorf("%q: mask: %+v", in, st)
		}
		if twice, st := mask(t, detect.Options{}, masked); twice != masked || st.Unclosed != 0 {
			t.Errorf("%q: mask, second pass %q: %+v", in, twice, st)
		}
		masked, st = mask(t, bare, in)
		if st.Unclosed != 1 {
			t.Errorf("%q: bare: %+v", in, st)
		}
		if twice, st := mask(t, bare, masked); twice != masked || st.Unclosed != 0 {
			t.Errorf("%q: bare, second pass %q: %+v", in, twice, st)
		}
		hashed, st := hashRun(t, detect.Options{}, testKey, 12, EmailHashFull, in)
		if st.Unclosed != 1 {
			t.Errorf("%q: hash: %+v", in, st)
		}
		if twice, st := hashRun(t, detect.Options{}, testKey, 12, EmailHashFull, hashed); twice != hashed || st.Unclosed != 0 {
			t.Errorf("%q: hash, second pass %q: %+v", in, twice, st)
		}
		if _, restored, _ := roundTrip(t, detect.Options{}, in); restored != in {
			t.Errorf("%q: restored %q", in, restored)
		}
	}
}

func TestPEMBareFormat(t *testing.T) {
	f, err := label.ParseFormat("{type}_{n}")
	if err != nil {
		t.Fatal(err)
	}
	opts := detect.Options{Format: f}
	in := pemBegin + "\nAAAA\n" + pemEnd + "\n"
	masked, restored, _ := roundTrip(t, opts, in)
	if want := pemBegin + "\nsecret_1\n" + pemEnd + "\n"; masked != want {
		t.Errorf("got %q", masked)
	}
	if restored != in {
		t.Errorf("restored %q", restored)
	}
	if twice, st := mask(t, opts, masked); twice != masked || st.Total() != 0 {
		t.Errorf("second pass %q", twice)
	}
}
