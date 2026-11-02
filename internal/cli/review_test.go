package cli

import (
	"strings"
	"testing"
)

func TestReview(t *testing.T) {
	const in = "to taro@example.com\nid abcdefghij0123456789\n"
	r := run(t, in, nil, "mask", "--review")
	if r.code != 0 || !strings.Contains(r.stdout, "\x1b[36m<email_1>\x1b[0m") || !strings.Contains(r.stdout, "\x1b[30;43mabcdefghij0123456789\x1b[0m") {
		t.Fatalf("%+v", r)
	}
	// 値を stderr に出さない。
	if r.stderr != "logscrub: 1 string looks like an unreplaced value (line 2).\n" {
		t.Errorf("%q", r.stderr)
	}
	plain := run(t, in, map[string]string{"NO_COLOR": "1"}, "mask", "--review")
	if plain.stdout != "to <email_1>\nid abcdefghij0123456789\n" {
		t.Errorf("%q", plain.stdout)
	}
	// 空の NO_COLOR は、ないものとして扱う。
	if e := run(t, in, map[string]string{"NO_COLOR": ""}, "mask", "--review"); !strings.Contains(e.stdout, "\x1b[") {
		t.Errorf("%q", e.stdout)
	}
}

func TestReviewNotices(t *testing.T) {
	const word = "abcdefghij0123456789"
	two := run(t, word+" "+word+"\nx\n"+word+"\n", nil, "mask", "--review")
	if two.stderr != "logscrub: 3 strings look like unreplaced values (lines 1, 3).\n" {
		t.Errorf("%q", two.stderr)
	}
	many := run(t, strings.Repeat(word+"\n", 7), nil, "mask", "--review")
	if many.stderr != "logscrub: 7 strings look like unreplaced values (lines 1, 2, 3, 4, 5, ...).\n" {
		t.Errorf("%q", many.stderr)
	}
	if n := run(t, word+"\n", nil, "mask"); n.stderr != "" {
		t.Errorf("without --review: %q", n.stderr)
	}
}

// 置換の結果、--stats、終了コードは、--review の有無で変わらない(仕様 9 章)。
func TestReviewKeepsTheResult(t *testing.T) {
	const in = "to taro@example.com\n"
	r := run(t, in, nil, "mask", "--review", "--stats", "--fail-on-detect")
	if r.code != exitDetected || r.stderr != "logscrub: email=1\n" {
		t.Errorf("%+v", r)
	}
	if none := run(t, "abcdefghij0123456789\n", nil, "mask", "--review", "--fail-on-detect"); none.code != exitOK {
		t.Errorf("a suspicious string must not change the exit status: %+v", none)
	}
	h := run(t, in, hashEnv(), "mask", "--review", "--mode", "hash")
	if h.code != 0 || !strings.Contains(h.stdout, "\x1b[36memail_") {
		t.Errorf("%+v", h)
	}
}

func TestReviewConflicts(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "x"}, {"-o", "x"}, {"--out-dir", "x"}, {"-o", "-"},
	} {
		r := run(t, "x\n", nil, append([]string{"mask", "--review"}, args...)...)
		if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "--review cannot be used") {
			t.Errorf("%v: %+v", args, r)
		}
	}
	if r := run(t, "", nil, "restore", "--review", "--source", "x"); r.code != exitError {
		t.Errorf("restore --review: %+v", r)
	}
}
