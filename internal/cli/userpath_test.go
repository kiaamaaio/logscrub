package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserPathMaskAndRestore(t *testing.T) {
	src := filepath.Join(t.TempDir(), "app.log")
	in := "File \"/home/yamada/app.py\"\nC:\\Users\\Taro Yamada\\x /Users/yamada/y\n"
	if err := os.WriteFile(src, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "", nil, "mask", src, "--stats")
	want := "File \"/home/<user_path_1>/app.py\"\nC:\\Users\\<user_path_2>\\x /Users/<user_path_1>/y\n"
	if r.code != 0 || r.stdout != want || r.stderr != "logscrub: user_path=3\n" {
		t.Fatalf("%+v", r)
	}
	back := run(t, r.stdout, nil, "restore", "--source", src)
	if back.code != 0 || back.stdout != in {
		t.Errorf("%+v", back)
	}
}

func TestUserPathTypes(t *testing.T) {
	const in = "/home/yamada/x a@example.com\n"
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"mask", "--types", "email"}, "/home/yamada/x <email_1>\n"},
		{[]string{"mask", "--types", "user_path"}, "/home/<user_path_1>/x a@example.com\n"},
		{[]string{"mask", "--types", "default"}, "/home/<user_path_1>/x <email_1>\n"},
		{[]string{"mask", "--allow", "yamada"}, "/home/yamada/x <email_1>\n"},
		{[]string{"mask", "--deny", "yamada"}, "/home/<custom_1>/x <email_1>\n"},
	} {
		if r := run(t, in, nil, tt.args...); r.code != 0 || r.stdout != tt.want {
			t.Errorf("%v: %+v", tt.args, r)
		}
	}
}

func TestUserPathHash(t *testing.T) {
	r := run(t, "/home/yamada/x\n", hashEnv(), "mask", "--mode", "hash")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "/home/user_path_") || !strings.HasSuffix(r.stdout, "/x\n") {
		t.Fatalf("%+v", r)
	}
	again := run(t, r.stdout, hashEnv(), "mask", "--mode", "hash")
	if again.stdout != r.stdout {
		t.Errorf("second pass: %+v", again)
	}
}

// 種別名が、ヘルプに載る(仕様 9 章)。--stats の並びは、custom の次。
func TestUserPathStatsOrderAndHelp(t *testing.T) {
	r := run(t, "/home/yamada/x acme\n", nil, "mask", "--deny", "acme", "--stats")
	if r.stderr != "logscrub: custom=1\nlogscrub: user_path=1\n" {
		t.Errorf("%q", r.stderr)
	}
	if h := run(t, "", nil, "mask", "--help"); !strings.Contains(h.stdout, "user_path") {
		t.Error("mask --help lacks user_path")
	}
}
