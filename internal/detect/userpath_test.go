package detect

import (
	"strings"
	"testing"
)

func TestUserPathForms(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindUserPath)})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		line string
		want []string
	}{
		// 対象の形
		{`File "/home/yamada/proj/app.py", line 3`, []string{"yamada"}},
		{"/Users/hanako/Library/Logs", []string{"hanako"}},
		{`C:\Users\yamada\AppData`, []string{"yamada"}},
		{`c:\users\yamada\AppData`, []string{"yamada"}},
		{`D:\USERS\yamada\x`, []string{"yamada"}},
		{`{"path":"C:\\Users\\yamada\\app.log"}`, []string{"yamada"}},
		{"C:/Users/yamada/app.log", []string{"yamada"}},
		{"/mnt/c/Users/yamada/app.log", []string{"yamada"}},
		{"/c/Users/yamada/app.log", []string{"yamada"}},
		{"file:///home/yamada/a.txt", []string{"yamada"}},
		{"file:///Users/yamada/a.txt", []string{"yamada"}},
		{"file:///C:/Users/yamada/a.txt", []string{"yamada"}},
		{"jar:file:/C:/Users/Taro Yamada/app.jar", []string{"Taro Yamada"}},
		{"file:/c:/users/yamada/app.jar", []string{"yamada"}},
		{"file:/C:/Users/PUBLIC/app.jar", nil},
		{"/C:/Users/yamada/x", []string{"yamada"}},
		{`C:\Users/yamada/x`, []string{"yamada"}},
		{`C:/Users\Taro Yamada\x`, []string{"Taro Yamada"}},
		{`\\wsl$\Ubuntu\home\yamada\x`, []string{"yamada"}},
		{`\\wsl.localhost\Ubuntu-22.04\home\yamada`, []string{"yamada"}},
		{`{"p":"\\\\wsl$\\Ubuntu\\home\\yamada\\x"}`, []string{"yamada"}},
		{`\\wsl$\Ubuntu\home\user\x`, nil},
		{`\\wsl$\Ubuntu\var\home\yamada`, nil},
		{`x\\wsl$\Ubuntu\home\yamada`, nil},
		{`//wsl$/Ubuntu/home/yamada/x`, []string{"yamada"}},
		{`cd //wsl.localhost/Ubuntu-22.04/home/yamada`, []string{"yamada"}},
		{`//wsl$/Ubuntu/home/user/x`, nil},
		{`//wsl$/Ubuntu/var/home/yamada`, nil},
		{`x//wsl$/Ubuntu/home/yamada`, nil},
		{`https://wsl.localhost/Ubuntu/home/yamada`, nil},
		{`file://wsl$/Ubuntu/home/yamada`, nil},
		{`\\WSL$\Ubuntu\home\yamada`, nil},
		{`\\wsl$\Ubuntu/home/yamada`, nil},
		{`url="file:///home/yamada/a.txt"`, []string{"yamada"}},
		// JSON の文字列の中の形
		{`{"stderr":"Traceback\n/home/yamada/app.py:3: boom"}`, []string{"yamada"}},
		{`{"msg":"x\t/Users/hanako/a.py"}`, []string{"hanako"}},
		{`{"msg":"x\r\nC:\\Users\\yamada\\x"}`, []string{"yamada"}},
		{`{"file":"\/home\/yamada\/app\/x.php"}`, []string{"yamada"}},
		{`{"file":"\/Users\/hanako\/x.php"}`, []string{"hanako"}},
		{`{"file":"C:\/Users\/yamada\/x.php"}`, []string{"yamada"}},
		{`{"file":"C:\/Users\/Taro Yamada\/x.php"}`, []string{"Taro Yamada"}},
		{`{"file":"c:\/users\/Taro Yamada\/x.php"}`, []string{"Taro Yamada"}},
		{`{"file":"C:\/Users\/PUBLIC\/x.php"}`, nil},
		{`{"file":"\/var\/home\/yamada"}`, nil},
		{`\\?\C:\Users\yamada\x`, []string{"yamada"}},
		{`\\\\?\\C:\\Users\\yamada\\x`, []string{"yamada"}},
		// 値の範囲
		{"HOME=/home/yamada", []string{"yamada"}},
		{"/home/yamada:/bin/bash", []string{"yamada"}},
		{"see /home/yamada.", []string{"yamada"}},
		{"/home/t.yamada/x", []string{"t.yamada"}},
		{"/home/山田/x", []string{"山田"}},
		{"パスは/home/yamada/x", []string{"yamada"}},
		{"/home/yamada /home/hanako", []string{"yamada", "hanako"}},
		{`C:\Users\Taro Yamada\AppData`, []string{"Taro Yamada"}},
		{"C:/Users/Taro Yamada/AppData", []string{"Taro Yamada"}},
		{`{"p":"C:\\Users\\Taro Yamada\\x"}`, []string{"Taro Yamada"}},
		{`C:\Users\taro is missing`, []string{"taro"}},
		{`C:\Users\taro: see D:\x`, []string{"taro"}},
		{`C:\Users\taro /var/log`, []string{"taro"}},
		{`C:\Users\taro/x`, []string{"taro"}},
		// 空白を含められるのは Windows の形だけ
		{"/home/Taro Yamada/x", []string{"Taro"}},
		// 対象外の形
		{"https://example.com/home/x", nil},
		{"/var/home/x", nil},
		{"/api/Users/x", nil},
		{"//home/x", nil},
		{`\home\x`, nil},
		{`\\server\Users\x`, nil},
		{"x:/Users", nil},
		{"/home/", nil},
		{"/home", nil},
		{"/homes/x", nil},
		{"/HOME/x", nil},
		{"/users/x", nil},
		{"ab:/users/x", nil},
		{"/ab/Users/x", nil},
		{"/opt/c/Users/x", nil},
		{"/root/x", nil},
		// 値にならない文字
		{"/home/$USER/x", nil},
		{"/home/${USER}/x", nil},
		{"/home/*/x", nil},
		{"/home/<user>/x", nil},
		{`C:\Users\%USERNAME%\x`, nil},
		{"/home/../x", nil},
		// 対象外の名前
		{"PWD=/home/user", nil},
		{"/home/ubuntu/x /home/ec2-user/x /home/runner/x", nil},
		{"/Users/Shared/x", nil},
		{`C:\Users\Public\x`, nil},
		{`C:\Users\public\x`, nil},
		{`C:\Users\Default User\x`, nil},
		{`C:\Users\All Users\x`, nil},
		{"/home/Ubuntu/x", []string{"Ubuntu"}},
		{"/home/ubuntu2/x", []string{"ubuntu2"}},
		// バージョンの表記を除外しないことも、ここで確かめる(Q102)
		{"GET /home/v1/items", []string{"v1"}},
	}
	for _, c := range cases {
		ms, _ := d.Find([]byte(c.line), nil)
		var got []string
		for _, m := range ms {
			if m.Kind != KindUserPath {
				t.Errorf("%q: kind %v", c.line, m.Kind)
			}
			got = append(got, c.line[m.Start:m.End])
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}

func TestUserPathOverlaps(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		line string
		want Kind
		text string
	}{
		{"email wins with the same range", Options{}, "/home/taro@example.com/x", KindEmail, "taro@example.com"},
		{"ip wins with the same range", Options{}, "/home/10.0.0.1/x", KindIPv4, "10.0.0.1"},
		{"a longer secret wins", Options{}, "password=/home/yamada/x", KindSecret, "/home/yamada/x"},
		{"custom wins with the same range", Options{Deny: []string{"yamada"}}, "/home/yamada/x", KindCustom, "yamada"},
		{"a longer name wins", Options{Deny: []string{"acme"}}, "/home/acme-prod/x", KindUserPath, "acme-prod"},
	}
	for _, c := range cases {
		d, err := New(c.opts)
		if err != nil {
			t.Fatal(err)
		}
		ms, _ := d.Find([]byte(c.line), nil)
		if len(ms) != 1 || ms[0].Kind != c.want || c.line[ms[0].Start:ms[0].End] != c.text {
			t.Errorf("%s: %+v", c.name, ms)
		}
	}
}

func TestUserPathAllow(t *testing.T) {
	d, err := New(Options{Allow: map[string]struct{}{"deploy": {}}})
	if err != nil {
		t.Fatal(err)
	}
	if ms, _ := d.Find([]byte("/home/deploy/x /home/yamada/x"), nil); len(ms) != 1 || ms[0].Kind != KindUserPath {
		t.Errorf("%+v", ms)
	}
}

// 区切りが多い行でも、線形の時間で終わる(空白を含む名前の先読みが、2 乗にならない)。
func TestUserPathLongLine(t *testing.T) {
	d, err := New(Options{Kinds: KindSet(0).With(KindUserPath)})
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat(`C:\Users\a b `, 100000))
	if ms, _ := d.Find(line, nil); len(ms) != 100000 {
		t.Errorf("%d matches", len(ms))
	}
}
