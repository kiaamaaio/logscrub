package transform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKeyFromEnvironment(t *testing.T) {
	k, err := LoadKey(envOf(map[string]string{"LOGSCRUB_KEY": "env-key"}), "")
	if err != nil || string(k) != "env-key" {
		t.Errorf("key = %q, err = %v", k, err)
	}
}

func TestLoadKeyFromFile(t *testing.T) {
	for name, tt := range map[string]struct{ content, want string }{
		"plain":                    {"file-key", "file-key"},
		"trailing lf":              {"file-key\n", "file-key"},
		"trailing crlf":            {"file-key\r\n", "file-key"},
		"only one newline is cut":  {"file-key\n\n", "file-key\n"},
		"inner newline stays":      {"a\nb\n", "a\nb"},
		"spaces stay":              {" key \n", " key "},
		"binary":                   {"\x00\xff\x01key", "\x00\xff\x01key"},
		"cr only is not a newline": {"key\r", "key\r"},
		"non-ascii":                {"鍵🔑\n", "鍵🔑"},
	} {
		t.Run(name, func(t *testing.T) {
			k, err := LoadKey(envOf(nil), writeKeyFile(t, tt.content))
			if err != nil || string(k) != tt.want {
				t.Errorf("key = %q, err = %v, want %q", k, err, tt.want)
			}
		})
	}
}

// Q20: --key-file と環境変数の両方があれば、--key-file を優先する。
func TestLoadKeyFilePrecedesEnvironment(t *testing.T) {
	k, err := LoadKey(envOf(map[string]string{"LOGSCRUB_KEY": "env-key"}), writeKeyFile(t, "file-key\n"))
	if err != nil || string(k) != "file-key" {
		t.Errorf("key = %q, err = %v", k, err)
	}
}

// 受け入れ基準: LOGSCRUB_KEY 未設定で hash モードを使うとエラー終了する(鍵が読めない)。
func TestLoadKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		file string // 内容。"" で指定なし、"\x00missing" で存在しないファイル
	}{
		{"unset", nil, ""},
		{"empty environment", map[string]string{"LOGSCRUB_KEY": ""}, ""},
		{"empty file", nil, "\x00empty"},
		{"only newline", nil, "\x00newline"},
		{"missing file", map[string]string{"LOGSCRUB_KEY": "env-key"}, "\x00missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := ""
			switch tt.file {
			case "\x00empty":
				path = writeKeyFile(t, "")
			case "\x00newline":
				path = writeKeyFile(t, "\n")
			case "\x00missing":
				path = filepath.Join(t.TempDir(), "nope")
			}
			k, err := LoadKey(envOf(tt.env), path)
			if err == nil {
				t.Fatalf("key = %q, want an error", k)
			}
			// 鍵の値は、エラーメッセージに出さない。
			if strings.Contains(err.Error(), "env-key") {
				t.Errorf("the error contains the key: %v", err)
			}
		})
	}
}

// --key-file が読めないときは、環境変数に切り替えずに、エラーにする(意図しない鍵で変換しないため)。
func TestLoadKeyDoesNotFallBackToEnvironment(t *testing.T) {
	_, err := LoadKey(envOf(map[string]string{"LOGSCRUB_KEY": "env-key"}), filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Error("want an error when the key file cannot be read")
	}
}
