package transform

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// KeyEnv は、hash の鍵を渡す環境変数の名前(仕様 5.2)。
const KeyEnv = "LOGSCRUB_KEY"

// LoadKey は、hash の鍵を読む(仕様 5.2、Q20)。
//
//   - keyFile が空でなければ、そのファイルの内容を使う。環境変数より優先する。
//     末尾の改行(`\n` または `\r\n`)を 1 つだけ除く。読めない場合は、環境変数に切り替えずに、エラーにする
//   - そうでなければ、環境変数 LOGSCRUB_KEY を使う
//   - 鍵が空なら、エラーにする
//
// エラーメッセージに、鍵の値は含めない。
func LoadKey(getenv func(string) string, keyFile string) ([]byte, error) {
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the key file: %w", err)
		}
		switch {
		case bytes.HasSuffix(b, []byte("\r\n")):
			b = b[:len(b)-2]
		case bytes.HasSuffix(b, []byte("\n")):
			b = b[:len(b)-1]
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("the key file %q is empty", keyFile)
		}
		return b, nil
	}
	if v := getenv(KeyEnv); v != "" {
		return []byte(v), nil
	}
	return nil, errors.New(KeyEnv + " is not set (set it, or use --key-file)")
}
