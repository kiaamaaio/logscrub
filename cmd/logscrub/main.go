// logscrub は、ログやテキストに含まれるメールアドレス・IP アドレス・トークン類などを、
// ラベル(mask)またはハッシュ(hash)に置換する CLI。使い方は `logscrub --help`。
package main

import (
	"os"

	"github.com/kiaamaaio/logscrub/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}
