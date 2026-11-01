# logscrub

ログやテキストに含まれる **メールアドレス・IP アドレス・トークン類(URL のパスワードを含む)・UUID・AWS の値(アカウント ID、S3 のバケット名、サービスのホスト名)・利用者が指定した語やドメイン** を、
種別が分かるラベル(`<email_1>`)またはハッシュ値に置き換える CLI です。
ログ調査の内容を AI に安全に渡すことを、主な用途としています。

```console
$ echo "taro@example.com 192.168.0.1 password=hunter2" | logscrub mask
<email_1> <ipv4_private_1> password=<secret_1>
```

- 標準入力 → 標準出力のパイプで使います(ファイルも指定できます)。
- 行単位のストリーム処理で、大きなログでもメモリを使い切りません。行の長さに上限はありません。
- 改行コード(LF / CRLF)、末尾改行の有無、置換した部分以外のバイト列は、1 バイトも変えません。
- 外部との通信は一切行いません。外部ライブラリも使いません(Go の標準ライブラリだけ)。

> **注意**: 検出は完全ではありません(正規表現による形式の一致が基本です)。
> 外部に出す前に、必ず出力を確認してください。見逃しや誤検出の例は、[LIMITATIONS.md](LIMITATIONS.md) にまとめています。

## 導入

### バイナリを取得する

[Releases](https://github.com/kiaamaaio/logscrub/releases) から、環境に合うファイルを取得します。Go の環境は要りません。
ファイル名は `logscrub-<版>-<OS>-<CPU>` で、OS は `linux`・`darwin`・`windows`、CPU は `amd64`・`arm64` です(Windows は末尾に `.exe`)。

```console
$ curl -fLO https://github.com/kiaamaaio/logscrub/releases/download/v1.4.0/logscrub-v1.4.0-linux-amd64
$ curl -fLO https://github.com/kiaamaaio/logscrub/releases/download/v1.4.0/SHA256SUMS
$ sha256sum --check --ignore-missing SHA256SUMS
$ chmod +x logscrub-v1.4.0-linux-amd64
$ sudo mv logscrub-v1.4.0-linux-amd64 /usr/local/bin/logscrub
$ logscrub --version
```

- macOS: `sha256sum` の代わりに `shasum -a 256 --check --ignore-missing SHA256SUMS` を使います。バイナリは署名していないので、ブラウザで取得すると、Gatekeeper に止められます。`curl` で取得するか、`xattr -d com.apple.quarantine logscrub-…` で解除してください。
- Windows: 署名していないので、SmartScreen の警告が出ることがあります。PowerShell のパイプは文字コードを変えることがあるので、ファイルを引数で渡してください(`logscrub.exe mask app.log -o masked.log`)。

### Go でインストールする

Go 1.27 以上が必要です。

```console
$ go install github.com/kiaamaaio/logscrub/cmd/logscrub@latest
```

## 使い方

### mask: ラベルに置き換える(既定)

同じ値には同じラベル、違う値には次の番号が付きます。番号は、入力の中で最初に現れた順です。

```console
$ cat app.log | logscrub mask | pbcopy        # AI に貼る
```

AI の回答に含まれるラベルは、`restore` で元の値に戻せます。対応表のファイルは作りません。
元の入力から、その場で対応を作り直します。

```console
$ pbpaste | logscrub restore --source app.log
```

`mask` に渡した入力を、パイプなどで絞り込んだ場合は、`restore` にも同じ内容を渡します。
bash / zsh なら、プロセス置換が使えます。

```console
$ grep ERROR app.log | logscrub mask | pbcopy
$ pbpaste | logscrub restore --source <(grep ERROR app.log)
```

**`restore` には、`mask` のときと同じ検出オプション**(`--types`、`--uuid-versions`、`--ip-scope`、
`--allow`、`--deny`、`--deny-file`、`--domain`、`--mask-format`)と、同じ入力を、同じ順で指定してください。違うと、連番がずれます。
`mask` と `restore` は、同じ版で使ってください(`logscrub --version` で確かめられます)。

AI の回答でラベルがエスケープされていても(`&lt;email_1&gt;`、`\<email_1\>`)、元の値に戻します。括りを外した `email_1` は戻しません。

### hash: 鍵つきのハッシュに置き換える

同じ値は、同じ鍵なら、常に同じ出力になります。別のマシンでも同じです。元には戻せません。
HMAC-SHA256 の先頭 12 桁(`--hash-length` で 8〜64)を使います。

```console
$ export LOGSCRUB_KEY=test-key      # 例では短い鍵。実際は、長いランダムな文字列にする(または --key-file FILE)
$ echo "taro@example.com 192.168.0.1" | logscrub mask --mode hash
email_99a207efd719 ipv4_private_dca2f4f38564
$ echo "taro@example.com" | logscrub mask --mode hash --email-hash local
hash_a746604745a4@example.com
```

### その他

```console
$ logscrub mask --types email app.log               # メールアドレスだけ
$ logscrub mask --types default,uuid app.log        # 既定の種別に UUID を加える
$ logscrub mask --types default,aws app.log         # 既定の種別に AWS の値(アカウント ID、バケット名、ホスト名)を加える
$ logscrub mask --uuid-versions 4,7 app.log         # UUID の v4 と v7 だけ(uuid も有効になる)
$ logscrub mask --ip-scope global app.log           # グローバルな IP だけ(内部アドレスは残す)
$ logscrub mask --allow support@example.com app.log # この値は置換しない(複数回指定できる)
$ logscrub mask --deny acme app.log                 # 会社名などの語を <custom_1> にする(複数回指定できる)
$ logscrub mask --deny-file words.txt app.log       # 語の一覧のファイルから読む(1 行 1 語)
$ logscrub mask --domain example.co.jp app.log      # このドメインのホスト名を <host_1> にする(複数回指定できる)
$ logscrub mask --stats app.log                     # 種別ごとの件数を stderr に出す
$ logscrub mask --fail-on-detect app.log            # 1 件でも置換したら、終了コード 2
$ logscrub mask app.log -o masked.log               # ファイルに書く
$ logscrub types --verbose                          # 対応する種別と、secret の形式
```

オプションは、ファイル名の前後どちらにも書けます。`--` の後ろは、すべてファイル名として扱います。
ファイルを複数指定すると、順に連結した 1 つの入力として処理します(番号も通しです)。

## オプション

### `logscrub mask [FILE ...]`

| オプション | 説明 |
|---|---|
| `--mode mask\|hash` | `mask`(既定): ラベル。`hash`: ハッシュ(元に戻せない) |
| `--types LIST` | 対象の種別、または種別のまとまり(カンマ区切り)。指定した種別**だけ**が対象。`default` を含めると既定の種別が加わる([検出対象](#検出対象)) |
| `--uuid-versions 4,7` | 対象にする UUID のバージョン(1〜8)。これだけで `uuid` が対象に加わる |
| `--ip-scope all\|global\|private` | 置換する IP アドレスの範囲(既定 `all`) |
| `--allow VALUE` | 置換しない値(完全一致、複数回指定可) |
| `--deny VALUE` | 伏せる語(複数回指定可)。`custom` が対象に加わる。[詳細](docs/detection.md#指定した語custom) |
| `--deny-file FILE` | 語の一覧のファイル(1 行 1 語。空行と `#` の行は無視。複数回指定可) |
| `--domain DOMAIN` | ホスト名を伏せるドメイン(サブドメインを含む。複数回指定可)。`host` が対象に加わる。[詳細](docs/detection.md#指定したドメインのホスト名host) |
| `--mask-format FMT` | ラベルの書式。`{type}` と `{n}` をちょうど 1 回ずつ含める(既定 `<{type}_{n}>`) |
| `--email-hash full\|local` | hash モードのメールアドレス。`full`(既定): 全体、`local`: ローカルパートだけ |
| `--hash-length N` | hash モードの桁数(8〜64、既定 12) |
| `--key-file FILE` | hash モードの鍵のファイル(環境変数 `LOGSCRUB_KEY` より優先。末尾の改行 1 つは除く) |
| `--stats` | 置換した件数を、種別ごとに stderr に出す |
| `--fail-on-detect` | 1 件でも置換したら、終了コード 2 で終える(出力は通常どおり) |
| `-o`, `--output FILE` | 出力先のファイル(入力と同じファイルは指定できない) |

hash モード専用のオプション(`--hash-length`、`--email-hash`、`--key-file`)を、mask モードで指定するとエラーです。

### `logscrub restore --source FILE [--source FILE ...] [ANSWER_FILE]`

`ANSWER_FILE`(省略時は標準入力)のラベルを、元の値に戻します。`--source` は必須で、複数指定できます
(`mask` のときと同じ順に並べてください)。`--source -` は標準入力で、`ANSWER_FILE` を指定した場合だけ使えます。
検出オプションは `mask` と同じです。戻せなかったラベルは、そのまま残し、ラベル名(元の値は出しません)を
stderr に出します(終了コードは 0)。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 正常 |
| 1 | エラー(オプションの誤り、ファイルが開けない、書き込みの失敗、鍵の未設定など) |
| 2 | `--fail-on-detect` を指定して、置換があった(エラーのときは 1 が優先) |

## 検出対象

| 種別 | 内容 | 既定 |
|---|---|---|
| `email` | メールアドレス(TLD は英字 2 文字以上) | 有効 |
| `ipv4` / `ipv6` | IP アドレス。グローバルとプライベートを、ラベルで区別する(`<ipv4_global_1>`、`<ipv4_private_1>`) | 有効 |
| `secret` | トークン類([対応形式](docs/detection.md#secret-の対応形式)) | 有効 |
| `uuid` | UUID(バージョン 1〜8) | 無効 |
| `aws_account` | AWS アカウント ID(ARN・ECR・SQS・S3 Control の中のもの。[AWS の値](docs/detection.md#aws-の値)) | 無効 |
| `aws_s3_bucket` | S3 のバケット名(`s3://`・S3 の URL・ARN の中のもの。[AWS の値](docs/detection.md#aws-の値)) | 無効 |
| `aws_host` | AWS のサービスのホスト名の、利用者ごとの部分(RDS、ELB、CloudFront など。[AWS のサービスのホスト名](docs/detection.md#aws-のサービスのホスト名)) | 無効 |
| `host` | `--domain` で指定したドメインのホスト名([指定したドメイン](docs/detection.md#指定したドメインのホスト名host)) | `--domain` で有効 |
| `custom` | `--deny`・`--deny-file` で指定した語([指定した語](docs/detection.md#指定した語custom)) | `--deny` で有効 |

`--types` には、種別名のほかに、次のまとまりを書けます。

| まとまり | 含まれる種別 |
|---|---|
| `default` | 既定で有効の種別(`email`、`ipv4`、`ipv6`、`secret`) |
| `aws` | `aws_` で始まる種別(`aws_account`、`aws_s3_bucket`、`aws_host`) |
| `cloud` | すべてのクラウドの種別(今は `aws` と同じ) |

例: `--types default,aws` は既定の種別と AWS の種別、`--types aws` は AWS の種別だけが対象です。
`logscrub types` で、種別とまとまりの一覧を確認できます。

IP アドレスのうち、`0.0.0.0`、`255.255.255.255`、`::`、マルチキャストは、隠す意味がないので置換しません。
プライベートは、RFC1918、ループバック、リンクローカル、`100.64.0.0/10`、IPv6 の ULA です。
IPv6 は、割り当て済みの範囲(`2000::/3`、`fc00::/7`、`fe80::/10`、`::1`、IPv4-mapped、NAT64)だけを検出します。

EC2 のホスト名に `-` 区切りで埋め込まれた IPv4 も、`ipv4` として置換します(既定で有効)。
IP アドレスだけを隠しても、ホスト名から元の値が読めてしまうためです。数値の部分だけを置換します。

| 形 | 例 | 置換後 |
|---|---|---|
| パブリック DNS | `ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com`、`ec2-54-250-1-2.compute-1.amazonaws.com` | `ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com` |
| プライベート DNS | `ip-10-0-1-23.ap-northeast-1.compute.internal`、`ip-10-0-1-23.ec2.internal` | `ip-<ipv4_private_1>.ap-northeast-1.compute.internal` |
| ドメインのない IP 名 | `ip-10-0-1-23`(シェルのプロンプト、Kubernetes のノード名など) | `ip-<ipv4_private_1>` |

詳しい形式は [docs/detection.md](docs/detection.md) にあります([`secret` の対応形式](docs/detection.md#secret-の対応形式)、[AWS の値](docs/detection.md#aws-の値)、[AWS のサービスのホスト名](docs/detection.md#aws-のサービスのホスト名)、[指定した語](docs/detection.md#指定した語custom)、[指定したドメイン](docs/detection.md#指定したドメインのホスト名host))。

## 性質

- **決定的**: 同じ入力・同じオプションなら、常に同じ出力です。
- **冪等**: 置換済みの出力を、同じオプションで再度流しても変わりません(`<email_1>`、`password=<secret_1>`、
  hash の `email_<hex>` など)。置換済みの形のため置換せずに残した文字列があると、件数と行番号を stderr に
  1 行で知らせます(本物の値がたまたま同じ形だった場合に、気づくためです)。手で作らない限り現れない入力での例外は、
  [LIMITATIONS.md の「冪等性」](LIMITATIONS.md#冪等性)を見てください。
- **値を出さない**: stderr やエラーメッセージに、置換対象の値(元の入力の中身)は出しません。

## 限界

検出は、形式の一致に基づく推定です。**外部に出す前に、出力を必ず確認してください。** 主なものは次のとおりで、すべての限界は [LIMITATIONS.md](LIMITATIONS.md) にまとめています。

- 決まった形式に当てはまらない値(独自形式のトークン、決まった形の外にある AWS の値など)は検出されません。
- 引用符なしで空白を含む値(`password: my secret phrase`)は、最初の語だけが置換されます。
- `version 1.2.3.4` のような 4 つ組のバージョン番号は、IP アドレスとして検出されます。
- `restore` は、`mask` と同じ入力・同じ検出オプションでないと、正しく戻りません。

## 性能

目標は 50MB/s 以上です。実測は次のとおりです(合成ログ 100MB を、ビルドしたバイナリで処理)。

| 実行 | 速度 | 最大メモリ |
|---|---|---|
| `logscrub mask < big.log > /dev/null` | 約 374 MB/s | 36 MB |
| 同上(`GOMAXPROCS=1`) | 約 208 MB/s | 38 MB |
| `cat big.log \| logscrub mask > /dev/null` | 約 332 MB/s | 40 MB |
| `logscrub mask --types default,uuid < big.log` | 約 370 MB/s | 38 MB |
| AWS の値(ホスト名、URL のパスワードを含む)を含む合成ログを `--types default,aws` で | 約 290 MB/s | 42 MB |
| 同上(`aws_host` なし: `--types default,aws_account,aws_s3_bucket`) | 約 334 MB/s | 38 MB |
| 語を 1000 個指定(`--deny-file`) | 語の綴りにより 約 270〜345 MB/s | 36 MB |
| `--domain` を指定 | 約 333 MB/s | 36 MB |
| `--mode hash` | 約 407 MB/s | 18 MB |
| `logscrub restore --source big.log`(MB/s は元の入力の大きさ) | 約 326 MB/s | 46 MB |

- **メモリ**: 対応表(検出した値の種類数に比例)が主です。値の種類数が一定(1,000 種類)なら、入力が
  20MB でも 100MB でも、最大 15〜17MB ほどです。ほぼすべての値が異なる 100MB のログでは、36.1MB でした。
  ほかに、ワーカーごとの固定の作業領域と、処理中の最長の行の分を使います。
- **並列処理**: 検出は、複数のワーカーで並列に行います。ワーカー数は `GOMAXPROCS`(既定は CPU の数)から決め、上限は 8 です。
  連番を振る処理は 1 か所なので、ワーカー数によらず出力は同じです。上の値は 2 CPU での測定で、3 CPU 以上では測っていません。
- **測定条件**: 合成ログ(1 行 200 バイト前後、約 30% の行に検出対象があり、1MB の JSON を 1 行で数行含む)、
  既定の種別、mask モード。AMD Ryzen 9 9950X、WSL2 上の Docker コンテナ(`golang:1.27.2`、2 CPU)内で測定し、
  3 回のうちの最速の値です。実際のログでは、検出対象の割合や行の長さで変わります。
- **再現**: `./scripts/go test -run Perf -v ./cmd/logscrub -perf`(`-perf-size 100` で大きさを指定)。

速度のために、正規表現を当てる前に、行の中に手がかり(`@`、`.` `:` と数字の並び、トークンの接頭辞、
`=` `:`、ハイフンの並び、`arn:`・`.amazonaws.` など)があるかを確かめて、ほとんどの行では正規表現を使いません。

## 開発

Go の操作は、開発環境に依存しないよう、すべて Docker コンテナ(`golang:1.27.2`)の中で行います。
ラッパー `scripts/go` が、引数をそのまま `go` に渡します(ネットワークなし、ホストのユーザーで実行)。

```console
$ ./scripts/go test ./...
$ ./scripts/go vet ./...
$ ./scripts/go build -o bin/logscrub ./cmd/logscrub
```

配布用のバイナリは `scripts/build-release` で作ります(手順は [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) 4 章)。

仕様は [docs/SPEC.md](docs/SPEC.md)(目次。章ごとの本文は [docs/spec/](docs/spec/)。パッケージ構成は 8 章)、開発環境・構成・設計の注意点は [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)、版ごとの実装計画と進捗・判断の記録は [docs/plans/](docs/plans/) にあります。

## 変更点

版ごとの変更点は [CHANGELOG.md](CHANGELOG.md) にあります。

## ライセンス

[MIT License](LICENSE)
