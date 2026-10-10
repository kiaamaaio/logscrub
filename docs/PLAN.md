# logscrub v1 実装計画

- 仕様: [SPEC.md](SPEC.md)(以下「仕様」。節番号は仕様のもの)
- 前提: Go 1.27 系、標準ライブラリのみ
- モジュールパス: `github.com/kiaamaaio/logscrub`(git remote から。→ Q30 で確認)
- 各段階の完了条件: `go test ./...` と `go vet ./...` が通ること(CLAUDE.md)。どちらも 0 章の Docker コンテナ内で実行する
- **5 章「未確定事項」の回答待ちの項目は、推測で実装しない。** 各段階の「前提となる確認」に挙げた項目が決まるまで、その段階には入らない(2026-10-11 時点で Q1〜Q31 はすべて確定)

---

## 0. 開発環境(Docker)

開発環境に依存しないため、Go に関する操作(`go mod`、ビルド、テスト、vet、ベンチマーク、性能測定)は**すべて Docker コンテナ内で行う**。ホストの Go は使わない。

- イメージ: `golang:1.27.2`(公式イメージ。パッチ版まで固定し、上げるときは意図して変える)
- `go.mod` の `go` 行は `go 1.27`
- 呼び出しは、段階 1 で作るラッパー `scripts/go` に統一する。引数はそのまま `go` に渡す
  - 例: `./scripts/go test ./...`、`./scripts/go vet ./...`、`./scripts/go build -o bin/logscrub ./cmd/logscrub`
- ラッパーの中身(`docker run` の主なオプション):

| オプション | 目的 |
|---|---|
| `--rm -i` | 使い捨て。性能測定で stdin からパイプで流せるように `-i` |
| `-u "$(id -u):$(id -g)"` | 作られるファイル(`go.mod`、`bin/`)を root 所有にしない |
| `-v <リポジトリ>:/src -w /src` | リポジトリをマウントして作業 |
| `-v <リポジトリ>/.cache:/cache`、`GOCACHE=/cache/go-build`、`GOMODCACHE=/cache/mod`、`HOME=/tmp` | ビルドキャッシュを実行ごとに捨てない。`.cache/` は `.gitignore` に入れる |
| `GOTOOLCHAIN=local` | 別バージョンのツールチェーンを勝手に取得しない(1.27.2 で固定) |
| `--network none` | 外部の依存を取得できない状態にし、「標準ライブラリのみ」を構造的に守る |

- 前提: ホストのユーザーが Docker を使えること
  - ホストの Docker は snap 版(29.8.0、サービス名は `snap.docker.dockerd.service`、再起動は `sudo snap restart docker`)。snap 版はホームディレクトリ配下しかマウントできない
  - 2026-10-11 に `docker` グループを作成し、ソケットが `root:docker` になったことを確認した。上の表の `-u`、`--network none`、`GOTOOLCHAIN=local`、リポジトリと `.` で始まるディレクトリのマウントが動くことも確認済み。`.cache/` への書き込みも、段階 1 で動くことを確認した(ビルドキャッシュが作られ、所有者はホストのユーザー)

---

## 1. パッケージ構成と主要な型・関数

仕様 8 章の構成を土台に、2 つのパッケージを追加する。

```
logscrub/
├── go.mod                       # 依存なし
├── README.md
├── cmd/logscrub/main.go         # os.Exit(cli.Run(...)) だけの薄い入口
├── internal/
│   ├── cli/                     # 【追加】サブコマンド振り分け・flag 解析・終了コード
│   ├── label/                   # 【追加】--mask-format の解析/生成/走査、hash 出力形の走査
│   ├── detect/                  # 種別ごとの検出、重なりの解決、置換対象外の除外
│   ├── transform/               # mask.go, hash.go, restore.go, engine.go(行の書き換え)
│   └── stream/                  # 行単位の入出力(改行コード・末尾改行の保持)
└── testdata/                    # 往復テスト・E2E 用の入力と期待出力
```

### 仕様 8 章から変える点と理由

| 変更 | 理由 |
|---|---|
| `internal/label` を追加 | ラベルの書式は「mask で生成」「restore で読み取り」「検出時に置換済みとして除外」の 3 か所で使う。`detect` に置くと `transform` → `detect` の依存は良いが、書式の責務が検出に混ざる。`transform` に置くと `detect` → `transform` の循環になる。独立させて両方から使う |
| `internal/cli` を追加し、`main.go` は薄くする | `cli.Run(args, stdin, stdout, stderr, getenv) int` にすると、終了コード・stdout/stderr の分離・オプション順序などの受け入れ基準を、バイナリを作らずにテストで確認できる |
| `transform/engine.go` を追加 | 「行を読む → 検出 → 置換 → 書く」の流れを mask / hash / restore(の対応表作り直し)で共有する。restore が mask と**同じコード経路**で連番を振ることが、連番の決定性(4.3 節)の要になる |

### 主要な型・関数(案)

**stream**

```go
// Reader は 1 行ずつ返す。行の長さに上限はない(bufio.Reader.ReadSlice + ErrBufferFull 時のみ連結)。
type Reader struct { ... }
func NewReader(r io.Reader) *Reader
// Next は行の中身(改行コードを含まない)と改行コード("\n" / "\r\n" / 末尾改行なしなら空)を返す。
// 返すスライスは次の Next まで有効。
func (r *Reader) Next() (content, eol []byte, err error)

// ForEachLine は inputs を順に読み、1 行ごとに fn を呼ぶ。行は入力ごとに区切る(Q22)。
func ForEachLine(inputs []io.Reader, fn func(content, eol []byte) error) error
// Copy は ForEachLine で読み、行を変えずに w へ書く(恒等変換)。入力の間に改行は足さない。
func Copy(w io.Writer, inputs ...io.Reader) error
```

- 単独の `\r` は改行とみなさず、行の中身として扱う(仕様 7 章は LF / CRLF のみ言及)。
- バイト列として扱い、UTF-8 の妥当性は一切確認しない(不正なバイト列もそのまま通る)。

**label**

```go
// 置換後の種別名。IP は区別を含む。並びは連番・--stats の出力順にも使う。
var Types = []string{"email", "ipv4_global", "ipv4_private", "ipv6_global", "ipv6_private", "secret", "uuid"}

type Format struct { ... }                          // '<{type}_{n}>' を前後・中間のリテラルに分解したもの
func ParseFormat(s string) (Format, error)          // {type} と {n} を含まなければエラー
func (f Format) Append(dst []byte, typ string, n int) []byte
// Scan は行中のラベル(既知の種別名 + 1 以上の整数)の位置を返す。restore の読み取りと、置換済みの除外で共用。
func (f Format) Scan(line []byte, fn func(start, end int, typ string, n int))
// ScanHashed は hash の出力形(<種別>_<hex>、hash_<hex>@ドメイン)の位置を返す。
func ScanHashed(line []byte, hexLen int, fn func(start, end int))
```

**detect**

```go
type Kind uint8   // Email, IPv4, IPv6, Secret, UUID(この順が同じ長さのときの優先順位)
type Class uint8  // ClassNone, Global, Private, Special(IP のみ使用)

type Match struct {
    Start, End int  // 置換する範囲(行内のバイト位置)
    Kind       Kind
    Class      Class
}
func (m Match) LabelType() string  // "email", "ipv4_private" など

func ParseTypes(spec string) (KindSet, error)  // "default,uuid" → 集合。不明な名前はエラー

type Options struct {
    Kinds        KindSet
    UUIDVersions uint16          // ビット i = バージョン i(1〜8)
    IPScope      Scope           // All / Global / Private
    Allow        map[string]struct{}
    Format       label.Format    // 置換済みラベルの除外用
    HashLen      int             // hash 出力形の除外用(→ Q10)
}
type Detector struct { ... }
func New(o Options) (*Detector, error)
// Find は、重なりを解決し、除外を適用した結果を、開始位置の順に dst に追記して返す。
func (d *Detector) Find(line []byte, dst []Match) []Match
```

内部では種別ごとに次の形の検出器を持つ。

```go
type finder interface {
    kind() Kind
    may(line []byte, hint lineHint) bool             // 前処理(4.4 節)。必要条件だけを見る
    find(line []byte, dst []candidate) []candidate   // 候補を追記(重なりはまだ解決しない)
}
```

**transform**

```go
// Replacer は 1 件の一致を置換後のバイト列にする。
type Replacer interface {
    Append(dst []byte, line []byte, m detect.Match) []byte
}
type Masker struct { ... }   // 種別名ごとの map[string]int と次の番号。Format で出力
type Hasher struct { ... }   // HMAC-SHA256(鍵)。email の local / full、桁数
func LoadKey(getenv func(string) string, keyFile string) ([]byte, error)

type Stats struct { ... }    // 種別名ごとの件数(→ Q19)

// Engine は入力群を行ごとに検出・置換して w に書く。
type Engine struct { Det *detect.Detector; Rep Replacer; Stats *Stats }
func (e *Engine) Run(inputs []io.Reader, w io.Writer) error

// Restore は sources から mask と同じ規則で対応を作り直し、answer 中のラベルを戻して w に書く。
// 戻せなかったラベル名(元の値は含まない)を返す。
func Restore(sources []io.Reader, answer io.Reader, w io.Writer, det *detect.Detector, f label.Format) (missing []string, err error)
```

**cli**

```go
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int
```

- サブコマンドごとに `flag.FlagSet`(`ContinueOnError`、出力先は stderr)。
- 「Parse → 残りの先頭を 1 つファイル名として取る → 残りを再度 Parse」を繰り返す(仕様 6.1)。`--` 以降はすべてファイル名、単独の `-` は stdin。
- `--allow` / `--source` は `flag.Value` を実装したスライス型。`-o` と `--output` は同じ変数に 2 つの名前で登録。
- 入力ファイルは処理開始前にすべて開く(途中で存在しないファイルに当たって、出力が半端に書かれた状態で終わるのを避ける)。

---

## 2. 実装の段階

各段階は「その段階のテストがすべて通り、`go vet` も通る」状態で止められる。段階の終わりにコミットする(コミットは指示があれば)。

### 段階 1: 入出力の土台(`stream`、`go.mod`) — ✅ 完了(2026-10-11)

- `scripts/go`(0 章のラッパー)、`.gitignore`(`.cache/`、`bin/`)
- `go.mod`(依存なし。`./scripts/go mod init github.com/kiaamaaio/logscrub` で作る)、`stream.Reader`、恒等変換で書き戻す小さなヘルパー(`stream.ForEachLine` / `stream.Copy`)
- テスト:
  - LF / CRLF / 混在 / 末尾改行なし / 空入力 / 改行だけの入力 / 単独 `\r` を含む行が、1 バイトも変わらず往復する
  - 64KB 超、1MB の 1 行(テスト内で生成)
  - 不正な UTF-8、日本語・全角文字を含む行がそのまま通る
  - 複数の入力をつないだときの扱い(Q22: ファイルごとに行を区切り、出力は各入力をそのままつなぐ)
- 前提となる確認: なし

**実装メモ・気づいた点**

- 実装: `internal/stream/reader.go`(`Reader`)、`internal/stream/copy.go`(`ForEachLine`、`Copy`)。テストは `internal/stream/*_test.go` とリポジトリ直下の `modfile_test.go`
- `go mod init` は `go 1.27.2` と書くため、PLAN の指定どおり `go 1.27` に直した
- Q22 は確定済みなので、「回答前は保留」としていた複数入力のテストも、この段階で実装した。複数入力の処理は `ForEachLine` に置いたので、段階 7 の `Engine.Run` はこれを使えばよい
- `Reader.Next` の読み込みエラー時の扱い: 読みかけの行は返さずエラーだけを返す(エラーなら処理全体を異常終了するため)
- 「受け入れ基準の 100MB を処理でき、メモリが増え続けない」は段階 11 で確認する。この段階の `Reader` は、**1 行がどれだけ長くてもその行をまるごとメモリに持つ**(行の長さに上限を設けない、という仕様 7 章の結果)。改行のない巨大な入力は、その大きさ分のメモリを使う。README の限界に書く候補
- 通常の行(64KB 以内)は、コピーも割り当てもしない(`TestReaderShortLinesDoNotAllocate`)。50MB/s のための前提
- 「`go.mod` に外部依存なし」は、`modfile_test.go` が `require` などの指令と `go.sum` の有無を確認する。全段階で維持される

### 段階 2: 検出の枠組み(`label`、`detect` の骨組み)

- `label.ParseFormat` / `Append` / `Scan`、`label.ScanHashed`
- `detect.ParseTypes`、`Kind` / `Match`、重なりの解決、置換済みの値の除外、`--allow` と IP の区別による除外の差し込み口
- 検出器はテスト用の偽物(固定の範囲を返すもの)で、重なりの規則だけを先に検証する
  - 長いほうが勝つ / 同じ長さは優先順位 / 一部だけ重なる / 3 つ以上が連鎖して重なる / 同じ種別・同じ長さ
  - 置換済みラベル・hash 出力形との重なり(4.2 節の方針)
- ベンチマークの枠(`BenchmarkFind`、合成ログの生成器)をこの時点で用意し、以降の段階で毎回測る
- 前提となる確認: Q1、Q2、Q10、Q11、Q12

### 段階 3: email

- 検出器(TLD は英字 2 文字以上。`pass@10.0.0.1` を拾わない)
- 前処理: 行に `@` がなければ呼ばない
- 前提となる確認: Q5(正規表現の境界)

### 段階 4: ipv4 / ipv6

- 候補の切り出し → `netip.ParseAddr` → 区別(global / private / 特殊)の判定 → `--ip-scope` の適用
- 前後の文字の条件、ポート付き・`[...]`・CIDR、IPv4 埋め込み(埋め込まれた IPv4 で区別を判定)
- 前処理: IPv4 は `.` と数字、IPv6 は `:` を含む行だけ
- 前提となる確認: Q6、Q7、Q8

### 段階 5: secret

- 固定形式(AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT)、`Bearer` / `Basic`、キー名ベース
- 前処理: 固定形式は接頭辞のリテラル(`AKIA`、`ghp_`、`xox`、`eyJ` など)を `bytes.Index` で探してから正規表現を当てる。キー名ベースは `=` か `:` を含む行だけ
- 前提となる確認: Q13、Q14、Q15、Q16、Q17

### 段階 6: uuid

- 8-4-4-4-12、バージョン(1〜8、または `--uuid-versions`)、バリアント、前後の文字、`{...}` / `urn:uuid:`
- 全種別がそろうので、「除外の確認」(電話番号・郵便番号が検出されない)をここで確認する
- 前提となる確認: Q9

### 段階 7: mask(`transform.Masker`、`Engine`、`Stats`)

- 行の書き換え(一致していない部分は元のスライスをそのまま書く)
- 最初に現れた順の連番、種別名(IP は区別込み)ごとのカウンタ、`--mask-format`
- 冪等性のテスト: すべてのテスト入力で `mask(mask(x)) == mask(x)` を確認。`testing.F` のファズテストでも確認する
- 前提となる確認: Q3、Q4、Q19

### 段階 8: hash(`transform.Hasher`、`LoadKey`)

- HMAC-SHA256 の先頭 N 桁、email の `local` / `full`、鍵の読み込み(環境変数 / `--key-file`)
- 冪等性: `hash(hash(x)) == hash(x)`(ファズテスト含む)
- 前提となる確認: Q10、Q18、Q20、Q21

### 段階 9: restore

- `--source` を mask と同じ `Engine` に通して対応を作り直す(出力は捨てる)→ 回答中のラベルを `Format.Scan` で探して戻す
- 戻せなかったラベル名の一覧を返す(stderr への出力は段階 10)
- 往復テスト: `restore(mask(x)) == x`(testdata の全入力 × 複数のオプションの組)。追記後も戻ること
- 前提となる確認: Q22、Q23、Q24

### 段階 10: CLI(`cli`、`cmd/logscrub`)

- サブコマンド、オプションの前後自由な解析、`--`、`-`、`-o`、`--help`、`types [--verbose]`、終了コード、`--output`、`--stats`、`--fail-on-detect`
- 受け入れ基準を `cli.Run` 経由の E2E テストとして全項目そろえる(段階 3〜9 で個別に確認したものも、ここで改めて通す)
- 前提となる確認: Q25、Q26、Q27、Q28

### 段階 11: 性能・メモリ・README

- 合成ログ(100MB)で `cmd/logscrub` を実測し、50MB/s を確認。足りなければ 4.4 節の手順で改善する
- 最大メモリ使用量の確認(値の種類数を一定に保った 100MB 入力で、最大 RSS が入力サイズに比例して増えないこと)。`golang` イメージには `/usr/bin/time` がないため、テストからビルド済みのバイナリを子プロセスで起動し、`ProcessState.SysUsage()` の `Maxrss` を読む(標準ライブラリのみで完結する)
- 性能・メモリの測定もコンテナ内で行う。合成ログはコンテナ内で生成し、リポジトリ外の一時領域に置く
- README: 使い方、`secret` の対応形式、限界(仕様に「README に明記する」とあるもの全部)、ベンチ結果
- 前提となる確認: Q29

---

## 3. 受け入れ基準(仕様 9 章)と段階の対応

「ライブラリ」はその段階のパッケージ単体のテストで確認する段階、「E2E」は `cli.Run` 経由で確認する段階。

| 受け入れ基準 | ライブラリ | E2E |
|---|---|---|
| **基本** | | |
| `taro@example.com 192.168.0.1` → `<email_1> <ipv4_private_1>` | 7 | 10 |
| 同じメールは同じラベル、別のメールは別のラベル | 7 | 10 |
| 同じ入力・同じオプションの 2 回実行で同じ出力 | 7 | 10 |
| 置換済みテキストを再度流しても変わらない(mask) | 7 | 10 |
| └ `password=<secret_1>`、`Authorization: Bearer <secret_1>` が再置換されない | 7 | 10 |
| └ hash の `password=secret_3f9a1c0b7d2e` が再ハッシュされない | 8 | 10 |
| └ `--mask-format '[{type}-{n}]'` の出力を再度流しても変わらない | 7 | 10 |
| 日本語・全角文字混じりの行 | 1、3、7 | 10 |
| 64KB を超える 1 行(1MB の JSON 1 行) | 1 | 10 |
| CRLF のまま出力、末尾改行の有無を保つ | 1 | 10 |
| 100MB をパイプで処理でき、メモリが増え続けない | — | 11 |
| **種別の指定** | | |
| `--types email` でメールだけ置換、IP は残る | 2、7 | 10 |
| `--types default,uuid` で既定 + UUID | 2、6 | 10 |
| 存在しない種別名でエラー終了 | 2 | 10 |
| **範囲の重なり** | | |
| `::ffff:10.0.0.1` が全体で 1 つの `<ipv6_private_1>` | 4 | 10 |
| `https://user:pass@10.0.0.1/` → `https://user:pass@<ipv4_private_1>/` | 4 | 10 |
| **email / hash** | | |
| `--email-hash local` で `hash_<hex>@example.com`、再度流しても変わらない | 8 | 10 |
| `--email-hash full` でメール全体が置換 | 8 | 10 |
| `LOGSCRUB_KEY` 未設定の hash モードでエラー終了 | 8 | 10 |
| **IP アドレス** | | |
| global / private の判定と区別ごとの連番 | 4、7 | 10 |
| `--ip-scope global` / `private` | 4 | 10 |
| `::1`、`fe80::1`、`fd00::1` は private、`2001:4860:4860::8888` は global | 4 | 10 |
| `0.0.0.0`、`255.255.255.255`、`::`、`224.0.0.1` は置換しない | 4 | 10 |
| `10.0.0.1:8080`、`[::1]:8080`、`10.0.0.0/8` はアドレス部分だけ | 4 | 10 |
| `999.1.1.1`、`1.2.3` は検出しない | 4 | 10 |
| `connected to 10.0.0.1.` は検出、`1.2.3.4.5` は検出しない | 4 | 10 |
| **secret** | | |
| AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT がそれぞれ `<secret_N>` | 5 | 10 |
| `Authorization: Bearer xxxxx` の値部分のみ | 5 | 10 |
| `password=abc123&user=x` → `password=<secret_1>&user=x` | 5、7 | 10 |
| `"api_key": "abc def"` → `"api_key": "<secret_1>"` | 5、7 | 10 |
| `X-Auth-Token: xxx`、`DB_PASSWORD=xxx` は置換、`max_tokens: 4096`、`token_count=5`、`PWD=/home/user` は置換しない | 5 | 10 |
| **UUID** | | |
| 何も指定しないと置換されない | 6 | 10 |
| `--types default,uuid` で v1〜v8(大文字・小文字・`{}`・`urn:uuid:`)が `<uuid_1>` | 6 | 10 |
| `req-123e4567-...` の UUID 部分が置換 | 6 | 10 |
| `--uuid-versions 4` で v4 のみ | 6 | 10 |
| nil UUID、ハイフン無し 32 桁、バリアント不正は検出しない | 6 | 10 |
| **restore** | | |
| 往復テスト(1 バイトも違わず戻る) | 9 | 10 |
| `--source` 複数指定でも往復 | 9 | 10 |
| 追記後も追記前のラベルは戻る | 9 | 10 |
| オプション違い: ラベルは残り、件数とラベル名が stderr、終了コード 0 | 9 | 10 |
| `--source -` を ANSWER_FILE なしで指定するとエラー | — | 10 |
| 実行後に対応表のファイルが残らない | 9 | 10 |
| stderr やエラーメッセージに元の値が出ない | 9 | 10 |
| **除外の確認** | | |
| `03-1234-5678`、`09012345678`、`123-4567` は検出されない | 6 | 10 |
| **オプション** | | |
| `--allow support@example.com` のアドレスだけ残る | 2、7 | 10 |
| `--fail-on-detect` で検出あり 2、なし 0 | 7(件数) | 10 |
| `--stats` が stderr に出て stdout に混ざらない | 7(件数) | 10 |
| `--mask-format '[{type}-{n}]'` が反映、`{n}` なしはエラー | 2、7 | 10 |
| 置換済みの形を残したとき、件数と行番号を stderr に 1 行で通知(値は出さない、終了コードは不変) | 2、7、8、9(件数・行番号) | 10 |
| **CLI** | | |
| `mask app.log --stats` と `mask --stats app.log` が同じ | — | 10 |
| `mask -- -weird-name.log` | — | 10 |
| `--stats` = `-stats`、`--output` = `-o` | — | 10 |
| `--allow` / `--source` の複数回指定 | — | 10 |
| サブコマンドなし・不明で使い方を stderr、終了コード 1 | — | 10 |
| `go.mod` に外部依存なし | 1 | 全段階で維持 |

「対応表のファイルが残らない」は、テストで一時ディレクトリを作業ディレクトリ・`TMPDIR` にして restore を実行し、実行前後でファイルが増えていないことを確認する。
「stderr に元の値が出ない」は、テスト入力に含めた元の値のどれも stderr に含まれないことを、全 E2E テスト共通の後処理で確認する。

---

## 4. 慎重に設計すべき点と方針

### 4.1 範囲が重なった場合の解決

1 行ごとに次の手順で決める。

1. 有効な種別の検出器が、それぞれ候補(範囲・種別・区別)を出す。この時点では重なりを気にしない
2. 置換しない候補を外す(`--types` で無効な種別はそもそも候補を出さない。`--allow`、IP の特殊アドレス・`--ip-scope` 外を外す時点は → **Q11**)
3. 置換済みのラベル・hash 出力形を「保護範囲」として候補に加える(4.2 節)。`--allow` の値の扱いも Q11 の回答による
4. 候補を「長さの降順 → 優先順位(保護範囲 → email → ipv4/ipv6 → secret → uuid)→ 開始位置の昇順」で並べ、先頭から順に、すでに採用した範囲と重ならないものだけ採用する
5. 採用したもののうち保護範囲を除き、開始位置の順に並べて返す

- 負けた候補は、重なっていない部分も含めて捨てる(仕様「一部だけ重なる場合も 1 つに決める」)。部分を再検出はしない
- 同じ種別・同じ長さの重なりは開始位置が前のほうを採る(仕様に記述なし。順序が決定的であれば良い点なので、確認事項には入れず、この方針で進める。異論があれば指摘してほしい)
- ipv4 と ipv6 は同じ優先順位だが、同じ長さで重なることは形式上起きない(IPv6 は必ず `:` を含み、IPv4 は含まない)
- 候補は 1 行に数個なので、単純なソート + 線形の重なり確認で十分

### 4.2 冪等性(置換済みの値を検出しない仕組み)

- `label.Format.Scan` が現在の `--mask-format` のラベル(既知の種別名 × 1 以上の整数)を、`label.ScanHashed` が hash 出力形を見つける
- これらを「保護範囲」として、重なりの解決に**最優先の候補として参加**させる(保護範囲が勝てば、その範囲は置換されない)
  - 単に「保護範囲と重なる候補を捨てる」方式だと、`"password": "<secret_1> 本物の値"` のような値で、本物の値まで残ってしまう。参加させる方式なら、より長い候補が勝って全体が置換される(見逃しを減らす側。仕様 7 章)
  - `--mask-format '[{type}-{n}]'` では、キー名ベースのクォートなしの値が `]` の直前で切れるため、`password=[secret-1]` の値は `[secret-1` になる。保護範囲 `[secret-1]` のほうが長いので保護範囲が勝ち、再置換されない(この書式の受け入れ基準を、この仕組みで満たす)
  - 同じ長さのとき保護範囲が勝つ(`password=<secret_1>` の値 `<secret_1>` と保護範囲は同じ範囲)
  - この方式は仕様の「置換済みの形の文字列は検出しない」の解釈を含むため、**Q1** で確認する
- mask の出力が、周囲の文字とつながって新しい候補を生まないことは、例を挙げて確かめきれないため、ファズテスト(`mask(mask(x)) == mask(x)`、hash も同様)で確認する

### 4.3 restore が前提とする連番の決定性

連番が決まる要素をすべて固定し、mask と restore で同じコードを通す。

- 連番の順序 = 入力の順(ファイルの指定順 → 行の順 → 行内の開始位置の順)。重なりの解決は 4.1 節のとおり決定的
- 「同じ値」の判定キー = (種別名, 値のバイト列)。正規化しない場合、ラベル → 値の対応が一意になり、往復で 1 バイトも変わらないことが保証される(→ **Q3**)
- 番号を消費しないもの: `--allow` の値、特殊アドレス、`--ip-scope` 外、保護範囲
- Go の map の反復順に依存する処理を、出力・連番・stats のどこにも入れない(stats は `label.Types` の固定順で出す)
- 前処理(4.4 節)は「その種別が一致しうる必要条件」だけにする。前処理あり/なしで結果が同じことをファズテストで確認する(前処理の誤りが、mask と restore で同じように効いて気づきにくいのを防ぐ)
- restore は `--source` を mask と同じ `Engine` に通し、`Masker` の対応表だけを使う。restore 独自の検出経路は作らない
- 連番に影響するオプションがすべて restore でも指定できることが必要。`--hash-length` が restore にない点を **Q10** で確認する
- 回答(ANSWER)を先に読み、含まれるラベルを集めてから `--source` を処理する。必要なラベルがすべて見つかった時点で `--source` の残りを読まずに終えてよい(連番は最初に現れた順なので、後ろを読んでも既存の対応は変わらない)。回答は AI の返答なので全体をメモリに読む前提とする(→ Q24)

### 4.4 性能目標(50MB/s)のための前処理

- 入出力: `bufio.Reader`(64KB)の `ReadSlice` で、改行までがバッファに収まる通常の行はコピーしない。`bufio.Writer` で書く。置換のない行は読んだスライスをそのまま書く
- 行ごとのヒント: 行を 1 回走査して、`@` `.` `:` `=` `-` `_` 数字・英大文字の有無などをビット集合にまとめ、各検出器の `may` はそれを見るだけにする
  - email: `@` がある / IPv4: `.` と数字がある / IPv6: `:` がある / uuid: `-` があり、行の長さが 36 以上 / キー名ベース: `=` か `:` がある / 固定形式の secret: 接頭辞リテラルを `bytes.Index` で探す
- 正規表現は「アンカーの周辺だけ」に当てる(例: email は `@` の位置の前後の窓だけ、キー名ベースは区切り文字の手前の窓だけ)。1MB の 1 行でも、正規表現を行全体に何度も当てない
- メモリ割り当て: `Match` のスライス・出力バッファは再利用。map の参照は `m[string(b)]`(Go はこの形で割り当てしない)、新しい値のときだけ文字列を作る
- 計測: 段階 2 でベンチマーク(`b.SetBytes` で MB/s を出す)と合成ログ生成器を用意し、段階 3 以降は毎回測って PLAN の進捗欄に記録する。合成ログの中身(一致を含む行の割合など)は → Q29
- それでも 50MB/s に届かない場合の手段: 遅い種別の正規表現を、手書きの走査に置き換える。その場合、元の正規表現版をテスト内に残し、ファズテストで結果が一致することを確認する(仕様 4 章「正規表現による形式の一致を基本とし」との関係を → **Q2** で確認)

---

## 5. 未確定事項(仕様の曖昧な点・矛盾している点)

推測では埋めず、回答をもらってから該当する段階に入る。「案」は判断材料としての提案で、採用は回答後。

**2026-10-11: Q1〜Q31 はすべて案どおりで確定。** Q31 は SPEC.md(6 章、7 章、9 章「オプション」)にも反映済み。

### 枠組み・冪等性

- **Q1(冪等性の範囲)** 置換済みの形の文字列を「その範囲は置換しない」とするのか、「それと重なる候補はすべて捨てる」とするのか。後者は `"password": "<secret_1> 本物の値"` で本物の値が残る。
  - 案: 前者(4.2 節の、保護範囲が最優先の候補として重なりの解決に参加する方式)
- **Q2(正規表現以外の実装)** 性能が足りない場合に、正規表現を手書きの走査に置き換えてよいか(判定結果は正規表現版と一致させる)。
- **Q10(hash 出力形の桁数・矛盾)** 4 章の除外対象 `<種別>_<16 進数>` の桁数が未定義(5.2 節の `hash_` 側は `--hash-length` 桁と明記)。任意の桁数にすると、mask モードでも `password=secret_abc123` のような本物の値(`abc123` は 16 進数)が置換されなくなる。また `--hash-length` 桁とすると、**restore には `--hash-length` がない**ため、mask 時に `--hash-length` を変えると restore で連番がずれる。
  - 案: 桁数は `--hash-length` に限定。hash 専用オプション(`--hash-length`、`--email-hash`、`--key-file`)を mask モードで指定したらエラーにして、mask モードでは常に既定の 12 桁で除外する(restore も 12 桁)
- **Q11(除外と重なりの解決の順序)** `--allow`、特殊アドレス、`--ip-scope` 外の候補を、重なりの解決の**前**に外すか**後**に外すか。
  - 前に外す場合: `--ip-scope private` で `api_key=203.0.113.5` は secret として置換される(同じ長さで IP が優先されるが、IP は対象外なので外れ、secret が残る)。`token=0.0.0.0` も secret として置換される。ただし `--allow ::ffff:10.0.0.1` では、末尾の `10.0.0.1` だけが置換される
  - 後に外す場合: 上の 2 例は IP が勝ったうえで置換されず、値がそのまま残る
  - 案: 除外の理由で分ける。特殊アドレスと `--ip-scope` 外は**前に外す**(その範囲を他の種別が置換できるようにする。見逃しを減らす側)。`--allow` の値は保護範囲と同じく**重なりの解決に加え、勝てばそのまま残す**(利用者が「この文字列は残す」と明示したものなので、`--allow ::ffff:10.0.0.1` で一部だけ置換されることを避ける。より長い候補に含まれる場合は、長いほうが勝って置換される)
- **Q12(`--mask-format` の制約)** `{type}` / `{n}` が 2 回以上現れる書式、改行を含む書式、`{` `}` のリテラル、`{type}{n}` のように区切りがない書式を許すか。
  - 案: `{type}` と `{n}` はちょうど 1 回ずつ、改行(`\r` `\n`)を含む書式はエラー、それ以外は許す

### mask・hash

- **Q3(「同じ値」の判定)** 大文字・小文字の違う `Taro@Example.com` と `taro@example.com`、`2001:DB8::1` と `2001:db8::1`、UUID の大文字・小文字や `{}` の有無を同じ値として扱うか。同じ値として 1 つのラベルにすると、restore で 1 バイトも違わずに戻すことができなくなる(往復テストと矛盾)。
  - 案: mask はバイト列が完全に同じものだけを同じ値とする。hash も同じ扱い(入力のバイト列をそのままハッシュ)
- **Q4(番号の対象)** 連番は種別名(IP は区別込み)ごとに数える、で良いか(仕様 4.3 は IP について明記。他の種別も同様と読んでいる)。
- **Q18(HMAC の入力)** 「別のマシンでも同じ出力」のために、HMAC に渡すバイト列を固定する必要がある。値のバイト列だけか、種別名を前に付けるか(種別をまたいで同じ値が同じハッシュになるかが変わる)。`local` のときはローカルパートのバイト列か。16 進数は小文字か。
  - 案: 値のバイト列だけ(`local` はローカルパートだけ)、小文字の 16 進数
- **Q20(鍵)** `LOGSCRUB_KEY` と `--key-file` の両方がある場合の優先。`--key-file` の末尾の改行を除くか。空の値は未設定とみなすか。
  - 案: `--key-file` を優先、末尾の改行(`\n` / `\r\n` 1 つ)は除く、空はエラー
- **Q21(`--hash-length`)** 許す範囲。
  - 案: 8〜64(64 は SHA-256 の 16 進数の全桁)、範囲外はエラー
- **Q19(`--stats` と `--fail-on-detect`)** 件数は出現回数か、値の種類数か。`--allow` で残した値・特殊アドレス・`--ip-scope` 外は数えるか。出力形式。
  - 案: 置換した出現回数のみ数える。形式は 1 行 1 種別の `logscrub: email=3` のような形で、0 件の種別は出さない

### 種別ごと

- **Q5(email の正規表現)** 「一般的な」の範囲。
  - 案: ローカルパート `[A-Za-z0-9._%+-]+`、ドメイン `([A-Za-z0-9-]+\.)+[A-Za-z]{2,}`、大文字・小文字を区別しない、前後に `[A-Za-z0-9._%+-]` / `[A-Za-z0-9-]` が続かないこと。日本語などの非 ASCII 文字は「英数字でない」扱い。引用符つきのローカルパートや国際化ドメインは対象外
- **Q6(IPv6 のゾーン)** `fe80::1%eth0` の置換範囲に `%eth0` を含めるか。
  - 案: 含める(`<ipv6_private_1>` に置換)
- **Q7(先頭 0 付きの IPv4)** `192.168.001.001` は `netip.ParseAddr` が受け付けないため、仕様どおりだと検出されない。ログによってはゼロ埋めされることがあり、7 章「見逃しを減らす側」と食い違う。
  - 案: 仕様どおり検出しない(README の限界に書く)
- **Q8(IPv4 埋め込みの範囲)** 「埋め込まれた IPv4 で区別を判定」の対象は `::ffff:a.b.c.d`(IPv4-mapped)だけか、`::a.b.c.d`(IPv4-compatible、非推奨)や `64:ff9b::/96`(NAT64)も含むか。また `::ffff:0.0.0.0` のように埋め込み先が特殊アドレスなら置換しないか。
  - 案: IPv4-mapped のみ埋め込みとして扱い、埋め込み先が特殊なら置換しない
- **Q9(UUID の置換範囲)** `{123e4567-...}` と `urn:uuid:123e4567-...` で、置換するのは括弧・接頭辞を含む全体か、UUID 部分だけか。
  - 案: UUID 部分だけ(`{<uuid_1>}`、`urn:uuid:<uuid_1>`)。そうすると、括弧の有無で同じ値として扱える(Q3 とも整合)
- **Q13(`Bearer` / `Basic` の値の範囲)** 値の範囲の定義がない。また、大文字・小文字(`bearer`)を区別するか、`Authorization:` の後ろに限るか(文章中の「Bearer token is ...」も拾うか)。
  - 案: 方式名(`Bearer` / `Basic`)は大文字・小文字を区別せず、前が英数字でなく、後ろに空白が 1 つ以上あること。`Authorization:` の後ろに限らない(見逃しを減らす側)。値は RFC 7235 の token68 の文字(`A-Z a-z 0-9 - . _ ~ + /`、末尾に `=` が続いてもよい)が続く範囲。`Basic` だけは、値を base64 として解読でき、結果に `:` を含む(`user:pass` の形)場合に限る。英文の「Basic setup complete」のような誤検出を防ぐため(仕様の文面より絞り込む提案)
- **Q14(固定形式の境界)** AWS(16 文字ちょうど)、Google(35 文字ちょうど)などで、前後に英数字が続く場合に検出するか。仕様は `sk-` だけ「前が英数字でない」と明記。JWT の各部の文字種(base64url)と、署名部が空の JWT(`alg: none`)の扱いも未定義。
  - 案: 全形式で「前後が英数字でない」を条件にする。JWT は `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`(署名部は空でも可)
- **Q15(キーと値の区切りの空白)** `password = abc`、`token:  abc`(空白 2 つ)、`"key" : "value"` のように区切りの前後に空白がある場合を拾うか。仕様の区切り一覧(`=`、`:`、`: `、JSON)に含まれない。
  - 案: 区切りの前後の空白(スペース・タブ)は任意個を許す
- **Q16(閉じクォートがない値)** `password="abc` のように閉じクォートがない場合の値の範囲。
  - 案: 行末まで(見逃しを減らす側)
- **Q17(JSON の文字列以外の値)** `"token": 12345` や `"password": null` は、クォートなしの規則で `"token": <secret_1>` となり、JSON として不正になる。これで良いか。
  - 案: 仕様どおり置換する(`null`・`true`・`false` も置換)

### restore・CLI

- **Q22(複数ファイルの連結)** `mask a.log b.log` で、`a.log` が末尾改行なしで終わる場合、`a.log` の最後の行と `b.log` の最初の行を 1 行として検出するか(バイト列としての連結)、ファイルごとに行を区切るか。
  - 案: ファイルごとに行を区切る(値がファイルをまたがない)。出力のバイト列は各ファイルの出力をそのままつないだもの(間に改行を足さない)
- **Q23(戻せなかったラベルの数え方)** 同じラベルが回答に 2 回出た場合に 1 件と数えるか。一覧の並び順。「ラベル」と見なす範囲(既知の種別名でないもの、`<email_0>`、`<email_01>` は対象か)。
  - 案: 種類数で数え、回答に現れた順に並べる。ラベルとみなすのは、現在の書式で既知の種別名 + 1 以上の整数(先頭 0 なし)のものだけ
- **Q24(restore の入力)** 回答(ANSWER)全体をメモリに読んでよいか(4.3 節の最適化に使う)。ANSWER_FILE に `-` を指定した場合は stdin とみなすか。`--source` に同じ `-` を 2 回指定した場合はエラーか。
  - 案: すべて「はい」
- **Q25(hash 専用オプションと mask モード)** Q10 の案と合わせて、mask モードでの `--hash-length` `--email-hash` `--key-file` をエラーにしてよいか(無視する案もある)。
- **Q26(`--output` と入力が同じファイル)** `logscrub mask app.log -o app.log` は入力を消してしまう。
  - 案: 同じファイル(`os.SameFile`)ならエラー
- **Q27(`logscrub types` の出力形式)** 形式の指定がない。`ipv4` / `ipv6` を種別として出すか、`ipv4_global` などの区別まで出すか。
  - 案: 1 行 1 種別で `種別 ID  既定で有効かどうか  説明`。区別は説明の中で示す。`--verbose` で secret の形式一覧を追加
- **Q28(エラーと終了コード 2 の優先)** `--fail-on-detect` で検出ありの状態で、途中で書き込みエラーなどが起きた場合。
  - 案: エラー(1)を優先

### 性能・その他

- **Q29(50MB/s の測定条件)** どんなログで、どんな環境で測るか。
  - 案: 合成ログ(1 行 200 バイト前後、約 30% の行に何らかの検出対象、1MB の JSON 行を少し混ぜる)、既定の種別、mask モード、手元の WSL2 上の Docker コンテナ(`golang:1.27.2`)内で `cat file | logscrub mask > /dev/null` の実時間から算出。README の記録には CPU とコンテナ内での測定であることを併記する
- **Q30(モジュールパス)** `github.com/kiaamaaio/logscrub` で良いか。
- **Q31(置換済みの形として残した値の通知)** 利用者からの提案。置換済みのラベルや hash 出力形と同じ形の文字列を、置換せずに残した場合に stderr で知らせる。仕様にない出力の追加になる。
  - 案: 処理の最後に、1 件以上あれば 1 行だけ出す。件数と行番号(最初の 5 件まで)のみを出し、値は出さない(仕様 7 章)。例: `logscrub: 2 strings were left unchanged because they look already replaced (lines 12, 40). Check them before sharing.`
  - mask・hash・restore の `--source` で共通。restore では仕様 5.3 の限界(元の入力にラベルと同じ形の文字列がある)の検知にもなる
  - 終了コードは変えず、`--fail-on-detect` の件数にも含めない。抑止するオプションは設けない
  - 置換済みの出力をもう一度流すと、毎回この行が出る(元の値か前回の出力かを区別できないため)

---

## 6. 進捗

| 段階 | 状態 | メモ |
|---|---|---|
| 計画 | 完了 | 2026-10-11 作成。Q1〜Q31 確定 |
| 1. 入出力の土台 | ✅ 完了 | 2026-10-11。`go test ./...`、`go vet ./...`(`-race` も)通過 |
| 2. 検出の枠組み | 未着手 | 保護範囲の件数・行番号を数える仕組みを含める(Q31) |
| 3. email | 未着手 | |
| 4. ipv4 / ipv6 | 未着手 | |
| 5. secret | 未着手 | |
| 6. uuid | 未着手 | |
| 7. mask | 未着手 | |
| 8. hash | 未着手 | |
| 9. restore | 未着手 | |
| 10. CLI | 未着手 | Q31 の stderr 出力 |
| 11. 性能・README | 未着手 | |

### ベンチマーク記録

(段階 2 以降で追記)
