# logscrub 開発の資料

版をまたいで使う、開発環境・パッケージ構成・設計の注意点をまとめる。
版ごとの実装計画と進捗は [plans/](plans/) にある(この資料の内容は、v1.0.0 の実装計画から移した)。

- 仕様: [SPEC.md](SPEC.md)(以下「仕様」。節番号は仕様のもの。SPEC.md は目次で、4〜6 章・9 章の本文は [spec/](spec/) にある)
- 文中の Q 番号は、Q1〜Q31 が [plans/v1.0.0.md](plans/v1.0.0.md)、Q32〜Q46 が [plans/v1.1.0.md](plans/v1.1.0.md)、Q47〜Q70 が [plans/v1.2.0.md](plans/v1.2.0.md)、Q71〜Q84 が [plans/v1.3.0.md](plans/v1.3.0.md) の 5 章「未確定事項」の項目(すべて確定済み)

---

## 1. 開発環境(Docker)

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
- コミットの前の検査: git の pre-commit hook(`.githooks/pre-commit`)が、`main` へのコミットを止め、資料の長さ、`go.mod` の依存(`scripts/allowed-modules` にないものを止める)、`gofmt`、test、vet(Linux・Windows)を確かめる。失敗の出力は、コミットの結果として表示される
  - クローンごとに、最初に 1 回だけ `git config core.hooksPath .githooks` を実行して有効にする
  - git が実行するので、Claude のコミットにも人のコミットにも、コマンドの書き方によらず動く。人の判断でコミットするときは `git commit --no-verify` で飛ばせる
  - 確認するのは作業ツリーの状態で、ステージした内容だけではない
  - Docker が使えずテストを実行できない場合も、コミットを止める
- Claude Code によるコミットの前の確認: `.claude/settings.json` の PreToolUse hook が、Claude が Bash で `git commit` を実行する直前に `scripts/claude-commit-check` を呼ぶ。pre-commit hook が有効でなければコミットを止める(終了コード 2。理由は Claude に返る)。また、次のどれかに当たるときはユーザーに確認を求める(`permissionDecision: "ask"`)
  - `feature/` で始まらないブランチへのコミット
  - ゴールデン、`go.mod`、`CLAUDE.md`、仕様、`.claude/`、`.githooks/`、検査に関わるスクリプトの変更
  - テストの弱体化(`t.Skip` の追加、`func Test` / `func Fuzz` の削除、`f.Add` の削除)
  - 判定はコマンドの文字列で行うので、書き方によっては確認が飛ばされる。検査と違い、確認は確実には働かない
  - ホストの `go` の実行も、ここで止める。権限のルールの `Bash(go *)` は `./scripts/go` まで止めるので使えない
  - 権限のルールや hook を変えるときは、止めるコマンドと通すコマンドの両方を確かめる
  - スクリプトを起動できない場合(ファイルが無いなど)は、`onFailure: "block"` により Claude の Bash の実行がすべて止まる

---

## 2. パッケージ構成と主要な型・関数

パッケージ構成(ディレクトリと、それぞれの役割)は、仕様 8 章が正本。ここには、構成を決めたときの理由を残す。

### 仕様の最初の構成に加えたもの(v1.0 の計画で決めた)

| 追加 | 理由 |
|---|---|
| `internal/label` | ラベルの書式は「mask で生成」「restore で読み取り」「検出時に置換済みとして除外」の 3 か所で使う。`detect` に置くと `transform` → `detect` の依存は良いが、書式の責務が検出に混ざる。`transform` に置くと `detect` → `transform` の循環になる。独立させて両方から使う |
| `internal/cli`(`main.go` は薄くする) | `cli.Run(args, stdin, stdout, stderr, getenv) int` にすると、終了コード・stdout/stderr の分離・オプション順序などの受け入れ基準を、バイナリを作らずにテストで確認できる |
| `internal/synthlog` | ベンチマーク(段階 2〜)と性能測定(段階 11)で同じ合成ログを使うため。テスト以外のコードからは使わない。v1.1 で AWS の値を含める設定を追加(Q39)、v1.2 で AWS のサービスのホスト名と URL のパスワードも含める |
| `transform/engine.go` | 「行を読む → 検出 → 置換 → 書く」の流れを mask / hash / restore(の対応表作り直し)で共有する。restore が mask と**同じコード経路**で連番を振ることが、連番の決定性(3.3 節)の要になる |

テストの入力と期待値は `internal/transform/testdata/` にある(`app.log`、v1.1 の AWS の値と v1.2 のホスト名・URL のパスワードの `aws.log`、それぞれの mask の期待値、ファズテストの入力)。

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
// 置換後の種別名。IP は区別を含む。並びは連番・--stats の出力順にも使う(aws_account・aws_s3_bucket は v1.1、aws_host は v1.2 で追加)。
var Types = []string{"email", "ipv4_global", "ipv4_private", "ipv6_global", "ipv6_private", "secret", "uuid",
    "aws_account", "aws_s3_bucket", "aws_host", "host", "custom"}
const NumTypes = 12                                 // len(Types)。統計・連番の表を固定長の配列で持つため

type Format struct { ... }                          // '<{type}_{n}>' を前後・中間のリテラルに分解したもの
func ParseFormat(s string) (Format, error)          // {type} と {n} を含まなければエラー
func (f Format) Append(dst []byte, typ string, n int) []byte
// Scan は行中のラベル(既知の種別名 + 1 以上の整数)の位置を返す。restore の読み取りと、置換済みの除外で共用。
func (f Format) Scan(line []byte, fn func(start, end int, typ string, n int))
// ScanHashed は hash の出力形(<種別>_<hex>、hash_<hex>@ドメイン)の位置を返す。
func ScanHashed(line []byte, hexLen int, fn func(start, end int))

// AnswerScanner は、restore の回答を読む。Format.Scan に加えて、HTML・Markdown で崩れた形も読む(仕様 5.3。v1.3)。
// Format.Scan は変えない(検出の保護範囲と連番に、崩れた形を混ぜないため)。
func NewAnswerScanner(f Format) *AnswerScanner
func (a *AnswerScanner) Scan(line []byte, skip map[string]struct{}, fn func(start, end int, typ string, n int))
func (a *AnswerScanner) ScanEscaped(line []byte, fn func(form []byte))
```

**detect**

```go
type Kind uint8   // KindEmail, KindIPv4, KindIPv6, KindSecret, KindUUID, KindAWSAccount, KindAWSS3Bucket, KindAWSHost, KindHost, KindCustom(0 は無効)
type KindSet uint32 // ビット k が Kind k(v1.1 で uint8 から広げた。v1.2 の aws_host で 8 ビットを超えるため)
type Class uint8  // ClassNone, ClassGlobal, ClassPrivate, ClassSpecial(IP のみ使用)

type Match struct {
    Start, End int  // 置換する範囲(行内のバイト位置)
    Kind       Kind
    Class      Class
    HideDomain bool // メールアドレスのドメインに、利用者が指定した値がある(--email-hash local でも全体を置換。仕様 5.2)
}
func (m Match) LabelType() string  // "email", "ipv4_private" など

// TypeInfo は、--types に書ける種別 1 つ(種別、既定で有効か、クラウド名)。Types は、その一覧
// (共通の種別のあとに、クラウドごとにまとめる。logscrub types とエラーメッセージの順)。
type TypeInfo struct { Kind Kind; Default bool; Cloud string }
var Types []TypeInfo
// Group は、種別のまとまり。Groups(default、クラウド名(aws)、cloud)は Types から求める
// (種別を足したとき、まとまりの定義を書き換えなくて済むように。plans/v1.1.0.md 2.1)。
type Group struct { Name string; Kinds KindSet }
var Groups []Group
var DefaultKinds KindSet                       // Types の Default から求める

func ParseTypes(spec string) (KindSet, error)  // "default,aws" → 集合。Groups と Types から引く。不明な名前はエラー(完全一致のみ)

type Options struct {
    Kinds        KindSet
    UUIDVersions uint16          // ビット i = バージョン i(1〜8)
    IPScope      Scope           // All / Global / Private
    Allow        map[string]struct{}
    Deny         []string        // --deny・--deny-file の語。指定すると custom が加わる
    Domains      []string        // --domain のドメイン。指定すると host が加わる
    Format       label.Format    // 置換済みラベルの除外用
    HashLen      int             // hash 出力形の除外用(→ Q10)。ゼロ値は 12、範囲は 8〜64
}
type Detector struct { ... }       // 作業領域を持つので、同時に使えない
func New(o Options) (*Detector, error)
// Find は、重なりを解決し、除外を適用した結果を、開始位置の順に dst に追記して返す。
// 2 つ目の戻り値は、置換済みの形のため置換せずに残した範囲の数(Q31)。
func (d *Detector) Find(line []byte, dst []Match) ([]Match, int)
```

`Options` のゼロ値の項目は既定値になる(`Kinds` は `DefaultKinds`、`Format` は `label.DefaultFormat`、`IPScope` は `ScopeAll`、`HashLen` は 12)。
`UUIDVersions` が 0 以外なら `Kinds` に uuid が加わる。1〜8 以外のビットはエラー。

内部では種別ごとに次の形の検出器を持つ。

```go
type finder interface {
    kind() Kind
    find(line []byte, dst []Match) []Match           // 候補を追記(重なりはまだ解決しない)
}
```

検出器は、種別ごとのファイルにある(`email.go`、`ip.go`、`secret.go`、`uuid.go`、v1.1 の `aws.go`。v1.2 の `aws_host` も `aws.go`)。
v1.1 では、既存の検出器に形を加え(`secret` に AWS の署名、`ipv4` に EC2 のホスト名の IPv4。`ipv4Finder` は、
ドット区切りの `dotted` と、ホスト名の `hosts` に分かれる)、`aws.go` に `aws_account`・`aws_s3_bucket` の検出器と、
AWS の形の表(パーティション、ドメイン、リージョン、S3 のエンドポイント、ホスト名の末尾の条件)を置いた。
将来のクラウドの表も、同じ形で書き足す。
v1.2 では、`aws.go` に `aws_host` の検出器 `awsHostFinder` と、その「末尾の形」の表 `awsHostForms` を加えた。
表の 1 行はサービス 1 つで、末尾の形(`.{region}.rds.{domain}` のように、`{region}`・`{domain}` と決まった語の並び)を持つ。
サービスの追加は、表に行を足すだけで済む(終端ごとの手がかりと、手前の部品の照合は、表から作る)。
`aws_account` の ECR・S3 Control のホストも、`accountHostMarkers` の表に行を足す形にした。
`secret` に URL のパスワードを加え(`urlPasswordStart`)、`email` は、その形の `@` を候補にしない。重なりの解決の規則(3.1 節)は変えていない。
v1.3 では、`custom.go` に `customFinder`(`--deny`)と `hostFinder`(`--domain`)を、`literal.go` に、両方が使う照合器 `literalMatcher`(Aho-Corasick。遷移の表は、語に現れるバイトの同値類を列にする)を置いた。
語の読み込み(`--deny-file`)は `internal/cli` で行い、`detect` には語の一覧だけを渡す。語・ドメインを指定しなければ、検出器を作らない。
`--email-hash local` のために、`Detector.Find` は、email の一致のドメインの部分を `customFinder`・`hostFinder` で確かめ、`Match.HideDomain` を立てる。

前処理(3.4 節)用の `may(line, hint)` と `lineHint` は設けない。各検出器が `find` の先頭で、自分の手がかり
(email は `'@'` の `bytes.IndexByte` など)を探し、なければすぐ戻る。
行ごとに 1 回の走査でヒントを作る方式は、実測で約 0.95GB/s、種別ごとの `IndexByte`(ベクトル化されている)は
約 13GB/s で、後者のほうが約 14 倍速かったため(段階 3 の実装メモ参照)。

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
// Inspect は任意で、変換した 1 行を受け取り、置換済みの形として数える数を返す(restore が、崩れた形を集めるために使う。Q82)。
type Engine struct { Det *detect.Detector; Rep Replacer; Stats Stats; Inspect func(out []byte) int }
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

## 3. 慎重に設計すべき点と方針

### 3.1 範囲が重なった場合の解決

1 行ごとに次の手順で決める。

1. 有効な種別の検出器が、それぞれ候補(範囲・種別・区別)を出す。この時点では重なりを気にしない
2. 置換しない候補を外す(`--types` で無効な種別はそもそも候補を出さない。`--allow`、IP の特殊アドレス・`--ip-scope` 外を外す時点は → **Q11**)
3. 置換済みのラベル・hash 出力形を「保護範囲」として候補に加える(3.2 節)。`--allow` の値の扱いも Q11 の回答による
4. 候補を「長さの降順 → 優先順位(保護範囲 → email → ipv4/ipv6 → secret → uuid)→ 開始位置の昇順」で並べ、先頭から順に、すでに採用した範囲と重ならないものだけ採用する
5. 採用したもののうち保護範囲を除き、開始位置の順に並べて返す

- 採用の確認は、候補の両端が採用済みの範囲に入っているかだけを見る(候補は長い順なので、採用済みの範囲は候補以上の長さで、重なれば、候補の端のどちらかが入る)。`--deny "--"` と長い `-` の連なりのように、連鎖して重なる候補が 1 つの塊になっても、2 乗の時間にならない(v1.3)
- 負けた候補は、重なっていない部分も含めて捨てる(仕様「一部だけ重なる場合も 1 つに決める」)。部分を再検出はしない
- 同じ種別・同じ長さの重なりは開始位置が前のほうを採る(仕様に記述なし。順序が決定的であれば良い点なので、確認事項には入れず、この方針で進める。異論があれば指摘してほしい)
- ipv4 と ipv6 は同じ優先順位だが、同じ長さで重なることは形式上起きない(IPv6 は必ず `:` を含み、IPv4 は含まない)
- 実装は、候補を開始位置で並べ、**重なる候補の塊(推移的に重なるもの)ごと**に上の規則で解決する。塊が違う候補は重ならないので、全体に対する貪欲法と同じ結果になる(乱数テストで、単純な参照実装との一致を確認している)。
  当初は「候補は 1 行に数個なので、単純なソート + 線形の重なり確認で十分」としていたが、1MB の JSON 1 行に候補が数万件ある場合に 2 乗の時間になるため変えた

### 3.2 冪等性(置換済みの値を検出しない仕組み)

- `label.Format.Scan` が現在の `--mask-format` のラベル(既知の種別名 × 1 以上の整数)を、`label.ScanHashed` が hash 出力形を見つける
- これらを「保護範囲」として、重なりの解決に**最優先の候補として参加**させる(保護範囲が勝てば、その範囲は置換されない)
  - 単に「保護範囲と重なる候補を捨てる」方式だと、`"password": "<secret_1> 本物の値"` のような値で、本物の値まで残ってしまう。参加させる方式なら、より長い候補が勝って全体が置換される(見逃しを減らす側。仕様 7 章)
  - `--mask-format '[{type}-{n}]'` では、キー名ベースのクォートなしの値が `]` の直前で切れるため、`password=[secret-1]` の値は `[secret-1` になる。保護範囲 `[secret-1]` のほうが長いので保護範囲が勝ち、再置換されない(この書式の受け入れ基準を、この仕組みで満たす)
  - 同じ長さのとき保護範囲が勝つ(`password=<secret_1>` の値 `<secret_1>` と保護範囲は同じ範囲)
  - この方式は仕様の「置換済みの形の文字列は検出しない」の解釈を含むため、**Q1** で確認する
- mask の出力が、周囲の文字とつながって新しい候補を生まないことは、例を挙げて確かめきれないため、ファズテスト(`mask(mask(x)) == mask(x)`、hash も同様)で確認する
- 見つかった問題の振り分け(v1.2 で決めた。仕様 7 章の冪等の但し書き):
  - 直す: 現実にありうる形で、値が置換されずに残るもの。置換済みのログを流し直す使い方で、結果が変わるもの
  - 直さず、[LIMITATIONS.md](../LIMITATIONS.md) の「冪等性」に書く: 値どうし・値と記号が区切りなしで密着するなど、手で作らない限り現れない形の冪等性の違反。その入力は `testdata/fuzz/` に加えない(`go test` が失敗し続けるため)
  - ファズテストの探索(`-fuzz`)は、版のリリース前などに時間を決めて行い、見つかったものをこの基準で振り分ける。普段の `go test` は、`testdata/fuzz/` の入力と種だけを流す。現実的な形は、表のテストや合成ログの断片として加える
- 冪等性のファズテスト(`FuzzMaskStable`・`FuzzHashStable`。`internal/transform/fuzz_test.go`)の入力は、現実的な断片の組み合わせ(v1.2 で変えた): ファズテストのバイト列を、断片の表(`fuzzFragments`。各種別の値・置換済みの形・文脈の語)と区切りの表(`fuzzSeparators`。空白を含む区切り・改行・JSON の区切り)の選び方として読み、行を組み立てる(`fragmentText`)。区切りなしの密着や、記号だけで断片を直接つなぐ形は作らない
  - 断片・区切りを足すときは、ログ・テキストに実際に現れる形にする。記号が値に隣り合う形は、断片の中に書く
  - 往復のファズテスト(`FuzzRestoreRoundTrip`)は、どの入力でも成り立つべき性質なので、任意の文字列のまま
  - 以前の(任意の文字列を入力にしていた)ファズテストの種と、見つかって直した入力は、表のテスト `TestMaskAndHashStableOnExamples` に移した。今後、断片の組み合わせで見つかって直した入力は、`testdata/fuzz/` に加える(入力はバイト列の形)

### 3.3 restore が前提とする連番の決定性

連番が決まる要素をすべて固定し、mask と restore で同じコードを通す。

- 連番の順序 = 入力の順(ファイルの指定順 → 行の順 → 行内の開始位置の順)。重なりの解決は 3.1 節のとおり決定的
- 「同じ値」の判定キー = (種別名, 値のバイト列)。正規化しない場合、ラベル → 値の対応が一意になり、往復で 1 バイトも変わらないことが保証される(→ **Q3**)
- 番号を消費しないもの: `--allow` の値、特殊アドレス、`--ip-scope` 外、保護範囲
- Go の map の反復順に依存する処理を、出力・連番・stats のどこにも入れない(stats は `label.Types` の固定順で出す)
- 前処理(3.4 節)は「その種別が一致しうる必要条件」だけにする。前処理あり/なしで結果が同じことをファズテストで確認する(前処理の誤りが、mask と restore で同じように効いて気づきにくいのを防ぐ)
- restore は `--source` を mask と同じ `Engine` に通し、`Masker` の対応表だけを使う。restore 独自の検出経路は作らない
- 連番に影響するオプションがすべて restore でも指定できることが必要。`--hash-length` が restore にない点を **Q10** で確認する
- 回答(ANSWER)を先に読み、含まれるラベルを集めてから `--source` を処理する。必要なラベルがすべて見つかった時点で `--source` の残りを読まずに終えてよい(連番は最初に現れた順なので、後ろを読んでも既存の対応は変わらない)。回答は AI の返答なので全体をメモリに読む前提とする(→ Q24)

### 3.4 性能目標(50MB/s)のための前処理

本文は [development/performance.md](development/performance.md) に分けた(節番号は変えない)。

---

## 4. リリースの手順

1. 人が `develop` を `main` へ merge commit でマージし、そのマージコミットにタグ(`vX.Y.Z`)を付ける(AI はマージしない)
2. `main` のタグの位置で `scripts/build-release` を実行する。`dist/` に 6 環境のバイナリと `SHA256SUMS` ができる
   - 版はタグから入る(`-ldflags` は使わない)。変更のある作業ツリーや、タグの位置でない HEAD では動かない。linux/amd64 のバイナリで版を確かめる
   - v2 以上のタグでは、`go.mod` のモジュールのパスに `/v2` などを付けないと、タグの版にならない(このスクリプトの確認で止まる)
   - WSL なら、`dist/logscrub-…-windows-amd64.exe` も実行して確かめられる。darwin と arm64 は、手元ではビルドの確認まで
3. タグを push して、Release にファイルを置く: `gh release create vX.Y.Z dist/* --title vX.Y.Z --notes-file <CHANGELOG の該当の節>`
4. README の「導入」の URL の版を更新する
