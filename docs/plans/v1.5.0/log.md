# logscrub v1.5.0 段階ごとの記録

[計画](README.md)へ戻る。何をしたか、測った値、実際に確かめた方法を書く。測定の詳細は docs/development/performance.md に置く。

## 段階 0: 確定の反映

Q100〜Q111 が確定した(2026-11-01)。すべて案どおり。Q102 に、バージョンの表記(`v1`、`v1.2`)の除外を一度加えたが、同じ日に取り消した(効くのが `/home/v1/` のようなまれな形だけのため)。a4c3bc0 には、この除外と、questions.md の回答の記録漏れ(置換の誤りで未回答のままだった)があり、次のコミットで直した。Q100 の確認に対して、今の種別名はすべてアンダースコアで、`user_path` はそれに揃うことを答えた。

仕様へ反映した: 2 章、4 章、4.1、4.8(新設)、6 章、9 章、10 章(決定事項 28〜31)、11 章。DEVELOPMENT.md の Q の範囲と 3.3 節。

仕様の規則のうち、Q の文言より細かくしたもの(実装の中で問題があれば、止まって確認する):

- 4.8: 形の前の条件に `\` を足した。`file:///` の形の前は `file:` の前で判定する
- 4.1: ブロックに入る条件は、BEGIN の印が行末(後ろは空白か引用符 1 つまで)にあること。END の行の、印の手前の本文は 1 つのラベルにする
- 6 章: END のない PEM の通知と、怪しい語の通知の文面。`--out-dir` の失敗で、作ったディレクトリは残す

### 変更前の基準値

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(6972f69、100MB、3 回の最速、2 コア)。3 つのテストが PASS。

| 測定 | 速度 | 最大メモリ |
|---|---|---|
| mask、ファイルから / パイプから | 373.6 / 316.1 MB/s | 37 / 32 MB |
| mask、`GOMAXPROCS=1` / `2` / `8` | 206.4 / 375.5 / 340.6 MB/s | 35 / 36 / 47 MB |
| uuid あり | 348.1 MB/s | 39 MB |
| AWS のログ、既定 / `default,aws` / `aws_host` なし | 388.8 / 274.9 / 315.7 MB/s | 31 / 39 / 36 MB |
| 語 10 個 / 語 1000 個 / 綴りが多様な語 1000 個 | 329.9 / 329.7 / 262.8 MB/s | 34 / 36 / 37 MB |
| `--domain` | 327.7 MB/s | 36 MB |
| `--mode hash` | 400.6 MB/s | 16 MB |
| restore | 316.2 MB/s | 39 MB |

版の完了条件の「5% を超えて遅くならない」は、`GOMAXPROCS=1` / `2` の mask(206.4 / 375.5 MB/s)と restore(316.2 MB/s)を基準にする。v1.4.0 の仕上げの記録(365 MB/s 前後)と比べて、測定ごとのばらつきは数 % ある。判定の前に、同じマシンで交互に測る。合成ログの生成器は変えない(基準が変わるため。新しい値は別の設定で足す)。

## 段階 1: `user_path`

`internal/detect/userpath.go` に検出器を加えた。種別の登録、`logscrub types`、`--help`、`docs/detection.md`、LIMITATIONS.md、README を更新した。新しいゴールデンは `testdata/paths.log`(既存のゴールデンは変えていない)。

- 仕様 4.8 に「末尾の空白は含めない」を足した(`C:\Users\taro /var/log` の値を `taro` にするため)
- 既存のテストの変更: 既定の種別の一覧に `user_path` を足した(`TestParseTypes`、`TestTypesTable`、`TestTypesCommand`、`TestTypesAreTheDocumentedSet`)。`TestTypesTable` の「`_` を含む種別はクラウドの種別」の確認は、`user_path` だけを例外にした
- `PWD=/home/user` の 3 つのテストは変更なしで通る

### 速度(基準を超えた)

変更前のバイナリ(`develop`)と交互に 9 回ずつ、100MB の合成ログ。合成ログに対象の値は 0 件で、1 行に `/` が約 7 個ある。

| 測定 | 変更前(最速) | 変更後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 211.0 MB/s | 191.5 MB/s | -9.3% / -9.0% |
| mask、`GOMAXPROCS=2` | 384.5 MB/s | 352.4 MB/s | -8.4% / -7.4% |
| restore、`GOMAXPROCS=2` | 378.0 MB/s | 351.8 MB/s | -6.9% / -7.4% |

- 種別を足しただけ(`--types email,ipv4,ipv6,secret`)の差は、最速 -1.8%、中央値 +0.4%。原因はラベルの走査でなく、検出器
- `BenchmarkEngineMask` のプロファイルで、`userPathFinder.find` は全体の 7.29%(240ms)。うち `/` の `IndexByte` が 140ms、`\` の `IndexByte` が 50ms
- 試したこと: 次のバイトで `h`・`u` 以外を振り落とす。mask は -8.0〜-11.1% で効果がなかったので、戻した

判断(2026-11-01): ユーザーが案 A を選び、この低下を受け入れた。別案は、ブロック単位の事前確認(スタックトレースなどの、この機能が役立つログでは効かない)と、既定で無効にすること(Q100 の変更)だった。

あわせて、「5% を超えて遅くならない」を合否の基準にするのは不適切と判断し、計画の 4.1 節の基準に改めた。機能の費用は避けられないことがあるので、5% は確認のきっかけとする。次の段階の比較の基準は、この段階のコミットの値にする。

## 段階 2: PEM の秘密鍵

`internal/detect/pem.go` に `PEMScanner` を加えた。読み取りの段(`readBlocks`)がブロックごとに範囲を求めて `block.pem` に記録し、ワーカーは `Detector.FindSpans` で候補に加える。状態は読み取りの段だけにあり、入力ごとに戻す(Q98)。1 行の形もここで扱うので、`secretFinder` は変えていない。

新しいゴールデンは `testdata/pem.log`。既存のゴールデンは変えていない。

仕様 4.1 を、実装の中で次のように絞った(どれも誤検出と 2 回目の結果の変化を防ぐため):

| 規則 | 変更 | 理由 |
|---|---|---|
| BEGIN の印の後ろ | 空白か引用符 1 つ → 空白だけ | `"-----BEGIN…-----"` の行で、END なしの通知が誤って出る |
| ヘッダーの形 | 本文の行より前だけ | `INFO: done` のようなログの行が本文になる |
| 空白のあとの本文(END なしの 1 行の形) | base64 の文字 16 文字以上 | `expected -----BEGIN…----- got foo` の `got foo` が伏せられる |
| 置換済みの形の行 | 行全体が `secret` の形だけ | `… <email_1>` の行でブロックが続き、2 回目だけ後ろの行が伏せられる |
| END の行の本文 | 行頭から印の直前まで | `t=3 -----END…` の `t=3` が伏せられた(テストで検出) |
| 行末だけが本文の行 | ほかの種別の検出も行う | 下記のファズテストの見つけた問題 |

### ファズテストで見つけて直したもの

行末に base64 の文字が 40 文字以上続く行を `Body` にしていたので、ほかの検出が止まり、行の前半の値が 1 回目に残っていた(`sk_live_… - X-Amz-Signature=…`、`xoxb-… - X-Amz-Signature=…`)。行全体が本文の行だけ `Body` にして直した。入力は `testdata/fuzz/` に加えた。

### 確かめたこと

- `./scripts/go test ./...`、`./scripts/go vet ./...`: 通った
- `FuzzMaskStable`・`FuzzHashStable`・`FuzzRestoreRoundTrip` を各 60 秒: 失敗なし(修正の後)
- `TestPEMAcrossBlocks`: ワーカー数 1・2・4・8、読み取りの大きさ 3 通りで一致
- `CGO_ENABLED=1 ./scripts/go test -race -timeout 40m ./...`: `detect`(890 秒)ほかは通った
- `transform` の `-race` は OOM で落ちる。この環境のメモリは約 2GB で、`TestEngineMatchesSequential` で止まる。`develop` のコードでも同じように落ちる(今回の変更の問題でない)。この 1 テストだけを除いて `-race -skip '^TestEngineMatchesSequential$'` で通した。**このテストは `-race` では実行していない**

### 速度

段階 1 のコミットのバイナリと交互に 9 回ずつ、100MB の合成ログ(印はない)。基準(計画の 4.1 節)の範囲内。

| 測定 | 段階 1(最速) | 段階 2(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 187.7 MB/s | 186.2 MB/s | -0.8% / +0.8% |
| mask、`GOMAXPROCS=2` | 348.0 MB/s | 338.1 MB/s | -2.9% / -0.0% |
| restore、`GOMAXPROCS=2` | 347.2 MB/s | 334.5 MB/s | -3.7% / -3.0% |

## 段階 3: `--out-dir`

`internal/cli/outdir.go` を加えた。`Engine.Run` をファイルごとに呼び、`Rep` と `Stats` を引き継ぐ。`Engine` の変更は、`Run` を繰り返したときに END なしの行番号が 5 件を超えないようにする 1 か所だけ。

- 仕様 6 章を変えた: 受け付ける入力を「ディレクトリ以外」から「通常のファイルだけ」にした。FIFO(`<(…)` など)は、確かめるために開いて閉じると中身が失われるため
- 「書き出し先が同じになる入力」は、共通の親からの相対パスでは起きないので、仕様の項目から除いた(同じファイルの 2 回指定はエラーのまま)
- 入力は事前に開いて確かめるが、開いたままにしない(ファイルが多いと、開ける数の上限に当たるため)。確かめたあとに消えた場合は、途中のエラーとして、今回書いたファイルを消す
- 既存のファイルの確認のあとに作られたファイルも、`O_EXCL` で上書きしない

### 確かめたこと

- `./scripts/go test ./...`、`./scripts/go vet ./...`、`GOOS=windows ./scripts/go vet ./...`: 通った
- `TestOutDirMatchesConcatenatedMask`: 書き出したファイルの連結が `mask a b` の出力と同じで、`restore` で戻る
- 実バイナリで、README の例を実行した: 出力の配置、番号の通し、権限(0700・0600)、2 回目のエラー、`restore`
- 速度: 段階 2 のコミットのバイナリと交互に 9 回ずつ。mask、`GOMAXPROCS=2` は 342.2 → 341.9 MB/s(最速 -0.1%、中央値 +3.1%)、`GOMAXPROCS=1` は 186.1 → 183.1 MB/s(最速 -1.6%、中央値 -0.5%)。測定のばらつきの範囲

## 段階 4: `--review`

`internal/transform/review.go` を加えた。`Engine.Review` が `nil` でないときだけ、書き換えの段の `reviewLine` が表示を作る。通常の経路の変更は `nil` の確認 1 つだけ。

- 仕様 6 章の「制御文字」の範囲を具体的にした: C0、DEL、C1(U+009B の CSI など)、双方向テキストの制御文字、不正な UTF-8 のバイト。双方向の制御文字は、表示の順を入れ替えて値を読めなくできるので含めた
- 通知の行番号の組み立てを `lineList` にまとめた(`printUnchanged`・`printUnclosed`・`printSuspects`)

### 怪しい語の量

合成ログ(100MB、492,576 行)で 22,177 件。`logscrub mask --review` の出力を集計すると、上位は `req=<UUID>` の形で、`uuid` を無効にしている分だった(既定で無効の種別なので、知らせる意味がある)。`testdata` では、`app.log` が 17 行で 2 件、`pem.log` が 23 行で 1 件(`CERTIFICATE` の本文)、`paths.log`・`custom.log` は 0 件。規則は調整しない。

### 確かめたこと

- `./scripts/go test ./...`、`./scripts/go vet ./...`: 通った
- `TestReviewMatchesMask`: `testdata` の 4 つで、色の指定を除いた出力が通常の mask と同じ。件数も同じ
- 実バイナリで、`ESC[8m` で隠した文字列が `^[[8mhidden-value^[[0m` と表示されること
- 実際の端末での色の見え方は確かめていない(自動の環境に端末がない)。Windows のコンソールも同じ
- 速度: 段階 3 のコミットのバイナリと交互に 9 回ずつ。`GOMAXPROCS=2` は 315.9 → 314.3 MB/s(最速 -0.5%、中央値 +0.7%)、`GOMAXPROCS=1` は 172.9 → 171.3 MB/s(最速 -0.9%、中央値 -0.7%)。測定のばらつきの範囲。絶対値が段階 3 より低いのは、測定の時点のマシンの状態による(同じ回の比較では差がない)
- `--review` 自体は 245 MB/s(1 回)

## 段階 5: 仕上げ

### ファズテスト

各 90 秒。失敗なし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 999,176 |
| `FuzzHashStable` | 466,613 |
| `FuzzRestoreRoundTrip` | 194,185 |

`CGO_ENABLED=1 ./scripts/go test -race -timeout 20m -skip '^TestEngineMatchesSequential$' ./internal/transform ./internal/cli ./internal/stream`: 通った(除いた理由は段階 2。`detect` の `-race` は段階 2 のあと変えていないので、再度は実行していない。**段階 4 の変更は `transform`・`cli` だけ**)。

### 性能

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(1a8bd9d、100MB、3 回の最速、2 コア)。3 つのテストが PASS。README の性能の表は、この結果の値。

段階 0 の基準値との比較。別の時に測った値なので、数 % のばらつきを含む(段階ごとの差は、交互に測った各段階の記録を見る)。

| 測定 | v1.4.0 のあと | v1.5.0 | 差 | 最大メモリ |
|---|---|---|---|---|
| mask、ファイルから | 373.6 MB/s | 346.0 MB/s | -7.4% | 37 → 38 MB |
| mask、パイプから | 316.1 MB/s | 297.2 MB/s | -6.0% | 32 → 38 MB |
| mask、`GOMAXPROCS=1` | 206.4 MB/s | 182.6 MB/s | -11.5% | 35 → 38 MB |
| mask、`GOMAXPROCS=2` | 375.5 MB/s | 348.1 MB/s | -7.3% | 36 → 36 MB |
| AWS のログ、`default,aws` | 274.9 MB/s | 265.8 MB/s | -3.3% | 39 → 40 MB |
| 語 1000 個 | 329.7 MB/s | 306.8 MB/s | -6.9% | 36 → 38 MB |
| `--domain` | 327.7 MB/s | 299.8 MB/s | -8.5% | 36 → 36 MB |
| `--mode hash` | 400.6 MB/s | 360.2 MB/s | -10.1% | 16 → 16 MB |
| restore | 316.2 MB/s | 278.9 MB/s | -11.8% | 39 → 44 MB |
| 10MB の行、検出対象なし(`GOMAXPROCS=1`) | 2,187.5 MB/s | 1,930.4 MB/s | -11.8% | 29.3 → 32.2 MB |

仕様 7 章の目標(50MB/s)は、すべて満たす。段階ごとの差は、計画の 4.1 節の基準の範囲か、受け入れたもの(段階 1)。累積の -12% 近い値は、段階 1 の約 -9% の上に、ばらつきと段階 2 の小さな増加が重なったものと見ている(原因の内訳は確かめていない)。

### 確かめたこと

- 実バイナリで、README と detection.md の例を実行した: `user_path`、PEM、`--review`、`logscrub types`、`mask --help`。`--out-dir` は段階 3
- `./scripts/doc-size-check`

## `/code-review` の修正

指摘の全体は PR の説明に書く。ここには修正の内容と、残した判断を書く。

- `user_path`: 形の前の条件に、文字の `\n`・`\t`・`\r` と `\\?\` の直後を足した。`\/home\/`、`\/Users\/`、`C:\/Users\/` を形に足した。PHP の JSON は現実にある形なので、振り分けの基準で直した。2 重のエスケープ、`file:///mnt/c/…`、`file:///c/…`、`\/mnt\/c\/…` は LIMITATIONS.md に書いた
- PEM: END のない 1 行の形で、`\r\n`(文字)を本文の始まりと認めた。END の手前に空白があっても、40 文字以上なら本文にした。`t=3` の扱いは変わらない
- PEM の誤通知: 行末が `secret` の置換済みの形の行でブロックが終わったら、通知しない。ブロックを続ける形にはしなかった。`token=<secret_1>` の行でブロックが続くと、2 回目だけ後ろの行が伏せられるため
- PEM の行番号: 数え終えた位置から続けて数えるようにして、BEGIN の行が続く入力の 2 乗の時間をなくした。指摘の案(書き換えの段で求める)は、END のないブロックが入力の終わりで決まるので変更が大きく、採らなかった。印のないブロックの `bytes.Count` は残るので、DEVELOPMENT.md の記述を直した
- `Stats`: 行番号の記録を `appendLine` にまとめ、上限は `MaxKeptLines = detect.MaxUnclosedLines` の 1 か所にした
- 確認の記録がなかった規則は、Q112 に書いた。2026-11-01 に、案のとおり今の実装のままと確定した

### 修正のあとの確認

4f90d6f で実行した。

`./scripts/go test ./internal/transform -run '^$' -fuzz … -fuzztime 90s`: 失敗なし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 922,525 |
| `FuzzHashStable` | 430,829 |
| `FuzzRestoreRoundTrip` | 113,068 |

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 298.0 MB/s、パイプからは 250.7 MB/s、`GOMAXPROCS=1` は 168.2 MB/s、hash は 338.0 MB/s、restore は 262.2 MB/s。段階 5 の値(346.0、297.2、182.6、360.2、278.9 MB/s)より 6〜16% 低いので、修正の前後を交互に測って切り分けた。

修正の前(b80f8eb)と後(4f90d6f)のバイナリを交互に 9 回ずつ、100MB の合成ログ。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 168.6 MB/s | 169.2 MB/s | +0.4% / +0.8% |
| mask、`GOMAXPROCS=2` | 308.8 MB/s | 316.6 MB/s | +2.5% / +0.2% |
| restore、`GOMAXPROCS=2` | 274.2 MB/s | 273.3 MB/s | -0.3% / +1.7% |

修正による低下はなく、計画の 4.1 節の基準の範囲内。`-perf` の絶対値が低いのは、修正前のバイナリも同じ回に同じ程度まで下がっているので、測定の時点のマシンの状態による。README の性能の表は、段階 5 の値のまま変えない。

## 2 回目の `/code-review` の修正

指摘の全体は PR の説明に書く。Q113〜Q116 は 2026-11-01 に確定した。

- `user_path`: `C:\/Users\/` が、先に macOS の形の分岐に入っていた。Windows の分岐を先にして、空白を含む名前と、対象外の名前の照合が働くようにした。既存のテストは空白のない名前だけだった
- `user_path`(Q115): `file:/C:/Users/`、`/C:/Users/`、`C:\Users/`、`C:/Users\`、`\\wsl$\<配布>\home\`、`\\wsl.localhost\<配布>\home\` を形に足した。`%20`、`-I`・`-L` は LIMITATIONS.md に書いた
- PEM(Q113): BEGIN の後ろが文字の `\n` と閉じ引用符のときは、ブロックに入る。ブロックの中は、開き引用符から `\n` までで本文の形を判定する。実装を `bodyForm`(範囲の判定)と `bodyView`(範囲の決定)に分けた。ソースコードの `"…\n" +` の形も、同じ規則で検出するようになった
- PEM(Q114): BEGIN の印の手前に空白以外があるときは、印と同じ列から判定する。列の直前が base64 の文字の行は、語が切れるので、行全体の判定にする
- Q116 は LIMITATIONS.md に書いた
- `https://example.com/C:/Users/x` は、変更の前から macOS の形に当たって置換される。伏せる側の誤りなので変えていない
- 既存のゴールデンは変えていない

### 修正のあとの確認

- `./scripts/go test ./...`、`./scripts/go vet ./...`、`GOOS=windows ./scripts/go vet ./...`: 通った
- `CGO_ENABLED=1 ./scripts/go test -race -timeout 40m -skip '^TestEngineMatchesSequential$' ./internal/detect ./internal/transform ./internal/cli ./internal/stream`: 通った(`detect` 821 秒)。**`TestEngineMatchesSequential` は、段階 2 と同じ理由で `-race` では実行していない**。前の `/code-review` の修正(4f90d6f)のあとの `-race` の記録はなかったが、これで確かめた
- 実バイナリで、指摘の入力が直ったこと、2 回目の mask で変わらないこと、Docker の形が `restore` で戻ることを確かめた

`./scripts/go test ./internal/transform -run '^$' -fuzz … -fuzztime 90s`: 失敗なし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 1,004,734 |
| `FuzzHashStable` | 486,411 |
| `FuzzRestoreRoundTrip` | 277,844 |

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 341.2 MB/s、パイプからは 300.3 MB/s、`GOMAXPROCS=1` は 189.4 MB/s、hash は 370.7 MB/s、restore は 299.3 MB/s。

修正の前(6b088d1)と後のバイナリを交互に 9 回ずつ。合成ログの生成器でなく、対象の値と `/` を含む同じ形の行を並べた 100MB のログで測った。計画の 4.1 節の基準の範囲内。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 151.9 MB/s | 147.6 MB/s | -2.8% / -2.7% |
| mask、`GOMAXPROCS=2` | 288.7 MB/s | 280.6 MB/s | -2.8% / -0.8% |

## 3 回目の `/code-review`

別のセッションで c64e9c7 を中心に high で行った。指摘の全体と扱いは PR の説明に書く。判断が必要なものは Q117〜Q120 に書いた。修正はまだしていない。

- `./scripts/go vet ./...`: 指摘なし。`./scripts/go test ./...`: すべて ok(キャッシュの結果)
- `wslHomeStart` の費用: `{\"a\":\"b\", \"c\":\"d\"} ` を 8 回繰り返した行で `userPathFinder.find` を測った。`./scripts/go test ./internal/detect -run '^$' -bench … -benchtime 2s`。一時的なベンチマークで、リポジトリには入れていない

| 版 | 速度 |
|---|---|
| 6b088d1 の `userpath.go` | 465.41 MB/s |
| c64e9c7 | 89.79 MB/s |

エンジン全体の速度は測っていない。前の節の 100MB のログは `\` を多く含まないので、この形の低下は表れない。
