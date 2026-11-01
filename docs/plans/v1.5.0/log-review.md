# logscrub v1.5.0 `/code-review` の修正の記録

[計画](README.md)へ戻る。`/code-review` の修正の内容と、修正のあとの確認を書く。段階ごとの記録は [log.md](log.md)。指摘の全体は PR の説明に書く。

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

## 3 回目の `/code-review` の修正

Q117〜Q120 は 2026-11-01 に、すべて案のとおりと確定した。修正の前に止まる条件(3 回レビューしても重要な指摘が減らない)に当たったが、ユーザーの判断で修正を進めた。

- PEM(Q117): `column` を、文字列で包まれた形では開き引用符の次から数える。判定の順を、列、本文の範囲、行全体に揃えた。`bodyView` は `bodyRange`(文字列の範囲)にして、列の判定を `bodyLine` に移した
- PEM の誤通知: 閉じる行の判定を、行全体でなく本文の範囲の末尾で行う。`{"log":"password: <secret_2>\n",…}` で通知が出なくなった。レビューの指摘の例に近い `token=abc` は全体が base64 の文字なので本文になり、ブロックを閉じない
- `user_path`(Q120): `//wsl$/`、`//wsl.localhost/` を形に足した。前が `:` の形は対象にしない。`https://wsl.localhost/…` はドメインのある URL で、4.8 節の対象外のため。そのため `file://wsl$/…` も対象外で、LIMITATIONS.md に書いた
- `wslHomeStart`: `\` が 2 つ続くときだけ呼び、形を表 `wslForms` にして、文字列の連結をなくした
- Q118、Q119、Q120 の残りの形と、列と同じ長さの行の扱いを LIMITATIONS.md に書いた。END の印に続けて書かれた本文は、文字列で包まれた形でも残ることを実バイナリで確かめ、あわせて書いた
- `docs/detection.md` の表に、Q115 と Q120 の形を足した
- エンジンの段のテスト: `TestPEMReplacedTailInAString`、`TestGoldenInputsAreStable`(`paths.log`・`pem.log` の 2 回目)。ファズテストの断片に、日時付きの Docker の形と `//wsl` の形を足した

### ゴールデンの差分

`paths.log` に 3 行、`pem.log` に 10 行を末尾に足し、期待値も同じ行を足した。どれも v1.5.0 で加えたファイルで、前からある行の期待値は変えていない。`develop` にあるゴールデンは変えていない。

理由は、レビューの指摘(Docker の形の PEM と Q115 の形に、エンジンの段のゴールデンがない)。足した行は、`file:/C:/Users/`、`/C:/Users/`、区切りが混ざる形、WSL の各形、`https://wsl.localhost/…`(置換しない)、Docker の形、日時付きの Docker の形。期待値は `mask` の出力を目で確かめた。

### 修正の直後の確認

- `./scripts/go test ./...`、`./scripts/go vet ./...`、`GOOS=windows ./scripts/go vet ./...`: 通った
- `wslHomeStart` の費用: 前の節と同じ行で `userPathFinder.find` を測った。一時的なベンチマークで、リポジトリには入れていない。89.79 → 347.53 MB/s。別の時に測った 6b088d1 の 465.41 MB/s までは戻っていない

修正の前(64dbb92)と後のバイナリを交互に 9 回ずつ。「`\` が多い」は、前の節の行を並べた 100MB のログ。計画の 4.1 節の基準の範囲内。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 191.6 MB/s | 185.0 MB/s | -3.4% / -3.4% |
| mask、`GOMAXPROCS=2` | 346.1 MB/s | 346.1 MB/s | +0.0% / +2.5% |
| mask、`\` が多い、`GOMAXPROCS=1` | 75.9 MB/s | 207.6 MB/s | +173.6% / +171.6% |
| mask、`\` が多い、`GOMAXPROCS=2` | 144.2 MB/s | 402.0 MB/s | +178.8% / +174.6% |

### 版の完了条件の確認

abc993d で実行した。

`./scripts/go test ./internal/transform -run '^$' -fuzz … -fuzztime 90s`: 失敗なし。実行回数が前回より少ないのは、ほかのプロセスでメモリが足りず、swap を使っていたため(空きは約 200MB)。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 212,764 |
| `FuzzHashStable` | 258,383 |
| `FuzzRestoreRoundTrip` | 351,255 |

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 329.6 MB/s、パイプからは 296.6 MB/s、`GOMAXPROCS=1` は 182.6 MB/s、hash は 361.2 MB/s、restore は 290.8 MB/s。README の性能の表は変えない。

`-perf` の 1 回目は、`TestPerfMemoryWithLongLines` が `signal: killed` で失敗し、値も半分ほどだった。原因は測定の手順で、メモリ不足で `-race` の `docker run` のクライアントだけが落ち、残ったコンテナと `-perf` が同時に動いていた。コンテナを止め、単独で実行し直した上の結果を採る。

`-race` は、`./scripts/go test -p 1 -race …` では `detect` と `transform` が OOM で強制終了された(dmesg で確認。テストの失敗ではない)。次の方法で通した。

- `CGO_ENABLED=1 ./scripts/go test -race -c -o .cache/<パッケージ>.race ./internal/<パッケージ>` で作ったバイナリを、ホストで `GOGC=25 GOMEMLIMIT=300MiB`、`-test.count=1 -test.skip '^TestEngineMatchesSequential$'` で実行した
- `transform`: PASS(19 秒、最大 404MB)。`detect`: PASS(約 21 分、最大 423MB)。`DATA RACE` の報告なし
- `cli`、`stream`: `-p 1` の実行で ok(キャッシュの結果)
- **`TestEngineMatchesSequential` は、abc993d の `-race` では実行していない**(`transform` のテスト以外の変更はなく、`internal/transform` の実装も変えていない。ただし `detect` は変えた)

### 残っていること

- 4 回目の `/code-review` は別のセッションで行い、判断が必要なものを Q121、Q122 に書いた。修正は次の節に書く
- PR の説明の 3 回目の表と確かめたことは、abc993d の内容に更新した。4 回目の結果は、まだ書いていない
- 3104a7a までは push した。そのあとのコミットは push していない

## 4 回目の `/code-review` の修正

別のセッションで abc993d を中心に high で行った。指摘の全体は PR の説明に書く。Q121、Q122 は 2026-11-02 に、どちらも案のとおりと確定した。

- PEM(Q121): BEGIN の印の後ろが、文字の `\n`(`\r\n`)のあとに行末か `\` だけのときも、ブロックに入る(`endsWithEscapedNewline`)。本文の範囲は、今の `\n` までの規則のまま。印の行の `\n`・`\n\` は置換しなくなった。本文が続かなければ、END なしの通知が出る
- PEM(Q121): 行末が `\` だけの形は実装を変えず、LIMITATIONS.md の「`\n` があるときだけ検出します」の説明に足した
- PEM(Q122): 実装は変えず、`\` を 2 重にした形を LIMITATIONS.md に書いた。テストで今の動作を確かめる
- `scanLine`: `bodyRange` を 1 回だけ求めて `bodyLine` に渡す。外側の `from` を隠す内側の `from` をなくした。動作は変わらない。ブロックを閉じた行の BEGIN の印の探索は、今までどおり行頭から
- LIMITATIONS.md: END のないブロックの中の、行全体がトークンの行で再度の mask の結果が変わることを書いた。`file:////wsl$/…`、`file:////wsl.localhost/…`、`\\?\UNC\wsl$\…` に加えて、同じように残る `\\?\UNC\wsl.localhost\…` も書いた
- 仕様 4.1: Q121 の形を足し、本文の範囲の説明を、開き引用符のない形に合わせた

実バイナリで確かめた形(架空の値、修正の前は 6ba303a のバイナリ):

| 入力 | 修正の前 | 修正の後 |
|---|---|---|
| `key=-----BEGIN…\n` と本文 `AAAA\n` | `\n` が `<secret_1>` になり、本文は残る | 本文が `<secret_1>\n` になる |
| `KEY="-----BEGIN…\n\` と本文 `AAAA\n\` | `\n\` が `<secret_1>` になり、本文は残る | 本文が `<secret_1>\n\` になる |
| `key=-----BEGIN…\r\n` と本文 `AAAA\r\n` | `\r\n` が `<secret_1>` になり、本文は残る | 本文が `<secret_1>\r\n` になる |
| `key=-----BEGIN…\n` と、本文でない行 | `\n` が `<secret_1>` になり、通知なし | 印の行は変わらず、通知が出る |
| `KEY=-----BEGIN…\` と本文 `AAAA\` | 本文が残り、通知なし | 同じ(LIMITATIONS.md) |

トークンの行は、`ghp_…`、JWT、`sk_live_…` を、`-----BEGIN…` のあとの本文の間に置いて、素の形と Docker の形で確かめた。1 回目は後ろの本文が残り、通知が出る。2 回目は後ろの本文が伏せられる。本文を別の値にすると、2 回目の本文のラベルは、1 回目の `<secret_1>` と同じ番号になる。

### ゴールデンの差分

`pem.log` の末尾に 7 行を足し、`pem.mask.golden` にも同じ数の行を足した。v1.5.0 で加えたファイルで、前からある行の期待値は変えていない(`mask` の出力と今のゴールデンの `diff` は、足した 7 行だけ)。`develop` にあるゴールデンは変えていない。

理由は、Q121 の形(行末が `\n`、行の継続)に、エンジンの段のゴールデンがないため。`TestGoldenInputsAreStable` で 2 回目も確かめる。期待値は `mask` の出力を目で確かめた。
