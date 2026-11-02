# logscrub v1.5.0 `/code-review` の修正の記録

[計画](README.md)へ戻る。`/code-review` の修正の内容と、修正のあとの確認を書く。段階ごとの記録は [log.md](log.md)。指摘の全体は PR の説明に書く。

1〜4 回目の記録は [log-review-1.md](log-review-1.md) に分けた。

## 5 回目の `/code-review`

別のセッションで `43be60f..974ef5c` を中心に high で行った。指摘の全体と扱いは PR の説明に書く。判断が必要なものは Q123 に書いた。修正はまだしていない。

- 974ef5c のバイナリで、Q121 の形(素の形、行の継続、CRLF、`--mode hash`、`--mask-format '{type}_{n}'`)を確かめた。本文は伏せられ、2 回目で変わらず、`restore` で戻る
- `\/\/wsl$\/…`、`\/\/wsl.localhost\/…`、`//?/UNC/wsl$/…` のユーザー名が残ることを確かめた。LIMITATIONS.md に書く指摘で、まだ書いていない
- `./scripts/go test ./...`: すべて ok(キャッシュの結果)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った
- ファズテスト、`-perf`、`-race` は実行していない(`ea8351b` のあとに実装の変更はない)
- Q の範囲の記述(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)は、Q123 の確定のときに直す

## 5 回目の `/code-review` の修正

Q123 は 2026-11-02 に、案のとおりと確定した。

- PEM(Q123): END のない 1 行の形でも、END なしの通知を出す。`Stats.Unclosed` に数えるので、件数と行番号は既存の通知と同じ文で出る。置換と本文の判定は変えていない。`\n` と `\` だけの規則(Q121)も変えていない
- 置換する範囲の全体が `secret` の置換済みの形なら、通知しない。`--mode hash` の `secret_<hex>` と `--mask-format '{type}_{n}'` の `secret_1` は base64 の文字で始まるので 1 行の形として読まれるが、この判定で 2 回目は出ない。既定の `<secret_1>` は 1 行の形に当たらない
- 判定はブロックの規則と同じく `secret` に限る。印に密着した IP アドレス(`-----BEGIN…10.0.0.1`)は同じ範囲で `ipv4_private` が勝つので、hash の出力を再度流すと通知が残る。鍵の残りを見落とす方向ではなく、この形は現実のログに現れにくいので変えていない
- LIMITATIONS.md: 「`\n` があるときだけ検出します」を 3 項目に分けた。通知が出て本文が残る形(本文の 1 行目が印と同じ行、`\n` の後ろに空白や `\n`)と、通知も出ない形を書いた。通知も出ない形に、実バイナリで確かめた `-----BEGIN… AAAA`(空白と短い語)を足した
- LIMITATIONS.md: `\/\/wsl$\/…`、`\/\/wsl.localhost\/…`、`//?/UNC/wsl$/…` を書いた。同じように残る `//?/UNC/wsl.localhost/…` も、実バイナリで確かめて足した
- 仕様 4.1、6 章、9 章、CHANGELOG、`docs/detection.md` を合わせた。Q の範囲を Q123 までに直した(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)

実バイナリで確かめた形(架空の値。修正の前は Q123 の変更を入れない 3d72d3d のバイナリ)。8 形とも、後ろに本文の行 `AAAA` を置いた。修正の前の通知は 0 行、修正の後は 1 行。2 回目の通知は、mask、`--mode hash`、`--mask-format '{type}_{n}'` のどれも 0 件。mask の出力は `restore --source` で戻り、hash の出力は 2 回目で変わらない。

| 形 |
|---|
| `{"log":"-----BEGIN…\nAAAA\n","stream":"stderr"}` |
| `KEY="-----BEGIN…\nAAAA\n\` |
| `key=-----BEGIN…\nAAAA\n` |
| `-----BEGIN… AAAAAAAAAAAAAAAA` |
| `key=-----BEGIN…\n `(行末の空白) |
| `KEY="-----BEGIN…\n \` |
| `KEY="-----BEGIN…\n\ `(行末の空白) |
| `key=-----BEGIN…\n\n` |

### 期待値とゴールデンの差分

Q123 による通知の増加だけを変えた。stdout の期待値は変えていない。

- `TestPEMScanner`: END のない 1 行の形の 4 件(`one line without END` とその派生)の `unclosed` を 0 から 1 にした
- `TestMaskGoldenPEM`: `pem.log` の `Unclosed` の期待値を 1 から 5 にした。足した 4 つの形の分
- `pem.log` の末尾に 8 行を足し、`pem.mask.golden` にも同じ数の行を足した。v1.5.0 で加えたファイルで、前からある行の期待値は変えていない(`mask` の出力と今のゴールデンの `diff` は、足した 8 行だけ)。`develop` にあるゴールデンは変えていない。理由は、Q123 の形に、エンジンの段のゴールデンがないため。後ろの本文の行が残ることも、期待値に入っている。期待値は `mask` の出力を目で確かめた

### 修正のあとの確認

54dde65 で実行した。

- `./scripts/go test ./...`、`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)

`./scripts/go test ./internal/transform -run '^$' -fuzz … -fuzztime 90s`: 失敗なし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 1,008,936 |
| `FuzzHashStable` | 507,879 |
| `FuzzRestoreRoundTrip` | 224,383 |

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 325.9 MB/s、パイプからは 282.2 MB/s、`GOMAXPROCS=1` は 177.0 MB/s、hash は 351.2 MB/s、restore は 289.7 MB/s。README の性能の表は変えない。

mask(ファイルから)が前回の 360.0 MB/s より低いので、修正の前(3d72d3d)と後のバイナリを交互に 9 回ずつ、`.cache/big.log`(105MB)で測った。修正による低下は 1.5% 以内で、計画の 4.1 節の基準の範囲内。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 185.3 MB/s | 183.2 MB/s | -1.1% / -1.5% |
| mask、`GOMAXPROCS=2` | 342.3 MB/s | 341.8 MB/s | -0.1% / -0.4% |

`-race` は、4 回目と同じ方法で、`CGO_ENABLED=1 ./scripts/go test -race -c` で作ったバイナリ(`./scripts/go version -m` で `-race=true`)を、ホストで `GOGC=25 GOMEMLIMIT=300MiB`、`-test.count=1` で 1 つずつ実行した。どれも PASS。出力は末尾の数行だけを残したので、`DATA RACE` の件数は数えていない(競合があれば、テストは FAIL になる)。

| 対象 | 時間 | 最大メモリ |
|---|---|---|
| `transform`(`TestEngineMatchesSequential` を除く) | 15 秒 | 425MB |
| `detect` | 19 分 26 秒 | 503MB |
| `cli` | 2 秒 | 76MB |
| `stream` | 15 秒 | 61MB |
| `TestEngineMatchesSequential` だけ(`-test.run`) | 27 秒 | 914MB |

### 残っていること(5 回目の修正のあと)

- 修正のあとの別のセッションのレビュー(6 回目)はまだ
- 2026-11-02 に、a75993e まで push し(ユーザーが実行)、PR の説明を更新した。このコミットは push していない

## 6 回目の `/code-review`

別のセッションで `3d72d3d..a75993e` を中心に high で行った。指摘の全体と扱いは PR の説明に書く。判断が必要なものは Q124 に書き、2026-11-02 に案のとおりと確定した。修正はまだしていない。

- 9284ee9 のバイナリ(実装は a75993e と同じ)で確かめた。テスト、ファズテスト、`-perf`、`-race` は実行していない(実装の変更はない)
- 指摘は 5 件。Q124 は LIMITATIONS.md に書く。ほかの 4 件の扱いは次のとおり
  - 再度流したときの通知: `{"log":"-----BEGIN…\n"}`、`{"log":"AAAA\n"}`、`{"log":"-----BEGIN…\nBBBB\n","stream":"x"}` の 3 行の出力を再度流すと、mask、hash、`{type}_{n}` のどれでも、1 行目の通知が 1 件残る。引用符のない 2 行目と `"-----BEGIN…\nBBBB\n" x` の形でも同じ。3 行目の `\n` が置換の範囲に含まれて消えるので、本文の範囲が行全体になり、末尾が置換済みの判定に当たらない。stdout は変わらず、値も残らない。LIMITATIONS.md に書く
  - 通知の文: `key=-----BEGIN…\nAAAA\n` の 2 行あとに END があっても `had no END line` と出る。文は Q123 の確定どおりで、害は文の不正確さだけなので、直さない
  - `user_path`: 次の形でユーザー名が残ることを確かめた。LIMITATIONS.md に書く。`\\.\C:\Users\yamada\x`、`\\\\?\\UNC\\wsl$\\Ubuntu\\home\\yamada\\x`、`\\\\?\\UNC\\wsl.localhost\\Ubuntu\\home\\yamada\\x`、`\/\/?\/UNC\/wsl$\/Ubuntu\/home\/yamada\/x`、`file://wsl.localhost/Ubuntu/home/yamada/x`
  - コメント: `pem.go` の `beginLine`、`Unclosed` と、`stats.go` の `Unclosed`、`common.go` の `printUnclosed` の説明に、1 行の形を足す。この PR で直す
- 問題のなかったこと: Q123 の通知の行番号は、ブロックの境目(2.7MB の入力)、複数の入力、`--out-dir`、`restore --source` で正しい。LIMITATIONS.md の WSL の形は、確かめた形ではユーザー名が残る
- 値が残る指摘が、PEM の 1 行の形の周辺で 3 回続いた(Q121、Q122、Q123、Q124)。起きる形は回ごとに狭くなっている

### 残っていること(6 回目のあと)

- 修正: LIMITATIONS.md(Q124、再度流したときの通知、`user_path` の形)、コメント、Q の範囲を Q124 までに直す(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)、CHANGELOG と仕様に変更が要らないことの確認
- 修正のあとの別のセッションのレビュー(7 回目)
- PR の説明に 6 回目の結果を書く(案は 6 回目のセッションで示した。push と PR の更新は許可を得てから)
