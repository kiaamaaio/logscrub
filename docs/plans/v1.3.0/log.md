# logscrub v1.3.0 段階ごとの記録

[計画](../v1.3.0.md)へ戻る。

### 段階ごとの記録

#### 段階 0: 確定の反映と資料の分割

- 分割: README.md 297 → 212 行(`docs/detection.md` へ)、DEVELOPMENT.md 29.1 → 21.7KB(`docs/development/performance.md` へ)。本文は変えていない
- 仕様の表現で補ったこと: 語のない `--deny-file` で `--types custom` を指定した場合はエラーにしない。エラーにするのは、`--deny`・`--deny-file` のどちらも指定していない場合

#### 段階 4: 語の照合器

- `resolve` の採用の確認を、候補の両端だけを見る形に変えた。計画になかった変更。`--deny "--"` と長い `-` の連なりで、候補が 1 つの塊になり、2 乗の時間になるため
- 既存の乱数テスト(参照実装との一致)は通る。`BenchmarkFind` は 3 回の比較で約 281 → 276 MB/s(約 1.5%)
- `BenchmarkLiteralMatcher`: 語 1・10・1000 個で、いずれも約 540 MB/s

#### 段階 8: 崩れたラベルの復元

実装時に、計画の 2 点を補正した(仕様も直した)。

- Markdown の規則: 「記号の前すべてに `\`」は、受け入れ基準の `\[email-1\]`(`-` に `\` がない)と矛盾した。始めと終わりの記号は必須、間のリテラルと種別名の記号は任意とした(`_` だけを任意にする Q81 の案を広げた形)
- Q82 の例: `\taro@example.com\>` の mask の出力は `\<email_1>\>` で、始めと終わりの両方が崩れた形ではないので、片方だけを認めない規則で既に守られる。Q82 の仕組みが要るのは、元の入力にもともと崩れた形がある場合と、終わりのリテラルが空の書式の場合。仕組みは計画どおり入れた

#### 段階 9: 往復・冪等性・性能

- ファズテスト(各 90 秒): `FuzzMaskStable` 約 105 万回、`FuzzHashStable` 約 50 万回、`FuzzRestoreRoundTrip` 約 35 万回(語・ドメインのある設定と、3 つの書式を加えた)。失敗なし。回答の走査の修正のあと、`FuzzRestoreRoundTrip` を 30 秒追加して失敗なし
- `testdata/custom.log` と `custom.mask.golden` を加えた。期待値は、実行前に手で書いたものと一致した

| 測定(同じマシンで develop と比較) | develop | v1.3.0 |
|---|---|---|
| 実バイナリ `logscrub mask < big.log`(100MB、3 回の最速) | 約 223〜227 MB/s | 約 220〜222 MB/s |
| 実バイナリ `--types default,aws` | 約 169 MB/s | 約 163〜168 MB/s |
| `BenchmarkEngineMask` | 約 234〜236 MB/s | 約 232〜238 MB/s |
| `BenchmarkRestore` | 約 218 MB/s | 約 204 MB/s |
| 実バイナリ 語 10 個 / 語 1000 個 / `--domain` | — | 約 157 / 155 / 154 MB/s |

- 計画の「既定の種別が v1.2.0 の記録から落ちないこと」は、厳密には満たしていない。記録の 229 MB/s は今の環境では再現せず、同じ環境の比較で約 1〜2% の低下。主な原因は `resolve` の変更。2 乗の時間を防ぐためのものなので受け入れた
- restore は、当初約 49 MB/s(develop の約 4.4 分の 1。目標の 50MB/s も下回る)だった。`AnswerScanner.start` の表で読み飛ばすようにして、約 204 MB/s にした

#### 段階 10: 配布

- `scripts/build-release` は、一時的なクローンの中のタグ `v1.9.9` で動作を確かめた(6 環境のビルド、`SHA256SUMS`、linux/amd64 と windows/amd64 の `--version`)。本物のタグと Release は作っていない
- 試しのタグを `v9.9.9` にすると、版がタグにならなかった(v2 以上は、モジュールのパスに `/v9` が要るため)。スクリプトの確認で止まることも確かめた
- darwin と arm64 は、ビルドと `SHA256SUMS` までの確認
- `GOOS=windows` の `go vet` の失敗(2 節)は、配布する環境で検査の指摘が出続けないように直した。最大メモリの読み取りを `perf_rss_unix_test.go`・`perf_rss_other_test.go` に分け、測れない環境では、メモリのテストを skip する。あわせて、macOS の `Maxrss` の単位(バイト)も直した
