# v1.3.0 の性能の調査

- 目的: v1.3.0 の性能の低下の大きさと原因を確かめ、今後の機能(open の issue)を見据えて、改善の余地があるかを判断する
- 確認日: 2026-11-01
- 対象の版やコミット: タグ `v1.2.0` と `0166bea`(`feature/v1.3.0-custom-values`)
- 環境: WSL2、2 コア、`golang:1.27.2` のコンテナ。3 コア以上では測っていない
- 範囲外: 実ログでの測定(リポジトリに入れない。合成ログのみ)、3 コア以上での測定

## 結論

- 低下が大きいのは restore だけで、約 8.6%。mask・hash は約 1.7% 以下
- 既定の mask には突出した箇所がない。逐次処理の調整だけで大きく伸ばすのは難しい
- 効果が大きいのは、検出の並列化。2 コアで約 2 倍。1 コアに制限しても遅くならない
- restore は、回答の走査の改善で低下を約 4.3% まで戻せる。`--domain` と語が少ない `--deny` は、照合器の読み飛ばしで約 27% 速くなる

## 確かめた事実

### v1.2.0 との比較

`./scripts/go -C <コピー> test -run xxx -bench … -benchtime 2s ./internal/transform` を、2 つの版で交互に 4 回実行した平均。

| ベンチマーク | v1.2.0 | 0166bea | 差 |
|---|---|---|---|
| `BenchmarkEngineMask` | 220.5 MB/s | 216.9 MB/s | -1.7% |
| `BenchmarkEngineMaskAWS` | 168.4 MB/s | 167.4 MB/s | -0.6% |
| `BenchmarkEngineHash` | 224.2 MB/s | 220.7 MB/s | -1.6% |
| `BenchmarkRestore` | 205.3 MB/s | 187.6 MB/s | -8.6% |

- 回ごとの幅は、各ベンチマークで約 1〜2 MB/s。上の差は、順序が 4 回とも同じだった(AWS は幅と重なる回がある)
- mask の 1.7% は、CPU プロファイルの差分(`pprof -diff_base`)では原因の関数を特定できなかった。上位の差は、増減とも 2% 未満で混ざっている

### 時間の内訳(`-cpuprofile`、`-benchtime 8s`、0166bea)

| 関数 | mask 既定 | `default,aws` | restore |
|---|---|---|---|
| `Detector.Find` | 82.9% | 85.9% | 73.8% |
| `secretFinder.find` | 44.5% | 34.5% | 42.1% |
| うち `keyed` / `fixed` | 23.1% / 15.2% | 17.3% / 10.9% | 21.7% / 13.8% |
| `ipv4Finder.find` | 15.2% | 12.6% | 11.9% |
| `ipv6Finder.find` | 9.6% | 6.4% | 6.6% |
| `emailFinder.find` | 6.9% | 6.3% | 5.9% |
| AWS の 3 つの検出器 | — | 計 19.5% | — |
| `Masker.Append` | 8.3% | 7.2% | 7.4% |
| `AnswerScanner.Scan` | — | — | 8.0% |

- `bytes.IndexByte` は mask 既定で 28%。呼び出し元は分散している(`nextFixedPrefix` 26%、`keyed` 21%、`ipv4WindowStart` 18%、`signatures` 9%、`ipv6Finder.find` 8%、ほか)
- 正規表現(`FindIndex`・`FindSubmatchIndex`)は計 約 11%
- `BenchmarkEngineMaskDeny`(語 1000 個と `--domain`)は、`literalMatcher.scan` が 46%
- restore の回答の走査は、v1.2.0 の `Format.Scan` が約 2.2ms/回、0166bea の `AnswerScanner.Scan` が約 4.5ms/回(プロファイルの時間を実行回数で割った値)

### 試作の結果

一時的なコピーで試した。リポジトリには入れていない。

| 試作 | 変更 | 前 | 後 |
|---|---|---|---|
| 回答の走査 | 行に `\` も `&` もなければ `Format.Scan` を使う。それ以外は先頭のバイトを `bytes.IndexByte` で探す | restore 187.6 MB/s | 195.3〜197.4 MB/s(3 回) |
| 照合器の読み飛ばし | 根の状態で、語の先頭 2 バイトの組にならない位置を読み飛ばす | `BenchmarkLiteralMatcher` 約 530 MB/s | 約 2,630 MB/s |
| 検出の並列化 | 下の表 | | |

全体での効果(照合器の読み飛ばし。合成ログ 8MB、全体の処理):

| 指定 | 前 | 後 |
|---|---|---|
| `--domain example.com` | 約 150 MB/s | 約 190 MB/s |
| 語 10 個(`project-N-name`) | 約 151 MB/s | 約 195 MB/s |
| 語 1000 個(`project-N-name`。先頭が同じ) | 約 152 MB/s | 約 194 MB/s |
| 語 1000 個(子音・母音の綴り。先頭の 2 バイトが多様) | 約 149 MB/s | 約 154 MB/s |
| 語 1000 個(英小文字の 2 文字の組をほぼ覆う) | 約 144 MB/s | 約 141 MB/s |

- 語が短い 1 バイトの場合は、2 バイトの読み飛ばしを使えない。試作は 1 バイトの表で読み飛ばす形にした
- 照合器の既存のテスト(単純な参照実装との乱数テストを含む)は、試作でも通った

検出の並列化(読み取り → 複数の検出 → 1 つの書き換えの順の処理。ブロック 256KB。合成ログ 32MB、`io.Discard` に出力):

| 測定 | 逐次 | ワーカー 1 | ワーカー 2 |
|---|---|---|---|
| mask 既定、2 コア | 222.3 MB/s | 253.3 MB/s | 439.6 MB/s |
| `default,aws`、2 コア | 164.8 MB/s | — | 331.0 MB/s |
| mask 既定、`-cpu 1` | 223.5 MB/s | 233.2 MB/s | 236.7 MB/s |

- 出力は、16MB の AWS の合成ログ(1MB の JSON 行を含む)で、ワーカー 4 の場合も逐次と 1 バイトも違わなかった。`-race` を付けた実行も通った
- 試作は mask の 1 入力だけで、エラー処理、複数の入力、`Inspect`(restore)を実装していない
- 検出器は、値の型か、読み取り専用の表だけを持つ。行をまたぐ状態はない(`internal/detect` の型とパッケージ変数を確認)。作業領域は `Detector` にあるので、ワーカーごとに分ければよい
- 今の出力の書き込みは 64KB のバッファで、行ごとに `Flush` しない(`internal/transform/engine.go`)。並列化しても、`tail -f` のような入力の出力の遅れは、今より悪くしなくて済む

## 推測・未確認

- 3 コア以上の効果。`Find` の割合 83% からの見積もりでは、4 コアで約 2.6 倍、8 コアで約 3.6 倍、上限が約 5.9 倍。2 コアの実測(約 2 倍)は同じ式の 1.7 倍を超えたので、この式は目安にすぎない
- 実バイナリの速度と最大メモリ。試作はベンチマークだけで測った。ブロックの分のメモリは、256KB × ワーカー数 × 3 個に、長い行の分が加わる見込み
- restore に残る差(約 4.3%)の原因。種別の増加と `Inspect` の 1 行ごとの確認の影響と考えられるが、切り分けていない
- 手書きの走査への置き換え、`bytes.IndexByte` の結果の検出器の間での共有は、試していない。後者は v1.2.0 で「数 % で、仕組みが大きい」として見送った判断のまま

## 判断に影響すること

open の issue が加える処理と、並列化との関係。いずれも issue の内容からの見込みで、測っていない。

| issue | 性能への影響の見込み | 並列化との関係 |
|---|---|---|
| [#18](https://github.com/kiaamaaio/logscrub/issues/18) `--pattern` | 大きい。手がかりで絞れず、正規表現を行全体に当てる | コア数に応じて緩和される |
| [#22](https://github.com/kiaamaaio/logscrub/issues/22) エントロピー | 大きい。行の中の語をすべて調べる | 同上 |
| [#20](https://github.com/kiaamaaio/logscrub/issues/20) 電話番号など | 中程度。数字の並びは文中に多い | 同上 |
| [#21](https://github.com/kiaamaaio/logscrub/issues/21) GCP / Azure | 中程度。検出器が増える | 同上 |
| [#13](https://github.com/kiaamaaio/logscrub/issues/13)、[#15](https://github.com/kiaamaaio/logscrub/issues/15) | 小さい。手がかりで絞れる | 影響なし |
| [#14](https://github.com/kiaamaaio/logscrub/issues/14) PEM | 小さい | **制約になる。** 行をまたぐ状態が要るので、検出が行ごとに独立でなくなる |
| [#19](https://github.com/kiaamaaio/logscrub/issues/19) `--out-dir` | 変わらない | 連番の処理が 1 か所なので、両立する見込み |
| [#11](https://github.com/kiaamaaio/logscrub/issues/11)、[#16](https://github.com/kiaamaaio/logscrub/issues/16) | 変わらない | 影響なし |

## 未確定事項

[v1.4.0 の計画の Q94〜Q99](../plans/v1.4.0/questions.md) に書いた。
