# logscrub v1.4.0 段階ごとの記録

[計画](README.md)へ戻る。何をしたか、測った値、実際に確かめた方法を書く。測定の詳細は docs/development/performance.md に置く。

## 段階 0: 確定の反映

- `feature/v1.4.0-perf` を、v1.3.0 のマージ後の `origin/develop`(`41971c4`)から作った
- `git fetch origin` は SSH の認証で失敗したので、`gh` の認証を使う HTTPS で取得した。`develop` と作業ブランチの差がないことを `git diff --stat 0166bea origin/develop` で確かめた
- 仕様: 7 章のストリーム処理の書き換え(Q95)、決定事項 27、11 章の Q の範囲
- DEVELOPMENT.md: 冒頭の Q の範囲、3.3 節に処理の 3 段と、行ごとに独立であることの制約(Q98)
- 計画の索引: v1.3.0 をリリース済み(タグ `v1.3.0`)として「完了」にした

## 段階 1: 測定の土台

- `cmd/logscrub/perf_test.go` に、`GOMAXPROCS` を 1・2 にした mask、語の綴りが多様な 1000 個、`--mode hash`、実バイナリの restore を加えた。`runBin` で、環境変数と、`mask` 以外のサブコマンドを渡せるようにした
- 語の一覧は、`variedWords`(子音と母音の綴り。乱数の種は固定)
- 既存の 9 通りの測定の入力と引数は変えていない

改善の前の基準値。コミット `41971c4` に上の測定を足した状態で、`./scripts/go test -run Perf -v ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア)。2 つのテストとも PASS。

| 測定 | 速度 | 最大メモリ |
|---|---|---|
| mask、ファイルから / パイプから | 205.9 / 183.5 MB/s | 29 MB |
| mask、`GOMAXPROCS=1` / `2` | 198.7 / 207.1 MB/s | 30 / 29 MB |
| uuid あり | 196.3 MB/s | 32 MB |
| AWS のログ、既定の種別 | 215.4 MB/s | 25 MB |
| AWS のログ、`default,aws` / `aws_host` なし | 154.5 / 176.4 MB/s | 34 / 29 MB |
| 語 10 個 / 語 1000 個 / 綴りが多様な語 1000 個 | 142.2 / 142.4 / 140.2 MB/s | 29 MB |
| `--domain` | 140.9 MB/s | 29 MB |
| `--mode hash` | 213.6 MB/s | 15 MB |
| restore | 180.3 MB/s | 36 MB |

- 値の種類が 1000 個のログは、20MB でも 100MB でも最大メモリが 15.3 MB で変わらない
- 段階 5 の最大メモリの基準(増加が 32MB 以内)は、上の表の値と比べる
