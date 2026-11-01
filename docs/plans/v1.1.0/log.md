# logscrub v1.1.0 段階ごとの記録

[計画](README.md)へ戻る。

## 6. 進捗

| 段階 | 状態 | メモ |
|---|---|---|
| 計画 | 完了 | 2026-10-15 作成。Q32〜Q39 確定(Q35 は Web で確認) |
| 1. 種別とまとまりの枠組み | 完了 | 2026-10-16。`KindAWSAccount`・`KindAWSS3Bucket` を追加し、`KindSet` を `uint32` に広げた。種別の表(`detect.Types`: 種別・既定・クラウド名)とまとまりの表(`detect.Groups`: `default`・クラウド名・`cloud`)を作り、`DefaultKinds`・`ParseTypes`・エラーの「valid:」の一覧・`logscrub types` の出力を表から作る形にした。`types` は共通の種別のあとに見出し `AWS:` で AWS の種別を並べ、最後に `Groups for --types:` でまとまりの中身を出す(列の幅は 8 → 15)。`mask --help` の `--types` の説明に種別とまとまりを加えた(`usageTop` などの全体の説明は段階 6 で README と合わせて直す)。AWS の検出器はまだないので、`--types aws` は何も置換しない。テストの補助 `newTestDetector` の既定の種別を「表のすべての種別」にし、重なりの解決の参照実装と乱数テストに AWS の種別を加えた |
| 2. secret(SigV4 の署名) | 完了 | 2026-10-16。`secret.go` に `signatures` を加えた。語は大文字・小文字を区別しないため、固定の接頭辞(`ignature=`)では探せない。`=` を `bytes.IndexByte` で探し、手前の 9 バイトを `signature` と照合し、さらに手前が `x-amz-` なら語に含める。正規表現の参照実装 `refSecrets` に署名を加え、既存の乱数テストのほか、署名の形に絞った乱数テスト(語・前後の文字・16 進数の長さの変形)を加えた。`types --verbose` と `mask --help` の対応形式の一覧に加えた(README は段階 6 で更新する)。参考の測定(本計測は段階 3): `BenchmarkFind` 244 → 239MB/s、`BenchmarkSecretFinder` 397 → 372MB/s |
| 3. ipv4(EC2 のホスト名) | 完了 | 2026-10-16。実装前に Q40〜Q42 を追加し、案どおりに確定して仕様 4.3・4.4 に反映した。`ip.go` の `ipv4Finder` に `hosts` を加えた(ドット区切りの検出は `dotted` に分けた)。AWS の形の定義(ドメイン、リージョン、ホスト名の末尾の条件)は、新しい `aws.go` に置いた(段階 4・5 でも使う)。手がかりは、計画 2.3 の `ec2-` / `ip-` の `bytes.Index` ではなく、`-` の `bytes.IndexByte` + 手前の `ec2` / `ip` の照合にした(`bytes.Index` は、先頭の文字 `e`・`i` が文中に多いため約 5 倍遅かった。下のベンチマーク記録)。正規表現の参照実装(全位置・形とドメインを 1 つずつ試す)との乱数テストを加えた。計画 2.4 節の確認事項(`ec2-ipv4_global_<hex>.…`、`ip-ipv4_private_<hex>`)は、保護範囲として見つかることをテストで固定した(`TestIPv4HostNamesAlreadyReplaced`、CLI の hash の冪等性) |
| 4. aws_account | 完了 | 2026-10-17。`aws.go` に `awsAccountFinder`(ARN・ECR・SQS)を加え、パーティションの表を置いた。手がかりは計画 2.2 のとおり(`arn:`、`.dkr.ecr`、`sqs.`、`queue.amazonaws.com` の `bytes.Index`)。ARN のサービス・リージョンの欄の「`*` も許す」(仕様 4.4)は、`*` を使える文字に加える形にした(`*` だけの欄も、`us-*` のような欄も許す)。`<リージョン>.queue.amazonaws.com` は、`queue.amazonaws.com` から手前のリージョンを手書きで遡る(遡る長さの合計は行の長さ以内)。正規表現の参照実装(全位置・形とドメインを 1 つずつ試す)との乱数テスト、ARN・ECR・SQS で同じラベルになること・`--types aws` / `cloud` / `default,aws`・`--stats` の並び・往復・mask と hash の冪等性の CLI テストを加えた |
| 5. aws_s3_bucket | 完了 | 2026-10-17。実装前に Q43〜Q46 を追加し、案どおりに確定して仕様 4.4 に反映した。`aws.go` に `awsS3BucketFinder`(`s3://` 形式・バーチャルホスト形式・パス形式・ARN)と、S3 のエンドポイントの表を加えた。手がかりは `://`(`s3://`・`s3a://`・`s3n://` をまとめて探す)、`.amazonaws.`(対象のドメインがすべて `amazonaws.` で始まるため。計画 2.2 の `.amazonaws.com` を広げた)、`:s3:::`。バーチャルホスト形式・パス形式は、手がかりから手前のラベルを遡る手書きの走査(エンドポイントは `.` を 2 つまでしか含まないので、遡るのは `.` 3 つまで)。正規表現の参照実装(全位置。バーチャルホスト形式は、バケット名の部分の最長一致で Q43 を表す)との乱数テストを加え、わざと Q43 の「短い区切り方に戻らない」・Q44 の「後ろの英大文字・`_`」を壊すと失敗することを確かめた(前者は最初は検出できなかったので、例を加えた)。段階 4 の CLI テストは、まとまり(`aws`、`cloud`)がバケット名も置換するようになったので、期待値を直した |
| 6. 往復・冪等性・性能・README | 完了 | 2026-10-17。段階 6 のあとの確認で、2 点を直した: (1) `default,aws` が既定の種別より約 30% 遅かったので、`aws_account`・`aws_s3_bucket` の手がかりの探し方を、文中に少ない 1 バイト(`:`、`z`)の `bytes.IndexByte` + 前後の照合に変えた(下のベンチマーク記録。正規表現の参照実装との乱数テストで、結果が変わらないことを確かめた)。(2) DEVELOPMENT.md 3.4 節の前処理の手がかりの一覧に、v1.1 の手がかりと、手がかりの探し方の注意を加えた。以下は段階 6 の当初の内容。合成ログ(Q39): `synthlog.Config.AWS` を加えた(検出対象の断片の 40% を AWS の値にする)。指定しない場合は乱数を余分に引かず、v1.0 と 1 バイトも同じ出力になることを、変更前の出力の SHA-256 でテストに固定した。往復・冪等性: AWS のサンプルログ `testdata/aws.log` と、手で 1 行ずつ確認した期待値 `aws.mask.golden` を加え、サンプル・AWS の合成ログ 3MB・個別の例で、`--types default,aws` などの往復(5 通りのオプション)と、mask(4 通りの書式)・hash(`full` / `local` × 8・12・64 桁)の冪等性を確かめた。ファズテスト(`FuzzMaskStable`・`FuzzHashStable`・`FuzzRestoreRoundTrip`)は、既定 + uuid に加えて `--types default,aws` でも確かめるようにし、AWS の値の種を加えた。それぞれ 90 秒(約 209 万回・112 万回・158 万回)で違反なし。性能: 下のベンチマーク記録。README: 対応する種別・まとまり、EC2 のホスト名、AWS の署名、AWS の値の節、限界(仕様 4.3・4.4)、性能の表、変更点(既定の動作の変更)を書いた。`--help` の全体の説明にも AWS の値を加えた。DEVELOPMENT.md 2 章を v1.1 に合わせた |
| レビュー対応 | 完了 | 2026-10-17。オブジェクトキーの中の S3 のエンドポイント(`…amazonaws.com/s3.us-east-1.amazonaws.com/other`)もパス形式として読む動作を、仕様の条件どおりとして、テストで固定した。`aws.go` の小さな整理(ECR のマーカーのループの `break`、ドメインのバイト列を最初に 1 回作る `awsDomainBytes`、`dotsBuf` の大きさのコメント) |

### ベンチマーク記録

v1.0.0 の記録([v1.0.0/README.md](../v1.0.0/README.md) 6 章「ベンチマーク記録」)と同じ環境(AMD Ryzen 9 9950X、Docker コンテナ内、`GOMAXPROCS=2`)・同じ合成ログで測る。
「変更前」は、同じ日に、その段階の変更を外して測った値。

| 日付 | 段階 | 内容 | 結果 |
|---|---|---|---|
| 2026-10-16 | 2 | 参考: `BenchmarkFind`(既定の種別。署名の検出を追加) | 約 0.24 GB/s(変更前 約 0.244 GB/s) |
| 2026-10-16 | 2 | 参考: `BenchmarkSecretFinder` | 約 0.37 GB/s(変更前 約 0.40 GB/s) |
| 2026-10-16 | 3 | `BenchmarkFind`(既定の種別。EC2 のホスト名の検出を追加。手がかりは `ec2-` / `ip-` の `bytes.Index`) | 約 0.20 GB/s(変更前 約 0.24 GB/s。採用しない) |
| 2026-10-16 | 3 | `BenchmarkIPv4Finder`(同上) | 約 0.90 GB/s(変更前 約 2.3 GB/s) |
| 2026-10-16 | 3 | `BenchmarkFind`(手がかりを `-` の `bytes.IndexByte` + 手前の照合に変更。**本番**) | 約 0.23 GB/s(変更前より約 5% 遅い) |
| 2026-10-16 | 3 | `BenchmarkIPv4Finder`(同上) | 約 1.77 GB/s、割り当ては変更前と同じ(1 パスあたり約 9,500 回) |
| 2026-10-16 | 3 | **実バイナリ**: `logscrub mask < big.log > /dev/null`(合成ログ 100MB、3 回の最速。`cmd/logscrub/perf_test.go`) | 約 184 MB/s、最大メモリ 32 MB(v1.0.0 は約 195 MB/s) |
| 2026-10-16 | 3 | 実バイナリ: `cat big.log \| logscrub mask > /dev/null`(パイプ) | 約 167 MB/s、最大メモリ 30 MB(v1.0.0 は約 176 MB/s) |
| 2026-10-16 | 3 | 実バイナリ: `--types default,uuid` | 約 174 MB/s、最大メモリ 34 MB(v1.0.0 は約 182 MB/s) |
| 2026-10-17 | 4 | `BenchmarkAWSAccountFinder`(aws_account の検出器だけ。既定では無効) | 約 0.88 GB/s、割り当て 0 |
| 2026-10-17 | 4 | 参考: `BenchmarkFind`(既定の種別。段階 4 の変更は既定の種別に影響しない) | 約 0.20〜0.22 GB/s(段階 4 の変更を外しても同じ値。この日はマシンの状態で、段階 3 の記録より全体に約 5〜10% 遅かった) |
| 2026-10-17 | 5 | `BenchmarkAWSS3BucketFinder`(aws_s3_bucket の検出器だけ。既定では無効) | 約 1.7 GB/s、割り当て 0 |
| 2026-10-17 | 6 | `BenchmarkEngineMask`(既定の合成ログ 8MB を既定の種別で mask) | 約 0.19 GB/s(v1.0.0 は約 0.20 GB/s) |
| 2026-10-17 | 6 | `BenchmarkEngineMaskAWS`(AWS の値を含む合成ログ 8MB を `--types default,aws` で mask) | 約 0.135 GB/s、1 パスあたり約 40,000 回の割り当て(約 14MB) |
| 2026-10-17 | 6 | `BenchmarkFind`(既定の種別) | 約 0.23 GB/s |
| 2026-10-17 | 6 | **実バイナリ**: `logscrub mask < big.log > /dev/null`(合成ログ 100MB、3 回の最速) | 約 187 MB/s、最大メモリ 30 MB(v1.0.0 は約 195 MB/s) |
| 2026-10-17 | 6 | 実バイナリ: `cat big.log \| logscrub mask > /dev/null`(パイプ) | 約 167 MB/s、最大メモリ 32 MB(v1.0.0 は約 176 MB/s) |
| 2026-10-17 | 6 | 実バイナリ: `--types default,uuid` | 約 174 MB/s、最大メモリ 36 MB(v1.0.0 は約 182 MB/s) |
| 2026-10-17 | 6 | 実バイナリ: AWS の値を含む合成ログ 100MB、既定の種別 | 約 193 MB/s、最大メモリ 28 MB |
| 2026-10-17 | 6 | 実バイナリ: AWS の値を含む合成ログ 100MB、`--types default,aws` | 約 131 MB/s、最大メモリ 38 MB(目標 50MB/s 以上) |
| 2026-10-17 | 6 | 実バイナリ: 値の種類数 1,000 の合成ログ(20 / 50 / 100MB) | 最大メモリ 10.7 / 13.6 / 13.9 MB |
| 2026-10-17 | 6 | 実バイナリ: ほぼすべての値が異なる 100MB | 最大メモリ 31.8 MB |
| 2026-10-17 | 6 のあと | `aws_account` の手がかりを変更(ARN は `:` の `bytes.IndexByte` + 手前の `arn`。ECR・SQS は `.amazonaws.` を `z` の `bytes.IndexByte` で探し、手前を遡る)。`aws_s3_bucket` の `.amazonaws.` も同じ探し方に変更 | `BenchmarkAWSAccountFinder` 約 0.85 → 約 4.9 GB/s、`BenchmarkAWSS3BucketFinder` 約 1.7 → 約 3.1 GB/s |
| 2026-10-17 | 6 のあと | `BenchmarkEngineMaskAWS`(同上の変更後) | 約 0.135 → 約 0.168 GB/s |
| 2026-10-17 | 6 のあと | 実バイナリ: AWS の値を含む合成ログ 100MB、`--types default,aws`(同上の変更後) | 約 131 → 約 157 MB/s、最大メモリ 38 MB |
| 2026-10-17 | 6 のあと | 実バイナリ: 既定の種別(ファイルから / パイプ / `default,uuid`)。変更の影響なし | 約 188 / 168 / 177 MB/s |
