# logscrub 開発の資料: 性能目標のための前処理(3.4 節)

[開発の資料](../DEVELOPMENT.md)の 3.4 節の本文。コードや計画の「3.4 節」は、ここを指す。

## 3.4 性能目標(50MB/s)のための前処理

- 入出力: `bufio.Reader`(64KB)の `ReadSlice` で、改行までがバッファに収まる通常の行はコピーしない。`bufio.Writer` で書く。置換のない行は読んだスライスをそのまま書く
- 前処理: 各検出器が、自分の手がかりを `bytes.IndexByte` / `bytes.Index` で探し、なければ戻る(行ごとに 1 回の走査で作るヒントの集合は、段階 3 の測定で約 14 倍遅かったため採用しない)
  - email: `@` がある / IPv4: `.` と数字がある / IPv6: `:` がある / uuid: `-` があり、行の長さが 36 以上 / キー名ベース: `=` か `:` がある / 固定形式の secret: 接頭辞の中の文中に少ない 1 バイトを `bytes.IndexByte` で探す(v1.2 の段階 7 で変更。下の v1.2 の性能の改善)
  - v1.1 で加えた手がかり:
    - AWS の署名(secret): `=` を探し、手前の 9 バイトが `signature`(大文字・小文字を区別しない)か、さらに手前が `x-amz-` かを照合する
    - EC2 のホスト名の IPv4(ipv4): `-` を探し、手前が `ec2` / `ip`、後ろが数字のときだけ、正規表現を当てる
    - aws_account: ARN は `:` を探し、手前が `arn` か。ECR と SQS は `.amazonaws.` を手がかりにし、手前のリージョンを遡って、その手前が `.dkr.ecr` / `.dkr.ecr-fips` / `sqs` / `queue` かを見る
    - aws_s3_bucket: `s3://`・`s3a://`・`s3n://` は `://`、バーチャルホスト形式・パス形式は `.amazonaws.`、ARN は `:s3:::`(v1.2 の段階 8 で、`://` と `:s3:::` は `:` の 1 回の走査にまとめた)
    - `.amazonaws.` は、`amazonaws` の中の `z` を `bytes.IndexByte` で探してから前後を照合する(`nextAmazonaws`。aws_account と aws_s3_bucket で共用)
  - v1.2 で加えた手がかり:
    - aws_account(S3 Control): ECR と同じ経路。`.amazonaws.` の手前のリージョンを遡り、その手前が `accountHostMarkers`(`.dkr.ecr`、`.dkr.ecr-fips`、`.s3-control`、`.s3-control.dualstack`、`.s3-control-fips`、`.s3-control-fips.dualstack`)かを見る
    - aws_host: 末尾の形の終端(決まった語で終わる部分)ごとに、`hostHintRank` の順で選んだ文中に少ない 1 バイトを `bytes.IndexByte` で探し、前後を照合する。手がかりが同じ終端は 1 回の走査でまとめる。現在の走査は `z`(`.amazonaws.` と `.amazoncognito.com`)、`w`(`.on.aws`、`.ip.aws`、`.awsglobalaccelerator.com`、`.awsapprunner.com`)、`l`(`.cloudfront.net`、`.amplifyapp.com`、`.elasticbeanstalk.com`)の 3 回。手前の部品(リージョンと決まった語)は後ろから照合し、利用者ごとの部分は、英数字・`-`・`.` の続く範囲を遡る。遡った範囲は覚えておき(`hostRunCache`)、手がかりが続いても同じ範囲を遡り直さない(遡る長さの合計が行の長さ以内)
    - URL のパスワード(secret)と、email の除外: `@` を探し(email と同じ手がかり)、手前を遡って `<スキーム>://<ユーザー>:<パスワード>` の形かを調べる(`urlPasswordStart`)。遡る範囲は、手前の `@`・`/`・空白などで止まる。`://` や `:` を手がかりにしないのは、`:` が時刻などで文中に多いため
  - v1.2 の性能の改善(段階 7〜9。検出の結果は変えていない):
    - 固定形式の secret: 接頭辞を、手がかりのバイトごとのまとまり `fixedPrefixes` にした(`A`: `AKIA`・`ASIA`・`AIza`、`g`: `gh`・`github_pat_`、`x`: `xox`、`k`: `sk`・`rk`、`J`: `eyJ`)。まとまりごとに 1 回走査し、次の出現位置を覚える。変更前は 9 つの接頭辞を `bytes.Index` で探しており、`sk` の `s`、`rk` の `r` などで遅い経路になっていた
    - aws_s3_bucket: `://` と `:s3:::` を、`:` の `bytes.IndexByte` の 1 回の走査にまとめた(`colonForms`)
    - aws_host: 終端を `bytes.HasPrefix` で照合する前に、終端の先頭の `.` と、手がかりの次の 1 バイトを比べる(`hostTerminal.nextMatches`)。`l` のように文中に多めの手がかりでも、外れを早く捨てられる
    - 見送り: `.amazonaws.` の走査(`z`)と `:` の走査を、検出器の間で共有すること。共有しても減るのは数 % で、検出器の間で行ごとの前処理を共有する仕組み(上で採らなかった「行ごとのヒント」に近い)が要るため
  - v1.3 で加えたもの: `--deny`・`--domain` は手がかりを使わず、`literalMatcher` が全バイトを 1 回走査する(語の数によらず約 540 MB/s。`BenchmarkLiteralMatcher`)。語・ドメインを指定しなければ検出器を作らないので、既定の速度に影響しない。restore の `AnswerScanner` は、ラベルの先頭になりうるバイト(`start` の表)以外を読み飛ばす(全バイトで照合すると、`BenchmarkRestore` が約 218 → 49 MB/s に落ちた。表を使うと約 204 MB/s)
  - **手がかりの先頭の文字が、文中に多い文字(英小文字の `a` `e` `i` `s`、`.` など)の場合は、`bytes.Index` で探さない。**
    `bytes.Index` は、先頭の 1 バイトを `bytes.IndexByte` で探して照合する経路で始まり、外れが多いと、遅い汎用の経路に切り替わる。
    手がかりの中の、文中に少ない 1 バイト(`:` `-` `=` `z` など)を `bytes.IndexByte` で探してから、前後を照合する
    - v1.1 の実測(8MB の合成ログ、1 パスあたり): `ec2-` / `ip-` の `bytes.Index` は約 5 倍遅く、既定の種別の `BenchmarkFind` が約 15% 落ちた(段階 3)。
      aws_account は、`arn:`・`.dkr.ecr`・`sqs.`・`queue.amazonaws.com` の `bytes.Index` で約 9.4ms、上の方法で約 1.7ms(段階 6 のあとの改善)
    - v1.2 の実測(`BenchmarkAWSHostFinder`): 終端ごとに文中に少ない文字を選ぶと走査が 5 回(`z` `w` `f` `y` `k`)で約 1.73 GB/s、`f` に cloudfront.net と amplifyapp.com をまとめると 4 回で約 2.04 GB/s、`l` に 3 つの終端をまとめると 3 回で約 2.2 GB/s。走査の回数を減らすほうが、手がかりの一致の増加より効いた。文字の出現率は、合成ログとリポジトリの資料で確かめた(`z` 0.15〜0.3%、`w` 約 0.5〜0.7%、`l` 約 1.3〜1.6%)
    - v1.2 の性能の改善の実測(8MB の合成ログ): 固定形式の secret は、`BenchmarkSecretFinder` で約 342 → 578 MB/s(接頭辞ごとに走査すると約 479 MB/s。まとまりごとのほうが速い)、既定の `BenchmarkFind` で約 213 → 297 MB/s。aws_s3_bucket は約 3.1 → 4.8 GB/s、aws_host は約 2.23 → 3.0 GB/s。合成ログの文字の出現率は `:` 約 2%、`s` 約 5%、`k` 約 1.7%、`g` 約 0.35%、`A` 約 0.2%、`x` 約 0.15%(../plans/v1.2.0.md 3 章「性能の改善の調査」)
- 正規表現は「アンカーの周辺だけ」に当てる(例: email は最初の `@` のローカルパートの先頭から、キー名ベースは区切り文字の手前から)。1MB の 1 行でも、手がかりのない区間に正規表現を当てない。段階 3 の測定では、行全体に当てる場合の約 15 倍速かった
- メモリ割り当て: `Match` のスライス・出力バッファは再利用。map の参照は `m[string(b)]`(Go はこの形で割り当てしない)、新しい値のときだけ文字列を作る
- 計測: 段階 2 でベンチマーク(`b.SetBytes` で MB/s を出す)と合成ログ生成器を用意し、段階 3 以降は毎回測って実装計画(plans/)の進捗欄に記録する。合成ログの中身(一致を含む行の割合など)は → Q29
- それでも 50MB/s に届かない場合の手段: 遅い種別の正規表現を、手書きの走査に置き換える。その場合、元の正規表現版をテスト内に残し、ファズテストで結果が一致することを確認する(仕様 4 章「正規表現による形式の一致を基本とし」との関係を → **Q2** で確認)
