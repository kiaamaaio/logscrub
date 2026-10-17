# logscrub

ログやテキストに含まれる **メールアドレス・IP アドレス・トークン類(URL のパスワードを含む)・UUID・AWS の値(アカウント ID、S3 のバケット名、サービスのホスト名)** を、
種別が分かるラベル(`<email_1>`)またはハッシュ値に置き換える CLI です。
ログ調査の内容を AI に安全に渡すことを、主な用途としています。

```console
$ echo "taro@example.com 192.168.0.1 password=hunter2" | logscrub mask
<email_1> <ipv4_private_1> password=<secret_1>
```

- 標準入力 → 標準出力のパイプで使います(ファイルも指定できます)。
- 行単位のストリーム処理で、大きなログでもメモリを使い切りません。行の長さに上限はありません。
- 改行コード(LF / CRLF)、末尾改行の有無、置換した部分以外のバイト列は、1 バイトも変えません。
- 外部との通信は一切行いません。外部ライブラリも使いません(Go の標準ライブラリだけ)。

> **注意**: 検出は完全ではありません(正規表現による形式の一致が基本です)。
> 外部に出す前に、必ず出力を確認してください。見逃しや誤検出の例は、[限界](#限界)にまとめています。

## 使い方

### mask: ラベルに置き換える(既定)

同じ値には同じラベル、違う値には次の番号が付きます。番号は、入力の中で最初に現れた順です。

```console
$ cat app.log | logscrub mask | pbcopy        # AI に貼る
```

AI の回答に含まれるラベルは、`restore` で元の値に戻せます。対応表のファイルは作りません。
元の入力から、その場で対応を作り直します。

```console
$ pbpaste | logscrub restore --source app.log
```

`mask` に渡した入力を、パイプなどで絞り込んだ場合は、`restore` にも同じ内容を渡します。
bash / zsh なら、プロセス置換が使えます。

```console
$ grep ERROR app.log | logscrub mask | pbcopy
$ pbpaste | logscrub restore --source <(grep ERROR app.log)
```

**`restore` には、`mask` のときと同じ検出オプション**(`--types`、`--uuid-versions`、`--ip-scope`、
`--allow`、`--mask-format`)と、同じ入力を、同じ順で指定してください。違うと、連番がずれます。

### hash: 鍵つきのハッシュに置き換える

同じ値は、同じ鍵なら、常に同じ出力になります。別のマシンでも同じです。元には戻せません。
HMAC-SHA256 の先頭 12 桁(`--hash-length` で 8〜64)を使います。

```console
$ export LOGSCRUB_KEY=test-key      # 例では短い鍵。実際は、長いランダムな文字列にする(または --key-file FILE)
$ echo "taro@example.com 192.168.0.1" | logscrub mask --mode hash
email_99a207efd719 ipv4_private_dca2f4f38564
$ echo "taro@example.com" | logscrub mask --mode hash --email-hash local
hash_a746604745a4@example.com
```

### その他

```console
$ logscrub mask --types email app.log               # メールアドレスだけ
$ logscrub mask --types default,uuid app.log        # 既定の種別に UUID を加える
$ logscrub mask --types default,aws app.log         # 既定の種別に AWS の値(アカウント ID、バケット名、ホスト名)を加える
$ logscrub mask --uuid-versions 4,7 app.log         # UUID の v4 と v7 だけ(uuid も有効になる)
$ logscrub mask --ip-scope global app.log           # グローバルな IP だけ(内部アドレスは残す)
$ logscrub mask --allow support@example.com app.log # この値は置換しない(複数回指定できる)
$ logscrub mask --stats app.log                     # 種別ごとの件数を stderr に出す
$ logscrub mask --fail-on-detect app.log            # 1 件でも置換したら、終了コード 2
$ logscrub mask app.log -o masked.log               # ファイルに書く
$ logscrub types --verbose                          # 対応する種別と、secret の形式
```

オプションは、ファイル名の前後どちらにも書けます。`--` の後ろは、すべてファイル名として扱います。
ファイルを複数指定すると、順に連結した 1 つの入力として処理します(番号も通しです)。

## オプション

### `logscrub mask [FILE ...]`

| オプション | 説明 |
|---|---|
| `--mode mask\|hash` | `mask`(既定): ラベル。`hash`: ハッシュ(元に戻せない) |
| `--types LIST` | 対象の種別、または種別のまとまり(カンマ区切り)。指定した種別**だけ**が対象。`default` を含めると既定の種別が加わる([検出対象](#検出対象)) |
| `--uuid-versions 4,7` | 対象にする UUID のバージョン(1〜8)。これだけで `uuid` が対象に加わる |
| `--ip-scope all\|global\|private` | 置換する IP アドレスの範囲(既定 `all`) |
| `--allow VALUE` | 置換しない値(完全一致、複数回指定可) |
| `--mask-format FMT` | ラベルの書式。`{type}` と `{n}` をちょうど 1 回ずつ含める(既定 `<{type}_{n}>`) |
| `--email-hash full\|local` | hash モードのメールアドレス。`full`(既定): 全体、`local`: ローカルパートだけ |
| `--hash-length N` | hash モードの桁数(8〜64、既定 12) |
| `--key-file FILE` | hash モードの鍵のファイル(環境変数 `LOGSCRUB_KEY` より優先。末尾の改行 1 つは除く) |
| `--stats` | 置換した件数を、種別ごとに stderr に出す |
| `--fail-on-detect` | 1 件でも置換したら、終了コード 2 で終える(出力は通常どおり) |
| `-o`, `--output FILE` | 出力先のファイル(入力と同じファイルは指定できない) |

hash モード専用のオプション(`--hash-length`、`--email-hash`、`--key-file`)を、mask モードで指定するとエラーです。

### `logscrub restore --source FILE [--source FILE ...] [ANSWER_FILE]`

`ANSWER_FILE`(省略時は標準入力)のラベルを、元の値に戻します。`--source` は必須で、複数指定できます
(`mask` のときと同じ順に並べてください)。`--source -` は標準入力で、`ANSWER_FILE` を指定した場合だけ使えます。
検出オプションは `mask` と同じです。戻せなかったラベルは、そのまま残し、ラベル名(元の値は出しません)を
stderr に出します(終了コードは 0)。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 正常 |
| 1 | エラー(オプションの誤り、ファイルが開けない、書き込みの失敗、鍵の未設定など) |
| 2 | `--fail-on-detect` を指定して、置換があった(エラーのときは 1 が優先) |

## 検出対象

| 種別 | 内容 | 既定 |
|---|---|---|
| `email` | メールアドレス(TLD は英字 2 文字以上) | 有効 |
| `ipv4` / `ipv6` | IP アドレス。グローバルとプライベートを、ラベルで区別する(`<ipv4_global_1>`、`<ipv4_private_1>`) | 有効 |
| `secret` | トークン類(下の表) | 有効 |
| `uuid` | UUID(バージョン 1〜8) | 無効 |
| `aws_account` | AWS アカウント ID(ARN・ECR・SQS・S3 Control の中のもの。[AWS の値](#aws-の値)) | 無効 |
| `aws_s3_bucket` | S3 のバケット名(`s3://`・S3 の URL・ARN の中のもの。[AWS の値](#aws-の値)) | 無効 |
| `aws_host` | AWS のサービスのホスト名の、利用者ごとの部分(RDS、ELB、CloudFront など。[AWS のサービスのホスト名](#aws-のサービスのホスト名)) | 無効 |

`--types` には、種別名のほかに、次のまとまりを書けます。

| まとまり | 含まれる種別 |
|---|---|
| `default` | 既定で有効の種別(`email`、`ipv4`、`ipv6`、`secret`) |
| `aws` | `aws_` で始まる種別(`aws_account`、`aws_s3_bucket`、`aws_host`) |
| `cloud` | すべてのクラウドの種別(今は `aws` と同じ) |

例: `--types default,aws` は既定の種別と AWS の種別、`--types aws` は AWS の種別だけが対象です。
`logscrub types` で、種別とまとまりの一覧を確認できます。

IP アドレスのうち、`0.0.0.0`、`255.255.255.255`、`::`、マルチキャストは、隠す意味がないので置換しません。
プライベートは、RFC1918、ループバック、リンクローカル、`100.64.0.0/10`、IPv6 の ULA です。
IPv6 は、割り当て済みの範囲(`2000::/3`、`fc00::/7`、`fe80::/10`、`::1`、IPv4-mapped、NAT64)だけを検出します。

EC2 のホスト名に `-` 区切りで埋め込まれた IPv4 も、`ipv4` として置換します(既定で有効)。
IP アドレスだけを隠しても、ホスト名から元の値が読めてしまうためです。数値の部分だけを置換します。

| 形 | 例 | 置換後 |
|---|---|---|
| パブリック DNS | `ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com`、`ec2-54-250-1-2.compute-1.amazonaws.com` | `ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com` |
| プライベート DNS | `ip-10-0-1-23.ap-northeast-1.compute.internal`、`ip-10-0-1-23.ec2.internal` | `ip-<ipv4_private_1>.ap-northeast-1.compute.internal` |
| ドメインのない IP 名 | `ip-10-0-1-23`(シェルのプロンプト、Kubernetes のノード名など) | `ip-<ipv4_private_1>` |

### `secret` の対応形式

| 区分 | 形式 |
|---|---|
| AWS アクセスキー ID | `AKIA` / `ASIA` + 英大文字・数字 16 文字 |
| URL のパスワード | `<スキーム>://<ユーザー>:<パスワード>@<ホスト>` のパスワード部分(`postgres://app:s3cret@db-host/`、`redis://:s3cret@host`)。その形の `@` は、メールアドレスとして扱わない |
| AWS の署名(SigV4) | `X-Amz-Signature=` / `Signature=`(語は大文字・小文字を区別しない)の後ろの、小文字の 16 進数ちょうど 64 文字。署名付き URL と、`Authorization: AWS4-HMAC-SHA256 …, Signature=…` の署名。語と `=` は残す |
| GitHub | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` + 英数字 36 文字以上、`github_pat_` + 英数字・`_` 22 文字以上 |
| Slack | `xoxb-` `xoxp-` `xoxa-` `xoxr-` `xoxs-` + 英数字・`-` 10 文字以上 |
| Stripe | `sk_live_` `sk_test_` `rk_live_` `rk_test_` + 英数字 24 文字以上 |
| Google API キー | `AIza` + 英数字・`-`・`_` 35 文字 |
| `sk-` 形式の API キー | `sk-` + 英数字・`-`・`_` 20 文字以上 |
| JWT | `eyJ…` `.` `eyJ…` `.` `…` の 3 部構成 |
| Authorization ヘッダ | `Bearer <値>` / `Basic <値>` の値部分(`Authorization` などのキー名の値の位置に限る) |
| キー名ベース | `password` `passwd` `secret` `token` `api_key` `apikey` `access_key` `private_key` `client_secret` `access_token` `refresh_token` `auth_token` `session_id` の値(`key=value`、`key: value`、`"key": "value"`) |

キー名の照合は、大文字・小文字を区別せず、`-` `_` `.` と camelCase の境目を区切りとして、
キー名の末尾の単位で行います(`X-Auth-Token`、`DB_PASSWORD`、`accessToken` は対象。`max_tokens`、
`token_count`、`passwordless`、`PWD` は対象外)。値の部分だけを置換し、キー名・区切り・引用符は残します。
JSON などの文法を壊さないよう、キー名が引用符で囲まれている場合は、文字列の値だけを置換します。

### AWS の値

AWS アカウント ID と S3 のバケット名は、秘密情報ではありませんが、組織を特定できます。
**既定では無効**で、`--types default,aws` のように指定した場合だけ置換します。
どちらも、**決まった形の中に現れたものだけ**を検出し、値の部分だけを置換します。同じ値は、どの形でも同じラベルになります。

| 種別 | 形 | 例(置換後) |
|---|---|---|
| `aws_account` | ARN | `arn:aws:iam::<aws_account_1>:role/deployer` |
| `aws_account` | ECR のレジストリ | `<aws_account_1>.dkr.ecr.ap-northeast-1.amazonaws.com/app:latest` |
| `aws_account` | SQS のキュー URL | `https://sqs.ap-northeast-1.amazonaws.com/<aws_account_1>/orders` |
| `aws_account` | S3 Control のホスト | `<aws_account_1>.s3-control.ap-northeast-1.amazonaws.com` |
| `aws_s3_bucket` | `s3://`(`s3a://`、`s3n://`) | `s3://<aws_s3_bucket_1>/logs/a.gz` |
| `aws_s3_bucket` | バーチャルホスト形式 | `https://<aws_s3_bucket_1>.s3.ap-northeast-1.amazonaws.com/a.txt` |
| `aws_s3_bucket` | パス形式 | `https://s3.ap-northeast-1.amazonaws.com/<aws_s3_bucket_1>/a.txt` |
| `aws_s3_bucket` | ARN | `arn:aws:s3:::<aws_s3_bucket_1>/logs/*` |

- ARN のパーティションは `aws`、`aws-cn`、`aws-us-gov`、`aws-iso`、`aws-iso-b`、`aws-iso-e`、`aws-iso-f`、`aws-eusc`。
  ホスト名のドメインは `amazonaws.com`、`amazonaws.com.cn`、`amazonaws.eu` です(ISO リージョンのドメインは対象外)。
- `.s3-control.`・`.s3-control.dualstack.`・`.s3-control-fips.`・`.s3-control-fips.dualstack.` のホストも対象です。
- ARN のアカウント ID の欄が空のもの(`arn:aws:s3:::bucket`)や `aws` のもの(`arn:aws:iam::aws:policy/…`)は、置換しません。
- バケット名は、今の命名規則(英小文字・数字・`.`・`-` の 3〜63 文字など)に合うものだけを置換します。
- ARN・ホスト名・`s3://` などの決まった部分は、大文字・小文字を区別します(小文字の形だけが対象)。

### AWS のサービスのホスト名

AWS のサービスのホスト名には、DB の名前、ロードバランサの名前、ランダムな ID などの**利用者ごとの部分**が入ります。
設定によっては AWS の外からアクセスできるため、組織と接続先を特定できる値として扱います。
**既定では無効**です(`--types default,aws` または `--types aws_host`)。
下の表の**末尾の形に一致するホスト名だけ**を検出し、末尾の形より前(利用者ごとの部分)をまとめて置換します。
サービス名とリージョンは残るので、「どのサービスへの接続か」は読めます。

```console
$ echo "connect mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432" | logscrub mask --types aws_host
connect <aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432
```

| サービス | 末尾の形(`<リージョン>` はホスト名の中のリージョン、`<ドメイン>` は `amazonaws.com`・`amazonaws.com.cn`・`amazonaws.eu`) |
|---|---|
| ELB(CLB、ALB / NLB、ALB) | `.<リージョン>.elb.<ドメイン>` / `.elb.<リージョン>.<ドメイン>` |
| API Gateway | `.execute-api.<リージョン>.<ドメイン>` |
| Lambda 関数 URL | `.lambda-url.<リージョン>.on.aws` |
| CloudFront / Global Accelerator | `.cloudfront.net` / `.awsglobalaccelerator.com` |
| EKS(IPv4 のクラスタ) | `.<リージョン>.eks.<ドメイン>` |
| RDS・Aurora・RDS Proxy | `.<リージョン>.rds.<ドメイン>` |
| Redshift | `.<リージョン>.redshift.<ドメイン>`、`.<リージョン>.redshift-serverless.<ドメイン>` |
| OpenSearch | `.<リージョン>.es.<ドメイン>`、`.<リージョン>.aoss.<ドメイン>` |
| MSK / Amazon MQ | `.kafka.<リージョン>.<ドメイン>` / `.mq.<リージョン>.<ドメイン>`、`.mq.<リージョン>.on.aws` |
| Transfer Family | `.server.transfer.<リージョン>.<ドメイン>` |
| AppSync | `.appsync-api.<リージョン>.<ドメイン>`、`.appsync-realtime-api.<リージョン>.<ドメイン>` |
| Cognito のドメイン | `.auth.<リージョン>.amazoncognito.com` |
| IoT Core | `.iot.<リージョン>.<ドメイン>`(AWS 共通の `data-ats.iot.…` は除く) |
| App Runner / Amplify Hosting | `.<リージョン>.awsapprunner.com` / `.amplifyapp.com` |
| Elastic Beanstalk | `.<リージョン>.elasticbeanstalk.com`、`.elasticbeanstalk.com` |
| EC2 のパブリックホスト名(IPv6・デュアルスタック) | `.<リージョン>.ip.aws` |

- 利用者ごとの部分は、英字(大文字・小文字)・数字・`-`・`.` からなり、先頭と末尾が英数字、`.` が 2 つ続かないもの。
  その前が、英数字・`-`・`_`・`.` でないこと。`dualstack.`(ELB)、`internal-`(内部向けの ELB)なども、利用者ごとの部分に含めます。
- 末尾の形の決まった部分は、小文字の形だけが対象です。複数の形が当てはまる場合(`.<リージョン>.elasticbeanstalk.com` と `.elasticbeanstalk.com`)は、長いほうの形を採ります。
- AWS 自体の API のエンドポイント(`rds.ap-northeast-1.amazonaws.com`、`kafka.ap-northeast-1.amazonaws.com`)は、利用者ごとの部分がないので置換しません。
- EC2 のホスト名(`ec2-…`、`ip-…`)は `ipv4`、S3 のホスト名は `aws_s3_bucket`、ECR・S3 Control のホスト名は `aws_account` として置換されます(`aws_host` にはなりません)。
- `admin@mydb.….rds.amazonaws.com` のように、メールアドレスの一部として読めるホスト名は、長いメールアドレスが優先されます。
- 表の形は、2026-10-18 に AWS の公式ドキュメントで確認しました。

## 性質

- **決定的**: 同じ入力・同じオプションなら、常に同じ出力です。
- **冪等**: 置換済みの出力を、同じオプションで再度流しても変わりません(`<email_1>`、`password=<secret_1>`、
  hash の `email_<hex>` など)。置換済みの形のため置換せずに残した文字列があると、件数と行番号を stderr に
  1 行で知らせます(本物の値がたまたま同じ形だった場合に、気づくためです)。
- **値を出さない**: stderr やエラーメッセージに、置換対象の値(元の入力の中身)は出しません。

## 限界

検出は、形式の一致に基づく推定です。次の限界を理解したうえで使ってください。

**全般**

- 検出は完全ではありません。**外部に出す前に、出力を必ず確認してください。**
- 氏名・住所、画像・PDF・バイナリ、複数行にまたがる値(PEM 秘密鍵など)は、対象外です。
- 電話番号、郵便番号、クレジットカード番号、マイナンバー、base64 の文字列、任意の正規表現(`custom`)は、v1 の対象外です。
- 上記の形式に当てはまらない、独自形式のトークンは検出されません。

**メールアドレス**

- 引用符つきのローカルパート、国際化ドメイン(`user@例え.jp`)、非 ASCII のローカルパートは、対象外です。
- URL のユーザー情報にパスワードがある形(`https://user:pass@example.com/`)の `@` は、メールアドレスとして扱いません(パスワードは `secret` として置換します)。ユーザーだけの形(`https://taro@example.com/`)は、メールアドレスとして検出されます。

**IP アドレス**

- `version 1.2.3.4` のような、4 つ組のバージョン番号は、IP アドレスとして検出されます。
- 先頭が 0 の IPv4(`192.168.001.001`)は、検出されません。
- 割り当てのない範囲の IPv6(`::10.0.0.1` など)は、IPv6 としては検出されません(IPv4 部分は検出されます)。
  後ろが英字・`_` とつながった IPv6(`2001:db8::1xyz`)は、アドレスとして扱いません。
- `2001::x` のように、割り当て済みの範囲の形をしたコードの記号は、IPv6 として検出されることがあります。
- ホスト名に埋め込まれた IPv4 は、`54-250-1-2` と `54.250.1.2` を別の値として扱います(同じアドレスでも、
  別のラベルになります。`restore` で 1 バイトも違わずに戻すためです)。
- EC2 のパブリックホスト名の IPv6 形式・デュアルスタック形式(`….ip.aws`)は、`aws_host` で置換します(`ipv4` や `ipv6` としては扱いません)。

**secret**

- 引用符なしの値は、空白・`&` `,` `;` `}` `]` `)` `"` `'` で終わります。空白を含む値
  (`password: my secret phrase`)は、最初の語だけが置換されます。
- JSON の数値だけのトークン(`"pin": 123456`)は、文法を壊さないため、置換されません。
- 文章中の `token: expired` の `expired` のように、キー名の後ろの語が置換されることがあります。
- `session_id=<UUID>` のように、キー名の値が UUID の場合は、`<uuid_N>` でなく `<secret_N>` になります。
- URL のパスワードは、`<スキーム>://<ユーザー>:<パスワード>@<ホスト名の文字>` の形のときだけ検出します。空白・`/`・`?`・`#`・`@` を含むパスワード(URL エンコードされていないもの)は、その手前までになるか、検出されません。`secret` を無効にして `email` だけを指定すると、パスワードは置換されずに残ります(その `@` は、メールアドレスとして扱いません)。

**AWS の値**

- 決まった形の外に現れた値は検出しません(例: `account_id=123456789012`、CloudTrail の `"accountId"`、
  `bucket=my-bucket`、`"bucketName": "my-bucket"`)。同じ値が決まった形の中と外の両方にあると、外の値から元の値が読めます。
- 旧形式のバケット名(2018 年 3 月 1 日より前に us-east-1 で作られた、英大文字・`_` を含むもの、64 文字以上のもの)は検出しません。
- アカウントのリージョン別の名前空間のバケット名(`<名前>-<アカウント ID>-<リージョン>-an`)は、アカウント ID を含みます。
  `aws_s3_bucket` を無効にして `aws_account` だけを有効にした場合、バケット名の中のアカウント ID は置換されません。
- ARN のリソース名(ロール名、ユーザー名など)や、`AROA…`・`AIDA…` などの一意 ID は置換しません。

**AWS のサービスのホスト名(`aws_host`)**

- 独自のドメイン(Route 53 の CNAME などで付けた `db.example.com`)は検出しません。
- `dualstack.` などの接頭辞の有無で、同じロードバランサが別のラベルになります(`dualstack.my-alb-1234567890` と `my-alb-1234567890` は別の値)。
- 表にないサービスのホスト名は検出しません。VPC の中からしかアクセスできないサービス(ElastiCache、DocumentDB、Neptune、VPC エンドポイント)、
  EKS の IPv6 のクラスタ(`<ID>.<リージョン>.api.aws`。AWS 自体の API のエンドポイントと区別できないため)、
  OpenSearch Serverless の NextGen(`….aoss.<リージョン>.on.aws`)、Cognito の FIPS(`….auth-fips.<リージョン>.amazoncognito.com`)も対象外です。
- `<ドメイン>` は `amazonaws.com`、`amazonaws.com.cn`、`amazonaws.eu` の 3 つです。公式ドキュメントで実在を確認できたのは `amazonaws.com` の形だけで、
  中国リージョンなどのホスト名(EKS の `amazonwebservices.com.cn` など)は、検出されないことがあります。

**UUID**

- 既定では無効です(リクエスト ID・トレース ID の場合もあるため)。ハイフン無しの 32 桁は、対象外です。

**restore**

- 元の入力が手元にない、または、`mask` のあとに書き換えられていると、戻せません
  (追記だけなら、追記前のラベルは戻ります)。
- 検出オプションや入力の順が `mask` と違うと、連番がずれ、**別の値に戻ることがあります**
  (対応のないラベルは、そのまま残り、stderr に出ます)。
- 元の入力に、もともとラベルと同じ形の文字列(`<email_1>` など)があると、正しく戻らないことがあります
  (そのような文字列があると、stderr に通知します)。
- AI が回答の中でラベルを書き換えた場合(`\<email_1\>`、`&lt;email_1&gt;`、`email_1` のように括りを外すなど)は、
  戻せません。
- hash モードの出力は、戻せません。

**hash**

- 鍵を失うと、同じ出力を再現できません。鍵を知らない人は、元の値を推測できません(HMAC-SHA256)が、
  鍵は秘密にして、共有する相手を限ってください。
- 本物の値が、たまたま `<種別>_<12 桁の小文字 16 進数>`(例: `secret_3f9a1c0b7d2e`)と同じ形だと、
  置換されません(上記の通知で気づけます)。

**冪等性**

- 値を置換した結果、隣の文字列とのつながりが変わり、2 回目に、新しい値が検出されることがあります
  (例: `000000A10.0.0.0fC00::` は、1 回目に `10.0.0.0` だけが置換され、2 回目に `fC00::` が検出されます)。
  置換済みのラベルを再度置換することは、ありません。

## 性能

目標は 50MB/s 以上です。実測は次のとおりです(合成ログ 100MB を、ビルドしたバイナリで処理)。

| 実行 | 速度 | 最大メモリ |
|---|---|---|
| `logscrub mask < big.log > /dev/null` | 約 184 MB/s | 30 MB |
| `cat big.log \| logscrub mask > /dev/null` | 約 165 MB/s | 32 MB |
| 同上(`--types default,uuid`) | 約 173 MB/s | 32 MB |
| AWS の値(ホスト名、URL のパスワードを含む)を含む合成ログを `--types default,aws` で | 約 138 MB/s | 36 MB |
| 同上(`aws_host` なし: `--types default,aws_account,aws_s3_bucket`) | 約 159 MB/s | 30 MB |

- **メモリ**: 対応表(検出した値の種類数に比例)が主です。値の種類数が一定(1,000 種類)なら、入力が
  20MB でも 100MB でも、最大 14MB ほどで変わりません。ほぼすべての値が異なる 100MB のログでは、29.9MB でした。
- **測定条件**: 合成ログ(1 行 200 バイト前後、約 30% の行に検出対象があり、1MB の JSON を 1 行で数行含む)、
  既定の種別、mask モード。AMD Ryzen 9 9950X、WSL2 上の Docker コンテナ(`golang:1.27.2`、2 CPU)内で測定し、
  3 回のうちの最速の値です。実際のログでは、検出対象の割合や行の長さで変わります。
- **再現**: `./scripts/go test -run Perf -v ./cmd/logscrub -perf`(`-perf-size 100` で大きさを指定)。

速度のために、正規表現を当てる前に、行の中に手がかり(`@`、`.` `:` と数字の並び、トークンの接頭辞、
`=` `:`、ハイフンの並び、`arn:`・`.amazonaws.` など)があるかを確かめて、ほとんどの行では正規表現を使いません。

## 開発

Go の操作は、開発環境に依存しないよう、すべて Docker コンテナ(`golang:1.27.2`)の中で行います。
ラッパー `scripts/go` が、引数をそのまま `go` に渡します(ネットワークなし、ホストのユーザーで実行)。

```console
$ ./scripts/go test ./...
$ ./scripts/go vet ./...
$ ./scripts/go build -o bin/logscrub ./cmd/logscrub
```

| パス | 内容 |
|---|---|
| `cmd/logscrub` | 入口(`cli.Run` を呼ぶだけ)。性能・メモリの測定テストもここ |
| `internal/cli` | サブコマンド、オプションの解析、入出力、終了コード |
| `internal/detect` | 種別ごとの検出と、範囲の重なりの解決、置換済みの値の除外 |
| `internal/transform` | mask / hash / restore と、行の書き換え(Engine)、統計。`testdata/` に、サンプルログと、手で確認した期待値 |
| `internal/label` | ラベルの書式と、hash 出力形の走査 |
| `internal/stream` | 行単位の入出力(改行コードの保持) |
| `internal/synthlog` | 性能測定用の合成ログの生成器(AWS の値を含める設定あり) |

仕様は [docs/SPEC.md](docs/SPEC.md)、開発環境・構成・設計の注意点は [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)、版ごとの実装計画と進捗・判断の記録は [docs/plans/](docs/plans/) にあります。

## 変更点

### v1.2.0

- **既定の動作が変わります**(どちらも、今まで隠せていなかった値を隠す方向の変更です)。
  - **URL のパスワード**(`<スキーム>://<ユーザー>:<パスワード>@<ホスト>`)を `secret` に加えました。
    あわせて、その形の `@` は、メールアドレスとして扱わなくなりました。
    - v1.1 まで: `postgres://app:s3cret@db.example.com/` は `postgres://app:<email_1>/` になり(ホスト名の情報が消えます)、
      `https://user:pass@10.0.0.1/` はパスワードが**そのまま残って** `https://user:pass@<ipv4_private_1>/` になっていました。
    - v1.2 から: それぞれ `postgres://app:<secret_1>@db.example.com/`、`https://user:<secret_1>@<ipv4_private_1>/` になります。
    - `secret` の `<secret_N>` の番号が、URL のパスワードの分だけ増えることがあります。`restore` は、`mask` と同じバージョンで使ってください。
- AWS のサービスのホスト名の種別 `aws_host` を加えました(既定では無効。[AWS のサービスのホスト名](#aws-のサービスのホスト名))。まとまり `aws`・`cloud` に含まれます。
- `aws_account` に、S3 Control のホスト(`<12 桁>.s3-control.<リージョン>.amazonaws.com`)のアカウント ID を加えました。
- EC2 のパブリックホスト名の IPv6 形式・デュアルスタック形式(`….ip.aws`)を、`aws_host` で置換するようになりました。
- `logscrub types` の出力と `--stats` の並びに、`aws_host` が加わりました。

### v1.1.0

- **既定の動作が変わります**(どちらも、今まで隠せていなかった値を隠す方向の変更です)。
  - `secret` に、AWS の署名(SigV4。署名付き URL の `X-Amz-Signature=` と、`Authorization: AWS4-HMAC-SHA256 …, Signature=`)を加えました。
  - EC2 のホスト名に埋め込まれた IPv4(`ec2-54-250-1-2.…`、`ip-10-0-1-23`)を、`ipv4` として置換するようになりました。
- AWS の値の種別 `aws_account`、`aws_s3_bucket` を加えました(既定では無効。[AWS の値](#aws-の値))。
- `--types` に、種別のまとまり `aws`、`cloud` を書けるようになりました。
- `logscrub types` の出力に、クラウドごとの見出しと、まとまりの一覧を加えました(列の幅も変わりました)。

## ライセンス

[MIT License](LICENSE)
