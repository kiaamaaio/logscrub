# logscrub の検出対象の詳細

[README.md](../README.md) の「検出対象」の補足です。限界は [LIMITATIONS.md](../LIMITATIONS.md) にまとめています。

## `secret` の対応形式

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
`passwd://…` のように `:` の直後が `//` の場合は、キー名ではなく URL のスキームとして扱います(パスワードがあれば、URL のパスワードとして置換します)。
値が `<スキーム>://<ユーザー>:<パスワード>@<ホスト>` の形で始まる場合(`password=postgres://app:s3cret@db/`)も、キー名ベースの値としては扱わず、パスワードの部分だけを置換します(`password=postgres://app:<secret_1>@db/`)。ユーザー情報のない URL(`token=https://hooks.example.com/…`)は、今までどおり値全体を置換します。

## AWS の値

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

## AWS のサービスのホスト名

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
| IoT Core | `.iot.<リージョン>.<ドメイン>`(AWS 共通の `data-ats.iot.…`・`api.tunneling.iot.…`・`data.tunneling.iot.…` は除く) |
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

## 指定した語(`custom`)

形式では判定できない会社名・案件名・社内のサービス名などを、語として指定します。`--deny`・`--deny-file` を指定すると、`custom` が対象に加わります(`--types` を指定していても加わります)。語だけを置換するなら `--types custom` と併用します。

```console
$ echo "Acme billing on acme-prod" | logscrub mask --deny acme
<custom_1> billing on <custom_2>-prod
```

- 英字の大文字・小文字は区別しません。ただし、綴りが違えば別のラベルになります(`restore` で元の綴りに戻すためです)。
- 語の端が英数字で、その外側も英数字の場合は、一致としません。`acme` は `acmerica`・`AcmeCorp` に一致せず、`acme-prod`・`acme_prod`・`acme.internal`・`Acmeの` に一致します。日本語の語は、前後を問わず一致します。
- 語は空白を含めます(`--deny "Acme Corp"`)。
- `--deny-file` は 1 行 1 語です。前後の空白、空行、`#` で始まる行は無視します。Windows のメモ帳で保存したファイル(BOM つき UTF-8、CRLF)も読めます。
- 語より長い値に含まれる場合は、その値全体が置換されます(`taro@acme.co.jp` は `<email_1>`)。
- `--allow` が優先します。`--deny acme --allow Acme` は、`Acme` だけを残して `ACME` を置換します。

`--deny` の値はシェルの履歴やプロセスの一覧に残るので、隠したい語は `--deny-file` で渡すことを勧めます。

## 指定したドメインのホスト名(`host`)

`--domain` で指定したドメインと、そのサブドメインのホスト名を、**全体を** `<host_N>` に置換します。ドメインそのもの(`example.co.jp`)も対象です。ホスト名ごとに別のラベルになるので、「同じ接続先か」は読めます。

```console
$ echo "curl https://internal.corp.example.co.jp/api" | logscrub mask --domain example.co.jp
curl https://<host_1>/api
```

- 大文字・小文字は区別しません。ただし、綴りが違えば別のラベルになります。
- `notexample.co.jp`、`example.co.jp.evil.org` は対象外です。
- 値は `example.co.jp` の形で指定します(`https://…`、`*.example.co.jp`、`.example.co.jp` はエラーです)。`--domain internal` のような 1 語も指定できます。
- メールアドレスは、`email` が有効なら全体が `<email_N>` になります。`email` を無効にすると `taro@<host_1>` になります。
- `--mode hash --email-hash local` は、ドメインを残します。ドメインに指定した語・ドメインを含むアドレスだけは、指定した値が残らないよう、全体をハッシュします(`email_<hex>`)。
