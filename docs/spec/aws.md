# logscrub 仕様: AWS の値(4.4、4.5)

[仕様の目次](../SPEC.md)。4 章の共通の規則は [detect.md](detect.md)、EC2 のホスト名に埋め込まれた IPv4 は [detect.md](detect.md) の 4.3、AWS の署名は [secret.md](secret.md) の 4.1 にある。

## 4.4 AWS の値(`aws_account`、`aws_s3_bucket`。v1.1 で追加)

AWS アカウント ID と S3 のバケット名は、秘密情報ではないが、組織を特定できる。ログを AI や他者に渡すときに隠したい値として扱う。
どちらも、**決まった形の中に現れたものだけ**を検出する(例: 12 桁の数字だけでは、タイムスタンプなどを大量に誤検出するため検出しない)。

共通:

- 既定では無効。`--types default,aws` のように指定した場合のみ対象にする(4 章「対象種別の指定」参照)
- 置換するのは値の部分だけ。前後の決まった部分(`arn:aws:iam::`、`.dkr.ecr.…`、`s3://` など)は残す
- 同じ値は、どの形に現れても同じラベルになる(値のバイト列で判定するため)
  - 例: `arn:aws:iam::123456789012:role/x` と `123456789012.dkr.ecr.…` の `123456789012` は、どちらも `<aws_account_1>`
- 対象のパーティション(ARN の 2 つ目の欄): `aws`、`aws-cn`、`aws-us-gov`、`aws-iso`、`aws-iso-b`、`aws-iso-e`、`aws-iso-f`、`aws-eusc`(AWS SDK の `partitions.json` で確認。2026-10-15)
- 対象のドメイン: `amazonaws.com`(`aws`、`aws-us-gov`)、`amazonaws.com.cn`(`aws-cn`)、`amazonaws.eu`(`aws-eusc`)
  - ISO リージョン(`aws-iso*`)のドメイン(`c2s.ic.gov` など)は対象外とし、ARN だけを対象にする
- ホスト名の中のリージョン(ECR、SQS、S3 のエンドポイント、EC2 のホスト名)は、英小文字・数字・`-` の 1 文字以上とする。`ap-northeast-1` のような実際の形には絞らない(新しいリージョンも拾うため。Q40)
- ホスト名の末尾のドメイン(ECR、S3 のバーチャルホスト形式)の後ろは、英数字・`-`・`_` でなく、「`.` + 英数字」でもないこと(4.3 の EC2 のホスト名と同じ。Q41)。ドメインは長いほうから照合する(`amazonaws.com.cn` を、`amazonaws.com` + `.cn` と読まない)
- 大文字・小文字を区別する。ARN・ホスト名・`s3://` などの決まった部分は、小文字の形だけを対象にする(Q42。4.1 の AWS の署名の語は、大文字・小文字を区別しない)
- `hash` の出力は `aws_account_<hex>`、`aws_s3_bucket_<hex>`。どちらも、値の形(12 桁の数字、バケット名に使える文字)に当てはまらないため、再度は検出されない

`aws_account`(AWS アカウント ID):

| 形 | 例 | 置換後(mask) |
|---|---|---|
| ARN | `arn:aws:iam::123456789012:role/deployer` | `arn:aws:iam::<aws_account_1>:role/deployer` |
| ECR のレジストリ | `123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/app:latest` | `<aws_account_1>.dkr.ecr.ap-northeast-1.amazonaws.com/app:latest` |
| SQS のキュー URL | `https://sqs.ap-northeast-1.amazonaws.com/123456789012/orders` | `https://sqs.ap-northeast-1.amazonaws.com/<aws_account_1>/orders` |
| S3 Control のホスト(v1.2 で追加) | `123456789012.s3-control.ap-northeast-1.amazonaws.com` | `<aws_account_1>.s3-control.ap-northeast-1.amazonaws.com` |

- ARN: `arn:` の前が英数字でないこと。`arn:<パーティション>:<サービス>:<リージョン>:<アカウント ID>:` の形で、アカウント ID の欄が 10 進数ちょうど 12 桁のときだけ置換する
  - サービスは英小文字・数字・`-` の 1 文字以上。リージョンは英小文字・数字・`-` の 0 文字以上(IAM などは空)
  - IAM ポリシーのワイルドカード(`arn:aws:ec2:*:123456789012:vpc/*`)のため、サービスとリージョンの欄には `*` も許す
  - アカウント ID の欄が空のもの(`arn:aws:s3:::bucket`)や、`aws` のもの(AWS 管理ポリシーの `arn:aws:iam::aws:policy/…`)は、置換しない
- ECR: 10 進数ちょうど 12 桁 + `.dkr.ecr.` または `.dkr.ecr-fips.` + リージョン + 対象のドメイン。12 桁の前が英数字・`-`・`_`・`.` でないこと
- SQS: ホストが `sqs.<リージョン>.<対象のドメイン>`、`<リージョン>.queue.amazonaws.com`、`queue.amazonaws.com` のいずれかで、その直後が `/` + 10 進数ちょうど 12 桁 + `/` であること。ホストの前が英数字・`-`・`_`・`.` でないこと
- S3 Control(v1.2 で追加): 10 進数ちょうど 12 桁 + `.s3-control.`・`.s3-control.dualstack.`・`.s3-control-fips.`・`.s3-control-fips.dualstack.` のいずれか + リージョン + 対象のドメイン。12 桁の前と、ドメインの後ろの条件は ECR と同じ

`aws_s3_bucket`(S3 のバケット名):

バケット名は、英小文字・数字・`.`・`-` からなる 3〜63 文字で、先頭と末尾が英小文字・数字、`.` が 2 つ続かず、IP アドレスの形(`192.168.5.4`)でないものとする(現在の命名規則。AWS のドキュメントで確認。2026-10-15)。IP アドレスの形は、数字 1 文字以上の組 4 つを `.` で区切った形とする(値の範囲は問わない。Q45)。

| 形 | 例 | 置換後(mask) |
|---|---|---|
| `s3://` 形式(`s3a://`、`s3n://` を含む) | `s3://my-bucket/logs/a.gz` | `s3://<aws_s3_bucket_1>/logs/a.gz` |
| バーチャルホスト形式 | `https://my-bucket.s3.ap-northeast-1.amazonaws.com/a.txt` | `https://<aws_s3_bucket_1>.s3.ap-northeast-1.amazonaws.com/a.txt` |
| パス形式 | `https://s3.ap-northeast-1.amazonaws.com/my-bucket/a.txt` | `https://s3.ap-northeast-1.amazonaws.com/<aws_s3_bucket_1>/a.txt` |
| ARN | `arn:aws:s3:::my-bucket/logs/*` | `arn:aws:s3:::<aws_s3_bucket_1>/logs/*` |

- S3 のエンドポイント(バーチャルホスト形式・パス形式で共通): `s3`、`s3.<リージョン>`、`s3-<リージョン>`(旧形式)、`s3.dualstack.<リージョン>`、`s3-fips.<リージョン>`、`s3-fips.dualstack.<リージョン>`、`s3-website-<リージョン>`、`s3-website.<リージョン>`、`s3-accelerate`、`s3-accelerate.dualstack` のいずれか + `.` + 対象のドメイン
- `s3://` 形式: `s3://`(`s3a://`、`s3n://`)の前が英数字でないこと。直後のバケット名を置換する
- バーチャルホスト形式: ホスト名の先頭から、`.` + S3 のエンドポイントの直前までを、バケット名として置換する(バケット名に `.` を含んでもよい)。ホスト名の前が英数字・`-`・`_`・`.` でないこと
  - 区切り方が 2 通り以上ある場合(`logs.s3.backup.s3.amazonaws.com` は、`logs` + `s3.backup` とも、`logs.s3.backup` + `s3` とも読める)は、エンドポイントをできるだけ後ろで取る(バケット名を最も長く取る)。そのバケット名が規則に合わない場合は、短い区切り方に戻らず、置換しない(Q43)
- パス形式: S3 のエンドポイント(前が英数字・`-`・`_`・`.` でないこと)の直後の `/` に続くバケット名を置換する
- ARN: `arn:<パーティション>:s3:::` の直後のバケット名を置換する。`arn:` の前が英数字でないこと(`aws_account` の ARN と同じ。Q46)
- どの形も、バケット名の後ろが、英数字(英大文字を含む)・`_`・`.`・`-` でないこと(旧形式のバケット名 `abc_def` の一部 `abc` だけを置換しないため。Q44)。バケット名の規則に合わない場合(長さ、文字種、先頭・末尾の文字)は、置換しない
  - `s3://`・パス形式・ARN で、バケット名の候補の末尾が `.` 1 つで、その後ろが上の条件を満たす場合は、末尾の `.` を文末の句点とみなして外す(`see s3://my-bucket.` の `my-bucket`。バケット名は `.` で終われないため。Q44)
- アクセスポイント(`*.s3-accesspoint.…`、`arn:aws:s3:<リージョン>:<アカウント ID>:accesspoint/…`)の名前は、バケット名ではないため対象外。ARN のアカウント ID は `aws_account` として置換される

限界: 利用者向けの説明は [LIMITATIONS.md](../../LIMITATIONS.md) の「AWS の値」が正本。この節の規則を変えたら、そちらも合わせて直す。

## 4.5 `aws_host`(AWS のサービスのホスト名。v1.2 で追加)

AWS のサービスのホスト名には、利用者ごとの部分(DB の名前、ロードバランサの名前、ランダムな ID など)が入る。設定によっては AWS の外からアクセスできるため、組織と接続先を特定できる値として扱う。
**下の表の「末尾の形」に一致するホスト名だけ**を検出し、ホスト名の先頭から末尾の形の直前まで(利用者ごとの部分)を、まとめて置換する。サービス名とリージョンは残す(調査で「どのサービスへの接続か」が分かるようにするため。決定事項 18)。

- 例: `mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com` → `<aws_host_1>.ap-northeast-1.rds.amazonaws.com`
- 既定では無効。まとまり `aws`・`cloud` に含まれる

| サービス | 末尾の形 | 例 |
|---|---|---|
| ELB(CLB、ALB) | `.<リージョン>.elb.<ドメイン>` | `my-alb-1234567890.ap-northeast-1.elb.amazonaws.com` |
| ELB(NLB、ALB) | `.elb.<リージョン>.<ドメイン>` | `my-nlb-0123456789abcdef.elb.ap-northeast-1.amazonaws.com` |
| API Gateway | `.execute-api.<リージョン>.<ドメイン>` | `a1b2c3d4e5.execute-api.ap-northeast-1.amazonaws.com` |
| Lambda 関数 URL | `.lambda-url.<リージョン>.on.aws` | `abcdefghij0123456789klmnop.lambda-url.ap-northeast-1.on.aws` |
| CloudFront | `.cloudfront.net` | `d111111abcdef8.cloudfront.net` |
| Global Accelerator | `.awsglobalaccelerator.com` | `a1234567890abcdef.awsglobalaccelerator.com` |
| EKS の API サーバ | `.<リージョン>.eks.<ドメイン>` | `0123456789ABCDEF0123456789ABCDEF.gr7.ap-northeast-1.eks.amazonaws.com` |
| RDS・Aurora・RDS Proxy | `.<リージョン>.rds.<ドメイン>` | `mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com` |
| Redshift | `.<リージョン>.redshift.<ドメイン>`、`.<リージョン>.redshift-serverless.<ドメイン>` | `my-cluster.c9akciq32.ap-northeast-1.redshift.amazonaws.com` |
| OpenSearch | `.<リージョン>.es.<ドメイン>`、`.<リージョン>.aoss.<ドメイン>` | `search-my-domain-abcdefghij.ap-northeast-1.es.amazonaws.com` |
| MSK | `.kafka.<リージョン>.<ドメイン>` | `b-1-public.my-cluster.abc123.c2.kafka.ap-northeast-1.amazonaws.com` |
| Amazon MQ | `.mq.<リージョン>.<ドメイン>`、`.mq.<リージョン>.on.aws` | `b-1234abcd-12ab-34cd-56ef-1234567890ab-1.mq.ap-northeast-1.amazonaws.com` |
| Transfer Family | `.server.transfer.<リージョン>.<ドメイン>` | `s-0123456789abcdef0.server.transfer.ap-northeast-1.amazonaws.com` |
| AppSync | `.appsync-api.<リージョン>.<ドメイン>`、`.appsync-realtime-api.<リージョン>.<ドメイン>` | `abcdefghijklmnopqrstuvwxyz.appsync-api.ap-northeast-1.amazonaws.com` |
| Cognito のドメイン | `.auth.<リージョン>.amazoncognito.com` | `my-app.auth.ap-northeast-1.amazoncognito.com` |
| IoT Core | `.iot.<リージョン>.<ドメイン>` | `a1b2c3d4e5f6g7-ats.iot.ap-northeast-1.amazonaws.com` |
| App Runner | `.<リージョン>.awsapprunner.com` | `abcdefghij.ap-northeast-1.awsapprunner.com` |
| Amplify Hosting | `.amplifyapp.com` | `main.d1a2b3c4d5e6f7.amplifyapp.com` |
| Elastic Beanstalk | `.<リージョン>.elasticbeanstalk.com`、`.elasticbeanstalk.com` | `my-env.ap-northeast-1.elasticbeanstalk.com` |
| EC2 のパブリックホスト名(IPv6・デュアルスタック) | `.<リージョン>.ip.aws` | `f5lnz-0khrm-nt2u3-gyqqt-nbdl5.ap-southeast-2.ip.aws` |

判定:

- `<ドメイン>` は 4.4 の対象のドメイン(`amazonaws.com`、`amazonaws.com.cn`、`amazonaws.eu`)。`<リージョン>` は、4.4 のホスト名の中のリージョンと同じ(英小文字・数字・`-` の 1 文字以上。Q40)
- 末尾の形の決まった部分は、小文字の形だけを対象にする(Q42)。末尾の形の後ろの条件は、4.4 のホスト名の末尾と同じ(Q41)
- 利用者ごとの部分: 英字(大文字・小文字)・数字・`-`・`.` からなる 1 文字以上で、先頭と末尾が英数字、`.` が 2 つ続かないこと。その前が、英数字・`-`・`_`・`.` でないこと
  - 英大文字を許すのは、EKS の ID のように、AWS が大文字で付ける値があるため(DNS の名前は大文字・小文字を区別しない)
- 利用者ごとの部分が次の名前そのものの場合は、検出しない(AWS 共通のエンドポイントで、利用者ごとの値ではないため)。IoT Core の `data-ats`(`data-ats.iot.us-east-1.amazonaws.com`)、`api.tunneling`・`data.tunneling`(Secure Tunneling の `api.tunneling.iot.us-east-1.amazonaws.com` など。[plans/v1.2.0.md](../plans/v1.2.0.md) Q61)。表の行ごとに持ち、必要な行にだけ加える。名前と完全に一致する場合だけ除く(`x.api.tunneling` や、Jobs の `<接頭辞>.jobs` は置換する)
- 1 つのホスト名に、複数の末尾の形が当てはまる場合(`.<リージョン>.elasticbeanstalk.com` と `.elasticbeanstalk.com`)は、長いほうの形を採る(利用者ごとの部分が短くなるほう)
- 置換するのは、利用者ごとの部分だけ。`dualstack.`(ELB)、`internal-`(内部向けの ELB)、アベイラビリティゾーンの接頭辞(NLB)なども、利用者ごとの部分に含める
- 同じ値の判定は、通常どおりバイト列で行う。`dualstack.my-alb-1234567890` と `my-alb-1234567890` は、別の値として扱う
- `hash` の出力は `aws_host_<hex>.ap-northeast-1.rds.amazonaws.com` のようになる。前が `_` のため利用者ごとの部分として読まれず、再度は検出されない

対象外:

- 4.3 の EC2 のホスト名(`ec2-…`、`ip-…`。`ipv4` として置換する)、4.4 の S3 のホスト名(`aws_s3_bucket`)、ECR・S3 Control のホスト名(`aws_account`)、SQS のホスト名(利用者ごとの部分がない)
- AWS のサービス自体の API のエンドポイント(`rds.ap-northeast-1.amazonaws.com`、`kafka.ap-northeast-1.amazonaws.com` など)。利用者ごとの部分がないため、表の形に当てはまらない
- VPC の中からしかアクセスできないサービス(ElastiCache、DocumentDB、Neptune、VPC エンドポイント `vpce-…` など)
- デュアルスタックのドメイン `api.aws` の形(`<ID>.<リージョン>.api.aws`)。AWS 自体の API のエンドポイント(`sqs.us-east-1.api.aws` など)と区別できないため
- 表にない新しい形: OpenSearch Serverless の NextGen(`<ID>.aoss.<リージョン>.on.aws`、`<アカウント ID>.aoss.<リージョン>.on.aws`)、Cognito の FIPS(`<接頭辞>.auth-fips.<リージョン>.amazoncognito.com`)。必要になったら、表に行を足すだけで追加できる

表の形は、2026-10-18 に AWS の公式ドキュメントで確認した([plans/v1.2.0.md](../plans/v1.2.0.md) Q47)。

範囲が重なった場合:

- `admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com` のように、ホスト名がメールアドレスの一部として読める場合は、長いメールアドレスが優先される(4 章「範囲が重なった場合」)。ホスト名は、メールアドレスのラベルの中に含まれて隠れる

限界: 利用者向けの説明は [LIMITATIONS.md](../../LIMITATIONS.md) の「AWS のサービスのホスト名(`aws_host`)」が正本。この節の規則を変えたら、そちらも合わせて直す。
