# logscrub v1.2.0 未確定事項(前半)

[計画](../v1.2.0.md)へ戻る。

## 5. 未確定事項

推測では埋めず、回答をもらってから該当する段階に入る。「案」は判断材料としての提案で、仕様書には案のとおりに書いてある。採用は回答後。
番号は v1.1.0 の計画(Q32〜Q46)から続ける。

**2026-10-17: Q47〜Q54 はすべて確定。2026-10-18: Q55〜Q59 も確定(推奨案)。** Q48 は「v1.2 に含める」(仕様 4.1、決定事項 20 に反映)。それ以外は案どおり。

- **Q47(ホスト名の形の確認)** 仕様 4.5 の表の 20 の形のうち、計画の作成時(2026-10-17)に公式ドキュメントで確認できたのは、ELB(NLB の `.elb.<リージョン>.` と、ALB・CLB の `.<リージョン>.elb.`)、EKS(`<ID>.<リージョン>.eks.amazonaws.com`。ID とリージョンの間に `gr7` のような短いラベルが入る例がある)、EC2 の `.ip.aws` だけ。MSK は `-public` の付いたブローカー名があることまで確認した。Amazon MQ・Redshift Serverless は、公式の形を確認できていない
  - 案: 段階 1 で、残りの形を公式ドキュメント(または AWS SDK のエンドポイントの定義)で確認する。確認できなかった形は、表から外すか、確認できた範囲に絞る(精度重視の方針。決定事項 16)
  - なお、「末尾の形より前をまとめて置換する」規則なので、確認が必要なのは**末尾の形だけ**で、利用者ごとの部分の細かい形(EKS の `gr7` のようなラベルなど)は確認しなくてよい
  - **段階 1 の確認結果(2026-10-18)**: 表の 20 の形を AWS 公式ドキュメント(docs.aws.amazon.com)で確認した。「○」は表と一致、「差」は Q55〜Q59 に記載。出典は、記載のページ(docs.aws.amazon.com/ 以下)
    - ○ NLB: `<名前>-<ID>.elb.<リージョン>.amazonaws.com`(`elasticloadbalancing/latest/network/network-load-balancers.html`。AZ 接頭辞 `us-east-2b.…` の例もある)
    - ○ CLB: `<名前>-<数字>.<リージョン>.elb.amazonaws.com`(`elasticloadbalancing/latest/classic/elb-internet-facing-load-balancers.html`)
    - 差 ALB: ALB のガイドは `<名前>-<ID>.elb.<リージョン>.amazonaws.com` と書いている(`elasticloadbalancing/latest/application/application-load-balancers.html`)→ Q55
    - ○ API Gateway: `<ID>.execute-api.<リージョン>.amazonaws.com`(`apigateway/latest/developerguide/how-to-call-api.html`)
    - ○ AppSync: `<ID>.appsync-api.<リージョン>.amazonaws.com`、`<ID>.appsync-realtime-api.<リージョン>.amazonaws.com`(`appsync/latest/devguide/real-time-websocket-client.html`)
    - ○ Lambda 関数 URL: `<URL ID>.lambda-url.<リージョン>.on.aws`(`lambda/latest/dg/urls-configuration.html`)
    - ○ CloudFront: `d111111abcdef8.cloudfront.net`(`AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-returned.html`)
    - ○ Global Accelerator: `a1234567890abcdef.awsglobalaccelerator.com`。デュアルスタックは `a1234567890abcdef.dualstack.awsglobalaccelerator.com`(末尾の形は同じで、`dualstack` は利用者ごとの部分に入る)(`global-accelerator/latest/dg/dns-addressing-custom-domains.dns-addressing.html`)
    - ○ EKS(IPv4 のクラスタ): `<名前>.<リージョン>.eks.amazonaws.com`(`eks/latest/userguide/cluster-endpoint.html`)。IPv6 のクラスタ(2024 年 10 月以降)は `.<リージョン>.api.aws` で、Q50 のとおり対象外。中国リージョンは `amazonaws.com.cn` でなく `amazonwebservices.com.cn` と書かれている → Q58
    - ○ RDS・Aurora: `<名前>.<ID>.<リージョン>.rds.amazonaws.com`(`AmazonRDS/latest/UserGuide/USER_ConnectToInstance.EndpointAndPort.html`)。RDS Proxy も `<リージョン>.rds.amazonaws.com` で終わる(`AmazonRDS/latest/UserGuide/rds-proxy-endpoints.html`)
    - ○ Redshift: `<クラスタ>.<ID>.<リージョン>.redshift.amazonaws.com`(`redshift/latest/mgmt/jdbc20-obtain-url.html`)。Serverless は `<ワークグループ>.<アカウント ID>.<リージョン>.redshift-serverless.amazonaws.com`(`redshift/latest/mgmt/serverless-connecting.html`)
    - ○ OpenSearch: `search-<名前>-<ID>.<リージョン>.es.amazonaws.com`(`opensearch-service/latest/developerguide/createupdatedomains.html`)。Serverless(Classic)は `<ID>.<リージョン>.aoss.amazonaws.com`(`opensearch-service/latest/developerguide/serverless-collection-endpoints.html`)。同ページの NextGen は `<ID>.aoss.<リージョン>.on.aws` → Q59
    - ○ MSK: `b-1.<名前>.<ID>.c2.kafka.<リージョン>.amazonaws.com`、パブリックは `b-1-public.…`(`msk/latest/developerguide/get-bootstrap-cli.html`。例は `kafka-beta` で、これは例の値)
    - 差 Amazon MQ: `<ブローカー ID>.mq.<リージョン>.amazonaws.com` は一致。ほかに `<ブローカー ID>.mq.<リージョン>.on.aws`(デュアルスタック。ActiveMQ は非対応)がある(`amazon-mq/latest/developer-guide/connect-to-amazonmq.html`)→ Q56
    - ○ Transfer Family: `<サーバー ID>.server.transfer.<リージョン>.amazonaws.com`(`transfer/latest/userguide/api-welcome.html`)
    - ○ Cognito: `<接頭辞>.auth.<リージョン>.amazoncognito.com`(`cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html`)。同ページに `auth-fips` の形がある → Q59
    - 差 IoT Core: `<接頭辞>-ats.iot.<リージョン>.amazonaws.com` は一致。ただし AWS 共通のエンドポイント `data-ats.iot.<リージョン>.amazonaws.com` も表の形に当てはまる(`general/latest/gr/iot-core.html`)→ Q57
    - ○ App Runner: `<ID>.<リージョン>.awsapprunner.com`(`cli/latest/reference/apprunner/associate-custom-domain.html` の `DNSTarget` の例)
    - ○ Amplify Hosting: `<ブランチ>.<アプリ ID>.amplifyapp.com`(`amplify/latest/userguide/custom-domains.html`)
    - ○ Elastic Beanstalk: `<名前>.<リージョン>.elasticbeanstalk.com`(`elasticbeanstalk/latest/dg/customdomains.html`)。リージョンなしの `.elasticbeanstalk.com` は、2016 年初めより前の環境の形(`Route53/latest/DeveloperGuide/routing-to-beanstalk-environment.html`)
    - ○ EC2 の `.ip.aws`: IPv6 は `f5lnz-0khrm-nt2u3-gyqqt-nbdl5.ap-southeast-2.ip.aws`、デュアルスタックは末尾に IPv4 の符号が付く(`AWSEC2/latest/UserGuide/hostname-types.html`)。IPv4 の名前は `ec2-….<リージョン>.compute.amazonaws.com` で、表のとおり対象外
    - 確認していない点: `<ドメイン>` を取る形で、`amazonaws.com.cn`・`amazonaws.eu` との組み合わせがサービスごとに実在するか → Q58。App Runner・Amplify は、AWS CLI の例・ガイドの例に基づく(専用の「形」の説明ページは見つからなかった)
- **Q48(DB の接続 URL のパスワード)** 計画の作成時に、v1.1.0 で次の動作を確認した。
  - `postgres://app:s3cret@mydb.cluster-….rds.amazonaws.com:5432/app` → `postgres://app:<email_1>:5432/app`
  - 既存のメールアドレスの規則で、`s3cret@<ホスト名>` 全体がメールアドレスとして置換される。パスワードは結果として隠れているが、種別が誤っており、`aws_host` を有効にしても RDS のホスト名だという情報が消える。また、ホスト名が IP アドレスの場合(`https://user:pass@10.0.0.1/`。v1.0 の受け入れ基準)は、**パスワードがそのまま残る**
  - 案: v1.2 の範囲に入れる。`secret` に「URL のユーザー情報のパスワード」(`<スキーム>://<ユーザー>:<パスワード>@`)を加え、その形のときは `@` の前後をメールアドレスとして扱わない。結果は `postgres://app:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app` になる。ただし、`secret`・`email` は既定で有効の種別なので、**既定の動作が変わる**(v1.1 の署名と同じく、隠せていなかった値を隠す方向の変更)
  - 別案: v1.2 では扱わず、別の版にする(v1.2 は「着手順 5 のみ」という当初の範囲を守る)。その場合、README の限界に書く
  - **回答(2026-10-17)**: v1.2 に含める
- **Q49(VPC の中からしかアクセスできないサービス)** ElastiCache(`.cache.amazonaws.com`)、DocumentDB、Neptune、VPC エンドポイントのホスト名も、組織を特定できる値で、形も決まっている。
  - 案: v1.2 では対象外とする(当初の範囲「設定によって AWS の外からアクセスできるもの」を守る)。必要になった時点で、表に行を足すだけで追加できる
- **Q50(`api.aws` の形)** EKS の IPv6 のクラスタは `<ID>.<リージョン>.api.aws` という形のエンドポイントを使う。一方 `api.aws` は、AWS 自体の API のデュアルスタックのエンドポイント(`sqs.us-east-1.api.aws` など)にも使われ、末尾の形だけでは区別できない。
  - 案: 対象外とする(仕様 4.5「対象外」)。README の限界に書く
- **Q51(接頭辞の扱い)** `dualstack.`(ELB)、`internal-`(内部向けの ELB)、アベイラビリティゾーンの接頭辞(NLB の `us-east-2a.`)を、利用者ごとの部分に含めるか、外して残すか。
  - 案: 含める(仕様 4.5)。外すと、サービスごとに接頭辞の表が必要になり、規則が複雑になる。同じロードバランサが接頭辞の有無で別のラベルになる点は、README の限界に書く
- **Q52(利用者ごとの部分の英大文字)** v1.1 の Q42 では「決まった部分は小文字だけ」とした。利用者ごとの部分は、EKS の ID のように AWS が大文字で付ける値がある。
  - 案: 利用者ごとの部分は英大文字を許す(仕様 4.5)。決まった部分(末尾の形)は、Q42 のとおり小文字だけ
- **Q53(S3 Control と EC2 の `.ip.aws` を v1.2 に入れること)** v1.1 の Q38 で「v1.2 で検討する」とした 3 つの候補のうち、S3 Control のホスト(`aws_account`)と EC2 の `.ip.aws`(`aws_host`)を入れ、アカウントのリージョン別の名前空間のバケット名の中のアカウント ID は入れない。
  - 案: 上のとおり(仕様 4.3〜4.5)。バケット名の中のアカウント ID は、バケット名の文脈の中だけで判定する必要があり、`aws_s3_bucket` を有効にすれば名前ごと隠れるため、v1.1 のまま README の限界として扱う

- **Q54(`secret` が無効なときのメールアドレスの除外)** `--types email` のように `secret` を無効にした場合も、`<スキーム>://<ユーザー>:<パスワード>@<ホスト>` の `@` をメールアドレスとして扱わないか。
  - 案: 扱わない(2.4 節)。メールアドレスの判定が、他の種別の有効・無効で変わると分かりにくいため。その場合、`--types email` ではパスワードが残る(`secret` を無効にした利用者の選択どおり)
  - **回答(2026-10-17)**: 案どおり。仕様 4.1 に反映した

段階 1(2026-10-18)で見つかった問題。**Q55〜Q59 はすべて推奨案で確定(2026-10-18)。仕様 4.5 と 9 章に反映した。**

- **Q55(ALB の形)** ALB のガイドは、ALB の DNS 名を `<名前>-<ID>.elb.<リージョン>.amazonaws.com`(NLB と同じ形)と書いている。表は ALB・CLB を `.<リージョン>.elb.<ドメイン>` としている。CLB のガイドは表のとおり。
  - 問題点: 公式の記述の間で食い違っており、ALB の実際の形を公式ドキュメントだけでは確定できない(ALB の形は実際には `.<リージョン>.elb.` と思われるが、ガイドの記述は違う)
  - 案: 表は変えない。ELB の行は「形」だけで決まり、`.elb.<リージョン>.` と `.<リージョン>.elb.` の両方が表にあるので、ALB がどちらの形でも検出は変わらない。仕様の「サービス」の欄を「ELB(CLB、ALB)」「ELB(NLB、ALB)」のように直すかどうかだけ決めたい(検出には影響しない)
  - **回答(2026-10-18)**: 案どおり(表は変えない。サービス欄を「ELB(CLB、ALB)」「ELB(NLB、ALB)」に直した)
- **Q56(Amazon MQ の `.on.aws` の形)** 公式ドキュメントに `<ブローカー ID>.mq.<リージョン>.on.aws`(デュアルスタック。RabbitMQ のみ)がある。表は `.mq.<リージョン>.<ドメイン>` だけで、`on.aws` を取らない。
  - 問題点: 確認できた公式の形が、表から漏れている
  - 案 A(推奨): 表に `.mq.<リージョン>.on.aws` を加える。Lambda 関数 URL ですでに `on.aws` を扱うので、表に 1 行足すだけで済む
  - 案 B: 加えない。README の限界に書く
  - **回答(2026-10-18)**: 案 A(表に `.mq.<リージョン>.on.aws` を加えた)
- **Q57(IoT Core の AWS 共通エンドポイント)** `data-ats.iot.<リージョン>.amazonaws.com` は AWS 共通のエンドポイントで、利用者ごとの部分がない。しかし表の形 `.iot.<リージョン>.<ドメイン>` に当てはまり、`data-ats` が利用者ごとの部分として置換される(`<aws_host_1>.iot.us-east-1.amazonaws.com`)。
  - 問題点: 精度重視の方針(決定事項 16)に反する誤検出。`data.iot-fips.…`、`<接頭辞>.credentials.iot.…` は影響しない
  - 案 A(推奨): 表の行に「利用者ごとの部分として扱わない名前」(IoT は `data-ats`)を持てるようにする。表(データ)の枠組みは変えず、特殊処理を増やさない
  - 案 B: 誤検出を許容し、README の限界に書く
  - 案 C: IoT Core を表から外す
  - **回答(2026-10-18)**: 案 A(表の行に「利用者ごとの部分として扱わない名前」を持たせ、IoT は `data-ats`)
- **Q58(`<ドメイン>` の組み合わせ)** 公式ドキュメントで実在を確認できたのは `amazonaws.com` の形だけ。EKS の中国リージョンは `amazonaws.com.cn` ではなく `amazonwebservices.com.cn` と書かれている。`amazonaws.com.cn`・`amazonaws.eu` との組み合わせが各サービスで実在するかは確認できなかった(v1.1 の Q40〜Q42 で決めたドメインの一覧をそのまま使う)。
  - 問題点: 実在しない組み合わせを表に含めていてもホスト名が存在しないので誤検出にはならないが、実在する形が漏れる可能性がある(EKS の中国リージョンなど)
  - 案 A(推奨): 表と `<ドメイン>` は変えない(v1.1 の決定のまま)。確認できなかった点は README の限界に書く
  - 案 B: 確認できた `amazonaws.com` に絞る
  - **回答(2026-10-18)**: 案 A(表と `<ドメイン>` は変えず、確認できなかった点を README の限界に書く)
- **Q59(表にない新しい形)** 公式ドキュメントに、表にない次の形がある。OpenSearch Serverless の NextGen(`<ID>.aoss.<リージョン>.on.aws`、`<アカウント ID>.aoss.<リージョン>.on.aws`)と、Cognito の FIPS(`<接頭辞>.auth-fips.<リージョン>.amazoncognito.com`)。
  - 問題点: 検出されない(隠れない)形がある。アカウント ID 版は、利用者ごとの部分がアカウント ID になる
  - 案 A(推奨): v1.2 では対象外とし、README の限界に書く。必要になったら、表に行を足すだけで追加できる
  - 案 B: 表に加える(`.aoss.<リージョン>.on.aws`、`.auth-fips.<リージョン>.amazoncognito.com`)。ただし FIPS の形は一部のリージョンだけで、公式の記述がまだ少ない
  - **回答(2026-10-18)**: 案 A(v1.2 では対象外。仕様の「対象外」と限界に書いた)

段階 6 のあとのコードレビュー(2026-10-18)で見つかった問題。

- **Q60(URL のパスワードの文字の条件)** 仕様 4.1 の条件では、ユーザー・パスワードに `"` や `,` を含められる。そのため、パスのない URL の後ろに、同じ行でメールアドレスが続くと、全体が URL のユーザー情報として読まれる。
  - 例: `{"origin":"https://app.example.com","email":"bob@example.com"}` → `"email":<secret_1>@example.com"}`。開きの `"` が置換されて JSON が壊れ(決定事項 15 に反する)、メールアドレスのドメインが残る。v1.1 では `"email":"<email_1>"` になっていたので、既定の種別での後退
  - 案 A: ユーザー・パスワードに、RFC 3986 でユーザー情報に書けない `"` `'` `` ` `` `<` `>` `\` `{` `}` `|` `^` を含めない
  - 案 B: 案 A に加えて、`,`・`;` も含めない(`origin=https://app.example.com,user:bob@example.com` の形も直るが、`,`・`;` は RFC 3986 ではユーザー情報に書ける)
  - **回答(2026-10-18)**: 案 A。仕様 4.1 と 9 章、README の限界に反映した
- **Q61(IoT の AWS 共通エンドポイント)** レビューで、`data-ats` 以外の AWS 共通のエンドポイントが IoT の形に当てはまらないかを、公式ドキュメントで確認した(2026-10-18)
  - `general/latest/gr/iot_device_management.html` の「Secure Tunneling Management APIs Endpoints」と「Secure Tunneling Device Connection Endpoints」に、`api.tunneling.iot.<リージョン>.amazonaws.com`・`data.tunneling.iot.<リージョン>.amazonaws.com` がある。リージョンごとの決まったホスト名で、利用者ごとの部分がない。今の実装では `<aws_host_N>.iot.<リージョン>.amazonaws.com` になる(誤検出)
  - 同じページの Jobs の `data.jobs.iot.<リージョン>.amazonaws.com` は、「`data` を利用者ごとの接頭辞に置き換える、一般的な表し方」と書かれている。実際のホスト名は利用者ごとの値なので、検出は正しい
  - 補足: `general/latest/gr/iot-core.html` も、`data-ats.iot.<リージョン>.amazonaws.com` を「利用者ごとのエンドポイントの一般的な表し方」と書いている(実際の形は `<接頭辞>-ats.iot.…`)。Q57 で `data-ats` を除外した前提(AWS 共通のエンドポイント)とは違うが、利用者の接頭辞が `data` になることはないので、除外したままでも害はない
  - 案 A(推奨): IoT の行の `exclude` に `api.tunneling`・`data.tunneling` を加える(Q57 の枠組みのまま、表を直すだけ)
  - 案 B: 加えず、README の限界に書く
  - **回答(2026-10-18)**: 案 A。仕様 4.5 と 9 章、README の表に反映した
- **Q62(AWS 以外の検出器の改善を v1.2.0 に含めるか)** 性能の調査(3 章「性能の改善の調査」)は、AWS の処理を加えた状態の確認が目的だった。最も効果が大きい段階 7 は、v1.0 からある `secret` の固定形式の改善で、AWS の追加とは関係がない(既定の種別の速度にも効く)
  - 案 A(推奨): 含める。検出の結果は変わらず、改善の中で最も効果が大きい(既定の `BenchmarkFind` で約 16%)
  - 案 B: 含めない。v1.2.0 は AWS の検出器の改善(段階 8・9)だけにし、段階 7 は次の版に回す
  - **回答(2026-10-18)**: 案 A
- **Q63(キー名が URL のスキームになっている場合。冪等性の違反)** 段階 10 のファズテスト(`FuzzMaskStable`)が、冪等性の違反を見つけた。段階 7〜9 の変更前の develop でも起きる(段階 5 の URL のパスワードで入った問題)
  - 例: `passwd://u:&x@db.example.com/`。キー名ベースは `passwd` + `:` をキー名と区切りとして読み、値は `//u:`(`&` の手前まで)。URL のパスワードは、スキーム `passwd`、ユーザー `u`、パスワード `&x`。2 つは重ならず隣り合うので両方が置換され、`passwd:<secret_1><secret_2>@db.example.com/` になる。値の区切りだった `&` が置換で消えるため、2 回目はキー名ベースの値が `<secret_1><secret_2>@db.example.com/` 全体になり、置換済みのラベルより長いので再び置換される(`passwd:<secret_1>`)。hash モードでも同じ(`passwd:secret_<hex>secret_<hex>@…` → `passwd:secret_<hex>`)
  - 起きる条件: キー名(`password`・`passwd`・`token`・`secret` など)がそのまま URL のスキームで、パスワードが値の区切り(`&` `,` `;` `)` `]` `}`)で始まる。ファズテストが見つけた形は `passwd://:&@0`
  - 根本は、仕様 4.1 のキー名ベースの規則が、`<キー名>://` の `:` を区切りとして読むこと。仕様には、この場合の記述がない
  - 案 A(推奨): キー名ベースで、区切りの `:` の直後が `//` なら、キー名と区切りとして扱わない(`<キー名>://` は URL のスキーム)。規則が単純。`token://abc` のように URL のパスワードの形でないものも置換しなくなる(v1.1 では `token:<secret_1>`)が、URL の参照であって値ではないので、置換しないほうが自然
  - 案 B: 区切りの `:` が、URL のパスワードとして検出される URL のスキームの `://` の場合だけ、キー名と区切りとして扱わない。`token://abc` は v1.1 のまま置換される。判定に URL のユーザー情報の照合が要り、案 A より複雑
  - どちらの案でも、`password://u:p@h` は `password:<secret_1>`(キー名ベースの値 `//u:p@h` 全体)から `password://u:<secret_1>@h` に変わる(ホスト名が残る)
  - **回答(2026-10-18)**: 案 A。仕様 4.1(キーと値の区切り)・9 章(URL のパスワード)・決定事項 20・11 章、README(キー名ベースの説明、v1.2.0 の変更点)に反映した
