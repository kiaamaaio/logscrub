# logscrub 仕様: 受け入れ基準(9 章)

[仕様の目次](../SPEC.md)。項目の節番号(4.1 など)は、目次の表からファイルを引く。

各項目は、テストで確かめる。どの段階で確かめたかと、達成の状況は、版ごとの計画(`docs/plans/<版>.md`)に記録する(この文書にはチェック欄を置かない)。

## 9. 受け入れ基準

基本:

- `echo "taro@example.com 192.168.0.1" | logscrub mask` が `<email_1> <ipv4_private_1>` を出力する
- 同じメールが複数回出ても同じラベル、別のメールは別のラベルになる
- 同じ入力・同じオプションで 2 回実行すると、同じ出力になる
- 置換済みテキストを再度流しても結果が変わらない(mask、hash の両方)
  - `password=<secret_1>`、`Authorization: Bearer <secret_1>` が再置換されない
  - hash モードの `password=secret_3f9a1c0b7d2e` が再ハッシュされない
  - `--mask-format '[{type}-{n}]'` の出力を同じ書式で再度流しても変わらない
- 日本語・全角文字混じりの行が正しく処理される
- 64KB を超える 1 行(例: 1MB の JSON 1 行)が処理できる
- CRLF の入力が CRLF のまま出力され、末尾改行の有無も保たれる
- 100MB 程度のログをパイプで処理でき、メモリ使用量が増え続けない

種別の指定:

- `--types email` ではメールアドレスだけが置換され、IP アドレスは残る
- `--types default,uuid` では既定の種別と UUID が置換される
- 存在しない種別名を指定するとエラー終了する

範囲の重なり:

- `::ffff:10.0.0.1` が、IPv4 部分だけでなく全体で 1 つの `<ipv6_private_1>` になる
- `https://user:pass@10.0.0.1/` が `https://user:<secret_1>@<ipv4_private_1>/` になる(`pass@10.0.0.1` はメールアドレスとして扱わない。パスワードは v1.2 で追加した URL のパスワードとして置換する)

email / hash:

- `--mode hash --email-hash local` で `hash_<hex>@example.com` になり、再度流しても変わらない
- 区切りなしで続くメールアドレス(`0@0.AA%@0.AA@0.AA`、`a@b.example.com-@c.example.com@d.example.com`)は、`--mode hash`(`full`・`local`)と、ラベルがローカルパートの文字だけでできる書式(`--mask-format '{type}_{n}'`)の `mask` で、再度流しても変わらない(Q69)
- `--mode hash --email-hash full` でメール全体が置換される
- `LOGSCRUB_KEY` 未設定で hash モードを使うとエラー終了する

IP アドレス:

- `203.0.113.5` は `<ipv4_global_1>`、`10.0.0.1` と `192.168.0.1` は `<ipv4_private_N>`(区別ごとに連番)になる
- `--ip-scope global` ではプライベートのアドレスが置換されず、`--ip-scope private` ではグローバルのアドレスが置換されない
- IPv6 の `::1`、`fe80::1`、`fd00::1` は `private`、`2001:4860:4860::8888` は `global` と判定される
- `std::string`、`std::bad_alloc`、`fmt::Error`、`core::fmt::Debug` などのコードの記号は、IPv6 として検出されない
- `::1::x`、`fe80::1::x` のような、`::` を 2 つ含む連なりの後ろに英字が続く形は、IPv6 として検出されない。`::1::0@0.AA` を `--mode hash` で 2 回流しても変わらない(v1.2。Q67)
- `src:2001:db8::1`、`tcp6:fe80::1`、`from 2001:db8::1: refused` は、アドレス部分だけが置換される
- `0.0.0.0`、`255.255.255.255`、`::`、`224.0.0.1` は置換されない
- `10.0.0.1:8080`、`[::1]:8080`、`10.0.0.0/8` はアドレス部分だけが置換される
- `999.1.1.1` や `1.2.3` のような不正な形式は IP アドレスとして検出されない
- 文末の `connected to 10.0.0.1.` は検出され、`1.2.3.4.5` は検出されない

secret:

- 4.1 の各形式(AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT)がそれぞれ `<secret_N>` になる
- `Authorization: Bearer xxxxx` の値部分のみが置換される
- `got Bearer abc123 here` のような、キー名のない文章中の `Bearer` は置換されない
- `token: Bearer abc123` は、`abc123` だけが置換される(方式名は残る)
- `password=abc123&user=x` が `password=<secret_1>&user=x` になる
- `"api_key": "abc def"` が `"api_key": "<secret_1>"` になる
- `X-Auth-Token: xxx`、`DB_PASSWORD=xxx` は置換され、`max_tokens: 4096`、`token_count=5`、`PWD=/home/user` は置換されない
- `accessToken=xxx`、`clientSecret: xxx`、`APIKey=xxx` は置換され、`maxTokens=5`、`PGPASSWORD=xxx` は置換されない
- JSON の 1 行に対する置換の結果が、JSON として妥当なままである(`{"msg":"password=abc"}` の閉じ引用符、`"token": 12345` の数値、入れ子の `{` `[` を壊さない)
- `"token": 12345`、`"password": null`、`"token": {"a":1}` は置換されない
- ログに文字列として埋め込まれた JSON(`{"message":"{\"password\":\"abc\"}"}`)の値が置換される
- JSON の文字列の中の `token=abc\ndef`、`?token=abc\u0026user=x` は、`abc` だけが置換される

UUID:

- 何も指定しないと UUID は置換されない
- `--types default,uuid` で、バージョン 1〜8 の UUID(大文字・小文字・`{}` 囲み・`urn:uuid:` 付き)が `<uuid_1>` になる(`{}` や `urn:uuid:` は残り、`{<uuid_1>}`、`urn:uuid:<uuid_1>` になる)
- `req-123e4567-e89b-42d3-a456-426614174000` の UUID 部分が置換される
- `--uuid-versions 4` のみ指定すると、v4 の UUID だけが置換され、v1 や v7 の UUID は置換されない
- nil UUID(全桁 0)、ハイフン無しの 32 桁の 16 進数、バリアントが不正な 8-4-4-4-12 の 16 進数列は検出されない

restore:

- `mask` の出力を、同じ入力・同じオプションで `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る(往復テスト)
- `--source` を複数指定した場合も、`mask` と同じ順なら往復テストが通る
- `--source` のファイルに行を追記したあとでも、追記前のラベルは正しく戻る
- オプションが `mask` と違う場合、対応しないラベルはそのまま残り、件数とラベル名が stderr に出て、終了コードは 0 になる
- `--source -` を ANSWER_FILE なしで指定するとエラー終了する
- `restore` の実行後に、対応表のファイルが残らない
- stderr やエラーメッセージに、元の値が出ない

AWS(v1.1 で追加):

- 何も指定しないと、`aws_*` の種別は置換されない(既定では無効)
- `--types default,aws` で、既定の種別と `aws_account`・`aws_s3_bucket` が対象になる。`--types aws` では、AWS の種別だけが対象になる
- `--types cloud` が、`--types aws` と同じ動作になる
- `logscrub types` に、`aws_account`・`aws_s3_bucket` と、まとまり(`default`、`aws`、`cloud`)が出る
- 署名付き URL の `X-Amz-Signature=<64 桁>` と、`Authorization: AWS4-HMAC-SHA256 …, Signature=<64 桁>` の署名が、既定の種別で `<secret_N>` になる(語と `=` は残る)
- `Signature=` の後ろが 64 桁の 16 進数でない場合(63 桁、65 桁、英大文字を含む)は、署名として置換されない
- `ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com` が `ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com` に、`ip-10-0-1-23.ec2.internal` と `ip-10-0-1-23` が `ip-<ipv4_private_1>…` になる(既定の種別)
- `ip-10-0-1-23` は `--ip-scope global` で置換されない。`ec2-0-0-0-0.compute-1.amazonaws.com` のような特殊アドレスは置換されない
- `ship-10-0-1-23`、`ip-10-0-1-256`、`ip-10-0-1-23-4`、`ec2-54-250-1-2.example.com` は、ホスト名の IP として置換されない
- ARN(`arn:aws:iam::`、`arn:aws-cn:`、`arn:aws-us-gov:`、リージョンありの `arn:aws:lambda:ap-northeast-1:…:function:x`)、ECR のレジストリ、SQS のキュー URL の、アカウント ID の部分だけが `<aws_account_N>` になる
- `arn:aws:s3:::bucket` と `arn:aws:iam::aws:policy/…` のアカウント ID の欄は置換されず、文中の単独の 12 桁の数字も置換されない
- 同じアカウント ID が ARN・ECR・SQS に現れると、すべて同じラベルになる
- `s3://`・`s3a://`・`s3n://`、バーチャルホスト形式(`.` を含むバケット名を含む)、パス形式、`arn:aws:s3:::` のバケット名の部分だけが `<aws_s3_bucket_N>` になり、同じバケットは同じラベルになる
- バケット名の規則に合わないもの(2 文字、64 文字、英大文字・`_` を含む、先頭・末尾が `.` や `-`)は置換されない
- `--types default,aws` の mask・hash の出力を、同じオプションで再度流しても変わらない
- `--types default,aws` の mask の出力を、同じオプションで `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る
- `--stats` で、`aws_account`・`aws_s3_bucket` の件数が `uuid` のあとに出る

AWS のホスト名(v1.2 で追加):

- 何も指定しないと、`aws_host` は置換されない。`--types default,aws`・`--types cloud`・`--types aws_host` で置換される
- 4.5 の表の各サービスの例が、`<aws_host_N>` + 末尾の形(サービス名・リージョン・ドメインが残る)になる
- 同じホスト名は同じラベルに、違うホスト名は別のラベルになる
- `.<リージョン>.elasticbeanstalk.com` の形では、リージョンが利用者ごとの部分に含まれない
- `<ID>.mq.ap-northeast-1.on.aws` が `<aws_host_N>.mq.ap-northeast-1.on.aws` になる
- `data-ats.iot.us-east-1.amazonaws.com`・`api.tunneling.iot.us-east-1.amazonaws.com`・`data.tunneling.iot.us-east-1.amazonaws.com` は置換されず、`a1b2c3d4e5f6g7-ats.iot.us-east-1.amazonaws.com` は置換される
- AWS 自体の API のエンドポイント(`rds.ap-northeast-1.amazonaws.com`、`https://kafka.ap-northeast-1.amazonaws.com/`)、`cloudfront.net` だけのもの、表にない形(`mydb.example.com`、`x.ap-northeast-1.cache.amazonaws.com`)は置換されない
- 末尾の形の後ろに英数字や「`.` + 英数字」が続くもの(`x.cloudfront.net.example.org`)、決まった部分が大文字のもの(`X.CLOUDFRONT.NET`)は置換されない
- EC2 のホスト名・S3 のホスト名・ECR のホスト名は、`aws_host` ではなく、それぞれ `ipv4`・`aws_s3_bucket`・`aws_account` として置換される
- `123456789012.s3-control.ap-northeast-1.amazonaws.com` のアカウント ID が `<aws_account_N>` になる
- `--types default,aws` の mask・hash の出力を、同じオプションで再度流しても変わらない。mask の出力を `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る
- `--stats` で、`aws_host` の件数が `aws_s3_bucket` のあとに出る

URL のパスワード(v1.2 で追加):

- `postgres://app:s3cret@db.example.com:5432/app` が、既定の種別で `postgres://app:<secret_1>@db.example.com:5432/app` になる(メールアドレスとして置換されない)
- `--types default,aws` で、`postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app` が `postgres://app:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app` になる
- `redis://:s3cret@10.0.0.5:6379`(ユーザーが空)と、`:` を含むパスワード(`ftp://u:a:b@host`)のパスワード部分が置換される
- `https://taro@example.com/`(ユーザーだけ)は、v1.1 と同じくメールアドレスとして扱われる
- `{"origin":"https://app.example.com","email":"bob@example.com"}`(パスのない URL の後ろの JSON の値)は、`"email":"<email_1>"` になる(`"` を含めてパスワードとして置換しない。JSON を壊さない)
- 置換後の `postgres://app:<secret_1>@…`、hash の出力 `postgres://app:secret_<hex>@…` を再度流しても変わらない
- スキームがキー名と同じ語の URL(`passwd://app:&x@db.example.com/`)は、`passwd://app:<secret_1>@db.example.com/` になり、再度流しても変わらない(hash も同様)。`token://abc` は置換されない(Q63)
- ユーザーの部分に `@` を含む URL(`postgres://myadmin@mydemoserver:s3cret@10.0.0.5:5432/db`、`https://bob@example.com:pw@10.0.0.1/repo`)のパスワードが置換され、ホスト名も残る。mask・hash とも再度流しても変わらず、restore で元に戻る(Q70)
- スキームの直前が `_` の形(hash の出力の後ろに `://` が続く `email_<16 進数>://:p@h` など)は、URL のパスワードとして扱わない。`0@0.ZA://:0@0` を `--mode hash` で 2 回流しても変わらない(Q64)
- キー名ベースの値が URL のパスワードの形で始まるもの(`password=https://u:p&q@db.example.com/`、`password=https://u:&x@db.example.com/`、`"password": "postgres://app:s3cret@db/"`)は、パスワードの部分だけが置換され(`password=https://u:<secret_1>@db.example.com/` など。`&q` が残らない)、mask・hash とも再度流しても変わらない。ユーザー情報のない URL(`token=https://hooks.example.com/T000/XXXX`)は、今までどおり値全体が置換される(Q65)
- キー名ベースの値が、パスワードが置換されていない URL で、ユーザーの部分か `@` の直後が置換済みの形のもの(`password=https://<uuid_1>:s3cret@db-host/`、`password=https://u:s3cret@<aws_host_1>.ap-northeast-1.rds.amazonaws.com/`)は、値全体がキー名ベースの値として置換され、パスワードが出力に残らない。mask・hash とも再度流しても変わらない(Q68)
- 置換される値の直後にキー名の語が続く形(`0.0.0.1passwd=0`)は、1 回目が `<ipv4_global_1>passwd=0` になり、再度流しても変わらない(hash も同様)。置換済みのラベルの直後のキー名(`<email_1>password=abc`)の値は置換されない(Q66)

除外の確認:

- 電話番号形式(`03-1234-5678`、`09012345678`)や郵便番号形式(`123-4567`)は検出されない

オプション:

- `--allow support@example.com` を指定すると、そのアドレスだけが置換されずに残る
- `--fail-on-detect` で、検出ありなら終了コード 2、検出なしなら 0 になる
- `--stats` の件数が stderr に出て、stdout には混ざらない
- `--hash-length`、`--email-hash`、`--key-file` を `--mode mask` で指定するとエラー終了する
- `--output` が入力ファイルと同じファイルなら、入力を変えずにエラー終了する(終了コード 1)
- 入力ファイルが開けない場合は、出力ファイルを作らず、何も書かずにエラー終了する
- 書き込みエラーなどで処理が失敗した場合は、`--fail-on-detect` で検出があっても、終了コード 1 になる
- `--mask-format '[{type}-{n}]'` が反映され、`{n}` を含まない書式はエラー終了する
- 置換済みの形の文字列(`<email_1>`、`secret_3f9a1c0b7d2e` 等)を含む入力では、件数と行番号が stderr に 1 行で通知され、値は出ず、終了コードは変わらない

CLI:

- `logscrub mask app.log --stats` と `logscrub mask --stats app.log` が同じ動作になる
- `logscrub mask -- -weird-name.log` で、`-weird-name.log` がファイル名として扱われる
- `--stats` と `-stats`、`--output` と `-o` が同じ動作になる
- `--allow` と `--source` を複数回指定すると、すべての値が反映される
- サブコマンドなし、または不明なサブコマンドで、使い方が stderr に出て終了コード 1 になる
- `go.mod` に外部の依存がない(標準ライブラリのみ)
