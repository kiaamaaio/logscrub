# logscrub 仕様書(Claude Code 向け)

ログやテキストに含まれる、メールアドレス・IP アドレス・トークン類などを、ハッシュ値または「種別が分かるマスク値」に置換する **CLI コマンド**。
標準入力 → 標準出力のパイプ処理を主な使い方とする。

## 1. 目的・用途

**目的**: ログ調査で出会う情報(メールアドレス、IP アドレス、トークン類など)を、マスクまたはハッシュ化した値に置換し、AI に安全に渡せるようにする。

**主な用途**: ログ調査で AI に渡すテキストの変換

- `mask`: 値を `<email_1>` のようなラベルに置換する。AI の回答中のラベルは `restore` で元に戻せる(元のログから対応をその場で作り直す。対応表のファイルは作らない)
  - `cat app.log | logscrub mask | pbcopy`
  - `pbpaste | logscrub restore --source app.log`
- `hash`: 同じ値は(同じ鍵なら)常に同じ出力になる。元には戻せない

**副次的な用途**: 調査結果を他者に共有する際の変換

**前提**: 検出は完全ではないため、外部に出す前に出力を確認する

## 2. スコープ

- **CLI のみ**(ライブラリ/ logging フィルタ連携は作らない)
- テキストを**行単位のストリーム**で処理する(大きなログでもメモリを使い切らない)
- 外部通信は一切行わない

対象外(v1): 氏名・住所の検出、画像/PDF/バイナリ、複数行にまたがる値。

## 3. 実装言語

**Go に決定**。

| 観点 | Go | Python | Rust |
|---|---|---|---|
| 大きなログ + パイプ | 速い。ストリーム処理が書きやすい | 遅め。起動も重い | 最速 |
| 配布 | 単一バイナリ | 実行環境が必要 | 単一バイナリ |
| 正規表現 | RE2 系(入力長に対し線形、ReDoS なし) | バックトラックあり | RE2 系(線形) |
| 開発の手軽さ | 手軽 | 最も手軽 | やや重い |

## 4. 検出対象

方針: **開発者がログで出会いやすい情報に絞る**。国や形式に依存して判定が難しいものは入れない。
クラウド固有の値(v1.1 で追加)は、**形式がはっきり決まっていて、確実に判定できるものから**対応する(精度重視)。
判定は正規表現による形式の一致を基本とし、UUID と IP アドレスは値の妥当性も確認する(4.2、4.3 参照)。

| 種別 ID | 判定 | 既定で有効 |
|---|---|---|
| `email` | 一般的なメールアドレスの正規表現。ドメインの最後の部分(TLD)は英字 2 文字以上とする(`pass@10.0.0.1` はメールアドレスとして扱わない) | ✅ |
| `ipv4` / `ipv6` | IP アドレス形式。グローバルとプライベートを区別する(4.3 参照) | ✅ |
| `secret` | 4.1 に列挙した形式 | ✅ |
| `uuid` | 4.2 参照 | ❌ |
| `aws_account` | AWS アカウント ID。決まった形の中に現れたものだけ(4.4 参照。v1.1 で追加) | ❌ |
| `aws_s3_bucket` | S3 のバケット名。決まった形の中に現れたものだけ(4.4 参照。v1.1 で追加) | ❌ |
| `aws_host` | AWS のサービスのホスト名のうち、利用者ごとの部分(4.5 参照。v1.2 で追加) | ❌ |

既定で有効にするのは、どこでも使われる技術的な値(メールアドレス、IP アドレス、秘密情報)だけとする。
特定のクラウドに依存する値(`aws_*` など)は、既定では無効にする(v1.1 で追加)。

### 対象種別の指定(`--types`)

- `--types` を指定すると、**指定した種別だけ**が対象になる。
  - 例: `--types email` → メールアドレスだけを置換する
- 既定の種別に追加したい場合は `default` を含める。
  - 例: `--types default,uuid` → `email`、`ipv4`、`ipv6`、`secret`、`uuid` が対象
- `--types` を省略した場合は `default`(既定で有効の種別)が対象。
- 種別のまとまり(v1.1 で追加)。種別名と同じ場所に書ける。
  - `default`: 既定で有効の種別
  - `aws`: `aws_` で始まるすべての種別(`aws_account`、`aws_s3_bucket`、`aws_host`)
  - `cloud`: すべてのクラウドの種別(今は `aws` と同じ。将来、`gcp_*` や `azure_*` を追加したときは、それも含む)
  - 例: `--types default,aws` → 既定の種別と、AWS の種別が対象
  - 例: `--types aws` → AWS の種別だけが対象(既定の種別は含まない)
- クラウド固有の種別名は、`<クラウド>_<対象>` の形にする(`aws_account`、将来は `gcp_project` など)。秘密情報(署名など)は、クラウドに関係なく `secret` に含める(4.1 の方針と同じ。利用者がトークンの種類を知らなくても使えるようにするため)
- `--uuid-versions` を指定すると、`--types` の内容に `uuid` が追加される(4.2 参照)。
- 存在しない種別名を指定した場合はエラー終了する。

### 範囲が重なった場合

- 複数の種別が重なる範囲に一致した場合は、**長く一致したほうを優先**する。
- 同じ長さの場合は、種別の優先順位で決める。優先順位は `email` → `ipv4`/`ipv6` → `secret` → `uuid` → `aws_account` → `aws_s3_bucket` → `aws_host`。
- 一部だけ重なる場合も、このルールで 1 つに決める。
  - 例: `::ffff:10.0.0.1` は、IPv6 全体(長い)と、末尾の IPv4 部分(短い)の両方に一致する。長い IPv6 を優先し、1 つの IPv6 として置換する。

### 置換済みの値は検出しない

冪等性(7 章)を守るため、次の形の文字列は、どの種別でも検出しない。

- 現在の `--mask-format` で作られるラベルの形(既定なら `<種別_連番>`)
- `hash` の出力の形(`<種別>_<16 進数>`、`hash_<16 進数>@ドメイン`)

特に `secret` のキー名ベースや `Bearer` の値は、値の中身を問わず拾うため、この除外がないと `password=<secret_1>` が再度置換されてしまう。

### v1 で除外したもの(将来対応)

- 郵便番号(`postal_jp`。日本限定の形式で、ハイフン無しの判別と、本当に郵便番号かの判定が難しいため)
- 電話番号(`phone_jp`)
  - 日本限定の形式で、郵便番号と同じ理由で見送る
  - 追加する場合は、ハイフンの有無に関係なく検出できる形で対応する
- ハイフン無しの UUID(ハッシュ値などと区別できないため)
- `base64`(文中からの検出は、閾値の調整が難しく精度を出しにくいため。`secret` で JWT・Basic 認証・キー名つきの値は拾える)
  - 将来対応する場合の判定案: 40 文字以上、大文字・小文字・数字をすべて含む、16 進数のみの文字列は除外、エントロピー 4.5 bit/文字程度以上。有効化時は stderr に注意書きを出す
- カード番号(`credit_card`)とマイナンバー(`my_number`)
  - 桁数だけの判定では、ログ中のタイムスタンプ・ID などを大量に誤検出し、意味のある精度にならないため
  - 検証ロジック(カード番号の Luhn チェック、マイナンバーのチェックデジット)を実装できる段階で追加する
  - ログファイルに現れる機会が少ないと想定されるため
- `custom` 正規表現

### 4.1 `secret` の対象

種別名は `secret` の 1 つにまとめる(ラベルは `<secret_1>`)。利用者がトークンの種類を知らなくても使えるようにするため。
対応する形式は、この節の内容を `logscrub types --verbose` と `--help` にも列挙し、README にも記載する。

| 区分 | 形式 |
|---|---|
| AWS アクセスキー ID | `AKIA` / `ASIA` + 英大文字・数字 16 文字 |
| AWS の署名(SigV4。v1.1 で追加) | `X-Amz-Signature=` または `Signature=` の後ろの、16 進数(小文字)ちょうど 64 文字。下記「AWS の署名」参照 |
| URL のパスワード(v1.2 で追加) | `<スキーム>://<ユーザー>:<パスワード>@<ホスト>` のパスワード部分。下記「URL のパスワード」参照 |
| GitHub | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` + 英数字 36 文字以上、`github_pat_` + 英数字・`_` 22 文字以上 |
| Slack | `xoxb-` `xoxp-` `xoxa-` `xoxr-` `xoxs-` + 英数字・`-` 10 文字以上 |
| Stripe | `sk_live_` `sk_test_` `rk_live_` `rk_test_` + 英数字 24 文字以上 |
| Google API キー | `AIza` + 英数字・`-`・`_` 35 文字 |
| `sk-` 形式の API キー | `sk-` + 英数字・`-`・`_` 20 文字以上(前が英数字でないこと) |
| JWT | `eyJ…` `.` `eyJ…` `.` `…` の 3 部構成 |
| Authorization ヘッダ | `Bearer <値>` / `Basic <値>` の値部分。キー名(`Authorization`、`Proxy-Authorization`、または下記の対象のキー名)の値が方式名で始まる場合に限る(`got Bearer abc` のような文章中は対象外)。`Basic` は、値が base64 として解読でき、結果に `:`(`user:pass` の形)を含む場合に限る |
| キー名ベース | 下記「キー名ベースのルール」参照 |

キー名ベースのルール:

- 対象のキー名: `password` `passwd` `secret` `token` `api_key` `apikey` `access_key` `private_key` `client_secret` `access_token` `refresh_token` `auth_token` `session_id`
- キー名の照合:
  - 大文字・小文字を区別しない。`-` と `_` は同一視する(`api-key` = `api_key`)
  - キー名は、区切りの単位で照合する。区切りは、`_` `-` `.` または英数字以外に加えて、**小文字・数字から大文字への変わり目**(`accessToken` の `s` と `T` の間)と、**大文字の連なりの終わり**(`APIKey` の `I` と `K` の間)とする(camelCase。2026-10-11 に改訂。決定事項 15)。上記の語がキー名の末尾の区切り単位として現れれば対象とする
    - 対象になる例: `token`、`access_token`、`X-Auth-Token`、`db.password`、`DB_PASSWORD`、`accessToken`、`clientSecret`、`sessionId`、`APIKey`
    - 対象にならない例: `tokens`、`max_tokens`、`maxTokens`、`token_count`、`tokenCount`、`passwordless`、`PGPASSWORD`(大文字だけの語は 1 つの単位)
    - `pwd` は対象にしない。環境変数の `PWD=/home/...`(現在のディレクトリ)を誤検出するため
  - キー名の連なり(英数字と `_` `-` `.` の続き)の直前が、置換済みのラベル(4 章「置換済みの値は検出しない」。現在の `--mask-format` の形)の終わりなら、キー名として扱わない(v1.2 で追加)。ラベルの直後にキー名が続く入力(`<email_1>password=abc`)の値は、置換しない
    - 理由: 置換される値の直後に、区切りなしでキー名の語が続く場合(`0.0.0.1passwd=0`)、1 回目はキー名の連なりが `0.0.0.1passwd`(末尾の単位 `1passwd` は対象のキー名でない)なので値を置換しないが、2 回目はラベルの終わりで連なりが切れて `passwd` になり、値が置換されてしまうため(冪等性。[plans/v1.2.0.md](plans/v1.2.0.md) Q66)
    - hash の出力形(`ipv4_global_<16 進数>`)は英数字で終わるので、後ろのキー名の語とつながって 1 つの連なりになり、この規則には当たらない(1 回目と同じ単位で切れる)
- キーと値の区切り: `=`、`:`、`: `(YAML、HTTP ヘッダ)、JSON の `"key": "value"`。区切りの前後の空白(スペース・タブ)は、任意個を許す
  - ただし、`:` の直後が `//` の場合は、区切りとして扱わない(v1.2 で追加)。`<キー名>://` は URL のスキームで、キーと値の組ではないため(`passwd://app:s3cret@db-host/` のパスワードは、下記「URL のパスワード」として置換する。`token://abc` は置換しない)。キー名と値として読むと、URL のパスワードと置換の範囲が隣り合い、置換済みのラベルが再度置換されることがあった([plans/v1.2.0.md](plans/v1.2.0.md) Q63)
- キー名は、引用符(`"` または `'`)で囲まれていてもよい。ログに JSON を文字列として埋め込んだ形(`\"password\":\"abc\"`)のように、引用符が `\"` でもよい
- 値の範囲:
  - 値が引用符(`"` または `'`、または `\"`)で始まる場合は、閉じ引用符の手前まで(`\` の次の文字は、値の一部とする)。閉じ引用符がなければ、行末まで
  - 引用符なしの場合は、空白(スペース・タブ)・`&`・`,`・`;`・`}`・`]`・`)`・`"`・`'`・行末のいずれかの直前まで。JSON の文字列の中のエスケープ(`\"` `\'` `\n` `\r` `\t` `\u0026`)がある場合も、その `\` の直前まで(`\\` は 1 つの文字)。**空白で終わるため、空白を含む値(`password: my secret phrase`)は、最初の語だけが置換される**
  - 引用符なしの値が `{` または `[` で始まる場合は、置換しない(構造であって、値ではない)
  - **キー名が引用符で囲まれている場合(JSON、Python の辞書の形)は、値が引用符で囲まれた文字列のものだけを置換する**。数値・`true`・`false`・`null`・`{`・`[` は置換しない(置換すると、JSON の文法が壊れるため)
  - 値の先頭(引用符で始まる場合は、開き引用符の直後)から、下記「URL のパスワード」の形(スキームから、`@` とその後ろのホスト名の文字まで)が始まる場合は、キー名ベースの値として扱わない(v1.2 で追加)。パスワードは「URL のパスワード」として置換し、スキーム・ユーザー・ホスト名は残す
    - 例: `password=postgres://app:s3cret@db-host/app` → `password=postgres://app:<secret_1>@db-host/app`、`"password": "https://u:p@h"` → `"password": "https://u:<secret_1>@h"`
    - この判定では、パスワードの部分が置換済みの形(4 章「置換済みの値は検出しない」)1 つだけのものも、この形に含める。そのときは、ユーザーの部分や `@` の直後も置換済みの形でよい(`https://<uuid_1>:<secret_1>@<aws_host_1>.…`)。置換後の出力を再度流したときに、キー名ベースの値として読まないため(冪等性)
    - パスワードの部分が置換済みの形でないときは、ユーザーの部分や `@` の直後が置換済みの形なら、この形に含めない(`password=https://<uuid_1>:s3cret@db-host`、`password=https://u:s3cret@<aws_host_1>.…`)。「URL のパスワード」の規則はこれらの形のパスワードを置換しないので、キー名ベースの値として置換する(パスワードを残さないため。v1.2 で明確化。[plans/v1.2.0.md](plans/v1.2.0.md) Q68)
    - 値の途中にある URL(`password=x,https://u:p@h`)は対象外で、今までどおりキー名ベースの値になる
    - ユーザー情報のない URL(`token=https://hooks.example.com/T000/XXXX`)は、この形に当たらず、今までどおりキー名ベースの値として置換する
    - 理由: キー名ベースの値は `&` などの値の区切りで終わるため、パスワードにその文字があると、2 つの範囲が隣り合って両方が置換され、2 回目に置換済みのラベルごと再度置換されたり(`password=https://u:&x@h`)、範囲の長いキー名ベースが採られてパスワードの残りが出力に残ったりした(`password=https://u:p&q@h` の `&q`)([plans/v1.2.0.md](plans/v1.2.0.md) Q65)
- **値の部分のみ置換**し、キー名・区切り・引用符は残す
  - 例: `password=abc123&user=x` → `password=<secret_1>&user=x`
  - 例: `"api_key": "abc def"` → `"api_key": "<secret_1>"`
  - 例: `{"msg":"password=abc123"}` → `{"msg":"password=<secret_1>"}`(閉じ引用符を残す)
- 値が空の場合は置換しない。
- 値が `Bearer ` / `Basic ` で始まる場合(`Authorization: Bearer abc`、`token: Bearer abc`)は、方式名を残し、その後ろの値(RFC 7235 の token68: 英数字と `-` `.` `_` `~` `+` `/`、末尾に `=`)だけを置換する。方式名の後ろに空白が 1 つ以上必要。**方式名の後ろが値として読めない場合(置換済みのラベル `Bearer <secret_1>`、`Basic` の値が base64 でない場合)は、何も置換しない**(方式名の語を値として置換しない。冪等性のため)。キー名が `Authorization` の場合は、方式名がなければ置換しない

URL のパスワード(v1.2 で追加):

- 対象は、URL のユーザー情報に書かれたパスワード。DB の接続文字列(`postgres://app:s3cret@db-host:5432/app`)や、`https://user:pass@10.0.0.1/` のような形
- 判定:
  - スキーム: 英字で始まり、英数字・`+`・`.`・`-` が続くもの。前が英数字・`+`・`.`・`-`・`_` でないこと。その後ろに `://`
    - 前の `_` は、hash の出力(`email_<16 進数>` など)の 16 進数の部分を、スキームとして読まないため(`email_fde789562e9a://:0@0` の `0` を、再度置換しない。冪等性のため。[plans/v1.2.0.md](plans/v1.2.0.md) Q64)
  - ユーザー: 0 文字以上で、空白・`:`・`/`・`?`・`#`・`@` と、下記の「URL に使えない文字」を含まない(`redis://:pass@host` のように、ユーザーが空の形も対象)
  - `:` + パスワード: 1 文字以上で、空白・`/`・`?`・`#`・`@` と、下記の「URL に使えない文字」を含まない(`:` は含んでよい。最初の `:` より後ろ、`@` の手前までがパスワード)
  - URL に使えない文字: `"` `'` `` ` `` `<` `>` `\` `{` `}` `|` `^`(RFC 3986 で、URL のユーザー情報に書けない文字)。JSON などで、パスのない URL の後ろに続く別の値を、ユーザー情報として読まないため(`{"origin":"https://app.example.com","email":"bob@example.com"}` の `bob@example.com` は、メールアドレスとして置換する。[plans/v1.2.0.md](plans/v1.2.0.md) Q60)。`,`・`;` などの RFC 3986 で書ける記号は含んでよい
  - `@` の後ろに、ホスト名の文字(英数字・`.`・`-`・`[`)が 1 文字以上続くこと
- 置換するのは、パスワードの部分だけ。スキーム・ユーザー・`:`・`@`・ホスト名は残す
  - 例: `postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app` → `postgres://app:<secret_1>@mydb.cluster-…`(`aws_host` も有効なら `postgres://app:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app`)
- この形のときは、`@` の前後をメールアドレスとして検出しない(4 章「範囲が重なった場合」の例外)。v1.1 までは、`s3cret@mydb….amazonaws.com` 全体がメールアドレスとして置換され、ホスト名の情報が消えていた。また、ホストが IP アドレスの場合は、パスワードがそのまま残っていた
  - ユーザーだけの形(`https://taro@example.com/`)は、この形に当たらない。メールアドレスの扱いは変わらない
  - `secret` が無効な場合(`--types email` など)も、この形の `@` はメールアドレスとして扱わない(メールアドレスの判定が、他の種別の有効・無効で変わらないようにするため。Q54)。この場合、パスワードは置換されずに残る
- ホスト名の部分は、通常どおり、他の種別(`ipv4`・`ipv6`・`aws_host` など)として検出される

AWS の署名(SigV4。v1.1 で追加):

- 対象は、署名付き URL のクエリ(`?X-Amz-Signature=…`)と、`Authorization: AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…` の署名
  - 署名付き URL は、有効期限内なら URL 全体をそのまま使えるため、署名を隠す
- 判定: 語 `X-Amz-Signature` または `Signature`(大文字・小文字を区別しない。前が英数字・`-`・`_` でないこと)+ `=` + 16 進数(`0-9` `a-f`)ちょうど 64 文字 + 後ろが英数字でないこと
- 置換するのは 64 文字の部分だけ。語と `=` は残す
  - 例: `&X-Amz-Signature=fe5f…1024&` → `&X-Amz-Signature=<secret_1>&`
  - 例: `SignedHeaders=host;x-amz-date, Signature=fe5f…1024` → `…, Signature=<secret_1>`
- 長さと文字種で絞り込むため、`AWS4-HMAC-SHA256` などの前後の文脈は条件にしない
- 対象外: SigV2 の `Signature=`(base64。廃止済みの方式で、64 桁の 16 進数のような決まった形がないため)、`x-amz-content-sha256` のような本文のハッシュ値(秘密ではないため)
- `X-Amz-Credential` の中のアクセスキー ID(`AKIA…`)は、上の表のアクセスキー ID として置換される。日付・リージョンなどの残りの部分は置換しない

補足:

- キー名ベースは、形式を知らない独自トークンも拾うための保険。
- 上記に当てはまらない独自形式のトークンは検出されない。この限界を README に明記する。
- キー名ベースの限界(README に明記する): 引用符なしで空白を含む値は、最初の語だけが置換される。JSON の数値だけのトークン(`"pin": 123456`)は、文法を壊さないため置換されない。引用符なしの値に含まれる `"` `'` `)` `&` `,` `;` で、値が途中で終わる。
- PEM 秘密鍵のような複数行にまたがるブロックは v1 の対象外。

### 4.2 `uuid` の対象

UUID(例: `123e4567-e89b-42d3-a456-426614174000`)は、ユーザー ID・セッション ID などとしてログに出ることが多いため、種別 `uuid` を設ける。
リクエスト ID やトレース ID の場合もあるため、**既定は無効**とし、指定した場合のみ対象に含める。

判定ルール(すべて満たしたものを検出):

- 形式: 8-4-4-4-12 桁の 16 進数(大文字・小文字どちらも可)。`{...}` で囲んだ形と `urn:uuid:` 付きも対象。**置換するのは UUID 部分だけ**で、括弧や接頭辞は残す(`{<uuid_1>}`、`urn:uuid:<uuid_1>`)
- バージョン: 3 つ目のグループの先頭桁が `1`〜`8`
- バリアント: 4 つ目のグループの先頭桁が `8` `9` `a` `b`
- 前後が英数字でないこと(`req-123e4567-...` のように、前後がハイフンの場合は検出する)
- ハイフン無し(32 桁)は対象外

有効化の方法:

- `--types default,uuid` / `--types uuid`: バージョン 1〜8 のすべてが対象
- `--uuid-versions 4,7`: 指定したバージョンのみが対象。これだけで `uuid` が対象に追加される
- 両方を指定した場合は、`--uuid-versions` を優先してバージョンを絞る
- `--uuid-versions` に 1〜8 以外を指定した場合はエラー終了する

補足:

- バージョンの目安: v4 はランダムな値(ユーザー ID・セッション ID に多い)、v7 は時刻順の値、v1 は時刻と端末由来の値を含む。
- バージョンとバリアントの確認により、全桁 0 の nil UUID や、UUID 形式ではない 8-4-4-4-12 の 16 進数列は除外される。

### 4.3 `ipv4` / `ipv6` の区別

IP アドレスを、グローバルとプライベートに分けて扱う。
ログ調査では「内部通信の問題か、外部からのアクセスの問題か」が手がかりになるため、値を隠しても、この区別はラベルに残す。

判定ルール:

- 正規表現で候補を拾ったあと、Go の `net/netip`(`netip.ParseAddr`)で妥当性を確認する。解析できないものは検出しない
- IPv4: 4 つの 0〜255 の数値をドットで区切った形式。IPv6: 標準的な表記(省略形、`::ffff:10.0.0.1` のような IPv4 埋め込み、`%eth0` のようなゾーン付きを含む)
- 前後の文字の条件:
  - IPv4: 前が数字・ドットでないこと。後ろが数字でなく、「ドット + 数字」でもないこと(文末の `connected to 10.0.0.1.` は検出し、`1.2.3.4.5` は検出しない)
  - IPv6: 16 進数・`:`・`.` の連なりを、伸ばせるだけ伸ばして候補とし、次の整理をしてから判定する(2026-10-11 に精度重視へ改訂。決定事項 14)
    - 連なりの前後の `.` は、含めない(文末の `::ffff:10.0.0.1.` の `.`)
    - 連なりの先頭・末尾の単独の `:`(`::` の一部でないもの)は、区切りとして外す(`src:2001:db8::1`、`from 2001:db8::1: refused`)
      - 単独かどうかは、元の行で判断する。下記の端のグループの切り離しのあとも同じで、切り離したあとの端の `:` が、元の行で `::` の一部なら外さない(v1.2 で明確化)。`::1::x` は、`x` の手前で切り離した `::1:` が残り、解析できないので検出しない
      - 理由: hash の出力(`email_…`)は 16 進数の英字で始まるため、`::1::0@0.AA` の 2 回目(`::1::email_<16 進数>`)に、連なりが `::1::e` に伸びて `e` が切り離され、`::` の片方の `:` を外した `::1` が置換されていた(冪等性。[plans/v1.2.0.md](plans/v1.2.0.md) Q67)
    - 連なりの前(後ろ)が英字または `_` のときは、その端の 16 進数のグループ(最初(最後)の `:` まで)を切り離す。端が英字・`_` と接しなくなるまで繰り返す(`tcp6:fe80::1` の `6`、`std::string` の `d`)
- ポート付き(`10.0.0.1:8080`、`[::1]:8080`)や CIDR 表記(`10.0.0.0/8`)は、アドレス部分だけを置換する

区別の基準:

| 区別 | 対象 | 扱い |
|---|---|---|
| `private` | RFC1918(`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`)、ループバック(`127.0.0.0/8`、`::1`)、リンクローカル(`169.254.0.0/16`、`fe80::/10`)、共有アドレス空間(`100.64.0.0/10`)、IPv6 の ULA(`fc00::/7`) | 置換する |
| 特殊アドレス | `0.0.0.0`、`255.255.255.255`、`::`、マルチキャスト(`224.0.0.0/4`、`ff00::/8`) | **置換しない**(隠す意味がないため) |
| `global` | IPv4: 上記以外。IPv6: 割り当て済みのグローバルユニキャスト(`2000::/3`)と NAT64(`64:ff9b::/96`) | 置換する |
| 検出しない(IPv6 のみ) | 上記以外の IPv6(`::/8`、`100::/8` など、割り当てのない範囲) | **検出しない**。`d::`、`::E`、`A::B` のようなコードの記号が、アドレスとして置換されるのを防ぐため。IPv4 は、すべて検出する |

- `::ffff:10.0.0.1` のような IPv4 埋め込みアドレスは、埋め込まれた IPv4 で区別を判定する。

ホスト名に埋め込まれた IPv4(v1.1 で追加):

EC2 のホスト名は、IP アドレスを `-` 区切りで含む。IP アドレスだけを置換しても、ホスト名から元の値が読めてしまうため、この部分も `ipv4` として置換する。

| 形 | 例 | 置換後(mask) |
|---|---|---|
| パブリック DNS | `ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com`、`ec2-54-250-1-2.compute-1.amazonaws.com`(us-east-1) | `ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com` |
| プライベート DNS(IP 名) | `ip-10-0-1-23.ap-northeast-1.compute.internal`、`ip-10-0-1-23.ec2.internal`(us-east-1) | `ip-<ipv4_private_1>.ap-northeast-1.compute.internal` |
| ドメインのない IP 名 | `ip-10-0-1-23`(シェルのプロンプト、`hostname -s` の結果、Kubernetes のノード名など) | `ip-<ipv4_private_1>` |

- 判定:
  - `ec2-` または `ip-` の前が、英数字・`-`・`_`・`.` でないこと
  - その後ろに、0〜255 の 10 進数 4 つを `-` で区切ったもの(先頭 0 は不可。IPv4 の判定と同じく `netip.ParseAddr` で確認する)
  - `ec2-` の場合は、その後ろが `.compute-1.amazonaws.com`、または `.<リージョン>.compute.<ドメイン>` であること(ドメインは 4.4 の対象のドメイン。中国リージョンは `amazonaws.com.cn`)
  - `ip-` の場合は、その後ろが `.ec2.internal`、`.<リージョン>.compute.internal`、または英数字・`-`・`_`・`.` 以外の文字(行末を含む)であること
  - リージョンは、英小文字・数字・`-` の 1 文字以上(4.4「共通」のホスト名の中のリージョンと同じ。Q40)
  - ドメイン(`amazonaws.com` など、`.ec2.internal`・`.compute.internal` の `internal`)の後ろは、英数字・`-`・`_` でなく、「`.` + 英数字」でもないこと(行末は可。文末の `.` と、FQDN の末尾の `.` は許す。Q41)
  - 大文字・小文字を区別する(`ec2-`・`ip-`・ドメインは、小文字の形だけを対象にする。Q42)
- 置換するのは、`-` 区切りの 4 つの数値の部分だけ。`ec2-`・`ip-` とドメインは残す
- 区別(`global` / `private` / 特殊アドレス)と `--ip-scope` は、通常の IPv4 と同じに扱う
- 同じ値の判定は、通常どおりバイト列で行う。`54-250-1-2` と `54.250.1.2` は別の値として扱い、別のラベルになる(`restore` で 1 バイトも違わずに戻すため)
- `hash` の出力は、`ec2-ipv4_global_a1b2c3d4e5f6.ap-northeast-1.compute.amazonaws.com` のようになる(数字 4 つの形ではなくなるため、再度は検出されない)
- 対象外: パブリックホスト名の IPv6 形式・デュアルスタック形式(`f5lnz-0khrm-….ap-southeast-2.ip.aws`)。IP アドレスを base36 で符号化した形で、`ipv4` / `ipv6` としては扱わない。`aws_host` で置換する(4.5 参照。v1.2 で追加)

ラベルと出力:

- `mask`: 区別ごとに種別名を分け、連番も区別ごとに数える。
  - `<ipv4_global_1>`、`<ipv4_private_1>`、`<ipv6_global_1>`、`<ipv6_private_1>`
- `hash`: 区別を含める。例: `ipv4_global_a1b2c3d4e5f6`、`ipv4_private_a1b2c3d4e5f6`

置換する範囲の指定:

- `--ip-scope global|private|all`(既定は `all`)
- `global` を指定すると、プライベートのアドレスは置換せずそのまま残す。内部アドレスを AI に見せたい場合に使う
- `private` を指定すると、プライベートのアドレスだけを置換する
- 既定を `all` にするのは、内部アドレスもネットワーク構成を示す情報であり、見逃しを減らす側に倒す方針のため

限界(README に明記する):

- `version 1.2.3.4` のような 4 つ組のバージョン番号は、IP アドレスとして検出される。
- IPv6 は、割り当て済みの範囲だけを検出する。割り当てのない範囲のアドレス(`::10.0.0.1` など)は、IPv6 としては検出されない(その IPv4 部分は、IPv4 として検出される)。
- `a::b` のように、割り当て済みの範囲の形をしたコードの記号(`2001::`、`fe80::x` に見えるもの)は、IPv6 として検出されうる。
- ホスト名に埋め込まれた IPv4 は、`54-250-1-2` と `54.250.1.2` を別の値として扱う(同じアドレスでも、別のラベルになる)。

### 4.4 AWS の値(`aws_account`、`aws_s3_bucket`。v1.1 で追加)

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

限界(README に明記する):

- 決まった形の外に現れた値は検出しない(例: `account_id=123456789012`、CloudTrail の `"accountId"`、`bucket=my-bucket`、`"bucketName": "my-bucket"`)。同じ値が決まった形の中と外の両方にあると、外の値から元の値が読める
- 旧形式のバケット名(2018 年 3 月 1 日より前に us-east-1 で作られた、英大文字・`_` を含むもの、64 文字以上のもの)は検出しない
- アカウントのリージョン別の名前空間のバケット名(`<名前>-<アカウント ID>-<リージョン>-an`)は、アカウント ID を含む。`aws_s3_bucket` を無効にして `aws_account` だけを有効にした場合、バケット名の中のアカウント ID は置換されない
- ARN のリソース名(ロール名、ユーザー名など)や、`AROA…`・`AIDA…` などの一意 ID は置換しない

### 4.5 `aws_host`(AWS のサービスのホスト名。v1.2 で追加)

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
- 利用者ごとの部分が次の名前そのものの場合は、検出しない(AWS 共通のエンドポイントで、利用者ごとの値ではないため)。IoT Core の `data-ats`(`data-ats.iot.us-east-1.amazonaws.com`)、`api.tunneling`・`data.tunneling`(Secure Tunneling の `api.tunneling.iot.us-east-1.amazonaws.com` など。[plans/v1.2.0.md](plans/v1.2.0.md) Q61)。表の行ごとに持ち、必要な行にだけ加える。名前と完全に一致する場合だけ除く(`x.api.tunneling` や、Jobs の `<接頭辞>.jobs` は置換する)
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

表の形は、2026-10-18 に AWS の公式ドキュメントで確認した([plans/v1.2.0.md](plans/v1.2.0.md) Q47)。

範囲が重なった場合:

- `admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com` のように、ホスト名がメールアドレスの一部として読める場合は、長いメールアドレスが優先される(4 章「範囲が重なった場合」)。ホスト名は、メールアドレスのラベルの中に含まれて隠れる

限界(README に明記する):

- 独自のドメイン(Route 53 の CNAME などで付けた `db.example.com`)は検出しない
- `dualstack.` などの接頭辞の有無で、同じロードバランサが別のラベルになる
- 表にないサービスのホスト名は検出しない
- `<ドメイン>` は 4.4 のドメインの一覧をそのまま使う。公式ドキュメントで実在を確認できたのは `amazonaws.com` の形だけで、`amazonaws.com.cn`・`amazonaws.eu` との組み合わせは確認していない。EKS の中国リージョン(`amazonwebservices.com.cn`)など、一覧にないドメインのホスト名は検出しない
- 表にない新しい形(OpenSearch Serverless の NextGen、Cognito の FIPS)は検出しない

## 5. 変換モードと復元

`--mode` の既定は `mask`。

### 5.1 `mask`(種別が分かるマスク)

- 値を `<種別_連番>` に置換する。同じ値には同じ番号、違う値には次の番号。
  - `taro@example.com` → `<email_1>`、`hanako@example.com` → `<email_2>`、`taro@example.com` → `<email_1>`
  - `192.168.0.1` → `<ipv4_private_1>`、`203.0.113.5` → `<ipv4_global_1>`
- 連番は、入力の中で**最初に現れた順**に振る。同じ入力・同じオプションなら、常に同じラベルになる(決定的)。
- 書式はテンプレートで変更可能(`--mask-format '<{type}_{n}>'` が既定)。
  - `{type}` と `{n}` の両方を含まない書式はエラー終了する。
  - 種別と連番の間に `_` を入れて、読み間違いを防ぐ(`<email_1>`)。
  - IP アドレスは、種別名にグローバル/プライベートの区別を含める(4.3 参照)。
- 対応表(元の値 ↔ ラベル)は**ファイルに保存しない**。`restore` は、元の入力から対応をその場で作り直す(5.3 参照)。

### 5.2 `hash`

HMAC-SHA256(秘密鍵つき)の先頭 N 文字(既定 12)を使う。単純な SHA-256 は、メールアドレスのように候補が限られる値では辞書攻撃で元に戻せるため使わない。

- 鍵: 環境変数 `LOGSCRUB_KEY`(または `--key-file`)。未設定ならエラー終了する。
- 決定的(同じ入力・同じ鍵 → 同じ出力)。同じ鍵を共有すれば、別のマシンでも同じ出力になる。
- email のみ、次の 2 パターンを選べる(`--email-hash local|full`、既定は `full`)。

| 指定 | 入力 | 出力 |
|---|---|---|
| `local` | `taro@example.com` | `hash_3f9a1c0b7d2e@example.com`(ローカルパートのみハッシュ、ドメインはそのまま) |
| `full` | `taro@example.com` | `email_3f9a1c0b7d2e`(全体をハッシュ) |

- `local` の出力は、ローカルパートを `hash_` + 16 進数の形にする。この形(`hash_` + `--hash-length` 桁の 16 進数)のローカルパートを持つメールアドレスは、**検出の対象外**とする。再度流しても再ハッシュされないようにするため(冪等性)。
- 同じ理由で、ローカルパートが、hash の出力形(`<種別>_` + `--hash-length` 桁の 16 進数。例: `email_3f9a1c0b7d2e`)や、現在の `--mask-format` のラベルそのもの(例: `{type}_{n}` 書式の `email_1`)であるメールアドレスも、検出の対象外とする。`user@example.com@bastion.example.org` のように、`@` が続く入力の、先頭の `user@example.com` だけが置換された結果(`email_<hex>@bastion.example.org`)を、全体で 1 つのメールアドレスとして再度置換しないため。
- email 以外の種別は、値全体をハッシュする。出力は `<種別>_<hex>`(例: `ipv4_global_a1b2c3d4e5f6`)。
- `hash` モードは復元不可。

### 5.3 `restore`(ラベルを元の値に戻す)

AI の回答などに含まれるラベル(`<email_1>` 等)を、元の値に戻す。
対応表をファイルとして残さないため、**元の入力をもう一度読み、`mask` と同じ規則で連番を振り直して対応を作る**。連番が決定的(5.1)であることを前提とした仕組み。

```
logscrub restore --source FILE [--source FILE ...] [検出オプション] [ANSWER_FILE]
```

- `--source`(必須): `mask` に渡したのと同じ入力。複数指定した場合は、`mask` のときと同じ順に並べる。
- 戻したいテキスト(AI の回答など)は、ANSWER_FILE または stdin から読む。結果は stdout(または `--output`)に出す。
- 検出オプション(`--types`、`--uuid-versions`、`--ip-scope`、`--allow`、`--mask-format`)は、**`mask` のときと同じものを指定する**必要がある。違うと連番がずれる。
- 作り直した対応表はメモリ上にだけ持ち、ファイルにもログにも書き出さない。
- 対応が見つからないラベルは、そのまま残す。その件数を stderr に出す(件数とラベル名のみ。元の値は出さない)。
  - 例: `logscrub: 2 labels could not be restored: <email_3>, <secret_2> (check that --source and options match the mask run)`
  - この場合も終了コードは 0(警告扱い)。
  - 件数は、種類数(同じラベルが回答に何度出ても 1 件)で数え、回答に現れた順に並べる。ラベルとみなすのは、現在の書式で、既知の種別名と、先頭が 0 でない 1 以上の整数からなるもの(`<email_0>`、`<email_01>`、`<unknown_1>` は、ラベルとみなさず、そのまま残す)
- `--source` の処理でも、6 章の「置換済みの形のため置換せずに残した文字列」の通知を、`mask` と同じ形で出す(元の入力にラベルと同じ形の文字列があり、正しく戻らない可能性があることの目安になる)。
- `--source -`(stdin)は、ANSWER_FILE を指定した場合のみ使える。両方を stdin から読もうとした場合はエラー終了する。
- `hash` モードの出力は戻せない(対象外)。

使い方の補足:

- `mask` の入力をパイプで絞り込んだ場合は、`restore` にも同じ内容を渡す。bash / zsh ならプロセス置換が使える。
  - `grep ERROR app.log | logscrub mask | pbcopy`
  - `pbpaste | logscrub restore --source <(grep ERROR app.log)`
- `--source` のファイルが `mask` のあとに**追記**されただけなら、既存のラベルの対応は変わらない(連番は最初に現れた順のため)。ローテーションや書き換えがあると対応がずれる。

限界(README に明記する):

- 元の入力が手元にない、または変わっていると戻せない。
- 元の入力に、もともとラベルと同じ形の文字列(`<email_1>` など)が含まれていると、新しく振ったラベルと区別できず、正しく戻らないことがある。
- AI が回答の中でラベルを書き換えた場合(`\<email_1\>`、`&lt;email_1&gt;`、`email_1` のように括りを外す等)は戻せない。

## 6. CLI

```
logscrub mask    [FILE ...] [--mode mask|hash] [--types default,uuid,...]
                 [--mask-format FMT]
                 [--email-hash local|full] [--hash-length N] [--key-file FILE]
                 [--uuid-versions 4,7] [--ip-scope global|private|all]
                 [--allow VALUE ...] [--stats] [--fail-on-detect] [--output FILE]
logscrub restore --source FILE [--source FILE ...] [ANSWER_FILE]
                 [--types ...] [--uuid-versions ...] [--ip-scope ...]
                 [--allow VALUE ...] [--mask-format FMT] [--output FILE]
logscrub types   [--verbose]
```

- FILE 省略時、または `-` を指定した場合は stdin から読む。出力は既定で stdout。
- `mask` で FILE を複数指定した場合は、指定した順に連結して 1 つの入力として処理する(連番も通しで振る)。
- `restore` の ANSWER_FILE は 1 つだけ指定できる。
- `--output FILE`(`-o`): 出力先をファイルにする。`-` は標準出力。出力先が、入力ファイル(`FILE`、`--source`、ANSWER_FILE)のどれかと同じファイルの場合は、入力を消さないため、何も書かずにエラー終了する。入力ファイルは、処理を始める前にすべて開き、開けないものがあれば、出力を始める前にエラー終了する。
- `--stats`: 置換した件数を、種別ごとに **stderr** に出力する(生の値は出さない)。IP アドレスは `ipv4_global` のように区別ごとに数える。形式は、1 行 1 種別の `logscrub: email=3`。件数は、値の種類数でなく、置換した出現回数で、`--allow` で残した値や特殊アドレスは数えない。0 件の種別は出さない。並びは、`email`、`ipv4_global`、`ipv4_private`、`ipv6_global`、`ipv6_private`、`secret`、`uuid`、`aws_account`、`aws_s3_bucket`、`aws_host` の順(`aws_account`・`aws_s3_bucket` は v1.1、`aws_host` は v1.2 で追加)。
- hash 専用のオプション(`--hash-length`、`--email-hash`、`--key-file`)を、`--mode mask`(既定)で指定すると、エラー終了する。`--hash-length` は 8〜64。
- `--allow VALUE`: 置換しない値(例: 問い合わせ窓口のアドレス)。完全一致で判定する。複数回指定できる。
- `--fail-on-detect`: 1 件でも検出した場合、終了コード 2 で終える(出力は通常どおり行う)。
- 終了コード: 0=正常、1=エラー、2=`--fail-on-detect` 指定時に検出あり。エラー(1)は、2 より優先する(書き込みエラーなどで処理が失敗した場合は、検出があっても 1)。
- 置換済みの形(4 章「置換済みの値は検出しない」)のため置換せずに残した文字列が 1 件以上あれば、処理の最後に **stderr** へ 1 行だけ通知する。`mask`(`--mode hash` を含む)と `restore` の `--source` の処理で共通。
  - 出すのは件数と行番号(最初の 5 件まで)のみ。値は出さない
  - 例: `logscrub: 2 strings were left unchanged because they look already replaced (lines 12, 40). Check them before sharing.`
  - 終了コードは変えない。`--fail-on-detect` の件数にも含めない。抑止するオプションは設けない
  - 置換済みの出力を再度流した場合も出る(元の値か前回の出力かは区別できないため)
  - 行番号は、入力をまたいで通しで数える(1 始まり)。件数が 1 件のときは `1 string was left unchanged because it looks already replaced (line 12)`。行が 6 行以上あるときは、最初の 5 行のあとに `, ...` を付ける
- `logscrub types`: 対応する種別の一覧を出す。1 行 1 種別で、種別 ID、既定で有効か(`on` / `off`)、説明。IP アドレスの区別(`ipv4_global` など)は、説明の中で示す。`--verbose` で `secret` の対応形式(4.1)も列挙する。種別は、共通の種別(`email` 〜 `uuid`)のあとに、クラウドごとにまとめて並べる。一覧の最後に、種別のまとまり(`default`、`aws`、`cloud`)と、それぞれに含まれる種別を出す(v1.1 で追加)。
- `--help` / `-h`(サブコマンドの後ろ、または単独)は、使い方を **stdout** に出して、終了コード 0 で終わる。`mask --help` には、`secret` の対応形式(4.1)も出す。
- `restore` で戻せなかったラベルの一覧は、50 件までを出し、超える場合は `, ...` を付ける(件数は、全体を出す)。件数が 1 件のときは `1 label could not be restored`。

### 6.1 CLI の実装方針

- **外部ライブラリは使わない**。オプションの解析は Go 標準の `flag` パッケージで行う。依存の保守を不要にし、実行ファイルを軽くするため。
- サブコマンド(`mask`、`restore`、`types`)は、`os.Args[1]` で自前で振り分ける。サブコマンドごとに `flag.FlagSet` を作る。
- **オプションはファイル名の前後どちらに書いてもよい**。
  - 例: `logscrub mask app.log --stats` と `logscrub mask --stats app.log` は同じ動作になる。
  - 実装: 「`FlagSet.Parse` でオプションを読む → 残りの先頭をファイル名として 1 つ取り出す → 残りをまた解析する」を、引数がなくなるまで繰り返す。
  - `--` 以降の引数は、`-` で始まっていてもすべてファイル名として扱う。
  - 単独の `-` は、stdin を表すファイル名として扱う。
- オプションは `--stats` と `-stats` のどちらの書き方でも受け付ける(`flag` の標準の動作)。
- 短い形式は `-o`(`--output`)だけを用意する。同じ変数に 2 つの名前を登録して実現する。短い形式をまとめて書く書き方(`-vx`)には対応しない。
- 複数回指定できるオプション(`--allow`、`--source`)は、`flag.Value` を実装して値を蓄積する。
- `--help` / `-h` で、サブコマンドごとの使い方を表示する。サブコマンドなし、または不明なサブコマンドでは、全体の使い方を stderr に出して終了コード 1 で終える。
- シェル補完は v1 では対応しない。

## 7. 非機能要件

- ストリーム処理: 1 行ずつ読み、メモリ使用量は、メモリ上に持つ対応表(検出した値の種類数に比例)程度に収める。
- **行の長さに上限を設けない**。Go の `bufio.Scanner` は初期設定だと 64KB を超える行でエラーになるため、`bufio.Reader` を使うか、上限を外す。
- 処理速度: 目標は **50MB/s 以上**(実測してベンチ結果を README に残す)。
  - Go の正規表現は安全な一方で速くはないため、前処理で絞り込む。例: `@` を含まない行ではメールアドレスの判定を行わない、`.` や `:` を含まない行では IP アドレスの判定を行わない。
- 入出力のバイト列の保持:
  - 改行コード(LF / CRLF)と、ファイル末尾の改行の有無をそのまま保つ
  - 置換した部分以外は、1 バイトも変えない
  - 不正な UTF-8 のバイト列は、そのまま通す(落とさない)
- 冪等: すでに置換済みの値(`<email_1>`、`hash_…@example.com`、`password=<secret_1>` の値部分 等)を再変換しない(4 章「置換済みの値は検出しない」参照)。
- 置換済みの形のため残した文字列は、件数と行番号を stderr に通知する(6 章参照)。本物の値がたまたま置換済みの形と一致した場合の見落としを防ぐため。
- ログ・エラーメッセージに、置換対象の生の値を出さない。
- 検出は、対象とした種別の中では、誤検出よりも見逃しを減らす側に倒す。
- 正規表現ベースのため完全ではないことを README に明記する。

## 8. 構成

```
logscrub/
├── go.mod
├── README.md
├── cmd/logscrub/main.go   # cli.Run を呼ぶだけの入口。性能・メモリの測定テスト(perf_test.go、-perf)もここ
├── internal/
│   ├── cli/           # サブコマンドの振り分け、オプションの解析(標準の flag のみ)、入出力、終了コード
│   ├── detect/        # 種別ごとの検出、範囲の重なりの解決、置換済みの値・--allow・IP の区別による除外
│   ├── transform/     # mask.go、hash.go、restore.go、engine.go(行の書き換え)、stats.go、key.go。
│   │                  #   testdata/ に、サンプルログと、手で確認した期待値、ファズテストの入力
│   ├── label/         # --mask-format の解析・生成・走査、hash 出力形の走査、メールアドレスの構文
│   ├── stream/        # 行単位の入出力(改行コードの保持を含む)
│   └── synthlog/      # 性能測定用の合成ログの生成器
├── scripts/go         # Go の操作を Docker コンテナ(golang:1.27.2)の中で行うラッパー
└── docs/              # SPEC.md(この文書)、DEVELOPMENT.md(開発環境・構成・設計の注意点)、plans/(版ごとの実装計画と進捗・判断の記録)
```

## 9. 受け入れ基準

基本:

- [ ] `echo "taro@example.com 192.168.0.1" | logscrub mask` が `<email_1> <ipv4_private_1>` を出力する
- [ ] 同じメールが複数回出ても同じラベル、別のメールは別のラベルになる
- [ ] 同じ入力・同じオプションで 2 回実行すると、同じ出力になる
- [ ] 置換済みテキストを再度流しても結果が変わらない(mask、hash の両方)
  - [ ] `password=<secret_1>`、`Authorization: Bearer <secret_1>` が再置換されない
  - [ ] hash モードの `password=secret_3f9a1c0b7d2e` が再ハッシュされない
  - [ ] `--mask-format '[{type}-{n}]'` の出力を同じ書式で再度流しても変わらない
- [ ] 日本語・全角文字混じりの行が正しく処理される
- [ ] 64KB を超える 1 行(例: 1MB の JSON 1 行)が処理できる
- [ ] CRLF の入力が CRLF のまま出力され、末尾改行の有無も保たれる
- [ ] 100MB 程度のログをパイプで処理でき、メモリ使用量が増え続けない

種別の指定:

- [ ] `--types email` ではメールアドレスだけが置換され、IP アドレスは残る
- [ ] `--types default,uuid` では既定の種別と UUID が置換される
- [ ] 存在しない種別名を指定するとエラー終了する

範囲の重なり:

- [ ] `::ffff:10.0.0.1` が、IPv4 部分だけでなく全体で 1 つの `<ipv6_private_1>` になる
- [ ] `https://user:pass@10.0.0.1/` が `https://user:<secret_1>@<ipv4_private_1>/` になる(`pass@10.0.0.1` はメールアドレスとして扱わない。パスワードは v1.2 で追加した URL のパスワードとして置換する)

email / hash:

- [ ] `--mode hash --email-hash local` で `hash_<hex>@example.com` になり、再度流しても変わらない
- [ ] `--mode hash --email-hash full` でメール全体が置換される
- [ ] `LOGSCRUB_KEY` 未設定で hash モードを使うとエラー終了する

IP アドレス:

- [ ] `203.0.113.5` は `<ipv4_global_1>`、`10.0.0.1` と `192.168.0.1` は `<ipv4_private_N>`(区別ごとに連番)になる
- [ ] `--ip-scope global` ではプライベートのアドレスが置換されず、`--ip-scope private` ではグローバルのアドレスが置換されない
- [ ] IPv6 の `::1`、`fe80::1`、`fd00::1` は `private`、`2001:4860:4860::8888` は `global` と判定される
- [ ] `std::string`、`std::bad_alloc`、`fmt::Error`、`core::fmt::Debug` などのコードの記号は、IPv6 として検出されない
- [ ] `::1::x`、`fe80::1::x` のような、`::` を 2 つ含む連なりの後ろに英字が続く形は、IPv6 として検出されない。`::1::0@0.AA` を `--mode hash` で 2 回流しても変わらない(v1.2。Q67)
- [ ] `src:2001:db8::1`、`tcp6:fe80::1`、`from 2001:db8::1: refused` は、アドレス部分だけが置換される
- [ ] `0.0.0.0`、`255.255.255.255`、`::`、`224.0.0.1` は置換されない
- [ ] `10.0.0.1:8080`、`[::1]:8080`、`10.0.0.0/8` はアドレス部分だけが置換される
- [ ] `999.1.1.1` や `1.2.3` のような不正な形式は IP アドレスとして検出されない
- [ ] 文末の `connected to 10.0.0.1.` は検出され、`1.2.3.4.5` は検出されない

secret:

- [ ] 4.1 の各形式(AWS、GitHub、Slack、Stripe、Google、`sk-`、JWT)がそれぞれ `<secret_N>` になる
- [ ] `Authorization: Bearer xxxxx` の値部分のみが置換される
- [ ] `got Bearer abc123 here` のような、キー名のない文章中の `Bearer` は置換されない
- [ ] `token: Bearer abc123` は、`abc123` だけが置換される(方式名は残る)
- [ ] `password=abc123&user=x` が `password=<secret_1>&user=x` になる
- [ ] `"api_key": "abc def"` が `"api_key": "<secret_1>"` になる
- [ ] `X-Auth-Token: xxx`、`DB_PASSWORD=xxx` は置換され、`max_tokens: 4096`、`token_count=5`、`PWD=/home/user` は置換されない
- [ ] `accessToken=xxx`、`clientSecret: xxx`、`APIKey=xxx` は置換され、`maxTokens=5`、`PGPASSWORD=xxx` は置換されない
- [ ] JSON の 1 行に対する置換の結果が、JSON として妥当なままである(`{"msg":"password=abc"}` の閉じ引用符、`"token": 12345` の数値、入れ子の `{` `[` を壊さない)
- [ ] `"token": 12345`、`"password": null`、`"token": {"a":1}` は置換されない
- [ ] ログに文字列として埋め込まれた JSON(`{"message":"{\"password\":\"abc\"}"}`)の値が置換される
- [ ] JSON の文字列の中の `token=abc\ndef`、`?token=abc\u0026user=x` は、`abc` だけが置換される

UUID:

- [ ] 何も指定しないと UUID は置換されない
- [ ] `--types default,uuid` で、バージョン 1〜8 の UUID(大文字・小文字・`{}` 囲み・`urn:uuid:` 付き)が `<uuid_1>` になる(`{}` や `urn:uuid:` は残り、`{<uuid_1>}`、`urn:uuid:<uuid_1>` になる)
- [ ] `req-123e4567-e89b-42d3-a456-426614174000` の UUID 部分が置換される
- [ ] `--uuid-versions 4` のみ指定すると、v4 の UUID だけが置換され、v1 や v7 の UUID は置換されない
- [ ] nil UUID(全桁 0)、ハイフン無しの 32 桁の 16 進数、バリアントが不正な 8-4-4-4-12 の 16 進数列は検出されない

restore:

- [ ] `mask` の出力を、同じ入力・同じオプションで `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る(往復テスト)
- [ ] `--source` を複数指定した場合も、`mask` と同じ順なら往復テストが通る
- [ ] `--source` のファイルに行を追記したあとでも、追記前のラベルは正しく戻る
- [ ] オプションが `mask` と違う場合、対応しないラベルはそのまま残り、件数とラベル名が stderr に出て、終了コードは 0 になる
- [ ] `--source -` を ANSWER_FILE なしで指定するとエラー終了する
- [ ] `restore` の実行後に、対応表のファイルが残らない
- [ ] stderr やエラーメッセージに、元の値が出ない

AWS(v1.1 で追加):

- [ ] 何も指定しないと、`aws_*` の種別は置換されない(既定では無効)
- [ ] `--types default,aws` で、既定の種別と `aws_account`・`aws_s3_bucket` が対象になる。`--types aws` では、AWS の種別だけが対象になる
- [ ] `--types cloud` が、`--types aws` と同じ動作になる
- [ ] `logscrub types` に、`aws_account`・`aws_s3_bucket` と、まとまり(`default`、`aws`、`cloud`)が出る
- [ ] 署名付き URL の `X-Amz-Signature=<64 桁>` と、`Authorization: AWS4-HMAC-SHA256 …, Signature=<64 桁>` の署名が、既定の種別で `<secret_N>` になる(語と `=` は残る)
- [ ] `Signature=` の後ろが 64 桁の 16 進数でない場合(63 桁、65 桁、英大文字を含む)は、署名として置換されない
- [ ] `ec2-54-250-1-2.ap-northeast-1.compute.amazonaws.com` が `ec2-<ipv4_global_1>.ap-northeast-1.compute.amazonaws.com` に、`ip-10-0-1-23.ec2.internal` と `ip-10-0-1-23` が `ip-<ipv4_private_1>…` になる(既定の種別)
- [ ] `ip-10-0-1-23` は `--ip-scope global` で置換されない。`ec2-0-0-0-0.compute-1.amazonaws.com` のような特殊アドレスは置換されない
- [ ] `ship-10-0-1-23`、`ip-10-0-1-256`、`ip-10-0-1-23-4`、`ec2-54-250-1-2.example.com` は、ホスト名の IP として置換されない
- [ ] ARN(`arn:aws:iam::`、`arn:aws-cn:`、`arn:aws-us-gov:`、リージョンありの `arn:aws:lambda:ap-northeast-1:…:function:x`)、ECR のレジストリ、SQS のキュー URL の、アカウント ID の部分だけが `<aws_account_N>` になる
- [ ] `arn:aws:s3:::bucket` と `arn:aws:iam::aws:policy/…` のアカウント ID の欄は置換されず、文中の単独の 12 桁の数字も置換されない
- [ ] 同じアカウント ID が ARN・ECR・SQS に現れると、すべて同じラベルになる
- [ ] `s3://`・`s3a://`・`s3n://`、バーチャルホスト形式(`.` を含むバケット名を含む)、パス形式、`arn:aws:s3:::` のバケット名の部分だけが `<aws_s3_bucket_N>` になり、同じバケットは同じラベルになる
- [ ] バケット名の規則に合わないもの(2 文字、64 文字、英大文字・`_` を含む、先頭・末尾が `.` や `-`)は置換されない
- [ ] `--types default,aws` の mask・hash の出力を、同じオプションで再度流しても変わらない
- [ ] `--types default,aws` の mask の出力を、同じオプションで `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る
- [ ] `--stats` で、`aws_account`・`aws_s3_bucket` の件数が `uuid` のあとに出る

AWS のホスト名(v1.2 で追加):

- [ ] 何も指定しないと、`aws_host` は置換されない。`--types default,aws`・`--types cloud`・`--types aws_host` で置換される
- [ ] 4.5 の表の各サービスの例が、`<aws_host_N>` + 末尾の形(サービス名・リージョン・ドメインが残る)になる
- [ ] 同じホスト名は同じラベルに、違うホスト名は別のラベルになる
- [ ] `.<リージョン>.elasticbeanstalk.com` の形では、リージョンが利用者ごとの部分に含まれない
- [ ] `<ID>.mq.ap-northeast-1.on.aws` が `<aws_host_N>.mq.ap-northeast-1.on.aws` になる
- [ ] `data-ats.iot.us-east-1.amazonaws.com`・`api.tunneling.iot.us-east-1.amazonaws.com`・`data.tunneling.iot.us-east-1.amazonaws.com` は置換されず、`a1b2c3d4e5f6g7-ats.iot.us-east-1.amazonaws.com` は置換される
- [ ] AWS 自体の API のエンドポイント(`rds.ap-northeast-1.amazonaws.com`、`https://kafka.ap-northeast-1.amazonaws.com/`)、`cloudfront.net` だけのもの、表にない形(`mydb.example.com`、`x.ap-northeast-1.cache.amazonaws.com`)は置換されない
- [ ] 末尾の形の後ろに英数字や「`.` + 英数字」が続くもの(`x.cloudfront.net.example.org`)、決まった部分が大文字のもの(`X.CLOUDFRONT.NET`)は置換されない
- [ ] EC2 のホスト名・S3 のホスト名・ECR のホスト名は、`aws_host` ではなく、それぞれ `ipv4`・`aws_s3_bucket`・`aws_account` として置換される
- [ ] `123456789012.s3-control.ap-northeast-1.amazonaws.com` のアカウント ID が `<aws_account_N>` になる
- [ ] `--types default,aws` の mask・hash の出力を、同じオプションで再度流しても変わらない。mask の出力を `restore --source` に通すと、元の入力と 1 バイトも違わずに戻る
- [ ] `--stats` で、`aws_host` の件数が `aws_s3_bucket` のあとに出る

URL のパスワード(v1.2 で追加):

- [ ] `postgres://app:s3cret@db.example.com:5432/app` が、既定の種別で `postgres://app:<secret_1>@db.example.com:5432/app` になる(メールアドレスとして置換されない)
- [ ] `--types default,aws` で、`postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app` が `postgres://app:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app` になる
- [ ] `redis://:s3cret@10.0.0.5:6379`(ユーザーが空)と、`:` を含むパスワード(`ftp://u:a:b@host`)のパスワード部分が置換される
- [ ] `https://taro@example.com/`(ユーザーだけ)は、v1.1 と同じくメールアドレスとして扱われる
- [ ] `{"origin":"https://app.example.com","email":"bob@example.com"}`(パスのない URL の後ろの JSON の値)は、`"email":"<email_1>"` になる(`"` を含めてパスワードとして置換しない。JSON を壊さない)
- [ ] 置換後の `postgres://app:<secret_1>@…`、hash の出力 `postgres://app:secret_<hex>@…` を再度流しても変わらない
- [ ] スキームがキー名と同じ語の URL(`passwd://app:&x@db.example.com/`)は、`passwd://app:<secret_1>@db.example.com/` になり、再度流しても変わらない(hash も同様)。`token://abc` は置換されない(Q63)
- [ ] スキームの直前が `_` の形(hash の出力の後ろに `://` が続く `email_<16 進数>://:p@h` など)は、URL のパスワードとして扱わない。`0@0.ZA://:0@0` を `--mode hash` で 2 回流しても変わらない(Q64)
- [ ] キー名ベースの値が URL のパスワードの形で始まるもの(`password=https://u:p&q@db.example.com/`、`password=https://u:&x@db.example.com/`、`"password": "postgres://app:s3cret@db/"`)は、パスワードの部分だけが置換され(`password=https://u:<secret_1>@db.example.com/` など。`&q` が残らない)、mask・hash とも再度流しても変わらない。ユーザー情報のない URL(`token=https://hooks.example.com/T000/XXXX`)は、今までどおり値全体が置換される(Q65)
- [ ] キー名ベースの値が、パスワードが置換されていない URL で、ユーザーの部分か `@` の直後が置換済みの形のもの(`password=https://<uuid_1>:s3cret@db-host/`、`password=https://u:s3cret@<aws_host_1>.ap-northeast-1.rds.amazonaws.com/`)は、値全体がキー名ベースの値として置換され、パスワードが出力に残らない。mask・hash とも再度流しても変わらない(Q68)
- [ ] 置換される値の直後にキー名の語が続く形(`0.0.0.1passwd=0`)は、1 回目が `<ipv4_global_1>passwd=0` になり、再度流しても変わらない(hash も同様)。置換済みのラベルの直後のキー名(`<email_1>password=abc`)の値は置換されない(Q66)

除外の確認:

- [ ] 電話番号形式(`03-1234-5678`、`09012345678`)や郵便番号形式(`123-4567`)は検出されない

オプション:

- [ ] `--allow support@example.com` を指定すると、そのアドレスだけが置換されずに残る
- [ ] `--fail-on-detect` で、検出ありなら終了コード 2、検出なしなら 0 になる
- [ ] `--stats` の件数が stderr に出て、stdout には混ざらない
- [ ] `--hash-length`、`--email-hash`、`--key-file` を `--mode mask` で指定するとエラー終了する
- [ ] `--output` が入力ファイルと同じファイルなら、入力を変えずにエラー終了する(終了コード 1)
- [ ] 入力ファイルが開けない場合は、出力ファイルを作らず、何も書かずにエラー終了する
- [ ] 書き込みエラーなどで処理が失敗した場合は、`--fail-on-detect` で検出があっても、終了コード 1 になる
- [ ] `--mask-format '[{type}-{n}]'` が反映され、`{n}` を含まない書式はエラー終了する
- [ ] 置換済みの形の文字列(`<email_1>`、`secret_3f9a1c0b7d2e` 等)を含む入力では、件数と行番号が stderr に 1 行で通知され、値は出ず、終了コードは変わらない

CLI:

- [ ] `logscrub mask app.log --stats` と `logscrub mask --stats app.log` が同じ動作になる
- [ ] `logscrub mask -- -weird-name.log` で、`-weird-name.log` がファイル名として扱われる
- [ ] `--stats` と `-stats`、`--output` と `-o` が同じ動作になる
- [ ] `--allow` と `--source` を複数回指定すると、すべての値が反映される
- [ ] サブコマンドなし、または不明なサブコマンドで、使い方が stderr に出て終了コード 1 になる
- [ ] `go.mod` に外部の依存がない(標準ライブラリのみ)

## 10. 決定事項

1. 言語は Go
2. `mask` のラベルは、元の文中との衝突を避けるため記号で括る。既定は `<email_1>` 形式で、`--mask-format` で変更可能
3. 郵便番号・電話番号(`phone_jp`)は v1 から除外
4. `secret` は 1 種別にまとめ、対応形式はドキュメントと `--help` で示す
5. `base64` は v1 から除外(将来対応)
6. `uuid` は v1 に含める。既定は無効で、指定した場合のみ対象にする
7. `credit_card` と `my_number` は v1 から除外(検証ロジックと合わせて将来対応)
8. IP アドレスはグローバル/プライベートをラベルで区別し、`--ip-scope` で置換範囲を選べる(既定は `all`)。特殊アドレスは置換しない
9. ツール名は `logscrub`
10. `--types` は指定した種別だけを対象にし、既定に足す場合は `default` を含める
11. `--email-hash local` の出力は `hash_<hex>@ドメイン` とし、検出の対象外にする
12. `restore` は v1 に含める。対応表はファイルに保存せず、`--source` で渡した元の入力から毎回作り直す
13. CLI は Go 標準の `flag` のみで実装し、外部ライブラリは使わない。オプションはファイル名の前後どちらに書いてもよい(6.1 参照)
14. IPv6 は、誤検出を防ぐため、割り当て済みの範囲(`2000::/3`、`fc00::/7`、`fe80::/10`、`ff00::/8`、`::1`、`::`、`::ffff:0:0/96`、`64:ff9b::/96`)だけを検出する。前後の文字の条件は、単独の `:` の区切り扱いと、英字・`_` と癒着した端のグループの切り離しに改めた(2026-10-11、段階 4 の実測に基づく。仕様 7 章の「見逃しを減らす側」より、IPv6 の誤検出の抑制を優先する)。v1.2 で、端のグループを切り離したあとの「単独の `:`」は、元の行で判断することを明確にした(2026-10-18。Q67。冪等性のため)
15. `secret` のキー名ベースと Authorization を、精度重視と JSON の文法の保持を基準に改めた(2026-10-11、段階 5 の実測と確認に基づく)。camelCase を区切りとする。`Bearer` / `Basic` は、キー名の値の位置に限る。キー名が引用符で囲まれた形では、文字列の値だけを置換する。引用符なしの値の終端に、`"` `'` `)` を加える。v1.2 で、キー名の連なりの直前が置換済みのラベルの終わりなら、キー名として扱わないことにした(2026-10-18。Q66。冪等性のため)
16. クラウド固有の値を v1.1 で追加する(2026-10-15)。精度を重視し、形式がはっきり決まっているものから対応する。種別名は `<クラウド>_<対象>`(`aws_account`、`aws_s3_bucket`)とし、まとまり(`aws`、`cloud`)で指定できるようにする。既定では無効(特定のクラウドに依存する値のため)。秘密情報(AWS の署名)は、クラウドに関係なく `secret` に含める
17. EC2 のホスト名に埋め込まれた IPv4 を、`ipv4` として置換する(2026-10-15)。IP アドレスを置換しても、ホスト名から元の値が読めてしまうため。既定の種別に含まれる
18. v1.2 で `aws_host`(AWS の外からアクセスできるサービスのホスト名)を追加する予定(2026-10-15)。決まった末尾のドメインより前の部分を、まとめて置換する(サービス名とリージョンを残すため)。EC2 のホスト名と S3 のバケットは対象から外す
19. `aws_host` を v1.2 で追加する(2026-10-17)。対象は、4.5 の表の「末尾の形」が決まっているサービスのホスト名だけ。あわせて、S3 Control のホストのアカウント ID を `aws_account` に加え、EC2 のパブリックホスト名の IPv6・デュアルスタック形式(`….ip.aws`)を `aws_host` で置換する
20. `secret` に URL のパスワード(`<スキーム>://<ユーザー>:<パスワード>@<ホスト>`)を加え、この形のときは `@` の前後をメールアドレスとして扱わない(2026-10-17)。DB の接続文字列で、ホスト名の情報が消えたり、ホストが IP アドレスのときにパスワードが残ったりしていたため。既定の種別の動作が変わる(隠せていなかった値を隠す方向の変更)。あわせて、キー名ベースで `<キー名>://` の `:` を区切りとして扱わないことにした(2026-10-18。Q63)、スキームの直前が `_` の形を URL のパスワードとして扱わないことにした(2026-10-18。Q64)、キー名ベースの値が URL のパスワードの形で始まる場合は、キー名ベースの値として扱わないことにした(2026-10-18。Q65)。どれも冪等性を守るため(Q65 は、パスワードの一部が残ることも防ぐ)。Q65 の判定で置換済みの形を読むのは、パスワードの部分が置換済みの形のときだけに絞った(2026-10-18。Q68。パスワードが残る形があったため)

## 11. 未決事項

なし(v1.1 の細部は [plans/v1.1.0.md](plans/v1.1.0.md) 5 章の Q32〜Q46、v1.2 の細部は [plans/v1.2.0.md](plans/v1.2.0.md) 5 章の Q47〜Q68 で確定済み)

---

## 付録: Claude Code への最初の指示(例)

```
SPEC.md を読んで、v1 を実装してください。
まず実装計画(構成・主要な型・テスト方針)を提示し、私が承認してから実装に入ってください。
決定事項(10 章)に従ってください。外部ライブラリは使わず、標準ライブラリのみで実装してください。
```
