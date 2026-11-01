# 変更点

logscrub の版ごとの変更点。使い方は [README.md](README.md) を見てください。

### v1.5.0

- **既定の動作が変わります**(どちらも、今まで隠せていなかった値を隠す方向の変更です)。
  - ホームディレクトリのパスのユーザー名を伏せる種別 `user_path` を加え、既定で有効にしました。`/home/yamada/app.py` は `/home/<user_path_1>/app.py` になります。`/Users/`、`C:\Users\` と、JSON のエスケープ、WSL、Git Bash の形も対象です([詳細](docs/detection.md#ホームディレクトリのパスuser_path))。`user`、`ubuntu` などの一般的な名前は対象外です。
  - PEM の秘密鍵の本文を `secret` に加えました。行ごとに別のラベルになり、印は残ります。1 行に収まった形(`\n` が文字の形、改行を空白にした形)は、印の間を 1 つのラベルにします([詳細](docs/detection.md#pem-の秘密鍵))。
  - 鍵を含む入力では、`<secret_N>` の番号が鍵の行の分だけ増えます。`restore` は、`mask` と同じバージョンで使ってください。
- END のない PEM のブロックと、END のない 1 行の形があると、BEGIN の行番号を stderr に通知します。
- `mask --out-dir DIR FILE ...` を加えました。入力ごとに伏せたファイルを書き出します。番号はファイルをまたいで通しで、既存のファイルは上書きしません([使い方](README.md#ai-エージェントにファイルを読ませる))。
- `mask --review` を加えました。置換した箇所と、置換しなかった怪しい語に色を付けて表示します。確認専用です([使い方](README.md#出力を確認する))。
- `<user_path_1>`、`user_path_<12 桁の 16 進数>` の形の文字列は、置換済みの形として扱います。`token=user_path_3f9a1c0b7d2e` のような値は、置換されなくなります(stderr に通知します)。
- `logscrub types` の出力と `--stats` の並びに、`user_path` が加わりました。
- 既定の mask と `restore` が、v1.4.0 より約 7〜12% 遅くなりました(2 CPU の mask は約 374 → 346 MB/s)。すべての行でパスを調べるためです([性能](README.md#性能))。

### v1.4.0

- 検出を、複数のワーカーで並列に行うようにしました。2 CPU の環境で、既定の種別の mask が約 206 → 365 MB/s、`restore` が約 180 → 320 MB/s になりました([性能](README.md#性能))。出力は変わりません。
- ワーカー数は `GOMAXPROCS`(既定は CPU の数)から決めます。上限は 8 です。オプションは増えていません。
- 1 CPU の環境でも、v1.3.0 で遅くなった `restore` は、v1.2.0 と同じ程度の速さに戻りました。
- `--domain` と、語が少ない `--deny` を、並列化とは別に約 27% 速くしました。語が多く、綴りが多様な場合は、ほとんど変わりません。
- 最大メモリが、ワーカーの作業領域の分だけ増えます(100MB の合成ログで、2 CPU で約 6〜13MB)。
- 入力の読み取りエラーのとき、エラーより前の完全な行を書き出してから、エラーで終了するようにしました。

### v1.3.0

- 利用者が指定した語を伏せる `--deny`・`--deny-file` を加えました。種別は `custom` で、ラベルは `<custom_1>` です([指定した語](docs/detection.md#指定した語custom))。
- 指定したドメインのホスト名を伏せる `--domain` を加えました。種別は `host` で、ホスト名全体が `<host_1>` になります([指定したドメイン](docs/detection.md#指定したドメインのホスト名host))。
- `--mode hash --email-hash local` で、ドメインに指定した語・ドメインを含むメールアドレスは、全体をハッシュします(指定した値を出力に残さないためです)。
- `restore` が、AI の回答でエスケープされたラベル(`&lt;email_1&gt;`、`\<email_1\>`)も戻すようになりました。
- `logscrub version`、`logscrub --version` を加えました。
- GitHub Releases に、linux・darwin・windows(amd64・arm64)のバイナリを置くようにしました。導入の手順は [README](README.md#導入) を見てください。
- 全体のヘルプと `mask --help` の説明を、今の検出対象に合わせました。
- `<host_1>`、`<custom_1>`、`host_<12 桁の 16 進数>`、`custom_<12 桁の 16 進数>` の形の文字列は、`--deny`・`--domain` を使わない場合も、置換済みの形として扱います。`token=host_3f9a1c0b7d2e` のような値は、置換されなくなります(stderr に通知します)。
- `logscrub types` の出力と `--stats` の並びに、`host`・`custom` が加わりました。

### v1.2.0

- **既定の動作が変わります**(どちらも、今まで隠せていなかった値を隠す方向の変更です)。
  - **URL のパスワード**(`<スキーム>://<ユーザー>:<パスワード>@<ホスト>`)を `secret` に加えました。
    あわせて、その形の `@` は、メールアドレスとして扱わなくなりました。
    - v1.1 まで: `postgres://app:s3cret@db.example.com/` は `postgres://app:<email_1>/` になり(ホスト名の情報が消えます)、
      `https://user:pass@10.0.0.1/` はパスワードが**そのまま残って** `https://user:pass@<ipv4_private_1>/` になっていました。
    - v1.2 から: それぞれ `postgres://app:<secret_1>@db.example.com/`、`https://user:<secret_1>@<ipv4_private_1>/` になります。
    - `secret` の `<secret_N>` の番号が、URL のパスワードの分だけ増えることがあります。`restore` は、`mask` と同じバージョンで使ってください。
    - キー名と同じ語がスキームの URL(`passwd://…`、`token://…`)は、キー名ベースの値として扱わなくなりました。
      v1.1 までは `token://abc` が `token:<secret_1>` に、`password://app:s3cret@db/` が `password:<secret_1>`(ホスト名ごと)になっていました。
      v1.2 からは、それぞれ置換されない・`password://app:<secret_1>@db/` になります。
    - ユーザーの部分に `@` を含む URL(`postgres://myadmin@mydemoserver:s3cret@10.0.0.5/`、`https://bob@example.com:pw@10.0.0.1/`)のパスワードも置換します。ユーザー情報とホストは、ホストの手前の最後の `@` で分けます。
    - キー名ベースの値が URL のパスワードの形で始まる場合(`password=postgres://app:s3cret@db/`)も、パスワードの部分だけを置換するようになりました。
      v1.1 までは `password=<secret_1>`(ホスト名ごと)になり、パスワードに `&` などを含むと、その後ろがそのまま残っていました(`password=https://u:p&q@h` → `password=<secret_1>&q@h`)。
- AWS のサービスのホスト名の種別 `aws_host` を加えました(既定では無効。[AWS のサービスのホスト名](docs/detection.md#aws-のサービスのホスト名))。まとまり `aws`・`cloud` に含まれます。
- `aws_account` に、S3 Control のホスト(`<12 桁>.s3-control.<リージョン>.amazonaws.com`)のアカウント ID を加えました。
- EC2 のパブリックホスト名の IPv6 形式・デュアルスタック形式(`….ip.aws`)を、`aws_host` で置換するようになりました。
- `::1::x` のような、IPv6 として正しくない連なり(`::` を 2 つ含むもの)の後ろに英字が続く形の一部を、IPv6 として置換しなくなりました(v1.1 までは `<ipv6_private_1>::x`)。
- 区切りなしで続くメールアドレス(`a@b.example.com-@c.example.com@d.example.com`)を `--mode hash` などで置換した結果を、再度流したときに、まとめて置換し直さないようにしました。ローカルパート全体が置換済みの形(`email_<hex>` など)の連なりのメールアドレスは、置換しません。
- `logscrub types` の出力と `--stats` の並びに、`aws_host` が加わりました。
- 検出を速くしました(既定の種別で約 184 → 229 MB/s、`--types default,aws` で約 138 → 173 MB/s。[性能](README.md#性能))。検出の結果は変わりません。

### v1.1.0

- **既定の動作が変わります**(どちらも、今まで隠せていなかった値を隠す方向の変更です)。
  - `secret` に、AWS の署名(SigV4。署名付き URL の `X-Amz-Signature=` と、`Authorization: AWS4-HMAC-SHA256 …, Signature=`)を加えました。
  - EC2 のホスト名に埋め込まれた IPv4(`ec2-54-250-1-2.…`、`ip-10-0-1-23`)を、`ipv4` として置換するようになりました。
- AWS の値の種別 `aws_account`、`aws_s3_bucket` を加えました(既定では無効。[AWS の値](docs/detection.md#aws-の値))。
- `--types` に、種別のまとまり `aws`、`cloud` を書けるようになりました。
- `logscrub types` の出力に、クラウドごとの見出しと、まとまりの一覧を加えました(列の幅も変わりました)。
