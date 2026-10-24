# 変更点

logscrub の版ごとの変更点。使い方は [README.md](README.md) を見てください。

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
- AWS のサービスのホスト名の種別 `aws_host` を加えました(既定では無効。[AWS のサービスのホスト名](README.md#aws-のサービスのホスト名))。まとまり `aws`・`cloud` に含まれます。
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
- AWS の値の種別 `aws_account`、`aws_s3_bucket` を加えました(既定では無効。[AWS の値](README.md#aws-の値))。
- `--types` に、種別のまとまり `aws`、`cloud` を書けるようになりました。
- `logscrub types` の出力に、クラウドごとの見出しと、まとまりの一覧を加えました(列の幅も変わりました)。
