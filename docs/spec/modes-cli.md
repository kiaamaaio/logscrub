# logscrub 仕様: 変換モードと復元、CLI(5 章、6 章)

[仕様の目次](../SPEC.md)。

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
- さらに、ローカルパート全体が、それらの置換済みの形(`hash_` + 16 進数、hash の出力形、現在の `--mask-format` のラベル)が区切りなしで 2 つ以上続いたものであるメールアドレスも、検出の対象外とする(v1.2 で追加。上の 2 つの規則は、1 つだけの場合)。置換済みの形でない部分を含むもの(`email_0123456789abjohn@example.com`、桁数の違う `hash_3f9a1c0b7d2e4455@example.com` など)は、今までどおりメールアドレス全体を検出する
  - 例: `email_d33dcb6233c3email_2ec9724db863@0.AA`、(`{type}_{n}` 書式の)`email_1email_2@0.AA` は検出しない
  - 理由: 区切りなしで続くメールアドレス(`a@b.example.com-@c.example.com@d.example.com`)は、1 回目は前の一致の終端で後ろのローカルパートが切れるが、置換の出力(`email_<hex>email_<hex>@d.example.com`)はローカルパートの文字だけでできているので、2 回目に境目が消えて全体が置換されてしまうため(冪等性。[plans/v1.2.0.md](../plans/v1.2.0.md) Q69)
- メールアドレスのドメインの末尾が、すぐ後ろに続く `hash_` + `--hash-length` 桁の 16 進数 + `@` の `hash` に食い込む場合は、その手前でドメインを終える(後ろが英数字でもよい。手前で終えるとドメインの形にならなければ、メールアドレスとして検出しない。v1.2 で追加)。`local` の出力 `hash_<hex>@0.AA` の直後に `hash_<hex>@…` が続く形(`hash_<hex>@0.AAhash_<hex>@0.AA`)で、2 回目に 1 つ目のドメインが `0.AAhash` に伸び、残りの `_<hex>@0.AA` が置換されないようにするため(冪等性。Q69)
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
