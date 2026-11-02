# logscrub v1.5.0 `/code-review` の修正の記録

[計画](README.md)へ戻る。`/code-review` の修正の内容と、修正のあとの確認を書く。段階ごとの記録は [log.md](log.md)。指摘の全体は PR の説明に書く。

1〜4 回目の記録は [log-review-1.md](log-review-1.md)、5〜6 回目の記録は [log-review-2.md](log-review-2.md)、7 回目と Q126 の記録は [log-review-3.md](log-review-3.md) に分けた。

## 8 回目の `/code-review`

別のセッションで `5e333ae..d9e37a6` を中心に high で行った。指摘の全体と扱いは PR の説明に書く(push と PR の説明の更新は、許可を得てから行う)。判断が必要なものは Q127 に書いた。修正はしていない。レビューの終了の条件は、まだ満たしていない(「この PR で直す」が 1 件、判断待ちの Q が 1 件)。

d9e37a6 のバイナリ(`./scripts/go build -o /cache/lgr8 ./cmd/logscrub`)で確かめた。値はすべて架空。ファズテスト、`-perf`、`-race` は実行していない(`.go` の変更はテストだけ)。

### 指摘の振り分け

| 指摘 | 振り分け |
|---|---|
| LIMITATIONS.md 53 行目の「それ以外の形では、2 回目の出力は変わりません」に反例がある | この PR で直す |
| `/` が重なるパスのユーザー名が残り、どの資料にもない | Q127 |
| MSYS2 のホームディレクトリ(`C:\msys64\home\yamada\x`、`/c/msys64/home/yamada/x`)が残り、どの資料にもない | LIMITATIONS.md に書く(Q125 の Cygwin のホームディレクトリと同じ) |
| UNC の `/` の形(`//fs01/home/yamada/x`、`//fs01/users/yamada/x`)が残り、どの資料にもない | LIMITATIONS.md に書く(Q125 の UNC と同じ) |
| ドライブ名だけの形で区切りが混ざるパス(`/c/Users\yamada\x`、`/mnt/c/Users\yamada\x`、`/cygdrive/c/Users\yamada\x`)が残り、どの資料にもない。仕様 4.8 の表にない形 | LIMITATIONS.md に書く |

### 53 行目の反例

実装は変えない。作り物の入力の冪等性の違反なので、言い切りをやめ、下の 2 つを書く。

| 形 | 1 回目の出力 | 2 回目に変わるところ |
|---|---|---|
| BEGIN の列が 10 で、`12:00:02: AAAA` の次に `x@example.org BBBB`、`12:00:04: CCCC` | `<email_1> BBBB` でブロックが終わり、`CCCC` が残る | 2 回目は `<email_1> ` の長さが列と同じなので本文の行になり、`BBBB`、`CCCC` が伏せられる |
| 列が 16 で、`8.8.8.8 BBBB`(`<ipv4_global_1> ` が 16 文字) | 同じ | 同じ |
| `--mode hash --key-file … --hash-length 64`(40 も同じ)で、`AAAA`、`contact taro@example.com`、`BBBB` | `contact email_<16 進数>` でブロックが終わり、`BBBB` が残る | 行末の 16 進数が 40 文字以上で本文の行になり、`BBBB` が伏せられる |
| `--hash-length 64` で、`t=1 ghp_…` の行 | 同じ | 同じ |

`--hash-length 39` と既定の長さでは変わらない。短い語でも(`x@example.org done`)、列が合えば変わる。2 回目のラベルは新しい連番なので、1 回目のラベルと同じ番号になる(44 行目と同じ)。

### 依頼された確認の結果

- `/cygdrive/`: 実装は仕様 4.8 と合う。大文字・小文字、形の前の条件、空白を含む名前、対象外の名前、`PATH=`、JSON の文字の `\n`、`scp` の `:` の後ろ、`--deny`、`--allow` を確かめた。`/opt/cygdrive/…`、`/cygdrive/cc/…`、`/cygdrive/1/…`、ドメインのある URL は変わらない。`private_key: /cygdrive/c/Users/Taro Yamada/.ssh/id_rsa` の `Yamada` が残るのは、LIMITATIONS.md の既知の形(Q116)
- `restore --source`: `/cygdrive/` の形と対象外の形を含む 28 行で、mask と `--mask-format '{type}_{n}'` が 1 バイトも違わずに戻る。2 回目の mask の stdout も変わらない
- LIMITATIONS.md 95 行目に足した形: Q125 の 8 形と Q126 の 4 形を、後ろの要素の有無を変えた 20 行にして、そのまま、`path=` を前に付けた形、`"` で囲んだ形の 3 通りで `mask` に通した。1 バイトも変わらない
- LIMITATIONS.md 49 行目: 書いた形をすべて確かめた。1 つ目が印だけの形は通知 0 件で本文が残る。1 つ目が `\n` で終わる形は `\nBBBB\n` が残り、閉じなければ通知 1 件、次の行が END なら 0 件。次の行が本文の形なら伏せられる
- 53 行目の、トークンの行と `{type}{n}` の `email1` の行は書いたとおり。ほかの形は上の反例のとおり
- `questions-1.md`: 分ける前(5e333ae)の 136〜251 行目と、`questions-1.md` の 5 行目以降は `diff` で差分なし。分ける前の 1〜135 行目、252〜300 行目と、今の `questions.md` の対応する行も差分なし。Q113〜Q122 へのアンカーのリンクはない
- 仕様 9 章、`docs/detection.md`、CHANGELOG の変更は、実装と合う

### 確認のコマンド

d9e37a6 で実行した。

- `./scripts/go test ./...`: すべて ok(キャッシュの結果)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)
- `git diff --stat b68dd83..d9e37a6 -- '*.go'` の変更は `userpath_test.go` だけ

### 止まる条件の判断

- 今回の差分で入った不具合は 0 件。`/cygdrive/` の実装と分割に指摘はない
- ただし、値が残る形の指摘は、5〜8 回目のすべてで出ている(Q123、Q124、Q125、Q127)。どれも前からの動きで、起きる形は狭くなっている。Q127 で止まるので、続け方も合わせて判断を受ける

### log-review.md の分割

書き足すと 300 行を超えるので、5〜6 回目を [log-review-2.md](log-review-2.md) に分けた。節の見出しと内容は変えていない(`diff` で差分なし)。計画の README と log-review-1.md のリンクを直した。

### 残っていること(8 回目のあと)

- Q127 は 2026-11-02 に、案のとおりと確定した。実装は変えず、`/` が重なるパスを LIMITATIONS.md に書く
- 修正: LIMITATIONS.md の 53 行目、95 行目、Q127 の分。Q の範囲を Q127 までに直す(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)
- 修正のあとの別のセッションのレビュー(9 回目)
- push と PR の説明の更新(8 回目の指摘を含む)。push はユーザーが実行する

## 8 回目の `/code-review` の修正

上の「残っていること」の修正。実装は変えていない(`git diff --stat -- '*.go'` は空)。資料だけの修正。

- LIMITATIONS.md 53 行目: 「それ以外の形では、2 回目の出力は変わりません」をやめ、「たとえば」で 4 つの形を挙げた(トークンの行、`{type}{n}` の `email1`、ラベルと空白の長さが BEGIN の印の列と同じになる行、`--hash-length` が 40 以上で行末がハッシュ値になる行)。mask のラベルが 1 回目と同じ番号になることも書いた
- LIMITATIONS.md 95 行目: 振り分けどおりの形を足した。MSYS2 のホームディレクトリ、ドライブ名だけの形で区切りが混ざるパス、UNC の `/` の形(既存の UNC の項目に足した)
- 同じ行に Q127 の `/` が重なるパス(6 形)を足した
- Q の範囲を Q127 までに直した(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)

### 確認の結果

1cb3532 のバイナリ(`./scripts/go build -o /cache/lgr9 ./cmd/logscrub`)で確かめた。値はすべて架空。

書いた文字列を打ち直さず、修正のあとの LIMITATIONS.md の 53 行目、95 行目から、`` ` `` の中身を取り出して通した。

- 95 行目: `…` を含まない 48 形(足した 13 形をすべて含む)を、そのまま `mask` に通して 1 バイトも変わらない。`path=` を前に付けた形、`"` で囲んだ形、`/x` を後ろに付けた形の 144 行も変わらない。足した 13 形は、`\x` を後ろに付けた形も変わらない。stderr の通知も出ない
- 53 行目の、変わる形: 下の表のとおり

| 形 | 1 回目 | 2 回目に変わるところ |
|---|---|---|
| BEGIN、`AAAA`、`ghp_…`(行全体)、`BBBB` | `<secret_2>` のあとの `BBBB` が残る | `BBBB` が `<secret_1>` |
| `--mask-format '{type}{n}'` で、BEGIN、`AAAA`、`x@example.org`、`BBBB` | `email1` のあとの `BBBB` が残る | `BBBB` が `secret1` |
| `12:00:01: -----BEGIN PRIVATE KEY-----`、`12:00:02: AAAA`、`x@example.org BBBB`、`12:00:04: CCCC` | `<email_1> BBBB` でブロックが終わる | `<email_1> <secret_1>`、`12:00:04: <secret_2>` |
| `--mode hash --hash-length 64`(40 も同じ)で、BEGIN、`AAAA`、`contact taro@example.com`、`BBBB` | `contact email_<16 進数>` のあとの `BBBB` が残る | `BBBB` が `secret_<16 進数>` |

- `--hash-length 39` では変わらない。`--hash-length 64` の `t=1 ghp_…` の行は変わる(行末がハッシュ値になる行に含まれる)
- `<email_1> ` は 10 文字、`12:00:01: ` の BEGIN の列は 10 で、書いたとおり
- 53 行目の、変わらない形: `-----BEGIN PRIVATE KEY-----` と `<secret_1>` の 2 行、本文の形でない行で終わるブロック、1 行の形(`{"log":…,"stream":"x"}`、`"…" x`)の単独と、ブロックのあとの形は、2 回目の stdout が変わらない。BEGIN の行番号の通知は、1 行の形の単独を除いて残る(単独の 1 行の形は、範囲の全体が置換済みなので通知しない。仕様 4.1)

### 確認のコマンド

- `./scripts/go test ./...`: すべて ok(キャッシュの結果。`.go` の変更がないため)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)
- ファズテスト、`-perf`、`-race` は実行していない(実装を変えていない)

### 見つかったこと

- 判断が必要なこと、仕様との食い違いは、見つからなかった。Q は足していない
- README の「冪等」の項は、例外の説明を LIMITATIONS.md の「冪等性」へリンクしているが、END のないブロックの例外は「secret」の 44、53 行目にある。44 行目の時点からの配置で、依頼の範囲の外なので変えていない

### 残っていること(8 回目の修正のあと)

- 修正のあとの別のセッションのレビュー(9 回目)。範囲は資料の差分
- push と PR の説明の更新(8 回目の指摘を含む)。push はユーザーが実行する

## 9 回目の `/code-review`

別のセッションで `1cb3532..194498a` を中心に high で行った(資料だけの差分)。指摘の全体と扱いは PR の説明に書く(push と PR の説明の更新は、許可を得てから行う)。判断が必要なものは Q128 に書いた。修正はしていない。レビューの終了の条件は、まだ満たしていない(「この PR で直す」が 2 件、判断待ちの Q が 1 件)。

194498a のバイナリ(`./scripts/go build -o /cache/lgr9b ./cmd/logscrub`)で確かめた。値はすべて架空。ファズテスト、`-perf`、`-race` は実行していない(`.go` の変更がないため)。

### 指摘の振り分け

| 指摘 | 振り分け |
|---|---|
| 置換済みのラベルの直後のパスが、2 回目に置換される(`GET http://10.0.0.5/home/dashboard HTTP/1.1`) | Q128 |
| README の「冪等」は、例外を「手で作らない限り現れない入力」として「冪等性」の節へリンクするが、END のないブロックの例外(44、53 行目)が節にない | この PR で直す |
| 44 行目の「その行でブロックが終わり」は、行末の base64 の文字が 40 文字以上のトークン(`ghp_` + 40 文字、`sk_live_` + 99 文字、署名の末尾に `-` `_` のない JWT)で成り立たない。ブロックが続き、後ろの本文は伏せられる | この PR で直す |
| `/Users/` がパスの途中の形(`/Volumes/Data/Users/yamada/x`)と、IP アドレスの URL(`https://10.0.0.1/home/yamada/x`)が残る。94 行目は `/home/` とドメインだけを書く | LIMITATIONS.md に書く |
| 95 行目は一覧に見えるが、一覧にない形も残る(`/Users//yamada`、`file:////home/yamada`、`/cygdrive/c//Users/yamada`、`/mnt/c\Users\yamada`) | LIMITATIONS.md に書く(例であることと、`docs/detection.md` の形に当たらないパスは残ることを書く。形を足し続けない) |
| 53 行目の「mask では…」は、44 行目と同じ文 | 直さない(項目ごとに読まれる) |

### 依頼された確認の結果

- 95 行目: 194498a の本文から取り出した、`…` を含まない 48 形を、12 通りの文脈(そのまま、`path=`、`"`、`'`、`/x`、`\x`、空白、JSON、`cwd:`、`(…)`、`,`、`file=…/a.txt:12`)で `mask` に通した。576 行とも 1 バイトも変わらず、stderr の通知も出ない
- 53 行目の、変わる 4 形: 書いた文字列で、書いたとおり。`--hash-length` は 39 で変わらず、40 と 64 で変わる。`ghp_` は 36 文字で確かめた
- 53 行目の、変わらない形: 2 回目の stdout は変わらない。`{"log":…,"stream":"x"}`、`"…" x` を単独で流すと、2 回目に BEGIN の通知は出ない。ブロックのあとに置くと、前のブロックの通知だけが残る。「ことがあります」の範囲なので、指摘にしていない
- Q の範囲: 4 か所とも Q127 まで。8 回目の修正の記録の 48 形、144 行、13 形の数も合う

### 確認のコマンド

- `./scripts/go test ./...`: すべて ok(キャッシュの結果)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)
- `git diff --stat 1cb3532..194498a -- '*.go'`: 空

### 止まる条件の判断

- 今回の差分で入った不具合は 0 件。ただし、「3 回レビューしても重要な指摘が減らない」に当たると判断した。値が残る形か出力が変わる形の指摘が、5〜9 回目のすべてで出ている(Q123、Q124、Q125、Q127、Q128)
- Q128 は `user_path` の最初からの動きで、Q127 までより現実のログに近い。修正を重ねずに止まり、続け方も合わせて判断を受ける

### 残っていること(9 回目のあと)

- Q128 は 2026-11-02 に、案のとおりと確定した。続け方も推奨のとおり: 95 行目には形を足し続けず、一覧は例であることを書く
- 修正: 上の表の分と Q128。Q の範囲を Q128 までに直す
- 修正のあとの別のセッションのレビュー(10 回目)。範囲は修正の差分と Q128 の周辺に絞る
- push と PR の説明の更新(8、9 回目の指摘を含む)。push はユーザーが実行する
