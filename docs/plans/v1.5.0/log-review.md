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

## 9 回目の `/code-review` の修正と Q128

上の「残っていること」の修正。修正の前は d5c6d2f。

### 分割

書き足すと 300 行を超えるので、先に 7 回目、7 回目の修正、Q126 の反映を [log-review-3.md](log-review-3.md) に分けた(e980cc4)。節の見出しと内容は変えていない(`diff` で差分なし)。リンクは、計画の README、log-review-1.md、log-review-2.md、この資料の 5 行目、questions.md の 7 回目と Q125 の 2 か所を直した。

### Q128 の修正

- `internal/detect/userpath.go`: `pathBoundary` に「置換済みのラベルの直後でない」を足した。形の判定はすべて `pathBoundary` を通るので、形ごとの変更はない。`>` の 1 文字でなく、`label.Format.EndsAt` で判定する(`[{type}-{n}]` でも効き、`x>/home/yamada`、`<user>/home/yamada`、`<email_01>/home/yamada` は今までどおり置換される)。書式を持つため、`userPathFinder` の関数をメソッドにした
- hash の出力は末尾が英数字なので、今の文字の条件で対象外のまま。`{type}_{n}`、`{type}{n}` のラベルも同じ
- 仕様 4.8 の形の前の条件と理由、仕様 9 章、LIMITATIONS.md(ホームディレクトリのパスの末尾の項目)に書いた
- テスト: `TestUserPathAfterLabel`(形ごと、書式ごと、ラベルでない形)、`TestUserPathAfterReplacedValue`(Q128 の表と「ほかに起きる形」。mask 4 書式と hash 2 種の 2 回目、`restore`)。`fuzzFragments` に、値の直後のパスの 11 形を足した(断片の数が変わるので、`testdata/fuzz/` の入力の読まれ方も変わる)
- `/home/yamada/home/hanako` の 1 回目の `/home/<user_path_1>/home/hanako` も同じ原因で、2 回目に `hanako` が置換されていた。Q128 の一覧にない形だが、同じ修正で直る。テストと断片に足した
- 修正の前に新しいテストと断片を流し、`TestUserPathAfterReplacedValue` と `FuzzMaskStable` の種が Q128 の形で失敗することを確かめた(`the second pass would replace a value that is not next to a placeholder`、`match: "dashboard"`)
- 修正のあとに直したのは、新しいテストの期待値の誤り 6 件で、実装は変えていない。`:` の直後の `/Users/` は macOS の形、`file:/C:/users/` は `/C:/` の前の `:` で、ラベルの直後かに関係なく対象になる(今の仕様どおりで、1 回目と 2 回目で変わらない)。ドライブの形でだけ読める小文字の `users` の行に変え、残る 3 形はテストの中に「対象」として残した
- ゴールデン: 変えていない

### 9 回目の指摘の修正

- README の「冪等」: 例外に END の印のない PEM の鍵のブロックを足した。LIMITATIONS.md の「冪等性」に項目を足し、「secret」の項目へリンクした。仕様 7 章は変えていない(依頼の範囲の外。手で作った入力に限る但し書きと、END のないブロックの例外の関係は、10 回目のレビューの目で見てほしい)
- LIMITATIONS.md 44 行目: 行末に base64 の文字が 40 文字以上続くトークンは本文の行として読まれ、ブロックが続くことを書いた
- LIMITATIONS.md 94 行目: `/Users/` がパスの途中の形と、IP アドレスの URL を足した
- LIMITATIONS.md 95 行目: 形は足さず、`docs/detection.md` の表の形に当たらないパスは残ること、一覧は例であることを書いた
- Q の範囲を Q128 までに直した(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)
- CHANGELOG は変えていない。`user_path` は v1.5.0 で加わるので、v1.4.0 から見た変更ではない

### 速度のための変更

最初の修正では、`pathBoundary` が毎回 `EndsAt` を呼び、変更した経路だけを通すログで 5% を超える低下が出た。原因を直した。どれも結果は変えない。

| 段階 | `/x/users/` が多い(最速 / 中央値) | `/home/` が多い | ラベルの直後のパスが多い |
|---|---|---|---|
| 最初の修正 | -7.9% / -9.7% | -6.4% / -3.2% | -37.7% / -39.0% |
| `matchAt`、`EndsAt` をポインタの受け手に(`Format` は 300 バイトを超え、呼ぶたびに写していた) | -2.1% / -3.2% | -3.4% / -3.4% | -6.2% / -8.6% |
| `EndsAt` で、ラベルの先頭になりえない位置を飛ばす | 回数を増やすと -4.6〜-6.1% / -5.9〜-7.2% | -4.3〜-5.4% / -4.0〜-4.6% | +24.3% / +23.4% |
| `pathBoundary` で、ラベルの末尾の文字と一致するときだけ `EndsAt` を呼ぶ(`labelEnd`。最終) | 下の表 | 下の表 | 下の表 |

- 3 行目までの結果を踏まえ、`labelEnd` を足した。末尾が連番や種別名の書式では文字がラベルごとに変わるが、英数字なので、そのラベルの直後は文字の条件で対象外になる
- `internal/label/format.go` の受け手の変更で、`(Format{}).EndsAt` がコンパイルできなくなるので、`email_test.go` の 1 か所を `var zero Format` に直した。期待値は同じ
- ラベルの直後のパスが多いログが速くなったのは、前のバイナリがそのパスを 2 回目に置換していた分がなくなるため

### 確認の結果

下はすべて最終のコードで実行した(コミットの前の作業ツリー。この記録の追記の前)。値はすべて架空。

- `./scripts/go test ./...`: すべて ok。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`(出力なし)、`./scripts/doc-size-check`: 通った
- ゴールデン: `git diff --quiet -- internal/transform/testdata` が成功。1 バイトも変わっていない
- 1 回目の出力: `paths.log`、`app.log`、`.cache/big.log` の mask の出力は、d5c6d2f のバイナリと sha256 が同じ
- Q128 の形と周辺の 14 行(`--domain example.com --deny acme`)を、既定、`[{type}-{n}]`、`{type}_{n}`、`{type}{n}`、`--mode hash` で流した。1 回目の stdout はすべて d5c6d2f のバイナリと同じ。2 回目の stdout はすべて 1 回目と同じ
- LIMITATIONS.md 95 行目: 本文から取り出した `…` を含まない 48 形と、`path=`、`"`、`/x` を付けた 144 行は、`mask --types user_path` で 1 バイトも変わらず、通知も出ない。9 回目の指摘の 4 形(`/Users//yamada`、`file:////home/yamada`、`/cygdrive/c//Users/yamada`、`/mnt/c\Users\yamada`)と 94 行目の 2 形(`/Volumes/Data/Users/yamada/x`、`https://10.0.0.1/home/yamada/x`)も、ユーザー名が残る
- LIMITATIONS.md 44 行目: BEGIN、`AAAA`、トークン、`BBBB` で確かめた。`ghp_` と `sk_live_` の後ろが 39 文字なら `BBBB` が残り、40 文字なら伏せられる。JWT の署名が 39 文字なら残り、40 文字なら伏せられる。署名の末尾の 40 文字に `-` か `_` があると残り、その手前にあれば伏せられる。`{"log":"…\n"}` の形でも、36・40 文字の `ghp_`、24・99 文字の `sk_live_`、20・43 文字の署名で同じ。ブロックが終わる形は、2 回目に `BBBB` が伏せられて出力が変わり、続く形は変わらない
- `-race` は実行していない。依頼の確認に入っておらず、足した項目は読むだけ(検出器の値は作ったあとに変わらない)

### ファズテスト

`./scripts/go test ./internal/transform -run '^$' -fuzz … -fuzztime 90s`。各 90 秒、失敗なし。`testdata/fuzz/` への追加もなし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 896,997 |
| `FuzzHashStable` | 461,625 |
| `FuzzRestoreRoundTrip` | 233,649 |

### 性能

d5c6d2f のバイナリと交互に測った。`big.log` は 105MB で 11 回ずつ。経路だけを通す 3 つは 50MB で、`/x/users/` と `/home/` は 25 回ずつ、ラベルの直後は 11 回ずつ。どの行にも手がかりが 2 つあるログ。計画の 4.1 節の基準(既定で動く検出は前の段階から 5% 以内)の範囲内。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| `big.log`、`GOMAXPROCS=1` | 182.9 MB/s | 178.9 MB/s | -2.2% / -3.2% |
| `big.log`、`GOMAXPROCS=2` | 333.7 MB/s | 330.4 MB/s | -1.0% / -1.1% |
| `/x/users/` が多い、`GOMAXPROCS=2` | 353.5 MB/s | 344.4 MB/s | -2.6% / -1.8% |
| `/home/` が多い、`GOMAXPROCS=2` | 380.5 MB/s | 379.9 MB/s | -0.2% / -0.7% |
| ラベルの直後のパスが多い、`GOMAXPROCS=2` | 380.7 MB/s | 467.6 MB/s | +22.8% / +22.7% |

同じコードの別の回では、`/x/users/` が +0.9〜-0.1% / -1.1〜-1.8%、`/home/` が -0.8〜+0.7% / -0.7%。`labelEnd` の前の `big.log` は -1.1〜+1.0% で、`big.log` の差はこの程度に揺れる。

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 302.0 MB/s、パイプからは 261.5 MB/s、`GOMAXPROCS=1` は 165.5 MB/s、`GOMAXPROCS=2` は 299.5 MB/s、`--mode hash` は 326.9 MB/s、restore は 262.8 MB/s。値が密な 10MB の行は 19.7〜20.8 MB/s で、仕様 7 章の 50MB/s より低い。これまでの記録(19.6〜20.7 MB/s)と同じ既知の形で、今回の変更では変わっていない。

### 残っていること(9 回目の修正のあと)

- 修正のあとの別のセッションのレビュー(10 回目)。範囲は d5c6d2f からの差分と Q128 の周辺に絞る
- push と PR の説明の更新(8、9 回目の指摘を含む)。push はユーザーが実行する

## 10 回目の `/code-review`

別のセッションで `d5c6d2f..a05c16b` と Q128 の周辺を high で行った。指摘の全体と扱いは PR の説明に書く(push と PR の説明の更新は、許可を得てから行う)。判断が必要なものは Q129 に書いた。修正はしていない。レビューの終了の条件は、まだ満たしていない(「この PR で直す」が 2 件、判断待ちの Q が 1 件)。

a05c16b のバイナリ(`./scripts/go build -o /cache/lgr10 ./cmd/logscrub`)で確かめた。値はすべて架空。ファズテスト、`-perf`、`-race` は実行していない(依頼の確認に入っていない)。

### 指摘の振り分け

| 指摘 | 振り分け |
|---|---|
| 仕様 7 章の但し書きと、手で作っていない PEM のブロックの例外が食い違う | Q129 |
| 例外の説明が「END のない」だが、END があっても、途中に本文の形でない行があれば同じ(`LIMITATIONS.md` 39、44、142 行目、README) | この PR で直す |
| 94 行目の「IP アドレスの URL は対象外」は、`[…]` の IPv6 で成り立たない(`http://[2001:db8::1]/home/dashboard` は `/home/<user_path_1>`) | この PR で直す |
| `wslHomeStart` のループ変数 `f` が受け手を隠す | 直さない(動きは正しい) |
| 断片を足すと `testdata/fuzz/` の入力が別の断片を選ぶ(`%len(fuzzFragments)`) | issue の案をユーザーに示す。前からの動きで、利用者に害はない |

### 依頼された確認の結果

- `pathBoundary`、`labelEnd`、`matchAt`、`EndsAt`: 指摘なし。値 31 種、間の文字 24 種、パス 23 種の 17,112 行を、10 種の書式と `--mode hash` で 2 回流し、変わった行は 0 件。対照の `lgr9b`(`.go` は d5c6d2f と同じ)は、既定の書式で 446 行が変わる
- 書式の 10 種: 既定、`[{type}-{n}]`、`{type}_{n}`、`{type}{n}`、`{{type}:{n}}`、`«{type}#{n}»`、`({n}:{type})`、`{n}{type}:`、`{type}_{n} `(末尾が空白)、`<<{type}|{n}>>`
- `restore --source`: `[{type}-{n}]`、`{type}{n}` は 1 バイトも違わない。既定の書式で違う 552 行は、すべて入力に `<email_1>` がある行で、LIMITATIONS.md 112 行目の既知の形
- ラベルの長さ: 連番 18 桁は直後のパスを置換せず、19 桁はラベルでないので置換する。`Scan` と同じ条件
- 44 行目: `ghp_`、`sk_live_`、JWT、`xoxb-`、`github_pat_`、`sk-` の末尾 40 文字で、ブロックが続き、mask と hash の 2 回目は変わらない。36 文字の `ghp_` は `BBBB` にあたる本文が残り、2 回目に変わる
- 95 行目と「冪等性」の項目: リンク先の `## secret`、`## 冪等性` はある
- 崩れたラベル(`&lt;ipv4_private_1&gt;/home/dashboard`)の直後のパスは置換される。mask の出力そのものでないので、指摘にしていない
- 仕様 7 章: Q129 のとおり、食い違う

### 確認のコマンド

- `./scripts/go test ./...`: すべて ok(キャッシュの結果)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)

### 止まる条件の判断

- 今回の差分の実装に、不具合の指摘はない。「重要な指摘が減らない」には当たらないと判断した。指摘は資料の 3 件で、うち 1 件が仕様の食い違いなので、Q129 で止まる

### 残っていること(10 回目のあと)

- Q129 の回答。回答に沿って、上の 2 件と Q129 を直し、Q の範囲を直す
- 修正の前に log-review.md を分ける(書き足すと 30KB を超える)
- 修正のあとの別のセッションのレビュー(11 回目)
- push と PR の説明の更新(8〜10 回目の指摘を含む)。push はユーザーが実行する
