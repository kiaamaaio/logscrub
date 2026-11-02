# logscrub v1.5.0 `/code-review` の修正の記録

[計画](README.md)へ戻る。`/code-review` の修正の内容と、修正のあとの確認を書く。段階ごとの記録は [log.md](log.md)。指摘の全体は PR の説明に書く。

1〜4 回目の記録は [log-review-1.md](log-review-1.md)、5〜6 回目の記録は [log-review-2.md](log-review-2.md) に分けた。

## 7 回目の `/code-review`

別のセッションで `e403f7a..7da1ab3` を中心に high で行った。指摘の全体と扱いは PR の説明に書く(push と PR の説明の更新は、許可を得てから行う)。判断が必要なものは Q125 に書いた。修正はしていない。レビューの終了の条件は、まだ満たしていない。

7da1ab3 のバイナリ(`./scripts/go build -o /cache/lg7 ./cmd/logscrub`)で確かめた。値はすべて架空。ファズテスト、`-perf`、`-race` は実行していない(実装の変更はない)。

### 指摘の振り分け

| 指摘 | 振り分け |
|---|---|
| LIMITATIONS.md の「2 回目の出力は変わりません」が、トークンの行の項目と合わない | この PR で直す |
| 仕様 9 章の「日時の付いた PEM…」の文に、END のある形という条件が書かれていない | この PR で直す |
| `/cygdrive/` と UNC の共有のパスのユーザー名が残り、どの資料にもない | Q125 |
| 同じ行の 1 つ目の BEGIN が 1 行の形でないと、2 つ目の本文が残る。通知が出ない形がある | LIMITATIONS.md に書く |
| log-review.md の「23 形」は、実際は 28 形 | 下に記録した。直す必要はない |

- 「2 回目の出力は変わりません」: 本文、`ghp_…` の行、本文の入力は、2 回目に最後の本文も伏せられる(mask、hash、`{type}_{n}` のどれも出力が変わる)。「本文の形でない行でブロックが終わる形」に含まれるので、言い切りが 44 行目の項目と合わない。`--mask-format '{type}{n}'` では、`<email_1>` にあたる `email1` の行でもブロックが続き、同じように変わる
- 同じ行の 2 つ目の BEGIN: `{"a":"-----BEGIN…","b":"-----BEGIN…\nBBBB\n"}` と `expected -----BEGIN… got -----BEGIN…\nBBBB\n` は本文が残り、通知は 0 件。`{"a":"-----BEGIN…\n","b":"-----BEGIN…\nBBBB\n"}` は本文が残り、通知は 1 件。Q124 の項目は 1 つ目が 1 行の形の場合だけを書いている。END のない鍵が 1 行に 2 つある形で、Q124 と同じ理由から、実装は変えない

### 依頼された確認の結果

- Q124(LIMITATIONS.md 48 行目): 2 形とも書いたとおり。mask、hash、`{type}_{n}` で 2 つ目が残り、通知は 1 件、`restore --source` で戻る。2 回目は stdout が変わらず、END なしの通知は出ない
- 再度流したときの通知(52 行目と、6 回目の修正の表の 6 形): 通知の件数と行番号は、すべて表のとおり
- 47〜51 行目の形も、書いたとおり(51 行目の「通知も出ません」は、END のある形で確かめた。END がなければ、ブロックの通知は出る)
- `user_path`(94 行目): 値の 28 形を、書いた文字列のままと、後ろに要素を足した形で、`mask` に通した。`path=`、`"` を前に付けた形も含め、28 形とも `yamada` が残る。6 回目の修正の「23 形」は数え違いで、今回 28 形すべてを確かめた
- コメント(`pem.go`、`stats.go`、`common.go`)は実装と合う。`git diff -U0 e403f7a..7da1ab3 -- '*.go'` の変更行は、すべてコメント
- Q の範囲: Q124 までに直っている。Q125 は確定のときに直す

### 仕様 9 章の読み方の判断

妥当と判断した。仕様と実装の食い違いではない。

- 文を足した 4f90d6f は、同じコミットで `TestPEMScanner` に END のある `a replaced line with a time stamp`(`t=1 BEGIN`、`t=2 <secret_1>`、`t=3 END`、通知 0 件)を足し、log-review-1.md も「PEM の誤通知」の修正として書いている。1 回目に通知のない出力で、2 回目に誤って通知しないことが目的
- END のある 8 形(列が同じ、幅が違う、`ts=1 msg=`、ヘッダーつき、Docker、CRLF、後ろに別の行)を、mask、hash、`--hash-length 64`、`{type}_{n}`、`{type}{n}` で実行した。2 回目の通知が 1 回目より増える形はない。幅が違う形の短い行は、40 行目の既知の形で、1 回目から通知が出る
- END のない形は 1 回目にも通知が出て、2 回目も同じ件数で残る。本物の鍵が閉じていないので、通知が残るのは 4.1 節の規則のとおり
- ただし、文だけを読むと END のない形も含むように読める。「END のある」を足すと、判断なしで読める

### 確認のコマンド

7da1ab3 で実行した。

- `./scripts/go test ./...`: すべて ok(キャッシュの結果)。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)

### 残っていること(7 回目のあと)

- Q125 は 2026-11-02 に、案のとおりと確定した。`/cygdrive/<ドライブ>/Users/` を形に足し、残りは LIMITATIONS.md に書く
- 修正: Q125 の実装と仕様 4.8、LIMITATIONS.md(52 行目、同じ行の 2 つ目の BEGIN、Q125 の分)、仕様 9 章の文、Q の範囲(Q125 まで)
- 修正のあとの別のセッションのレビュー(8 回目)
- push と PR の説明の更新。push はユーザーが実行する

## 7 回目の `/code-review` の修正

Q125 の回答と、7 回目の指摘の振り分けのとおりに直した。修正の前は 5e333ae。

- `internal/detect/userpath.go`: `/cygdrive/<ドライブ>/Users/` を Windows の形に足した(`windowsSlashStart`)。大文字・小文字を区別せず、空白を含む名前と対象外の名前も Windows の形の規則に従う
- テスト: `TestUserPathForms` に、対象の形、対象外の形、Q125 で LIMITATIONS.md に書いた形を足した。ファズテストの断片に `/cygdrive/` の 3 形を足した(断片の数が変わるので、`testdata/fuzz/` の入力の読まれ方も変わる。これまでの断片の追加と同じ)
- ゴールデン: 変えていない(`git diff --quiet -- internal/transform/testdata`)
- 仕様 4.8 の表、仕様 9 章(`/cygdrive/c/Users/yamada/x` の確認の項目)、`docs/detection.md` の表、CHANGELOG に `/cygdrive/` と Cygwin を足した
- LIMITATIONS.md(ホームディレクトリのパス): Q125 の残りの 7 形を足した。`file:///cygdrive/…` は、ほかの形に合わせて `file:///cygdrive/c/Users/…` と書いた。依頼の一覧にない `\/cygdrive\/c\/Users\/…` も、今回の修正のあとも残る形なので足した
- LIMITATIONS.md(secret)の「2 回目の出力は変わりません」: ブロックを終えた行が置換のあと本文の続きとして読める形(トークンの行、`{type}{n}` の `email1` の行)では、残っていた本文が 2 回目に伏せられて出力が変わる、と書き直した
- LIMITATIONS.md(secret): 同じ行の 2 つ目の BEGIN が残る形を足した(下の表)
- 仕様 9 章の「日時の付いた PEM…」に「END のある」を足した
- Q の範囲を Q125 までに直した(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)

### 同じ行の 2 つ目の BEGIN

7 回目の記録の 3 形に、END で閉じる形と、`"b"` の値が印と `\n` だけの形を足して確かめた。mask、`--mode hash --key-file`、`--mask-format '{type}_{n}'` で同じ結果で、どれも 2 回目の stdout は変わらない。

| 形(`B` は BEGIN の印) | 残るもの | 通知 |
|---|---|---|
| `{"a":"B","b":"B\nBBBB\n"}` | `\nBBBB\n` | 0 件 |
| `expected B got B\nBBBB\n` | `\nBBBB\n` | 0 件 |
| `{"a":"B","b":"B\n"}` の次に `CCCC`(後ろに END の行があっても同じ) | `CCCC` | 0 件 |
| `B B` の次に `CCCC` | `CCCC` | 0 件 |
| `{"a":"B\n","b":"B\nBBBB\n"}`(ブロックが閉じない) | `\nBBBB\n` | 1 件 |
| `{"a":"B\n","b":"B\nBBBB\n"}` の次に END の行 | `\nBBBB\n` | 0 件 |

最後の形は 7 回目の記録にない。1 つ目が複数行の形でも、後ろに END があれば通知が出ないので、LIMITATIONS.md に書いた。`{"a":"B\n","b":"B\n"}` の次の `CCCC` は、1 つ目のブロックの本文として伏せられる。

### 確認の結果

修正のあとの作業ツリーで実行した。ログの追記の前のもの(`.go` は同じ)。

- `./scripts/go test ./...`: すべて ok。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)
- 実バイナリ(`./scripts/go build -o /cache/lg8 ./cmd/logscrub`): `/cygdrive/` の形を含む 9 行(架空の値)で、ユーザー名が `<user_path_N>` になる。`Public`、`ADMINISTRATOR`、`Default User` と、`/opt/cygdrive/…`、`/cygdrive/cc/…` は変わらない
- `restore --source`: mask と `--mask-format '{type}_{n}'` で 1 バイトも違わずに戻る
- 2 回目: mask、`--mode hash`、`--mask-format '{type}_{n}'` で stdout が変わらない
- LIMITATIONS.md に足した 8 形(`file:///cygdrive/c/Users/yamada/x`、`\/cygdrive\/c\/Users\/yamada\/x` など)は、`yamada` が残る
- トークンの行の形(BEGIN、`AAAA`、`ghp_…`、`BBBB`)は、mask、hash、`{type}_{n}` で 2 回目の stdout が変わる。`taro@example.com` の行は、`{type}{n}` で変わり、既定の書式では変わらない
- `paths.log`、`app.log`、`.cache/big.log` の mask の出力は、5e333ae のバイナリと 1 バイトも違わない
- `-race` は実行していない。依頼の確認に入っておらず、変更は検出の中の状態のない関数だけのため

### ファズテスト

各 90 秒。失敗なし。`testdata/fuzz/` への追加もなし。

| 対象 | 実行回数 |
|---|---|
| `FuzzMaskStable` | 993,750 |
| `FuzzHashStable` | 449,403 |
| `FuzzRestoreRoundTrip` | 216,599 |

### 性能

5e333ae のバイナリと交互に 9 回ずつ。`.cache/big.log` は 105MB。「`/x/users/` が多い」は、変更した経路を通る行を並べた 50MB のログ。計画の 4.1 節の基準の範囲内で、低下はない。

| 測定 | 前(最速) | 後(最速) | 差(最速 / 中央値) |
|---|---|---|---|
| mask、`GOMAXPROCS=1` | 173.0 MB/s | 175.2 MB/s | +1.3% / +0.2% |
| mask、`GOMAXPROCS=2` | 314.9 MB/s | 316.7 MB/s | +0.6% / +0.7% |
| `/x/users/` が多い、`GOMAXPROCS=2` | 264.6 MB/s | 266.5 MB/s | +0.7% / +2.1% |

`./scripts/go test -run Perf -v -timeout 40m ./cmd/logscrub -perf`(100MB、3 回の最速、2 コア): 3 つのテストが PASS。mask(ファイルから)は 290.8 MB/s、パイプからは 261.1 MB/s、`GOMAXPROCS=1` は 162.4 MB/s、`GOMAXPROCS=2` は 288.0 MB/s、`--mode hash` は 320.1 MB/s、restore は 258.0 MB/s。前回の値より低いのは、測定の時点のマシンの状態による(上の、同じ時に交互に測った比較では差がない)。値が密な 10MB の行は 19.6〜20.7 MB/s で、仕様 7 章の 50MB/s より低い。v1.4.0 の時点でも 22.6〜23.0 MB/s で 50MB/s より低かった形で、この値は前後の比較をしていないが、変更した経路は `users/` の形でだけ通る。

### 見つかったこと(判断待ち)

- `/MNT/C/Users/yamada/x` と `FILE:///C:/users/yamada/x` は残る(実バイナリで確かめた)。仕様 4.8 の表の Windows の行は、大文字・小文字を「区別しない」とするが、実装が区別しないのは `Users` とドライブ名だけで、`/mnt`、`file:` の語は区別する。5e333ae より前からの動きで、今回の修正では変えていない。`/cygdrive` は、仕様の表のとおり区別しない
- 案: 実装は変えず、仕様 4.8 の「区別しない」を「`/mnt`、`file:` の語を除く」と直し、LIMITATIONS.md に書く。Linux のパスは大文字・小文字を区別するので、`/MNT/` は現実のログに出にくい
- questions.md は 300 行なので、Q を足す前に分割の案を示す必要がある。案: 1〜4 回目の指摘の Q(Q113〜Q122)を `questions-1.md` に移す(番号は変えない)

### 残っていること(7 回目の修正のあと)

- 上の、大文字・小文字の判断
- 修正のあとの別のセッションのレビュー(8 回目)
- push と PR の説明の更新。push はユーザーが実行する

## Q126 の反映

上の「見つかったこと」は、2026-11-02 に案のとおりと確定した(Q126)。実装は変えていない。資料と、テストの表だけの修正。

- 案の `file:` を、確かめた動きに合わせて `file:///` にした。`FILE:/C:/users/yamada/x` は置換されるので、語の区別が効くのは `file:///` の形だけ
- 仕様 4.8 の表、`docs/detection.md`、LIMITATIONS.md に、`/mnt` と `file:///` の語を区別することを書いた。`docs/detection.md` は依頼の範囲になかったが、同じ「区別せず」の文があるので合わせた
- `TestUserPathForms` に、残る 2 形と、置換される 2 形を足した
- questions.md が 300 行なので、Q113〜Q122 を [questions-1.md](questions-1.md) に分けた。番号、節の見出し、内容は変えていない(移した部分が元のファイルの内容のままであることを、スクリプトで確かめた)。計画の README にリンクを足した
- Q の範囲を Q126 までに直した(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)

### 確認の結果

- `./scripts/go test ./...`: すべて ok。`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...`、`./scripts/go run cmd/gofmt -l cmd internal`、`./scripts/doc-size-check`: 通った(gofmt の出力なし)
- `git diff --stat HEAD -- '*.go'` の変更は `userpath_test.go` だけ。`-trimpath -buildvcs=false -ldflags=-buildid=` で作った、b68dd83 と修正のあとのバイナリは 1 バイトも違わない
- LIMITATIONS.md に足した `/MNT/C/Users/yamada`、`FILE:///C:/users/yamada` を、書いた文字列のまま `mask` に通した。どちらも変わらない
- ファズテストと `-perf` は、実装の動きを変えないので実行していない

### 残っていること(Q126 のあと)

- 修正のあとの別のセッションのレビュー(8 回目)。範囲は `5e333ae..` を中心にする
- push と PR の説明の更新。push はユーザーが実行する

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

- Q127 の回答
- 修正: LIMITATIONS.md の 53 行目、95 行目、Q127 の分。Q の範囲を Q127 までに直す(SPEC.md 11 章、DEVELOPMENT.md、`docs/plans/README.md`、計画の README)
- 修正のあとの別のセッションのレビュー(9 回目)
- push と PR の説明の更新(8 回目の指摘を含む)。push はユーザーが実行する
