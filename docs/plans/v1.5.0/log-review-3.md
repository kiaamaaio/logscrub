# logscrub v1.5.0 `/code-review` の修正の記録(7 回目、Q126)

[計画](README.md)へ戻る。1〜4 回目は [log-review-1.md](log-review-1.md)、5〜6 回目は [log-review-2.md](log-review-2.md)、8 回目は [log-review-4.md](log-review-4.md)、9 回目以降は [log-review.md](log-review.md)。節の見出しと内容は、分ける前のまま。

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
