# ガードレール対応 段階ごとの記録

[計画](../guardrails.md)へ戻る。

### 段階ごとの記録

#### 段階 1: git の pre-commit hook

- `gofmt` は `./scripts/go run cmd/gofmt -l cmd internal` で実行する(`scripts/go` は変えない)。未整形でも終了コードは 0 なので、出力の有無でも判定する
- `scripts/claude-commit-check` は、検査の代わりに `core.hooksPath` を確かめる。hook を有効にし忘れると、Claude のコミットが無検査になるため。無効のとき終了コード 2、有効のとき 0 を確認した
- 実際に失敗させて確かめた(いずれもコミットされず、HEAD は変わらない)
  - 書き方: `git -c user.name=x commit`、`git --no-pager commit`、`git -C "./" commit`
  - 検査: `gofmt`、test、vet(unreachable code)、Windows 向けの vet(`//go:build windows` のファイル)、資料の長さ
  - `main` へのコミット: 別のクローンで止まることを確認した
  - `--no-verify`: 検査を飛ばしてコミットできることを確認した(確認のコミットは取り消した)
- 所要時間: キャッシュありで 1.3 秒、テストのキャッシュなしで 16.6 秒。Bash の既定の時間制限(120 秒)に収まる
- 確認の途中で、確認用のファイルが別の検査で止まっていたものを直した。`go test` は vet の一部(`printf` など)を実行するので、vet だけの確認には `unreachable` を使う

#### 段階 2: 権限の設定

- `.claude/settings.json` の変更は、実行中のセッションに反映される。ただし、反映が 1 手遅れることがある(段階 5 で確認した)
- auto モードのセッションで確かめた。公式資料では、ask ルールは auto モードでも確認の画面を強制し、deny ルールはすべてのモードで止める
- deny: `git -C . commit -n`、`git commit --no-verify`、`git push --force`、`git -C . push --force`、完了した版の計画への `>>` が止まることを確認した
- ask: `git -c push.default=current push --dry-run` で確認の画面が出ることを、セッションの記録(`ruleSource: projectSettings`)で確認した。ユーザーが承認したが、SSH の認証の失敗で送信はされていない
- ask の `Edit` ルールは、リダイレクト(`>> go.mod`)を覆わない。公式資料では、リダイレクトの検査の対象は `Edit` の allow と deny だけ。`go.mod` は段階 4 の pre-commit で守る
- `Write(path)` のルールは一致しないので、パスのルールは `Edit(path)` で書く
- `bypassPermissions` での hook の `"ask"` の動きは未確認のまま。使わないので、確かめない
- deny の `*--no-verify*` はコマンド全体を照合するので、コミットメッセージにこの語を含むコミットも止まる

#### 段階 3: 条件付きの確認

- 使い捨てのクローンで確かめた
  - コマンドの判定: 6 通りの `git commit` の書き方(`-C "a b"`、`-c`、`--no-pager` を含む)を検出し、`git status`、`git log`、`echo git`、`git commit-graph` は通した
  - 確認が出ない: `docs/plans/`、`scripts/build-release` の変更
  - 確認が出る: ゴールデン、`CLAUDE.md`、仕様、検査に関わるスクリプト、新しい `.claude/` のファイル、`t.Skip` の追加(既存と新規のテスト)、`func Test` の削除、`f.Add` の削除、`feature/` 以外のブランチ
  - ファイル名に `"` があっても、出力は JSON として読める
- 判定の取りこぼしは、確認が飛ばされるだけで、検査は pre-commit hook が行う
- 段階 3 のコミットで確認の画面が出ず、セッションの記録で分かった。hook の入力は JSON で、改行は `\\n` の 2 文字になる。判定は `git` の直前に英数字がないことを求めるので、`n` の直後の `git commit` を見逃していた。元の版にも同じ抜けがあり、複数行のコマンドでのコミットは検査されていなかった。`\\n`、`\\r`、`\\t` を直前の文字として認める形に直し、実際の JSON の形で 9 通りを確かめた。修正のあとのコミットで、確認の画面が出たことをセッションの記録で確認した

#### 段階 4: 依存の許可制

- 使い捨てのクローンで確かめた。1 行の `require` と、ブロックの `require`(`// indirect` つき)の両方で、コミットが止まる。許可リストに足すと、そのモジュールは通る
- `--network none` は変えていない。`./scripts/go get` は確認の画面が出る設定だが、許可しても取得はできない。実際に依存を許可するときに、取得の手順を決める

#### 段階 5: 資料の形式と運用

- `docs/templates/plan.md`、`docs/templates/research.md`、`docs/plans/README.md` を作り、CLAUDE.md を更新した
- 計画の形式は 3 つのファイルの案内を 1 つの形式のファイルにまとめた(形式のファイルを増やさないため)
- 段階の完了時に止まるルールに、依頼に続けて進めるとあれば続ける、という例外を加えた(計画にはなかった)
- 未実施: 新しいセッションで調査を 1 件依頼し、形式に沿って書かれることの確認。このセッションには CLAUDE.md の変更前の内容が読み込まれていて、確かめられない
- 段階 2 の不具合を直した: deny の `Bash(go *)` が、公式資料の説明と違って `./scripts/go` も止めていた。段階 2 では止めたいコマンドだけを確かめ、通すべきコマンドを確かめていなかったので、見逃した。この間のコミットの検査は pre-commit hook が行っていたので、影響はない
  - 切り分けの途中で、`Bash(/usr/bin/go *)` が原因と誤って判断し、記録に書いた。設定の変更の反映が 1 手遅れることがあり、外した効果を取り違えた。原因は `Bash(go *)` で、どちらのルールも外した
  - ホストの go の禁止は `scripts/claude-commit-check` に移した。コマンドの先頭の語が `go` のときだけ、終了コード 2 で止める。14 通りで確かめ、実際に `./scripts/go test`、`./scripts/go vet` が通り、`go version` が止まることを確認した
  - 文字列で判定するので、誤検知がある(`;` のあとに go が続く文字列が、コマンドやコミットの内容の中にあっても止まる)
- 権限のルールを変えるときは、止めるコマンドと通すコマンドの両方を確かめる

#### 段階 6: 既存の計画の分割

- v1.0.0〜v1.3.0 とこの計画を、入口、`questions.md`、`log.md` に分けた。v1.0.0 の段階は `stages-1.md`、`stages-2.md` に、v1.2.0 の Q は `questions-1.md`、`questions-2.md`(Q64 で分けた)に分けた
- 最大のファイルは `docs/plans/v1.2.0/log.md` の 33.6KB で、上限(40KB)に収まる
- 完了した版は、進捗の表にも詳しい記録があるので、6 章全体を `log.md` へ移した。v1.3.0 とこの計画は、進捗の表を入口に残した
- 分割の処理で確かめた: 元の行(5 件で合計 1854 行)がすべて残り、増えた行は案内の行と、移した先の節の見出しだけ。変えたのは、移した行の相対リンクと案内の行だけ。`docs/plans/` の相対リンクの切れは 0 件
- 分割の前に deny ルールを外し、分割のあとで新しいパスも含めて戻した。`docs/plans/v1.2.0/log.md` と `docs/plans/v1.0.0.md` への `>>` が止まり、`./scripts/go version` が通ることを確認した

#### 段階 7: PR によるマージの運用

- push の認証: SSH の鍵はあるが、このセッションから使える agent がない。`gh` のトークンには `repo` の権限があり、次の形の `--dry-run` が通った。リモートの設定は変えていない
  - `git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push https://github.com/kiaamaaio/logscrub.git HEAD:refs/heads/<ブランチ>`
- deny に `git merge` と `gh pr merge` を加えた(`git merge` は ask から移した)
  - 止まる: `git merge --no-ff`、`git -C . merge`、`gh pr merge`、`gh --repo ... pr merge`。止まらなかった場合に備えて、存在しないブランチと PR 番号で確かめた
  - 通る: `git merge-base`、`git log`、`gh pr list`、`./scripts/go version`
- `docs/templates/pr.md` を作り、CLAUDE.md のブランチ運用と DEVELOPMENT.md のリリースの手順を直した
- `develop` から `main` へのマージも、deny により人が行う形になった
- GitHub のマージ方法を、ユーザーの確認を得て merge commit だけにした。`gh api repos/kiaamaaio/logscrub` で読み直し、`allow_merge_commit` が true、`allow_squash_merge` と `allow_rebase_merge` が false であることを確認した

