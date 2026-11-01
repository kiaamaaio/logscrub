# ガードレール対応 実装計画

- 目的: Claude Code に実装を任せるときの検査漏れと、文章だけのルールの破れを、機械で防ぐ。あわせて、テストが通っても値が漏れる変更を人の確認に回す
- 開発環境・設計の注意点: [DEVELOPMENT.md](../../../DEVELOPMENT.md)
- 前提: logscrub の機能・出力は変えない。利用者から見た変更がないので、CHANGELOG.md には書かない
- ブランチ: `feature/v1.3.0-custom-values`(Q86)。段階ごとにコミットし、develop へは、指示があってから、`/code-review` のあとで AI が PR を作り、人がマージする(CLAUDE.md)
- 各段階の完了条件: `./scripts/go test ./...` と `./scripts/go vet ./...` が通ること(CLAUDE.md)に加え、段階ごとの「確かめること」を実際に動かして確かめること
- **5 章の回答待ちの項目は、推測で実装しない。** 各段階の「前提となる確認」が決まるまで、その段階には入らない

---

## 1. 範囲

| 対象 | 内容 | 段階 |
|---|---|---|
| コミットの検査 | git の pre-commit hook に検査を集め、書き方によらず必ず動かす | 1 |
| 検査の追加 | `gofmt`、Windows 向けの vet | 1 |
| 取り消しにくい操作の確認 | push、マージ、ガードレール自体の変更を確認必須にする | 2 |
| 条件付きの確認 | 特定の変更を含むコミットだけ、コミット前にユーザーに確認する | 3 |
| 値の漏れにつながる変更の確認 | ゴールデンの変更、テストの弱体化の検知 | 3 |
| 依存の許可制 | `go.mod` の `require` を、許可リストと比べる | 4 |
| 資料の形式と運用 | 計画と調査の形式、段階の完了時に止まる運用など | 5 |
| 既存の計画の分割 | 既存の計画を、Q90 の形に分ける | 6 |
| マージの運用 | AI は PR までとし、マージは人が行う | 7 |

範囲外:

- CI(GitHub Actions)。push は指示があるまで行わず、開発も 1 人のため、後回しにする
- 全 Bash コマンドの確認制。確認が多すぎると、中身を見ずに承認するようになるため
- 通常のコミットごとの確認。feature ブランチのコミットは push 前ならローカルで取り消せるため
- 人のコミットを検査で縛ること。人は `--no-verify` で自分の判断でコミットできる状態を保つ

---

## 2. 調査の結果(2026-11-01 に確認)

### 確かめた事実

| 確認したこと | 確かめた方法 | 結果 | 影響 |
|---|---|---|---|
| 今の Claude の hook の判定 | 正規表現に 7 通りのコマンドを当てた | `git -c user.name=x commit`、`git --no-pager commit`、`git -C "a b" commit` が素通りする | 段階 1 |
| git の hook の有無 | `git config core.hooksPath`、`.git/hooks` | 設定なし、hook なし | 段階 1 |
| 検査の所要時間 | `./scripts/go test -count=1 ./...` | 全体で 16.5 秒(うち `internal/detect` が 15.1 秒) | Bash の既定の時間制限(120 秒)の範囲に収まる |
| 未整形のファイル | `gofmt -l` | 現在のブランチで `internal/detect/detector.go`、`secret.go`。develop には未整形のファイルがない | 段階 0。v1.3.0 の作業で入った |
| ホストの Go | `command -v go` | `/usr/bin/go` がある | 段階 2 |
| `CLAUDECODE` 環境変数 | このセッションの `env` | `CLAUDECODE=1` が設定されている | Q85 |
| 既存の `t.Skip` | `grep` | 3 か所。すべて `cmd/logscrub/perf_test.go` | 段階 3 は追加の行だけを見る |
| ゴールデンの更新の仕組み | `grep`、`golden_test.go` | `-update` のフラグはなく、期待値は手で確認したもの | 段階 3 |
| 依存の方針の記述 | `grep` | `CLAUDE.md:15`、`README.md:15`、`docs/SPEC.md:118`(決定事項 13)、`docs/spec/modes-cli.md:131`、`docs/spec/acceptance.md:194`、`docs/DEVELOPMENT.md:28` | Q87 |
| リポジトリの公開範囲 | `gh repo view` | PUBLIC | 範囲外の CI を入れるときの参考 |

### 公式資料で確かめたこと(hooks、permissions)

- PreToolUse hook は `hookSpecificOutput.permissionDecision` に `"ask"` を返すと、ユーザーに確認できる。`permissionDecisionReason` は確認の画面に表示される
- 終了コード 2 は、JSON の内容によらず呼び出しを止める。確認を求めるときは、終了コード 0 で JSON を返す
- 権限のルールは deny、ask、allow の順に評価する。`&&` などでつないだコマンドは、部分ごとに deny と ask を適用する
- `Bash(git push *)` は `git -C . push origin main` や `git -c push.default=current push origin main` に**一致しない**。ルールは文字列の照合で、確実な防御にはならない

### 推測・未確認

- hook の `"ask"` と allow ルールの組み合わせ、`bypassPermissions` モードでの動き(資料から読み取れなかった)
- `Edit` の ask ルールが Bash のリダイレクト(`>> go.mod`)にも効くか(資料には allow と deny の記述しかなかった)
- `.claude/settings.json` の変更が、実行中のセッションにいつ反映されるか

いずれも段階 2・3 の最初に実際に動かして確かめる。

---

## 3. 設計の方針

### 3.1 2 種類の hook の役割を分ける

| hook | 役割 | 理由 |
|---|---|---|
| git の pre-commit | 検査(資料の長さ、`gofmt`、test、vet)。失敗なら止める | git が必ず実行するので、コマンドの書き方に左右されない |
| Claude の PreToolUse | 確認(ユーザーに聞く)。検査はしない | ユーザーに確認を求められるのはこちらだけ |

同じ検査が二重に走らないよう、検査は pre-commit へ移す。pre-commit の失敗の出力は Bash の結果として Claude に返るので、Claude は今までどおり原因を読める。

### 3.2 pre-commit が確認の代わりに止めるもの

Claude の hook は文字列の判定なので、書き方によっては確認が飛ばされる。そのため、次のものは pre-commit でも止める。

- `main` へのコミット(CLAUDE.md の運用)。`git merge` は pre-commit を通らないので、リリースのマージには影響しない。衝突を解決して `git commit` するときは止まるので、人は `--no-verify` を使う
- 許可リストにない依存(段階 4)

### 3.3 確認する変更の判定

`git commit` の hook の時点では、同じコマンドの中の `git add` はまだ実行されていない。そのため、ステージした変更だけでなく、`git diff --name-only HEAD` と追跡されていないファイルを合わせて判定する。

---

## 4. 実装の段階

### 段階 0: v1.3.0 の未整形の修正

- **作業:** `internal/detect/detector.go`、`secret.go` に `gofmt` をかける。v1.3.0 の作業で入ったものなので、`feature/v1.3.0-custom-values` で直す
- **確かめること:** `gofmt -l` の出力が空であること

### 段階 1: git の pre-commit hook

- **作業:**
  - `.githooks/pre-commit` を作る。誰のコミットでも動かす(Q85)。`scripts/doc-size-check`、`gofmt -l`、`./scripts/go test ./...`、`./scripts/go vet ./...`、`GOOS=windows GOARCH=amd64 ./scripts/go vet ./...` を実行する
  - `gofmt` は Docker コンテナ内で実行する(`scripts/go` は `go` しか実行しないので、`go vet` と同様に呼べる形を決める)
  - `main` でのコミットを止める(3.2)
  - `scripts/claude-commit-check` から検査を外す
  - 有効にする手順(`git config core.hooksPath .githooks`)を DEVELOPMENT.md 1 章に書く
- **確かめること:**
  - 素通りした 3 通りの書き方で、検査が動くこと
  - わざと失敗する変更で、コミットが止まること
  - `git commit --no-verify` を人が実行すると、検査が飛ばされること
  - コミット全体の所要時間を測り、記録に書くこと

### 段階 2: 権限の設定

- **前提となる確認:** 2 章の未確認の項目を、確認のルールを 1 つ入れて試す
- **作業:** `.claude/settings.json` に `permissions` を加える

| 区分 | 対象 |
|---|---|
| ask | `git push`、`git merge`、`.claude/`、`.githooks/`、`scripts/claude-commit-check`、`scripts/doc-size-check`、`scripts/go`、`scripts/allowed-modules`、`CLAUDE.md`、`go.mod`、`go get` |
| deny | `git push --force` と `-f`、`git commit --no-verify` と `-n`、完了した版の計画(`docs/plans/v1.0.0.md`〜`v1.2.0.md`)の編集 |

- `git -C` などの別の書き方のために、`Bash(git * push *)` の形も加える。ただし、文字列の照合なので完全には防げない。確実に守るのは pre-commit の範囲だけと考える
- **確かめること:** 各ルールを実際のコマンドで発動させ、`git -C . push` の形も含めて結果を記録する(実際には push しない。確認の画面で拒否する)

### 段階 3: 条件付きの確認

- **作業:** `scripts/claude-commit-check` を、次のどれかに当たるときに `"ask"` を返す形に変える。理由は `permissionDecisionReason` に書く
  - 現在のブランチが `feature/` で始まらない
  - 変更に `internal/transform/testdata/*.golden`、`go.mod`、`.claude/`、`.githooks/`、検査に関わるスクリプト(Q88)、`CLAUDE.md`、`docs/SPEC.md`、`docs/spec/` のどれかを含む
  - `*_test.go` の差分に、`t.Skip` の追加、`func Test` / `func Fuzz` の削除、`f.Add` の削除を含む
- コマンドの判定の正規表現は、`git` と `commit` の間のオプションを広く受ける形に直す。検査の必須の役割は pre-commit にあるので、ここは取りこぼしがあってもよい
- **確かめること:** 条件ごとに確認が出ること、通常の feature ブランチのコミットでは確認が出ないこと

### 段階 4: 依存の許可制

- **作業:**
  - `scripts/allowed-modules` を空で作る(1 行に 1 モジュール)。`go.mod` の `require` に、ここにないものがあれば pre-commit で止める
  - CLAUDE.md の依存の記述を「使わない。必要になったら、実装せずに確認する」に直す(Q87)。仕様と README は変えない
- 許可の流れ: 計画の段階で Q に書く。実装中に必要になったら、実装を止めて確認する。確認では、標準ライブラリで足りない理由、間接依存の数、ライセンス(配布バイナリへの表示の要否)、保守の状況を示す
- `scripts/go` の `--network none` は変えない。実際に依存を許可するときに、取得の手順を決める
- **確かめること:** `require` を足すと止まること、許可リストに足すと通ること(確かめたあと、どちらも元に戻す)

### 段階 5: 資料の形式と運用

- **作業:**
  - `docs/templates/plan.md`、`docs/templates/research.md` を作る。調査の形式では「確かめた事実」(確かめた方法を添える)と「推測・未確認」を分ける。計画の形式は Q90 の分け方(入口、`questions.md`、`log.md`)にする
  - `docs/plans/README.md` を作る。版ごとの Q の範囲と状態の索引だけを書く(Q90)
  - CLAUDE.md に、次の内容を加える。資料の長さの目安に収まる量にする
    - 計画と調査の形式へのリンク、調査の置き場(`docs/research/<日付>-<内容>.md`)、版に属さない計画の置き場(`docs/plans/misc/<内容>.md`)
    - 実装計画の分け方(Q90)。「Q が増えたら分ける」の記述は、最初から分ける形に置き換える
    - 依頼の 4 項目(目的、範囲外、完了条件、止まる条件)
    - 止まる条件: 仕様と食い違うとき、公開のオプションや出力の形を変えるとき、既存の期待値を変えるとき、同じ失敗を 2 回直せなかったとき
    - 段階の完了時に、コミット後に止まって差分と結果を報告し、次へ進む許可を待つこと
    - ゴールデンの差分の理由を、計画の記録に書くこと
    - 実行していない確認を、通ったと報告しないこと(コマンドと出力を添える)
    - develop へのマージの前に、実装とは別のコンテキストで `/code-review` を行うこと
    - 実ログをリポジトリに入れないこと、`testdata` は架空の値だけにすること
    - 版の完了条件に、時間を決めた `-fuzz` の探索と `-perf` の測定を入れること
  - DEVELOPMENT.md 1 章の hook の説明を、3.1 の役割に合わせて直す
- **確かめること:** `scripts/doc-size-check` が通ること。新しいセッションで調査を 1 件依頼し、形式に沿って書かれること

### 段階 6: 既存の計画の分割

- **作業:**
  - v1.0.0〜v1.3.0 とこのガードレールの計画を、Q90 の形に分ける(Q91)。文章は変えず、移すだけにする
  - CLAUDE.md の「完了した版は分割しない」を、「内容は書き換えない」に直す
  - 段階 2 の deny ルールを一時的に外し、分割のあとで新しいパスも含めて戻す
- **確かめること:** 分割の前後で、本文の行の集合が一致すること(見出しのリンクとして足した行を除く)、`scripts/doc-size-check` が通ること、計画どうしのリンク 10 件が切れていないこと

### 段階 7: PR によるマージの運用

- **前提となる確認:** push の認証。このセッションの SSH は失敗し、`gh` はログイン済みなので、どちらで push するかを確かめる
- **作業:**
  - `.claude/settings.json` の deny に `gh pr merge` と `git merge` を加える(`git merge` は ask から移す)。段階 5 の不具合があったので、止めるコマンドと通すコマンドの両方を確かめ、反映の遅れも考えて、変更の次の手で確かめる
  - `docs/templates/pr.md` を作る。目的、確かめたこと、ゴールデンの差分の理由、未確認の事項、`/code-review` の結果を書く
  - CLAUDE.md のブランチ運用を、Q92 の形に直す(PR は AI が作り、マージは人が行う)
  - GitHub の設定を、マージの方法を merge commit だけにする形に変える。リポジトリの設定の変更なので、実行の前に確認する
- **確かめること:** 上の deny の動作、`scripts/doc-size-check`

---

## 5. 未確定事項

別のファイルに移した: [未確定事項](questions.md)

---

## 6. 進捗

| 段階 | 状態 | メモ |
|---|---|---|
| 計画 | 完了 | 2026-11-01 作成。Q85〜Q93 は確定 |
| 0. 未整形の修正 | 完了 | 2026-11-01。`gofmt` のみで、動作の変更はない |
| 1. git の pre-commit hook | 完了 | 2026-11-01。検査を `.githooks/pre-commit` へ移した |
| 2. 権限の設定 | 完了 | 2026-11-01。deny を 5 通り、ask を push で確認した。ホストの go の禁止は段階 5 で hook に移した |
| 3. 条件付きの確認 | 完了 | 2026-11-01。`scripts/claude-commit-check` が `"ask"` を返す |
| 4. 依存の許可制 | 完了 | 2026-11-01。`scripts/allowed-modules` は空。仕様と README は変えていない |
| 5. 資料の形式と運用 | 一部未確認 | 2026-11-01。作成は完了。新しいセッションでの確認が未実施 |
| 6. 既存の計画の分割 | 完了 | 2026-11-01。全 5 件を分割した。本文の変更なし |
| 7. PR によるマージの運用 | 完了 | 2026-11-01。GitHub のマージ方法を merge commit だけにした |
| 8. 入口のフォルダへの移動 | 完了 | 2026-11-01。Q93。入口を `<版>/README.md` へ移した |

別のファイルに移した: [段階ごとの記録](log.md)
