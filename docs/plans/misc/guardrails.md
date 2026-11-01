# ガードレール対応 実装計画

- 目的: Claude Code に実装を任せるときの検査漏れと、文章だけのルールの破れを、機械で防ぐ。あわせて、テストが通っても値が漏れる変更を人の確認に回す
- 開発環境・設計の注意点: [DEVELOPMENT.md](../../DEVELOPMENT.md)
- 前提: logscrub の機能・出力は変えない。利用者から見た変更がないので、CHANGELOG.md には書かない
- ブランチ: `feature/v1.3.0-custom-values`(Q86)。段階ごとにコミットし、develop へのマージは指示があってから `--no-ff` で行う
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
| deny | `git push --force` と `-f`、`git commit --no-verify` と `-n`、ホストの `go`、完了した版の計画(`docs/plans/v1.0.0.md`〜`v1.2.0.md`)の編集 |

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

---

## 5. 未確定事項

番号は v1.3.0 の計画(Q71〜Q84)から続ける。

### Q85: `--no-verify` と `CLAUDECODE` のどちらで、人のコミットを検査から外すか

| 案 | 内容 | 長所 | 短所 |
|---|---|---|---|
| A(採用) | hook は誰のコミットでも動く。人は必要なら `--no-verify` を付ける | 環境変数が消えても検査が止まらない | 人のコミットでも約 17 秒待つ(省略はできる) |
| B | `CLAUDECODE=1` のときだけ検査する | 人は何もしなくてよい | Claude Code の変更で変数がなくなると、検査が無言で動かなくなる |

**回答(2026-11-01)**: A を採用

### Q86: ブランチをどうするか

CLAUDE.md の形式は `feature/<版>-<内容>` だが、この対応には版がない。

**回答(2026-11-01)**: `feature/v1.3.0-custom-values` に含める。新しいブランチは作らない

### Q87: 依存の方針を変えるか

利用者向けの README と、仕様の決定事項 13、受け入れ基準が「標準ライブラリのみ」と約束している。

**回答(2026-11-01)**: 今は仕様と README を変えない。CLAUDE.md だけを「使わない。必要になったら、実装せずに確認する」に直す。実際に依存を許可するときに、その確認の中で仕様と README を変更する

### Q88: 確認の対象に `scripts/` と資料を含めるか

**回答(2026-11-01)**: `scripts/` 全体ではなく、段階 2 の ask に挙げたスクリプトだけを対象にする。`scripts/build-release` のような、検査に関わらないスクリプトは対象にしない。`docs/plans/` と `LIMITATIONS.md` は確認の対象にしない(更新の頻度が高く、確認が多くなるため)

### Q89: 実ログの置き場を決めるか

**回答(2026-11-01)**: 実ログはない。置き場は決めず、Read の拒否も設定しない。CLAUDE.md のルールだけにする

### Q90: 計画書の肥大化への対応

計画書の大半は Q と段階ごとの記録で、完了した版は書き換えないため、1 版が大きくなるとそのまま残る(`docs/plans/v1.2.0.md` は 94.5KB)。

**回答(2026-11-01)**: 完了した版は動かさず、次の版から次の形にする

  - `docs/plans/<版>.md` を入口のまま残し、範囲、設計、段階、進捗の表だけを書く
  - Q は `docs/plans/<版>/questions.md`、段階ごとの記録は `docs/plans/<版>/log.md` に、最初から分ける
  - 調査の詳細は `docs/research/` に、測定の詳細は `docs/development/performance.md` に置き、計画にはリンクと結論だけを書く
  - `docs/plans/README.md` に、版ごとの Q の範囲と状態の索引を置く
  - Q が 15 件を超えそうなら、版を分けることを検討する

---

## 6. 進捗

| 段階 | 状態 | メモ |
|---|---|---|
| 計画 | 完了 | 2026-11-01 作成。Q85〜Q90 は確定 |
| 0. 未整形の修正 | 完了 | 2026-11-01。`gofmt` のみで、動作の変更はない |
| 1. git の pre-commit hook | 完了 | 2026-11-01。検査を `.githooks/pre-commit` へ移した |
| 2. 権限の設定 | 未着手 | |
| 3. 条件付きの確認 | 未着手 | |
| 4. 依存の許可制 | 未着手 | |
| 5. 資料の形式と運用 | 未着手 | |

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
