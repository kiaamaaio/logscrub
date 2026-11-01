# logscrub v1.0.0 実装の段階(段階 6〜11)

[計画](README.md)へ戻る。

### 段階 6: uuid — ✅ 完了(2026-10-11)

- 8-4-4-4-12、バージョン(1〜8、または `--uuid-versions`)、バリアント、前後の文字、`{...}` / `urn:uuid:`
- 全種別がそろうので、「除外の確認」(電話番号・郵便番号が検出されない)をここで確認する
- 前提となる確認: Q9(確定済み)

**実装メモ・気づいた点**

- 実装: `internal/detect/uuid.go`(`uuidFinder`)。`builtinFinders` が、`Kinds` に uuid があるとき(`--types ...uuid`、または `--uuid-versions` で加わる)に、`Options.UUIDVersions` を渡して作る
- 判定: 正規表現 `^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}`(正規表現がマッチャー)に、前後が英数字でないこと(ハイフンは許す)と、バージョンの絞り込み(3 つ目のグループの先頭桁。`UUIDVersions` のビット。0 は 1〜8 のすべて)を重ねる
  - 正規表現の `[1-8]` と、バージョンのビット判定は重複している(0、9 以上は、どちらでも拒否される)。結果は変わらないが、仕様の文言を両方に残した
- 前処理(`find` の中): ハイフンを `IndexByte` で探し、その位置を最初のハイフンとして、8・13・18・23 バイト目に 4 つが並ぶ位置にだけ、正規表現を当てる。日付(`2026-10-11`)のハイフンでは当てない。前の一致の終端より前の位置も飛ばす
  - 前処理なしの全位置に正規表現を当てる別実装 `refUUIDs` を、テストに置き、乱数 6 万通り(バージョンの指定も乱数)で一致を確認している
- **Q9(置換範囲)**: UUID の 36 バイトだけ。`{<uuid_1>}`、`urn:uuid:<uuid_1>` になる。`{` と `:` が英数字でないので、前後の条件だけで一致する(特別な処理はない)。SPEC 4.2 と受け入れ基準に、この確定内容を書き足した
- 他の種別との重なり: 同じ範囲なら email → ip → secret → uuid の順(仕様 4 章)なので、`session_id=<uuid>` は、キー名ベースの secret が勝つ(`TestDetectorUUIDPriority`)。キー名がなければ uuid になる
- 「除外の確認」(受け入れ基準): `03-1234-5678`、`09012345678`、`123-4567` と、その変形(`090-1234-5678`、`〒123-4567`、`2026-10-11` など)が、すべての種別(uuid を含む)で検出されないことを、`TestPhoneAndPostalCodesAreNotDetected` で確認した
- 検出器の構成: Q2 のとおり、正規表現がマッチャーで、前処理(ハイフンの位置)だけを手書きにした。測定(下の記録)は、目標を大きく超える

### 段階 7: mask(`transform.Masker`、`Engine`、`Stats`) — ✅ 完了(2026-10-11)

- 行の書き換え(一致していない部分は元のスライスをそのまま書く)
- 最初に現れた順の連番、種別名(IP は区別込み)ごとのカウンタ、`--mask-format`
- 冪等性のテスト: すべてのテスト入力で `mask(mask(x)) == mask(x)` を確認。`testing.F` のファズテストでも確認する
- 前提となる確認: Q3、Q4、Q19(確定済み)

**実装メモ・気づいた点**

- 実装: `internal/transform/{mask,stats,engine}.go`。`label.TypeIndex` / `label.NumTypes` を追加した(統計・連番の表を、`label.Types` の順の固定長の配列で持つため)
- **`Masker`**: 種別名(IP は区別込み)ごとに、「値のバイト列(完全一致。Q3)→ 連番」の map を持つ。初めて見た値に、その種別の次の番号を振る(Q4)。`--allow` の値、特殊アドレス、`--ip-scope` 外、保護範囲は、`Detector` が候補から外すので、番号を消費しない。map の反復には依存しない。restore 用の逆引き(番号 → 値)は、段階 9 で、必要になった形で加える
- **`Engine`**: `stream.ForEachLine`(入力ごとに行を区切る = Q22)で読み、`Detector.Find` で範囲を決め、`Replacer` で書き換えて、64KB のバッファ付きで書く。一致のない行は、読んだスライスをそのまま書く。`Run` は、`Stats` に加算する(`Engine.Stats` は、この計画の案のポインタでなく、値)
- **`Stats`**(Q19、Q31): 種別ごとの置換した出現回数(`Count` / `Types` は `label.Types` の順で、0 件は出さない / `Total`)、読んだ行数(`Lines`)、置換せずに残した置換済みの形の数(`Kept`)と、その行番号(`KeptLines`。入力をまたいで通しで数える 1 始まり、昇順、最初の 5 件まで)。値は持たない。stderr への出力(`--stats` と通知の文面)は、段階 10 が、この値から作る
- `internal/transform/testdata/app.log`(17 行。日本語、email、各種 IP、トークン、UUID、JSON、コードの記号、電話番号、置換済みの形)と、手で確認した `testdata/app.mask.golden` を追加した。段階 9(restore の往復)、段階 10(E2E)でも使う
- 受け入れ基準の「同じ入力・同じオプションで 2 回実行すると同じ出力」「置換済みテキストを再度流しても変わらない(mask)」「日本語」「64KB 超」「CRLF・末尾改行」は、`internal/transform/mask_test.go` で確認した

**冪等性のテストで見つけた不具合と、性質の見直し**

- **不具合(修正済み)**: `token: Bearer abc.def-ghi` → 1 回目は `token: Bearer <secret_1>`、2 回目は、方式名の後ろが値として読めないため、キー名の値として `Bearer` の語を置換して、`token: <secret_1> <secret_1>` になっていた。方式名(`Bearer ` / `Basic `)で始まる値は、後ろが値として読めない場合、何も置換しないことにした(SPEC 4.1 に追記。`secretFinder` を修正)。`Authorization: Bearer <secret_1>` は、もとから置換されなかった
- **ファズテストの性質の見直し**: ファズテスト(任意のバイト列)で、`000000A10.0.0.0fC00::` が見つかった。1 回目は `10.0.0.0` だけを置換し、2 回目は、間に挟まっていた `0.0.0.0` がなくなって独立した `fC00::` を IPv6 として検出する。置換によって、隣の文字列の文脈が変わる現象で、現実のログではほぼ起きない
  - 仕様の冪等性(置換済みの値を再度置換しない)には反しないので、ファズテストの性質を、「2 回目に新しく検出する値は、1 回目のラベルに隣接するものだけ。ラベルと重なる検出や、置換と無関係な場所での検出は、不具合」に改めた(`FuzzMaskStable`)。1 回目と 2 回目が完全に同じであること(`mask(mask(x)) == mask(x)`)は、現実的な入力(受け入れ基準の例、サンプルログ、合成ログ 3MB、各種書式)で、引き続き確認している
  - ファズテストは、60 秒 × 4 ラウンド(合計約 940 万回)で、この性質の違反が見つからなかった

### 段階 8: hash(`transform.Hasher`、`LoadKey`) — ✅ 完了(2026-10-11)

- HMAC-SHA256 の先頭 N 桁、email の `local` / `full`、鍵の読み込み(環境変数 / `--key-file`)
- 冪等性: `hash(hash(x)) == hash(x)`(ファズテスト含む)
- 前提となる確認: Q10、Q18、Q20、Q21(確定済み)

**実装メモ・気づいた点**

- 実装: `internal/transform/{hash,key}.go`。桁数の定数(`DefaultHashLen` 12、`MinHashLen` 8、`MaxHashLen` 64)は、`label` に置き、`detect` と `transform` で共有する
- **`Hasher`**(`Replacer`): HMAC-SHA256 に渡すのは、値のバイト列だけ(`local` はローカルパートだけ。種別名は含めない。正規化しない)。出力は、小文字の 16 進数の先頭 `hashLen` 桁。`<種別>_<hex>`(IP は区別込み。例: `ipv4_private_dca2f4f38564`)、`local` のメールアドレスは `hash_<hex>@ドメイン`。`NewHasher` は、鍵が空・桁数が 8〜64 の範囲外・`EmailHash` が不明、ならエラー(0 は既定の 12)。エラーに鍵を含めない
  - 別マシンでも同じ出力になることは、Python の `hmac` で別に求めた値(`TestHashKnownAnswers`、`TestHashLength`)で確認した
- **`LoadKey`**: `--key-file` を優先し、末尾の改行(`\n` または `\r\n`)を 1 つだけ除く。ファイルが読めない場合は、環境変数に切り替えずに、エラーにする(意図しない鍵で変換しないため)。空の鍵はエラー。環境変数 `LOGSCRUB_KEY` は、そのまま(改行は除かない)
- **Engine は、mask と同じものを使う**(`Replacer` を差し替えるだけ)。hash モードでは、`detect.Options.HashLen` を `--hash-length` と同じにする必要がある(置換済みの hash 出力形を認識する桁数)。mask と restore は、常に既定の 12(Q10)
- 受け入れ基準: `--email-hash local` が `hash_<hex>@example.com` になり再度流しても変わらない、`full` で全体が置換される、`password=secret_3f9a1c0b7d2e` が再ハッシュされない、鍵が未設定ならエラー(`LoadKey`)、を `hash_test.go`・`key_test.go` で確認した。CLI の終了コードは、段階 10 で確認する

**冪等性のテストで見つけた不具合と、仕様の追記**

- ファズテスト(`FuzzHashStable`)が、`0@0.AA@0.AA` のような、`@` が続く入力で、非冪等を見つけた。1 回目: 先頭の `0@0.AA` だけが email として置換され、`email_<hex>@0.AA` になる。2 回目: `email_<hex>` に `@0.AA` が続くので、全体が 1 つのメールアドレス(ローカルパート `email_<hex>`)として再検出され、再ハッシュされる。実在しうる形(`ssh user@example.com@bastion.example.org` のような、踏み台経由の表記)
- 修正: ローカルパートが、hash の出力形(`<種別>_<hex>`)、または現在の `--mask-format` のラベルそのもの(`{type}_{n}` 書式の `email_1`)であるメールアドレスは、検出の対象外にした(SPEC 5.2 に追記。`label.IsHashedLocalPart` を `<種別>_<hex>` に広げ、`label.Format.IsLabel` を追加し、`emailFinder` に書式を渡した)。mask の既定書式(`<...>`)では、ラベルがローカルパートの文字でないので、もともと起きない
- **ファズテストの性質の見直し(隣接の範囲)**: `0@0.AA:::1`(hash)と `::1:1.0.0.0`(mask)が見つかった。どちらも、置換によって、ラベルの 16 進数と連なっていた区切りが切り離され、ラベルの 1 文字隣(`:` を挟む)の値が、新しく検出できるようになる現象で、段階 7 で見つけた「置換で文脈が変わる」と同じ種類。ファズテストの「ラベルに隣接する」の範囲を、間が 1 バイト以内に広げた(mask と hash で、共通の `checkSecondPass` にした)
- 保存されたファズの入力(`internal/transform/testdata/fuzz/`)は、回帰テストとして残す
- ファズテスト: 修正後に、hash(`local` と `full`)が 91 秒、mask が 61 秒、違反が見つからなかった(段階 7 の分と合わせて、合計 1,000 万回以上)
- 性能: `BenchmarkEngineHash` は、`BenchmarkEngineMask` と同程度(HMAC の計算が増えるが、連番の map がなくなる)

### 段階 9: restore — ✅ 完了(2026-10-11)

- `--source` を mask と同じ `Engine` に通して対応を作り直す(出力は捨てる)→ 回答中のラベルを `Format.Scan` で探して戻す
- 戻せなかったラベル名の一覧を返す(stderr への出力は段階 10)
- 往復テスト: `restore(mask(x)) == x`(testdata の全入力 × 複数のオプションの組)。追記後も戻ること
- 前提となる確認: Q22、Q23、Q24(確定済み)

**実装メモ・気づいた点**

- 実装: `internal/transform/restore.go`(`Restore`、`RestoreResult`)と、`Masker.Value`(連番 → 値の逆引き)。`Masker` は、新しい値を振るたびに、値の文字列を種別ごとのスライスにも持つ(`ids` の map のキーと、文字列の中身は共有)
- **`Restore`**: sources を、mask と同じ `Engine` と `Masker` に通して(出力は `io.Discard`)連番を振り直し、answer を 1 行ずつ(`stream.Reader`。改行コード・末尾改行を保つ)読んで、`Format.Scan` で見つけたラベルを、`Masker.Value` の値に置き換えて書く。戻した値は、再度ラベルとして読まない
- **戻り値**: この計画の案の `(missing []string, err)` でなく、`RestoreResult`(`Missing`: 戻せなかったラベル = 種類数、回答に現れた順、重複なし。ラベルの文字列だけ / `Restored`: 戻した出現回数 / `Source`: `--source` の処理の `Stats`)と `error`
- **計画との違い 1(回答の読み方)**: DEVELOPMENT.md 3.3 は、回答を先に読み、必要なラベルがすべて見つかった時点で `--source` の残りを読まずに終えてよい、としていたが、採用しなかった。Q31 により、restore でも `--source` の全体を調べて、「ラベルと同じ形の文字列」(正しく戻らない可能性)を通知するため(`RestoreResult.Source.Kept` / `KeptLines`)。回答は、全体をメモリに読まず、1 行ずつ処理する
- **計画との違い 2(仕様の追記)**: Q23 の確定内容(種類数・回答に現れた順・ラベルとみなす範囲)と、`--source` の処理での Q31 の通知を、SPEC 5.3 に書き足した
- 受け入れ基準(ライブラリのテスト): 往復で 1 バイトも変わらない(受け入れ基準の例、`testdata/app.log` から、ラベルと同じ形の行を除いたもの × 9 つのオプションの組、合成ログ 3MB)、`--source` 複数指定でも往復、追記後も追記前のラベルが戻る、オプションが違うとラベルが残り `Missing` に記録される、restore がファイルを作らない、エラー(読み・書き)の伝播。CLI の項目(`--source -` のエラー、stderr への出力、終了コード 0)は、段階 10 で確認する
- 限界(`TestRestoreLimitationWithLabelLikeSource`): 元の入力に、ラベルと同じ形の文字列があると、正しく戻らない(仕様 5.3 の限界)。この場合は、`Source.Kept` が通知の材料になる。テストは、将来この限界が解消されたら失敗する(README の限界を直す合図)
- ファズテスト(`FuzzRestoreRoundTrip`): ラベルと同じ形の文字列を含まない任意の入力で、`restore(mask(x)) == x` が成り立つ。120 秒で違反なし
- 性能: `BenchmarkRestore`(8MB の合成ログ。元の入力の処理 + 回答 8MB の走査)は、約 185MB/s

### 段階 10: CLI(`cli`、`cmd/logscrub`) — ✅ 完了(2026-10-11)

- サブコマンド、オプションの前後自由な解析、`--`、`-`、`-o`、`--help`、`types [--verbose]`、終了コード、`--output`、`--stats`、`--fail-on-detect`
- 受け入れ基準を `cli.Run` 経由の E2E テストとして全項目そろえる(段階 3〜9 で個別に確認したものも、ここで改めて通す)
- 前提となる確認: Q25、Q26、Q27、Q28(確定済み)

**実装メモ・気づいた点**

- 実装: `cmd/logscrub/main.go`(`os.Exit(cli.Run(...))` だけ)、`internal/cli/{cli,flags,common,mask,restore,types,usage}.go`。標準の `flag` だけを使う。`detect.ParseUUIDVersions` / `detect.ParseScope`(`--uuid-versions` と `--ip-scope` の解析。段階 2 で見送ったもの)と、`Stats.KeptLineCount`(通知で行番号の省略を示すため)を追加した
- **オプションの前後自由な解析**(`parseArgs`): 「`Parse` → 残りの先頭を 1 つファイル名にして取る → 残りを再度 `Parse`」を繰り返す。`flag` は、終端の `--` と、オプションの値としての `--`(`--allow --`)を区別して教えてくれないので、`Parse` が読んだ引数の数から、`flag` の読み方を再現して判定する(`endedWithTerminator`)。単独の `-` は、ファイル名(標準入力)
- **処理の順序**: オプションの値の検証(`--mode`、`--types`、`--uuid-versions`、`--ip-scope`、`--mask-format`、`--hash-length`、`--email-hash`、鍵)→ 入力をすべて開く → 出力先を開く(入力と同じファイルなら、開かずにエラー)→ 変換 → 統計・通知 → 終了コード。開けない入力があれば、何も書かずに終わる
- Q25(hash 専用のオプションを mask モードで指定するとエラー)、Q26(`--output` が入力と同じファイルならエラー)、Q27(`types` の形式。1 行 1 種別、`on` / `off`、説明)、Q28(エラー(1)は、`--fail-on-detect` の 2 より優先)、Q19(`--stats` は、置換した出現回数を、`label.Types` の順に、1 行 1 種別の `logscrub: email=3`。0 件は出さない)を実装した。確定内容を、SPEC 6 章と 9 章に書き足した
- hash モードでも、`--mask-format` は受け付ける。ハッシュの出力には使わず、検出器が、すでに置換済みのラベルを認識する書式としてだけ使う
- restore は、`--source` と ANSWER_FILE をすべて開いてから、`transform.Restore` に渡す。`--source -` は、ANSWER_FILE を指定した場合だけ(両方が標準入力なら、エラー)。stdin は 1 回だけ使える
- 終了コード 0: 戻せないラベルがあっても(警告のみ)。通知(置換済みの形を残した件数と行番号)は、終了コードを変えない

**仕様で決まっていなかったため、決めた点(2026-10-11 に、利用者が確認済み。問題なし)**

- `--output -` は、標準出力(ファイル名 `-` ではない)。入力の `-` が標準入力であることに合わせた
- `logscrub --help` / `-h` / `help`(サブコマンドなし)と、`logscrub <command> --help` は、使い方を stdout に出して、終了コード 0。サブコマンドなし・不明なサブコマンドは、使い方を stderr に出して、終了コード 1(仕様どおり)
- `--stats` で、検出が 0 件のときは、何も出さない(Q19「0 件の種別は出さない」の延長)
- 通知の文面は、仕様の例を基準に、1 件のとき `1 string was left unchanged because it looks already replaced (line 12)`、6 行以上のとき `(lines 1, 2, 3, 4, 5, ...)` とした。戻せなかったラベルは、50 件まで並べ、超える場合は `, ...`(件数は全体)
- 出力ファイルは、入力の検証後に、`os.Create` で作る(途中で失敗した場合は、書きかけのファイルが残りうる。一時ファイルと rename にはしていない)

### 段階 11: 性能・メモリ・README — ✅ 完了(2026-10-11)

- 合成ログ(100MB)で `cmd/logscrub` を実測し、50MB/s を確認。足りなければ DEVELOPMENT.md 3.4 節の手順で改善する
- 最大メモリ使用量の確認(値の種類数を一定に保った 100MB 入力で、最大 RSS が入力サイズに比例して増えないこと)。`golang` イメージには `/usr/bin/time` がないため、テストからビルド済みのバイナリを子プロセスで起動し、`ProcessState.SysUsage()` の `Maxrss` を読む(標準ライブラリのみで完結する)
- 性能・メモリの測定もコンテナ内で行う。合成ログはコンテナ内で生成し、リポジトリ外の一時領域に置く
- README: 使い方、`secret` の対応形式、限界(仕様に「README に明記する」とあるもの全部)、ベンチ結果
- 前提となる確認: Q29(確定済み)

**実装メモ・気づいた点**

- 測定テスト: `cmd/logscrub/perf_test.go`。`go test` の中で、バイナリをビルドし、合成ログを一時ファイルに作り、子プロセスとして実行して、実時間と `Maxrss` を測る。時間がかかるので、`-perf` を付けたときだけ実行する(`./scripts/go test -run Perf -v ./cmd/logscrub -perf [-perf-size 100]`)。50MB/s を下回ると、テストが失敗する。メモリは、入力が 5 倍になっても、最大メモリ使用量が 16MB 以上増えないことを確認する
- `synthlog.Config.ValuePool` を追加した。検出対象の値を、固定数の候補から選ぶので、出力が大きくなっても、値の種類数が増えない(メモリの測定用)。0 では、従来どおり、行ごとにほぼ異なる値
- **測定結果**(合成ログ 100MB、AMD Ryzen 9 9950X、WSL2 上の Docker コンテナ(`golang:1.27.2`、2 CPU)内、3 回の最速)
  - `logscrub mask < big.log > /dev/null`: 約 195MB/s、最大 30MB
  - `cat big.log | logscrub mask > /dev/null`: 約 176MB/s、最大 30MB
  - `--types default,uuid`: 約 182MB/s、最大 34MB
  - 値の種類数が 1,000 のとき、入力 20MB / 50MB / 100MB の最大メモリ使用量は、どれも 16.8MB(入力の大きさに比例しない)。ほぼすべての値が異なる 100MB では、31.6MB(対応表が、値の種類数に比例して増える)
  - **目標(50MB/s)の約 3.5 倍以上**。DEVELOPMENT.md 3.4 節の改善手順(手書きへの置き換えなど)は、必要なかった
- README: 使い方(mask / hash / restore / types)、オプション、終了コード、検出対象、`secret` の対応形式、性質(決定的・冪等・値を出さない)、限界(仕様で「README に明記する」とされたもの、および実装で見つけたもの)、性能、開発(Docker、構成)。例の出力は、ビルドしたバイナリで確かめた
- 仕様 8 章の構成(案)を、実際の構成に合わせて直した
