# logscrub v1.4.0 段階ごとの記録

[計画](README.md)へ戻る。何をしたか、測った値、実際に確かめた方法を書く。測定の詳細は docs/development/performance.md に置く。

## 段階 0: 確定の反映

- `feature/v1.4.0-perf` を、v1.3.0 のマージ後の `origin/develop`(`41971c4`)から作った
- `git fetch origin` は SSH の認証で失敗したので、`gh` の認証を使う HTTPS で取得した。`develop` と作業ブランチの差がないことを `git diff --stat 0166bea origin/develop` で確かめた
- 仕様: 7 章のストリーム処理の書き換え(Q95)、決定事項 27、11 章の Q の範囲
- DEVELOPMENT.md: 冒頭の Q の範囲、3.3 節に処理の 3 段と、行ごとに独立であることの制約(Q98)
- 計画の索引: v1.3.0 をリリース済み(タグ `v1.3.0`)として「完了」にした
