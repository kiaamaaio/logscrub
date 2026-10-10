# logscrub

- 仕様書: docs/SPEC.md(実装はこの仕様に従う。仕様と食い違う場合は実装せずに確認すること)
- 実装計画: docs/PLAN.md(進捗もここに記録する)
- 外部ライブラリは使わない(標準ライブラリのみ)
- Go の操作(ビルド・テスト・vet など)はすべて Docker コンテナ(`golang:1.27.2`)内で行う。`scripts/go` 経由で実行し、ホストの Go は使わない(詳細は docs/PLAN.md 0 章)
- 変更後は `./scripts/go test ./...` と `./scripts/go vet ./...` が通ることを確認する
