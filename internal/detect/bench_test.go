package detect

import (
	"bytes"
	"sync"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

var (
	corpusOnce  sync.Once
	corpusLines [][]byte
	corpusSize  int
)

// benchCorpus は、合成ログ(Q29 の条件)を行に分けたもの。
func benchCorpus(b *testing.B) ([][]byte, int) {
	b.Helper()
	corpusOnce.Do(func() {
		var buf bytes.Buffer
		_, err := synthlog.Generate(&buf, synthlog.Config{
			Size:          8 << 20,
			Seed:          1,
			LongLineEvery: 4 << 20,
		})
		if err != nil {
			panic(err)
		}
		corpusSize = buf.Len()
		corpusLines = bytes.SplitAfter(buf.Bytes(), []byte("\n"))
	})
	return corpusLines, corpusSize
}

// BenchmarkFind は、既定の種別で合成ログの全行を検出する時間を測る。
// 段階が進むたびに(email、IP、secret、uuid の検出器が加わるたびに)結果を 実装計画(docs/plans/)の進捗に記録する。
func BenchmarkFind(b *testing.B) {
	lines, size := benchCorpus(b)
	d, err := New(Options{})
	if err != nil {
		b.Fatal(err)
	}
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst, _ = d.Find(line, dst[:0])
		}
	}
}
