package transform

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

// BenchmarkEngineMask は、合成ログ(8MB、1MB の JSON 行を含む)を、既定の種別で mask する時間を測る。
// 入出力の書き換えを含む、変換処理全体の速度(入出力の実ファイルは含まない)。実装計画(docs/plans/)のベンチマーク記録用。
func BenchmarkEngineMask(b *testing.B) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 8 << 20, Seed: 1, LongLineEvery: 4 << 20}); err != nil {
		b.Fatal(err)
	}
	data := []byte(sb.String())
	det, err := detect.New(detect.Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng := &Engine{Det: det, Rep: NewMasker(label.DefaultFormat)}
		if err := eng.Run([]io.Reader{bytes.NewReader(data)}, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEngineHash は、同じ合成ログを、hash モード(`--email-hash full`、12 桁)で変換する時間を測る。
func BenchmarkEngineHash(b *testing.B) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 8 << 20, Seed: 1, LongLineEvery: 4 << 20}); err != nil {
		b.Fatal(err)
	}
	data := []byte(sb.String())
	det, err := detect.New(detect.Options{})
	if err != nil {
		b.Fatal(err)
	}
	h, err := NewHasher([]byte("benchmark-key"), 12, EmailHashFull)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng := &Engine{Det: det, Rep: h}
		if err := eng.Run([]io.Reader{bytes.NewReader(data)}, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRestore は、合成ログ(8MB)の mask 結果を、元の入力から restore する時間を測る。
// 元の入力の処理(mask と同じ検出と連番)と、回答(8MB)の走査を含む。MB/s は、元の入力の大きさ。
func BenchmarkRestore(b *testing.B) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 8 << 20, Seed: 1, LongLineEvery: 4 << 20}); err != nil {
		b.Fatal(err)
	}
	src := []byte(sb.String())
	det, err := detect.New(detect.Options{})
	if err != nil {
		b.Fatal(err)
	}
	var masked bytes.Buffer
	if err := (&Engine{Det: det, Rep: NewMasker(label.DefaultFormat)}).Run([]io.Reader{bytes.NewReader(src)}, &masked); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Restore([]io.Reader{bytes.NewReader(src)}, bytes.NewReader(masked.Bytes()), io.Discard, det, label.DefaultFormat)
		if err != nil {
			b.Fatal(err)
		}
	}
}
