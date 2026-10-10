// Package synthlog は、性能測定とベンチマーク用の合成ログを作る(PLAN の Q29)。
//
// 作るログは、1 行が 200 バイト前後で、約 30% の行に検出対象(メールアドレス、IP アドレス、
// トークン類、UUID)を含み、一定の間隔で 1MB の JSON を 1 行で挟む。
// 検出対象でない行には、検出対象になりうる文字列(`@`、IP アドレス、キー名など)を入れない。
// 同じ設定なら、出力は常に同じになる。
package synthlog

import (
	"bufio"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
)

const (
	// DefaultLongLineEvery は、Q29 の「1MB の JSON 行を少し混ぜる」に当たる間隔(出力のバイト数)。
	DefaultLongLineEvery = 32 << 20

	longLineSize  = 1 << 20
	targetPercent = 30
)

// Config は、合成ログの設定。
type Config struct {
	// Size は、出力するおおよそのバイト数。この大きさに達した行で止める(最後の行の分だけ超える)。
	Size int
	// Seed は、乱数の種。
	Seed uint64
	// LongLineEvery は、この間隔(出力のバイト数)ごとに、1MB の JSON を 1 行で挟む。0 で挟まない。
	LongLineEvery int
}

// Stats は、作ったログの内訳。
type Stats struct {
	Bytes       int // 出力したバイト数
	Lines       int // 行数(1MB の JSON 行を含む)
	TargetLines int // 検出対象を含む通常の行の数
	LongLines   int // 1MB の JSON 行の数
}

// Generate は、c に従う合成ログを w に書く。
func Generate(w io.Writer, c Config) (Stats, error) {
	g := &generator{rng: rand.New(rand.NewPCG(c.Seed, c.Seed^0x9e3779b97f4a7c15))}
	bw := bufio.NewWriterSize(w, 64<<10)
	var st Stats
	nextLong := c.LongLineEvery
	var line []byte
	for st.Bytes < c.Size {
		line = line[:0]
		if c.LongLineEvery > 0 && st.Bytes >= nextLong {
			line = g.longLine(line)
			nextLong += c.LongLineEvery
			st.LongLines++
		} else {
			var target bool
			line, target = g.normalLine(line, st.Lines)
			if target {
				st.TargetLines++
			}
		}
		line = append(line, '\n')
		if _, err := bw.Write(line); err != nil {
			return st, err
		}
		st.Bytes += len(line)
		st.Lines++
	}
	return st, bw.Flush()
}

type generator struct {
	rng *rand.Rand
}

var (
	levels  = []string{"INFO", "INFO", "INFO", "DEBUG", "WARN", "ERROR"}
	loggers = []string{"app.svc.Orders", "app.svc.Billing", "app.http.Router", "app.db.Pool", "app.cache.Store", "app.queue.Worker"}
	words   = []string{
		"request", "completed", "cache", "miss", "hit", "queue", "worker", "flush", "retry", "timeout",
		"connection", "pool", "handler", "metrics", "batch", "commit", "rollback", "latency", "status",
		"upstream", "response", "payload", "schema", "validated", "dispatched", "scheduled", "finished",
		"started", "stopped", "reloaded", "refreshed", "expired", "renewed", "acquired", "released",
	}
	paths = []string{"/api/v1/items", "/api/v1/orders", "/healthz", "/api/v2/search", "/static/app.js", "/api/v1/users/profile"}
)

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const base64url = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

func (g *generator) pick(ss []string) string { return ss[g.rng.IntN(len(ss))] }

func (g *generator) chars(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[g.rng.IntN(len(set))]
	}
	return string(b)
}

func (g *generator) lower(n int) string { return g.chars("abcdefghijklmnopqrstuvwxyz", n) }

// normalLine は、200 バイト前後の通常の行を追記する。2 つ目の戻り値は、検出対象を含むかどうか。
func (g *generator) normalLine(dst []byte, index int) ([]byte, bool) {
	sec := index / 40
	dst = fmt.Appendf(dst, "2026-10-11T%02d:%02d:%02d.%03dZ %-5s [worker-%d] %s: ",
		(sec/3600)%24, (sec/60)%60, sec%60, g.rng.IntN(1000), g.pick(levels), g.rng.IntN(16), g.pick(loggers))

	var fragments []string
	target := g.rng.IntN(100) < targetPercent
	if target {
		for i, n := 0, 1+g.rng.IntN(2); i < n; i++ {
			fragments = append(fragments, g.targetFragment())
		}
	}

	want := 160 + g.rng.IntN(80) // 160〜239 バイト(平均 200)
	size := len(dst)
	for _, f := range fragments {
		size += len(f) + 1
	}
	var tokens []string
	for size < want {
		var t string
		switch g.rng.IntN(4) {
		case 0:
			t = fmt.Sprintf("took=%d.%dms", g.rng.IntN(900), g.rng.IntN(10))
		case 1:
			t = fmt.Sprintf("%s=%d", g.pick([]string{"bytes", "status", "retries", "shard", "attempt"}), g.rng.IntN(10000))
		case 2:
			t = "path=" + g.pick(paths)
		default:
			t = g.pick(words)
		}
		tokens = append(tokens, t)
		size += len(t) + 1
	}
	for _, f := range fragments {
		at := g.rng.IntN(len(tokens) + 1)
		tokens = append(tokens, "")
		copy(tokens[at+1:], tokens[at:])
		tokens[at] = f
	}
	dst = append(dst, strings.Join(tokens, " ")...)
	return dst, target
}

// targetFragment は、検出対象を 1 つ含む `key=value` の形の断片を返す。
func (g *generator) targetFragment() string {
	switch g.rng.IntN(10) {
	case 0, 1:
		return fmt.Sprintf("user=%s%d@example.%s", g.lower(4+g.rng.IntN(6)), g.rng.IntN(1000), g.pick([]string{"com", "org", "co.jp"}))
	case 2:
		return fmt.Sprintf("client=%s", g.privateIPv4())
	case 3:
		return fmt.Sprintf("remote=%s", g.globalIPv4())
	case 4:
		return fmt.Sprintf("addr=%s", g.pick([]string{
			fmt.Sprintf("2001:db8::%x", g.rng.IntN(0xffff)),
			fmt.Sprintf("fe80::%x:%x", g.rng.IntN(0xffff), g.rng.IntN(0xffff)),
			fmt.Sprintf("fd00::%x", g.rng.IntN(0xffff)),
		}))
	case 5:
		return "aws_id=AKIA" + g.chars(upperAlnum, 16)
	case 6:
		return "gh=ghp_" + g.chars(alnum, 36)
	case 7:
		return "Authorization: Bearer " + g.chars(base64url, 40)
	case 8:
		return g.pick([]string{"password=", "api_key=", "db_password="}) + g.chars(alnum, 8+g.rng.IntN(8))
	default:
		return fmt.Sprintf("req=%08x-%04x-4%03x-%x%03x-%012x", g.rng.Uint32(), g.rng.IntN(0x10000), g.rng.IntN(0x1000),
			8+g.rng.IntN(4), g.rng.IntN(0x1000), g.rng.Uint64()&0xffffffffffff)
	}
}

func (g *generator) privateIPv4() string {
	switch g.rng.IntN(3) {
	case 0:
		return fmt.Sprintf("10.%d.%d.%d", g.rng.IntN(256), g.rng.IntN(256), 1+g.rng.IntN(254))
	case 1:
		return fmt.Sprintf("192.168.%d.%d", g.rng.IntN(256), 1+g.rng.IntN(254))
	}
	return fmt.Sprintf("172.%d.%d.%d", 16+g.rng.IntN(16), g.rng.IntN(256), 1+g.rng.IntN(254))
}

func (g *generator) globalIPv4() string {
	switch g.rng.IntN(3) {
	case 0:
		return fmt.Sprintf("203.0.113.%d", 1+g.rng.IntN(254))
	case 1:
		return fmt.Sprintf("198.51.100.%d", 1+g.rng.IntN(254))
	}
	return fmt.Sprintf("34.%d.%d.%d", g.rng.IntN(256), g.rng.IntN(256), 1+g.rng.IntN(254))
}

// longLine は、約 1MB の JSON を 1 行で追記する(JSON 配列の中に、通常の行と同じ割合で検出対象を含む)。
func (g *generator) longLine(dst []byte) []byte {
	dst = append(dst, `{"source":"synthlog","events":[`...)
	for i := 0; len(dst) < longLineSize; i++ {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = fmt.Appendf(dst, `{"seq":%d,"level":%q,"msg":%q`, i, g.pick(levels), g.pick(words)+" "+g.pick(words)+" "+g.pick(words))
		if g.rng.IntN(100) < targetPercent {
			switch g.rng.IntN(3) {
			case 0:
				dst = fmt.Appendf(dst, `,"user":"%s%d@example.com"`, g.lower(6), g.rng.IntN(1000))
			case 1:
				dst = fmt.Appendf(dst, `,"client":%q`, g.privateIPv4())
			default:
				dst = fmt.Appendf(dst, `,"password":%q`, g.chars(alnum, 12))
			}
		}
		dst = append(dst, '}')
	}
	return append(dst, `]}`...)
}
