package transform

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
	"github.com/kiaamaaio/logscrub/internal/synthlog"
)

const testKey = "test-key"

// hmacHex は、testKey による HMAC-SHA256 の、先頭 n 桁(小文字の 16 進数)。
func hmacHex(v string, n int) string {
	m := hmac.New(sha256.New, []byte(testKey))
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:n]
}

// hashRun は、inputs を、hash モードで変換する。検出器の hash 出力形の桁数は、hashLen にそろえる。
func hashRun(t testing.TB, opts detect.Options, key string, hashLen int, mode EmailHash, inputs ...string) (string, *Stats) {
	t.Helper()
	opts.HashLen = hashLen
	det, err := detect.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher([]byte(key), hashLen, mode)
	if err != nil {
		t.Fatal(err)
	}
	eng := &Engine{Det: det, Rep: h}
	rs := make([]io.Reader, len(inputs))
	for i, s := range inputs {
		rs[i] = strings.NewReader(s)
	}
	var out bytes.Buffer
	if err := eng.Run(rs, &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), &eng.Stats
}

func hashDefault(t testing.TB, input string) string {
	t.Helper()
	out, _ := hashRun(t, detect.Options{}, testKey, 12, EmailHashFull, input)
	return out
}

// ---- 出力(既知の値は、Python の hmac で別に求めたもの) ----

func TestHashKnownAnswers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"email full", "taro@example.com\n", "email_99a207efd719\n"},
		{"ipv4 private", "192.168.0.1\n", "ipv4_private_dca2f4f38564\n"},
		{"ipv4 global", "203.0.113.5\n", "ipv4_global_2bd441c1ccd3\n"},
		{"ipv6 private", "::1\n", "ipv6_private_24307fa76d41\n"},
		{"secret keyed", "password=hunter2\n", "password=secret_65f93b070e9b\n"},
		{"secret aws", "AKIAIOSFODNN7EXAMPLE\n", "secret_c800dfd6ddc0\n"},
		// Q18/Q3: 値のバイト列だけを入力にする。大文字・小文字は、別の値
		{"case sensitive", "Taro@Example.com\n", "email_515e6e6ae3e8\n"},
		{"in text", "from taro@example.com to 192.168.0.1 ok\n", "from email_99a207efd719 to ipv4_private_dca2f4f38564 ok\n"},
		{"same value same hash", "taro@example.com taro@example.com\n", "email_99a207efd719 email_99a207efd719\n"},
		{"japanese", "接続元 192.168.0.1 から taro@example.com\n", "接続元 ipv4_private_dca2f4f38564 から email_99a207efd719\n"},
		{"crlf", "taro@example.com\r\n", "email_99a207efd719\r\n"},
		{"no final newline", "taro@example.com", "email_99a207efd719"},
		{"invalid utf8", "\xff taro@example.com \x80\n", "\xff email_99a207efd719 \x80\n"},
		{"nothing", "hello world\n", "hello world\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashDefault(t, tt.in); got != tt.want {
				t.Errorf("hash(%q)\n got  %q\n want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHashUUID(t *testing.T) {
	opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
	got, _ := hashRun(t, opts, testKey, 12, EmailHashFull, "id=123e4567-e89b-42d3-a456-426614174000 {123e4567-e89b-42d3-a456-426614174000}\n")
	want := "id=uuid_efd04084ef0d {uuid_efd04084ef0d}\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// 受け入れ基準: --email-hash local は、ローカルパートだけをハッシュし、ドメインはそのまま。
func TestHashEmailLocal(t *testing.T) {
	for in, want := range map[string]string{
		"taro@example.com\n":         "hash_a746604745a4@example.com\n",
		"Taro@Example.com\n":         "hash_576b54564305@Example.com\n",
		"x taro@example.com y\n":     "x hash_a746604745a4@example.com y\n",
		"a@b.co taro@example.com\n":  "hash_" + hmacHex("a", 12) + "@b.co hash_a746604745a4@example.com\n",
		"mailto:taro@example.com.\n": "mailto:hash_a746604745a4@example.com.\n",
	} {
		got, _ := hashRun(t, detect.Options{}, testKey, 12, EmailHashLocal, in)
		if got != want {
			t.Errorf("hash local(%q)\n got  %q\n want %q", in, got, want)
		}
	}
	// 他の種別は、local でも、値全体をハッシュする。
	got, _ := hashRun(t, detect.Options{}, testKey, 12, EmailHashLocal, "192.168.0.1\n")
	if want := "ipv4_private_dca2f4f38564\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHashLength(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{
		{8, "email_99a207ef\n"},
		{12, "email_99a207efd719\n"},
		{16, "email_99a207efd719edf1\n"},
		{64, "email_99a207efd719edf17c433dca6d2479c8a738f14d9cbff5282ab8068aa09a8d68\n"},
	} {
		got, _ := hashRun(t, detect.Options{}, testKey, tt.n, EmailHashFull, "taro@example.com\n")
		if got != tt.want {
			t.Errorf("length %d: got %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestHashDependsOnKey(t *testing.T) {
	a, _ := hashRun(t, detect.Options{}, "key-a", 12, EmailHashFull, "taro@example.com\n")
	b, _ := hashRun(t, detect.Options{}, "key-b", 12, EmailHashFull, "taro@example.com\n")
	a2, _ := hashRun(t, detect.Options{}, "key-a", 12, EmailHashFull, "taro@example.com\n")
	if a == b {
		t.Error("different keys produced the same output")
	}
	if a != a2 {
		t.Error("the same key produced different outputs")
	}
}

// 受け入れ基準: 元の値が、出力に残らない。
func TestHashOutputDoesNotContainOriginals(t *testing.T) {
	in := readSample(t)
	for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
		out, _ := hashRun(t, detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}, testKey, 12, mode, in)
		for _, secret := range []string{
			"hunter2", "abc123def456ghi789", "AKIAIOSFODNN7EXAMPLE", "203.0.113.45", "192.168.0.12", "10.0.0.5",
			"hanako@", "taro@", "2001:4860:4860::8888", "fe80::1", "123e4567-e89b-42d3-a456-426614174000",
		} {
			if strings.Contains(out, secret) {
				t.Errorf("mode %d: output contains %q", mode, secret)
			}
		}
	}
}

func TestHashAllowAndTypes(t *testing.T) {
	opts := detect.Options{
		Kinds: detect.KindSet(0).With(detect.KindEmail),
		Allow: map[string]struct{}{"support@example.com": {}},
	}
	got, _ := hashRun(t, opts, testKey, 12, EmailHashFull, "support@example.com taro@example.com 10.0.0.1\n")
	if want := "support@example.com email_99a207efd719 10.0.0.1\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHashLongLine(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"events":[`)
	for sb.Len() < 1<<20 {
		sb.WriteString(`{"user":"taro@example.com","ip":"10.0.0.1","password":"hunter2"},`)
	}
	sb.WriteString(`{}]}`)
	got, st := hashRun(t, detect.Options{}, testKey, 12, EmailHashFull, sb.String()+"\n")
	if strings.Contains(got, "taro@example.com") || strings.Contains(got, "hunter2") {
		t.Error("a value was not replaced")
	}
	if !strings.HasPrefix(got, `{"events":[{"user":"email_99a207efd719","ip":"ipv4_private_`) {
		t.Errorf("unexpected prefix: %.100q", got)
	}
	if st.Total() < 3 {
		t.Errorf("Total = %d", st.Total())
	}
}

func TestHashStats(t *testing.T) {
	_, st := hashRun(t, detect.Options{}, testKey, 12, EmailHashFull, "a@x.com a@x.com 10.0.0.1 password=abc\n")
	if st.Count("email") != 2 || st.Count("ipv4_private") != 1 || st.Count("secret") != 1 || st.Total() != 4 {
		t.Errorf("stats: %+v", st.Types())
	}
}

// ---- 冪等性(受け入れ基準) ----

// hash モードの出力を、同じ設定で再度流しても変わらない。
func TestHashIsIdempotent(t *testing.T) {
	inputs := map[string]string{
		"sample": readSample(t),
		"acceptance": "taro@example.com 192.168.0.1\npassword=abc123&user=x\nAuthorization: Bearer xxxxx\n" +
			`"api_key": "abc def"` + "\n::ffff:10.0.0.1 https://user:pass@10.0.0.1/\n",
		"json":     `{"user":"a@x.com","password":"p","n":1,"ip":"10.0.0.1"}` + "\n",
		"embedded": `{"m":"{\"password\":\"abc\",\"ip\":\"10.0.0.1\"}"}` + "\n",
		"crlf":     "a@x.com\r\nb@x.com\r\n",
		"japanese": "接続元 10.0.0.1 から taro@example.com\n",
		"uuid":     "id=123e4567-e89b-42d3-a456-426614174000\n",
	}
	for iname, in := range inputs {
		for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
			for _, n := range []int{8, 12, 16, 64} {
				opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
				once, _ := hashRun(t, opts, testKey, n, mode, in)
				twice, st := hashRun(t, opts, testKey, n, mode, once)
				if once != twice {
					t.Errorf("%s / mode %d / length %d: hash(hash(x)) != hash(x)\n once:  %q\n twice: %q", iname, mode, n, once, twice)
				}
				if st.Total() != 0 {
					t.Errorf("%s / mode %d / length %d: second pass replaced %d values", iname, mode, n, st.Total())
				}
			}
		}
	}
}

// 受け入れ基準: hash モードの password=secret_3f9a1c0b7d2e が再ハッシュされない。
// ローカルパートが hash_<hex> の形のメールアドレスも、再ハッシュされない。
func TestHashDoesNotRehashOutputForms(t *testing.T) {
	for _, in := range []string{
		"password=secret_3f9a1c0b7d2e\n",
		"hash_3f9a1c0b7d2e@example.com\n",
		"email_3f9a1c0b7d2e ipv4_private_a1b2c3d4e5f6 ipv4_global_a1b2c3d4e5f6\n",
		"ipv6_private_a1b2c3d4e5f6 ipv6_global_a1b2c3d4e5f6 uuid_a1b2c3d4e5f6 secret_a1b2c3d4e5f6\n",
		"to hash_3f9a1c0b7d2e@example.com, hash_000000000000@example.org.\n",
		"ssh email_3f9a1c0b7d2e@bastion.example.org\n",
	} {
		for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
			if got, _ := hashRun(t, detect.Options{}, testKey, 12, mode, in); got != in {
				t.Errorf("mode %d: hash(%q) = %q, want unchanged", mode, in, got)
			}
		}
	}
	// 桁数が、--hash-length と違うものは、出力形ではないので、通常どおり検出される。
	if got := hashDefault(t, "password=secret_3f9a1c0b7d2\n"); got == "password=secret_3f9a1c0b7d2\n" {
		t.Error("an 11-digit value was treated as a hash output")
	}
}

// `@` が続く入力(踏み台経由の `user@example.com@bastion.example.org`)の、先頭だけが置換された結果を、
// 全体で 1 つのメールアドレスとして、再度ハッシュしない。
func TestHashIsIdempotentForChainedAtSigns(t *testing.T) {
	for _, in := range []string{
		"ssh user@example.com@bastion.example.org\n",
		"a@b.co@c.com\n",
		"0@0.AA@0.AA\n",
		"x@y.zz@w.zz@v.zz\n",
	} {
		for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
			once, _ := hashRun(t, detect.Options{}, testKey, 12, mode, in)
			twice, st := hashRun(t, detect.Options{}, testKey, 12, mode, once)
			if once != twice || st.Total() != 0 {
				t.Errorf("mode %d: hash(hash(%q)) != hash(%q)\n once:  %q\n twice: %q", mode, in, in, once, twice)
			}
		}
	}
}

// 合成ログ(1MB の JSON 行を含む)でも、2 回流しても変わらない。
func TestHashSyntheticLogIsIdempotent(t *testing.T) {
	var sb strings.Builder
	if _, err := synthlog.Generate(&sb, synthlog.Config{Size: 3 << 20, Seed: 11, LongLineEvery: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	opts := detect.Options{Kinds: detect.DefaultKinds.With(detect.KindUUID)}
	for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
		once, st := hashRun(t, opts, testKey, 12, mode, sb.String())
		if st.Total() == 0 {
			t.Fatal("nothing was replaced")
		}
		twice, st2 := hashRun(t, opts, testKey, 12, mode, once)
		if once != twice || st2.Total() != 0 {
			t.Errorf("mode %d: hash(hash(x)) != hash(x) (second pass replaced %d)", mode, st2.Total())
		}
	}
}

// ---- ファズテスト(mask と同じ性質。ラベルと hash 出力形の両方を、置換済みの形として見る) ----

func FuzzHashStable(f *testing.F) {
	for _, s := range []string{
		"taro@example.com 192.168.0.1\n", "password=abc123&user=x\n", `"api_key": "abc def"` + "\n",
		"Authorization: Bearer xxxxx\r\n", "::ffff:10.0.0.1 [::1]:8080 fe80::1%eth0\n", "https://user:pass@10.0.0.1/\n",
		"id=123e4567-e89b-42d3-a456-426614174000 {123e4567-e89b-42d3-a456-426614174000}\n",
		`{"m":"{\"password\":\"abc\",\"user\":\"a@x.com\"}"}` + "\n", "AKIAIOSFODNN7EXAMPLE ghp_" + strings.Repeat("a", 36) + "\n",
		"email_3f9a1c0b7d2e password=secret_3f9a1c0b7d2e hash_3f9a1c0b7d2e@example.com\n", "token: Bearer abc.def-ghi\n",
		"接続元 10.0.0.1 から taro@example.com\n", "\xff\xfe a@b.co\r\n", "000000A10.0.0.0fC00::\n", "10.0.0.1abc a@b.coabc\n",
		"0@0.AA@0.AA\n", "0@0.AA:::1\n", "ssh user@example.com@bastion.example.org\n",
	} {
		f.Add(s)
	}
	for _, s := range awsFuzzSeeds {
		f.Add(s)
	}
	optsList, dets := fuzzOptions(f)
	f.Fuzz(func(t *testing.T, in string) {
		for i, opts := range optsList {
			for _, mode := range []EmailHash{EmailHashFull, EmailHashLocal} {
				once, _ := hashRun(t, opts, testKey, 12, mode, in)
				if strings.Count(once, "\n") != strings.Count(in, "\n") || strings.HasSuffix(in, "\n") != strings.HasSuffix(once, "\n") {
					t.Fatalf("mode %d: the line structure changed: %q -> %q", mode, in, once)
				}
				checkSecondPass(t, dets[i], in, once, func(b []byte) []secondPassSpan {
					var phs []secondPassSpan
					label.DefaultFormat.Scan(b, func(s, e int, _ string, _ int) { phs = append(phs, secondPassSpan{s, e}) })
					label.ScanHashed(b, 12, func(s, e int) { phs = append(phs, secondPassSpan{s, e}) })
					return phs
				})
			}
		}
	})
}

// ---- NewHasher の検証 ----

func TestNewHasherValidation(t *testing.T) {
	if _, err := NewHasher(nil, 12, EmailHashFull); err == nil {
		t.Error("an empty key was accepted")
	}
	if _, err := NewHasher([]byte{}, 12, EmailHashFull); err == nil {
		t.Error("an empty key was accepted")
	}
	for _, n := range []int{-1, 1, 7, 65, 100} {
		if _, err := NewHasher([]byte("k"), n, EmailHashFull); err == nil {
			t.Errorf("hash length %d was accepted", n)
		}
	}
	for _, n := range []int{0, 8, 12, 64} {
		if _, err := NewHasher([]byte("k"), n, EmailHashFull); err != nil {
			t.Errorf("hash length %d: %v", n, err)
		}
	}
	if _, err := NewHasher([]byte("k"), 12, EmailHash(9)); err == nil {
		t.Error("an unknown email mode was accepted")
	}
}

// エラーメッセージに、鍵を含めない。
func TestNewHasherErrorDoesNotContainKey(t *testing.T) {
	_, err := NewHasher([]byte("SUPER-SECRET-KEY"), 3, EmailHashFull)
	if err == nil || strings.Contains(err.Error(), "SUPER-SECRET-KEY") {
		t.Errorf("err = %v", err)
	}
}
