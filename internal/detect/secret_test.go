package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kiaamaaio/logscrub/internal/label"
)

func base64StdDecode(s string) ([]byte, error)    { return base64.StdEncoding.DecodeString(s) }
func base64RawStdDecode(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

func mustFormat(t *testing.T, s string) label.Format {
	t.Helper()
	f, err := label.ParseFormat(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// secretsIn は、secret 検出器だけを直接動かし、候補の文字列を返す。
func secretsIn(line string) []string {
	var got []string
	for _, m := range (secretFinder{}).find([]byte(line), nil) {
		if m.Kind != KindSecret || m.Class != ClassNone {
			panic("secretFinder returned a match that is not a plain secret")
		}
		got = append(got, line[m.Start:m.End])
	}
	return got
}

func rep(s string, n int) string { return strings.Repeat(s, n) }

const (
	jwtHeader  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	jwtPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
	jwtSig     = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	jwt        = jwtHeader + "." + jwtPayload + "." + jwtSig
)

func TestSecretFinderKind(t *testing.T) {
	if k := (secretFinder{}).kind(); k != KindSecret {
		t.Errorf("kind = %v", k)
	}
}

// ---- 固定形式(仕様 4.1 の表、Q14: 前後が英数字でないこと) ----

func TestSecretFixedFormats(t *testing.T) {
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	ghp := "ghp_" + rep("a", 36)
	pat := "github_pat_" + "11ABCDEFG0" + "abcdefghij_KLMN"
	slack := "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	stripe := "sk_live_" + rep("a", 24)
	google := "AIza" + "SyA-1234567890abcdefghijklmnopqrstu"
	skKey := "sk-" + "proj-abcdefghijklmnopqrstuvwx_YZ"
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"aws akia", aws, []string{aws}},
		{"aws asia", "ASIA" + "IOSFODNN7EXAMPLE", []string{"ASIA" + "IOSFODNN7EXAMPLE"}},
		{"aws in text", "key " + aws + " used", []string{aws}},
		{"aws in assignment", "aws_access_key_id=" + aws, []string{aws}},
		{"aws followed by underscore", aws + "_x", []string{aws}},
		{"github ghp", ghp, []string{ghp}},
		{"github gho", "gho_" + rep("A", 36), []string{"gho_" + rep("A", 36)}},
		{"github ghu", "ghu_" + rep("9", 36), []string{"ghu_" + rep("9", 36)}},
		{"github ghs", "ghs_" + rep("a", 40), []string{"ghs_" + rep("a", 40)}},
		{"github ghr", "ghr_" + rep("a", 36), []string{"ghr_" + rep("a", 36)}},
		{"github fine grained", pat, []string{pat}},
		{"github fine grained 22", "github_pat_" + rep("a", 22), []string{"github_pat_" + rep("a", 22)}},
		{"slack bot", slack, []string{slack}},
		{"slack user", "xoxp-" + rep("1", 10), []string{"xoxp-" + rep("1", 10)}},
		{"slack a", "xoxa-" + rep("1", 10), []string{"xoxa-" + rep("1", 10)}},
		{"slack r", "xoxr-" + rep("1", 10), []string{"xoxr-" + rep("1", 10)}},
		{"slack s", "xoxs-" + rep("1", 10), []string{"xoxs-" + rep("1", 10)}},
		{"stripe live", stripe, []string{stripe}},
		{"stripe test", "sk_test_" + rep("A", 30), []string{"sk_test_" + rep("A", 30)}},
		{"stripe restricted live", "rk_live_" + rep("a", 24), []string{"rk_live_" + rep("a", 24)}},
		{"stripe restricted test", "rk_test_" + rep("a", 24), []string{"rk_test_" + rep("a", 24)}},
		{"google", google, []string{google}},
		{"sk key", skKey, []string{skKey}},
		{"sk key min", "sk-" + rep("a", 20), []string{"sk-" + rep("a", 20)}},
		{"sk key in parentheses", "(" + "sk-" + rep("a", 20) + ")", []string{"sk-" + rep("a", 20)}},
		{"jwt", jwt, []string{jwt}},
		{"jwt in text", "token " + jwt + " ok", []string{jwt}},
		// 署名部が空の JWT(alg: none)。区切りの '.' までを範囲とする。
		{"jwt without signature", jwtHeader + "." + jwtPayload + ".", []string{jwtHeader + "." + jwtPayload + "."}},
		{"two tokens", aws + " " + ghp, []string{aws, ghp}},
		{"japanese around", "鍵:" + aws + "です", []string{aws}},
		{"invalid utf8 around", "\xff" + aws + "\x80", []string{aws}},

		// 検出しない: 長さが足りない・多い
		{"aws 15", "AKIA" + "IOSFODNN7EXAMPL", nil},
		{"aws 17", "AKIA" + "IOSFODNN7EXAMPLEX", nil},
		{"aws lowercase", "AKIA" + "iosfodnn7example", nil},
		{"ghp 35", "ghp_" + rep("a", 35), nil},
		{"ghp invalid char", "ghp_" + rep("a", 20) + "-" + rep("a", 20), nil},
		{"github pat 21", "github_pat_" + rep("a", 21), nil},
		{"slack 9", "xoxb-" + rep("1", 9), nil},
		{"slack unknown letter", "xoxz-" + rep("1", 10), nil},
		{"slack o is not in the spec", "xoxo-" + rep("1", 10), nil},
		{"stripe 23", "sk_live_" + rep("a", 23), nil},
		{"stripe unknown mode", "sk_prod_" + rep("a", 24), nil},
		{"stripe underscore in key", "sk_live_" + rep("a", 12) + "_" + rep("a", 12), nil},
		{"google 34", "AIza" + rep("a", 34), nil},
		{"google 36", "AIza" + rep("a", 36), nil},
		{"sk 19", "sk-" + rep("a", 19), nil},
		{"jwt two parts", jwtHeader + "." + jwtPayload, nil},
		{"jwt payload not eyJ", jwtHeader + ".abc." + jwtSig, nil},
		{"jwt header not eyJ", "abc." + jwtPayload + "." + jwtSig, nil},
		// 検出しない: 前が英数字
		{"aws after alnum", "x" + aws, nil},
		{"ghp after alnum", "x" + ghp, nil},
		{"sk after alnum", "task-" + rep("a", 26), nil},
		{"jwt after alnum", "x" + jwt, nil},
		{"google after alnum", "x" + google, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsIn(tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("secrets(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// indexFixedLiterals、indexFixed は、v1.2 の段階 7 より前の固定形式の検出(接頭辞を bytes.Index で探す)。
// 手がかりのバイトで探す今の実装(fixedPrefixes)と、結果が一致することを確かめる参照実装。
var indexFixedLiterals = [...][]byte{
	[]byte("AKIA"), []byte("ASIA"), []byte("AIza"), []byte("gh"), []byte("github_pat_"),
	[]byte("xox"), []byte("sk"), []byte("rk"), []byte("eyJ"),
}

func indexFixed(line []byte) []Match {
	var dst []Match
	n := len(line)
	var next [len(indexFixedLiterals)]int
	for i := range next {
		next[i] = -1
	}
	for pos := 0; pos < n; {
		best := n
		for i, lit := range indexFixedLiterals {
			if next[i] == n {
				continue
			}
			if next[i] < pos {
				j := bytes.Index(line[pos:], lit)
				if j < 0 {
					next[i] = n
					continue
				}
				next[i] = pos + j
			}
			best = min(best, next[i])
		}
		if best >= n {
			break
		}
		p := best
		if p > 0 && isASCIIAlnum(line[p-1]) {
			pos = p + 1
			continue
		}
		loc := fixedRe.FindIndex(line[p:])
		if loc == nil || p+loc[1] < n && isASCIIAlnum(line[p+loc[1]]) {
			pos = p + 1
			continue
		}
		dst = append(dst, Match{Start: p, End: p + loc[1], Kind: KindSecret})
		pos = p + loc[1]
	}
	return dst
}

// 固定形式の接頭辞を、手がかりのバイトで探す実装(段階 7)が、bytes.Index で探す参照実装と一致すること。
// 行は、接頭辞・その一部・形に合う続き・前後の文字を、ランダムに並べて作る。
func TestSecretFixedMatchesIndexReference(t *testing.T) {
	alphabet := []string{
		"AKIA", "ASIA", "AIza", "gh", "github_pat_", "xox", "sk", "rk", "eyJ",
		"A", "K", "I", "S", "z", "g", "h", "i", "x", "o", "s", "r", "k", "e", "y", "J",
		"p_", "u_", "b-", "_live_", "_test_", "-", "_", ".", " ", "=", "\"", ":", "/", "@", "あ", "\xff",
		"IOSFODNN7EXAMPLE", rep("a", 20), rep("b", 22), rep("C", 24), rep("1", 35), rep("d", 36), "hbGci", ".eyJ",
		// 形に合う値(前後の部品しだいで、一致したり、前後の英数字のため一致しなかったりする)
		"AKIAIOSFODNN7EXAMPLE", "ghp_" + rep("a", 36), "github_pat_" + rep("b", 22), "xoxb-" + rep("1", 10),
		"sk_live_" + rep("c", 24), "rk_test_" + rep("c", 24), "AIza" + rep("d", 35), "sk-" + rep("e", 20), "eyJa.eyJb.c",
	}
	rng := rand.New(rand.NewPCG(41, 42))
	f := secretFinder{}
	matched := 0
	for iter := 0; iter < 100000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(12); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		want := indexFixed(line)
		got := f.fixed(line, nil)
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		if len(want) > 0 {
			matched++
		}
	}
	// 一致する行が少なすぎると、比べた意味がない
	if matched < 20000 {
		t.Errorf("only %d lines had fixed-format matches", matched)
	}
	t.Logf("%d lines had fixed-format matches", matched)
}

// ---- AWS の署名(仕様 4.1「AWS の署名」、Q32) ----

// AWS のドキュメントの例の署名(64 桁の小文字の 16 進数)。
const (
	awsSig  = "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
	awsSig2 = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
)

func TestSecretAWSSignature(t *testing.T) {
	presigned := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=" + awsSig2
	authz := "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-date, Signature=" + awsSig
	tests := []struct {
		name string
		line string
		want []string
	}{
		// 署名付き URL: 署名と、X-Amz-Credential の中のアクセスキー ID だけ。日付・リージョンなどは残る。
		{"presigned url", presigned, []string{"AKIAIOSFODNN7EXAMPLE", awsSig2}},
		// SigV4 の Authorization: 方式名が Bearer / Basic でないので、キー名ベースの値にはならない。
		{"authorization header", authz, []string{"AKIAIOSFODNN7EXAMPLE", awsSig}},
		{"x-amz-signature", "X-Amz-Signature=" + awsSig, []string{awsSig}},
		{"signature", "Signature=" + awsSig, []string{awsSig}},
		{"after question mark", "/a?X-Amz-Signature=" + awsSig + "&b=1", []string{awsSig}},
		{"after ampersand", "&X-Amz-Signature=" + awsSig + "&", []string{awsSig}},
		{"after comma and space", "x, Signature=" + awsSig, []string{awsSig}},
		{"lowercase word", "x-amz-signature=" + awsSig, []string{awsSig}},
		{"uppercase word", "X-AMZ-SIGNATURE=" + awsSig, []string{awsSig}},
		{"mixed case word", "sIgNaTuRe=" + awsSig, []string{awsSig}},
		{"in double quotes", `"url":"https://b.s3.amazonaws.com/k?X-Amz-Signature=` + awsSig + `"`, []string{awsSig}},
		{"followed by period", "Signature=" + awsSig + ".", []string{awsSig}},
		{"followed by underscore", "Signature=" + awsSig + "_x", []string{awsSig}},
		{"followed by japanese", "Signature=" + awsSig + "です", []string{awsSig}},
		{"two signatures", "Signature=" + awsSig + " X-Amz-Signature=" + awsSig2, []string{awsSig, awsSig2}},
		{"invalid utf8 before", "\xffSignature=" + awsSig, []string{awsSig}},

		// 検出しない: 64 桁の小文字の 16 進数でない
		{"63 digits", "Signature=" + awsSig[:63], nil},
		{"65 digits", "Signature=" + awsSig + "0", nil},
		{"uppercase hex", "Signature=" + strings.ToUpper(awsSig), nil},
		{"one uppercase hex", "Signature=" + "F" + awsSig[1:], nil},
		{"non hex letter", "Signature=" + "g" + awsSig[1:], nil},
		{"followed by letter", "Signature=" + awsSig + "g", nil},
		{"sigv2 base64", "Signature=" + "nI3mmJwlFz1D2nOzfUHPmOjTkf6dbTO0xsYd4OO7bL8%3D", nil},
		{"space after equals", "Signature= " + awsSig, nil},
		{"colon separator", "X-Amz-Signature: " + awsSig, nil},
		// 検出しない: 語の前が英数字・`-`・`_`、または別の語
		{"after letter", "xSignature=" + awsSig, nil},
		{"after hyphen", "Foo-Signature=" + awsSig, nil},
		{"after underscore", "my_signature=" + awsSig, nil},
		{"x-amz after letter", "aX-Amz-Signature=" + awsSig, nil},
		{"x-amz after hyphen", "x-amz-x-amz-signature=" + awsSig, nil},
		{"signed headers", "X-Amz-SignedHeaders=" + awsSig, nil},
		{"signatures", "Signatures=" + awsSig, nil},
		// 本文のハッシュ値は、秘密ではないので対象外
		{"content sha256", "x-amz-content-sha256=" + awsSig, nil},
		{"short line", "Signature=", nil},
		{"only equals", rep("=", 100), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsIn(tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("secrets(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// ---- Authorization ヘッダ(仕様 4.1、決定事項 15: キー名の値の位置に限る) ----

func TestSecretBearerAndBasic(t *testing.T) {
	basic := "dXNlcjpwYXNz" // user:pass
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"bearer", "Authorization: Bearer abc123", []string{"abc123"}},
		{"bearer lowercase", "authorization: bearer abc123", []string{"abc123"}},
		{"bearer uppercase", "AUTHORIZATION: BEARER abc123", []string{"abc123"}},
		{"bearer equals", "authorization=Bearer abc123", []string{"abc123"}},
		{"bearer proxy", "Proxy-Authorization: Bearer abc123", []string{"abc123"}},
		{"bearer two spaces", "Authorization: Bearer  abc123", []string{"abc123"}},
		{"bearer tab", "Authorization: Bearer\tabc123", []string{"abc123"}},
		{"bearer token68 chars", "Authorization: Bearer a.b-c_d~e+f/g", []string{"a.b-c_d~e+f/g"}},
		{"bearer padding", "Authorization: Bearer abc==", []string{"abc=="}},
		{"bearer then comma", "Authorization: Bearer abc,def", []string{"abc"}},
		{"bearer then semicolon", "Authorization: Bearer abc; path=/", []string{"abc"}},
		{"bearer json", `{"Authorization": "Bearer abc123"}`, []string{"abc123"}},
		{"bearer json compact", `{"headers":{"authorization":"Bearer abc123","x":1}}`, []string{"abc123"}},
		{"bearer curl", `curl -H "Authorization: Bearer abc123" https://x`, []string{"abc123"}},
		{"bearer escaped json", `{"m":"{\"Authorization\":\"Bearer abc123\"}"}`, []string{"abc123"}},
		{"bearer jwt", "Authorization: Bearer " + jwt, []string{jwt, jwt}},
		// 他の対象のキー名の値が方式名で始まる場合も、方式名を残して、値だけを置換する
		{"token key", "token: Bearer abc123", []string{"abc123"}},
		// 方式名の後ろが値として読めない場合は、方式名の語を値として置換しない(冪等性)
		{"token key bearer placeholder", "token: Bearer <secret_1>", nil},
		{"token key bearer bracket placeholder", "token: Bearer [secret-1]", nil},
		{"token key basic prose", "token: Basic setup complete", nil},
		{"token key basic not base64", "token: Basic abc!def", nil},
		// 方式名の後ろに空白がなければ、方式名ではない(値として置換する)
		{"token key bearer alone", "token: Bearer", []string{"Bearer"}},
		{"token key bearer word", "token=Bearerabc", []string{"Bearerabc"}},
		{"api key header", "X-Api-Key: Bearer abc123", []string{"abc123"}},
		{"basic", "Authorization: Basic " + basic, []string{basic}},
		{"basic padded", "Authorization: Basic dXNlcjpwYXNzd29yZA==", []string{"dXNlcjpwYXNzd29yZA=="}},
		{"basic without padding", "Authorization: Basic YWJjOmRlZg", []string{"YWJjOmRlZg"}},
		{"basic uppercase", "Authorization: BASIC " + basic, []string{basic}},
		{"basic then period", "Authorization: Basic " + basic + ".", []string{basic + "."}},
		{"basic json", `{"Authorization":"Basic ` + basic + `"}`, []string{basic}},

		// 検出しない(精度重視): キー名のない文章中
		{"bearer in prose", "got Bearer abc123 here", nil},
		{"bearer alone", "Bearer abc123", nil},
		{"bearer token is", "Bearer token is required", nil},
		{"basic in prose", "Basic " + basic, nil},
		// 検出しない: Authorization で、方式名がない・値がない
		{"authorization without scheme", "Authorization: abc123", nil},
		{"authorization raw token", "authorization=abc123", nil},
		{"bearer no value", "Authorization: Bearer", nil},
		{"bearer then end", "Authorization: Bearer ", nil},
		{"bearer placeholder", "Authorization: Bearer <secret_1>", nil},
		{"bearer bracket placeholder", "Authorization: Bearer [secret-1]", nil},
		{"bearer quoted value", `Authorization: Bearer "abc"`, nil},
		{"bearer after alnum", "Authorization: xBearer abc123", nil},
		{"bearer without space", "Authorization: Bearerabc123", nil},
		{"bearers", "Authorization: Bearers abc", nil},
		{"basic prose value", "Authorization: Basic setup complete", nil},
		{"basic no colon", "Authorization: Basic dXNlcg==", nil}, // user
		{"basic not base64", "Authorization: Basic abc!def", nil},
		{"basic alone", "Authorization: Basic", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretsIn(tt.line)
			// JWT は、固定形式の規則と、Authorization の規則の両方に一致する(同じ範囲)。
			if tt.name == "bearer jwt" {
				got = slices.Compact(got)
				tt.want = []string{jwt}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("secrets(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// ---- キー名ベース(仕様 4.1、Q15〜Q17) ----

func TestSecretKeyedValues(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		// 受け入れ基準
		{"password query", "password=abc123&user=x", []string{"abc123"}},
		{"api_key json", `"api_key": "abc def"`, []string{"abc def"}},
		{"auth token header", "X-Auth-Token: xxx", []string{"xxx"}},
		{"env password", "DB_PASSWORD=xxx", []string{"xxx"}},

		// 対象のキー名(13 種)
		{"password", "password=v", []string{"v"}},
		{"passwd", "passwd=v", []string{"v"}},
		{"secret", "secret=v", []string{"v"}},
		{"token", "token=v", []string{"v"}},
		{"api_key", "api_key=v", []string{"v"}},
		{"apikey", "apikey=v", []string{"v"}},
		{"access_key", "access_key=v", []string{"v"}},
		{"private_key", "private_key=v", []string{"v"}},
		{"client_secret", "client_secret=v", []string{"v"}},
		{"access_token", "access_token=v", []string{"v"}},
		{"refresh_token", "refresh_token=v", []string{"v"}},
		{"auth_token", "auth_token=v", []string{"v"}},
		{"session_id", "session_id=v", []string{"v"}},
		// キー名の照合: 大文字・小文字を区別しない。'-' と '_' を同一視。区切りの単位で末尾に現れる。
		{"upper", "PASSWORD=v", []string{"v"}},
		{"mixed", "Password=v", []string{"v"}},
		{"hyphen", "api-key=v", []string{"v"}},
		{"hyphen header", "X-Api-Key: v", []string{"v"}},
		{"dot", "db.password=v", []string{"v"}},
		{"dot multi unit", "api.key=v", []string{"v"}},
		{"prefixed", "my_session_id=v", []string{"v"}},
		{"aws secret access key", "AWS_SECRET_ACCESS_KEY=v", []string{"v"}},
		{"github token", "GITHUB_TOKEN=v", []string{"v"}},
		{"leading underscore", "_token=v", []string{"v"}},
		{"after slash", "/token=v", []string{"v"}},
		{"after question mark", "GET /x?token=v HTTP/1.1", []string{"v"}},
		// camelCase(決定事項 15): 小文字・数字から大文字への変わり目と、大文字の連なりの終わりが区切り
		{"camel access token", "accessToken=v", []string{"v"}},
		{"camel pascal", "AccessToken=v", []string{"v"}},
		{"camel client secret", "clientSecret: v", []string{"v"}},
		{"camel refresh token", "refreshToken=v", []string{"v"}},
		{"camel session id", "sessionId=v", []string{"v"}},
		{"camel session ID", "sessionID=v", []string{"v"}},
		{"camel api key", "apiKey=v", []string{"v"}},
		{"camel acronym", "APIKey=v", []string{"v"}},
		{"camel private key", "privateKey=v", []string{"v"}},
		{"camel auth token", "authToken=v", []string{"v"}},
		{"camel access key", "accessKey=v", []string{"v"}},
		{"camel prefixed", "myAppToken=v", []string{"v"}},
		{"camel with digit", "v2Token=v", []string{"v"}},
		{"camel in json", `{"accessToken":"v","userId":"u"}`, []string{"v"}},
		{"go struct", "{Token:v Password:w}", []string{"v", "w"}},

		// 区切り(Q15: 前後の空白は任意個)
		{"colon", "password:abc", []string{"abc"}},
		{"colon space", "password: abc", []string{"abc"}},
		{"colon two spaces", "token:  abc", []string{"abc"}},
		{"equals spaces", "password = abc", []string{"abc"}},
		{"tabs", "password\t=\tabc", []string{"abc"}},
		{"json spaces", `"token" : "abc"`, []string{"abc"}},
		{"json compact", `{"user":"x","password":"hunter2","n":1}`, []string{"hunter2"}},
		{"json single quotes", `{'password': 'abc'}`, []string{"abc"}},
		{"yaml", "password: abc", []string{"abc"}},

		// 値の範囲(引用符、Q16: 閉じ引用符がなければ行末まで)
		{"double quoted", `password="a b c"`, []string{"a b c"}},
		{"single quoted", `password='a b'`, []string{"a b"}},
		{"escaped quote", `password="ab\"cd" next`, []string{`ab\"cd`}},
		{"apostrophe inside double", `password="it's"`, []string{"it's"}},
		{"quoted then more", `password="abc",user=x`, []string{"abc"}},
		{"unterminated double", `password="abc`, []string{"abc"}},
		{"unterminated single with space", `token='abc def`, []string{"abc def"}},
		{"unterminated after escape", `password="abc\`, []string{`abc\`}},
		// 値の範囲(引用符なし): 空白・& , ; } ] の直前まで
		{"stop ampersand", "password=abc&x=1", []string{"abc"}},
		{"stop comma", "password=abc,x", []string{"abc"}},
		{"stop semicolon", "password=abc;path=/", []string{"abc"}},
		{"stop brace", "{password=abc}", []string{"abc"}},
		{"stop bracket", "[password=abc]", []string{"abc"}},
		{"stop space", "password=abc def", []string{"abc"}},
		{"stop tab", "password=abc\tdef", []string{"abc"}},
		{"cookie", "Cookie: session_id=abc123; Path=/", []string{"abc123"}},
		{"url query", "GET /login?user=x&password=hunter2 HTTP/1.1", []string{"hunter2"}},
		{"two keys", "token=a password=b", []string{"a", "b"}},
		{"japanese around", "パスワード password=abc です", []string{"abc"}},
		{"value with equals", "password=a=b", []string{"a=b"}},
		// キー名が引用符で囲まれた形(JSON、辞書)では、文字列の値だけを置換する(決定事項 15)
		{"json number", `"token": 12345`, nil},
		{"json null", `"password": null`, nil},
		{"json true", `"token": true,`, nil},
		{"json false", `{"secret":false}`, nil},
		{"json object", `"token": {"a":1}`, nil},
		{"json array", `"token": ["a","b"]`, nil},
		{"json nested string inside object", `"token": {"password":"x"}`, []string{"x"}},
		{"dict number", `{'token': 12345}`, nil},
		{"dict string", `{'token': 'abc'}`, []string{"abc"}},
		// キー名が引用符で囲まれていない形では、数値・null も、引用符なしの値として置換する
		{"bare number", "token: 12345", []string{"12345"}},
		{"bare null", "password=null", []string{"null"}},
		{"bare object", "token={a:1}", nil},
		{"bare array", "token=[a,b]", nil},
		// 引用符なしの値の終端に、引用符と ')' を加える(閉じ引用符・閉じ括弧を巻き込まない)
		{"stop double quote", `{"msg":"password=abc123"}`, []string{"abc123"}},
		{"stop double quote then more", `{"msg":"login password=abc123 ok","n":1}`, []string{"abc123"}},
		{"stop single quote", `{'msg': 'password=abc'}`, []string{"abc"}},
		{"stop paren", "login(user=x, password=abc)", []string{"abc"}},
		{"stop paren token", "(token=abc)", []string{"abc"}},
		{"apostrophe in bare value", "password=it's", []string{"it"}},
		// ログに文字列として埋め込まれた JSON(引用符が \" の形)
		{"embedded json", `{"message":"{\"password\":\"abc123\",\"user\":\"x\"}"}`, []string{"abc123"}},
		{"embedded json token", `{"m":"{\"accessToken\":\"abc\"}"}`, []string{"abc"}},
		{"embedded key value", `{"msg":"password=\"abc\" ok"}`, []string{"abc"}},
		{"embedded number", `{"m":"{\"token\":12345}"}`, nil},
		// 引用符なしの値は、JSON の文字列の中のエスケープの手前で終わる
		{"embedded bare value before escaped quote", `{"m":"{\"pin\":\"token=abc123\"}"}`, []string{"abc123"}},
		{"escaped newline", `{"m":"token=abc\ndef"}`, []string{"abc"}},
		{"escaped carriage return", `{"m":"token=abc\r\nuser=x"}`, []string{"abc"}},
		{"escaped tab", `{"m":"token=abc\tdef"}`, []string{"abc"}},
		{"escaped ampersand", `{"u":"?token=abc\u0026user=x"}`, []string{"abc"}},
		{"escaped other unicode", `{"u":"token=a\u00e9b"}`, []string{`a\u00e9b`}},
		{"escaped backslash pair", `{"m":"password=ab\\cd"}`, []string{`ab\\cd`}},
		{"escaped backslash pair before quote", `{"m":"password=abc\\"}`, []string{`abc\\`}},
		{"lone backslash inside", `password=ab\cd`, []string{`ab\cd`}},
		{"lone backslash at end", `password=abc\`, []string{`abc\`}},
		{"backslash before space", `password=my\ secret`, []string{`my\`}},
		{"value is a placeholder-like text", "password=<secret_1>&x=1", []string{"<secret_1>"}},

		// 検出しない(受け入れ基準)
		{"max_tokens", "max_tokens: 4096", nil},
		{"token_count", "token_count=5", nil},
		{"pwd", "PWD=/home/user", nil},
		// 検出しない(キー名)
		{"tokens", "tokens=abc", nil},
		{"passwordless", "passwordless=true", nil},
		{"embedded in word", "mytoken=abc", nil},
		{"password hash", "password_hash=abc", nil},
		{"secret count", "secret_count=1", nil},
		{"token dot count", "token.count=1", nil},
		{"camel max tokens", "maxTokens=5", nil},
		{"camel token count", "tokenCount=5", nil},
		{"camel tokens", "Tokens=5", nil},
		{"camel token bucket", "TokenBucket=5", nil},
		{"all caps one unit", "PGPASSWORD=abc", nil},
		{"all caps token word", "MAXTOKENS=5", nil},
		{"lowercase glued", "accesstoken=abc", nil},
		// 検出しない(値が空)
		{"no value", "password=", nil},
		{"only spaces", "password=  ", nil},
		{"colon no value", "password:", nil},
		{"empty quoted", `"password": ""`, nil},
		{"empty single quoted", "password=''", nil},
		{"quote at end", `password="`, nil},
		{"no separator", "invalid password for user", nil},
		{"key without separator then text", "password abc", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsIn(tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("secrets(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// ---- Detector を通した動作(受け入れ基準、重なりと置換済みの形) ----

func newSecretDetector(t *testing.T, o Options) *Detector {
	t.Helper()
	if o.Kinds == 0 {
		o.Kinds = KindSet(0).With(KindSecret)
	}
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDetectorSecretAcceptance(t *testing.T) {
	d := newSecretDetector(t, Options{})
	// password=abc123&user=x → password=<secret_1>&user=x
	check(t, d, "password=abc123&user=x", []Match{m(KindSecret, 9, 15)}, 0)
	// "api_key": "abc def" → "api_key": "<secret_1>"
	check(t, d, `"api_key": "abc def"`, []Match{m(KindSecret, 12, 19)}, 0)
	// Authorization: Bearer xxxxx の値部分のみ
	check(t, d, "Authorization: Bearer xxxxx", []Match{m(KindSecret, 22, 27)}, 0)
	check(t, d, "X-Auth-Token: xxx", []Match{m(KindSecret, 14, 17)}, 0)
	check(t, d, "DB_PASSWORD=xxx", []Match{m(KindSecret, 12, 15)}, 0)
	check(t, d, "max_tokens: 4096", nil, 0)
	check(t, d, "token_count=5", nil, 0)
	check(t, d, "PWD=/home/user", nil, 0)
}

func TestDetectorSecretEachFixedFormat(t *testing.T) {
	for name, tok := range map[string]string{
		"aws": "AKIAIOSFODNN7EXAMPLE", "github": "ghp_" + rep("a", 36), "github pat": "github_pat_" + rep("a", 30),
		"slack": "xoxb-" + rep("1", 12), "stripe": "sk_live_" + rep("a", 24), "google": "AIza" + rep("a", 35),
		"sk": "sk-" + rep("a", 24), "jwt": jwt,
	} {
		d := newSecretDetector(t, Options{Kinds: DefaultKinds})
		line := "x " + tok + " y"
		got, kept := d.Find([]byte(line), nil)
		want := []Match{m(KindSecret, 2, 2+len(tok))}
		if !slices.Equal(got, want) || kept != 0 {
			t.Errorf("%s: Find(%q) = %+v kept=%d, want %+v", name, line, got, kept, want)
		}
	}
}

// 受け入れ基準: 署名付き URL と、SigV4 の Authorization の署名が、既定の種別で secret になる(語と `=` は残る)。
// Signature はキー名ベースの対象ではないので、キー名ベースの値と重なっても 1 つの範囲になる。
func TestDetectorSecretAWSSignature(t *testing.T) {
	d := newSecretDetector(t, Options{Kinds: DefaultKinds})
	line := "&X-Amz-Signature=" + awsSig + "&"
	check(t, d, line, []Match{m(KindSecret, 17, 17+64)}, 0)
	line = "SignedHeaders=host;x-amz-date, Signature=" + awsSig
	check(t, d, line, []Match{m(KindSecret, len(line)-64, len(line))}, 0)
	// 値全体がキー名ベースの値になる場合は、長いほう(キー名ベース)が勝つ。
	line = "token=Signature=" + awsSig
	check(t, d, line, []Match{m(KindSecret, 6, len(line))}, 0)
	// 隣のキー名ベースの値(X-Amz-Security-Token は token で終わるキー名)とは、別の範囲になる。
	line = "?X-Amz-Security-Token=FwoGZXIvYXdzEJr&X-Amz-Signature=" + awsSig
	check(t, d, line, []Match{m(KindSecret, 22, 37), m(KindSecret, len(line)-64, len(line))}, 0)
	// 置換済みの形は、64 桁の 16 進数でないので、再度は検出されない。
	check(t, d, "X-Amz-Signature=<secret_1>&", nil, 1)
	check(t, d, "Signature=secret_3f9a1c0b7d2e", nil, 1)
}

// 置換済みの値を、再度検出しない(受け入れ基準)。
func TestDetectorSecretDoesNotRedetectPlaceholders(t *testing.T) {
	d := newSecretDetector(t, Options{})
	check(t, d, "password=<secret_1>&user=x", nil, 1)
	check(t, d, "Authorization: Bearer <secret_1>", nil, 1)
	check(t, d, `"api_key": "<secret_1>"`, nil, 1)
	check(t, d, "password=secret_3f9a1c0b7d2e", nil, 1)
	check(t, d, "token=<email_1>", nil, 1)
}

func TestDetectorSecretPlaceholderWithCustomFormat(t *testing.T) {
	f := mustFormat(t, "[{type}-{n}]")
	d := newSecretDetector(t, Options{Format: f})
	check(t, d, "password=[secret-1]&user=x", nil, 1)
	check(t, d, `"api_key": "[secret-1]"`, nil, 1)
	check(t, d, "Authorization: Bearer [secret-1]", nil, 1)
	check(t, d, "password=<secret_1>", []Match{m(KindSecret, 9, 19)}, 0) // この書式では置換済みの形ではない
}

func TestDetectorSecretValueWithRealTextAfterPlaceholder(t *testing.T) {
	// 置換済みの形を含んでいても、引用符の中に続きがあれば、値全体を置換する(Q1)。
	d := newSecretDetector(t, Options{})
	line := `"password": "<secret_1> real"`
	start := strings.Index(line, "<secret_1>")
	check(t, d, line, []Match{m(KindSecret, start, len(line)-1)}, 0)
}

// 種別が重なる場合は、長いほうが勝ち、同じ長さなら email → ip → secret の順(仕様 4 章)。
func TestDetectorSecretOverlapWithOtherKinds(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	// 値が IPv4 のときは、同じ範囲なので IPv4 が優先される。
	got, _ := d.Find([]byte("api_key=10.0.0.1"), nil)
	if len(got) != 1 || got[0].Kind != KindIPv4 || got[0].Start != 8 || got[0].End != 16 {
		t.Errorf("api_key=10.0.0.1: %+v", got)
	}
	// 値が email のときは、同じ範囲なので email が優先される。
	got, _ = d.Find([]byte("token=taro@example.com"), nil)
	if len(got) != 1 || got[0].Kind != KindEmail {
		t.Errorf("token=taro@example.com: %+v", got)
	}
	// 値のほうが長ければ(ポート付き)、secret が勝ち、値全体が置換される。
	got, _ = d.Find([]byte("password=203.0.113.5:8080"), nil)
	if len(got) != 1 || got[0].Kind != KindSecret || got[0].Start != 9 || got[0].End != 25 {
		t.Errorf("password=203.0.113.5:8080: %+v", got)
	}
	// 固定形式の中に、キー名ベースの値が含まれる場合も、1 つの範囲になる。
	tok := "ghp_" + rep("a", 36)
	got, _ = d.Find([]byte("GITHUB_TOKEN="+tok), nil)
	if len(got) != 1 || got[0].Kind != KindSecret || got[0].Start != 13 || got[0].End != 13+len(tok) {
		t.Errorf("GITHUB_TOKEN=ghp_...: %+v", got)
	}
}

func TestDetectorSecretAllow(t *testing.T) {
	d := newSecretDetector(t, Options{Allow: allowSet("changeme")})
	check(t, d, "password=changeme&token=abc", []Match{m(KindSecret, 24, 27)}, 0)
}

func TestDetectorSecretDisabled(t *testing.T) {
	d := newSecretDetector(t, Options{Kinds: KindSet(0).With(KindEmail)})
	check(t, d, "password=abc AKIAIOSFODNN7EXAMPLE", nil, 0)
}

// ---- 正規表現・別実装との一致(Q2) ----

var (
	// refFixed は、固定形式(仕様 4.1 の表)の正規表現。
	refFixed = regexp.MustCompile(`^(?:` + strings.Join([]string{
		`(?:AKIA|ASIA)[A-Z0-9]{16}`,
		`gh[pousr]_[A-Za-z0-9]{36,}`,
		`github_pat_[A-Za-z0-9_]{22,}`,
		`xox[bpars]-[A-Za-z0-9-]{10,}`,
		`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`,
		`AIza[A-Za-z0-9_-]{35}`,
		`sk-[A-Za-z0-9_-]{20,}`,
		`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`,
	}, "|") + `)`)
	// キー名: 全体を camelCase の境目で区切り、小文字にして、'-' '.' を '_' にしてから、末尾の単位を見る。
	refCamel1  = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	refCamel2  = regexp.MustCompile(`([A-Z])([A-Z][a-z])`)
	refKeyName = regexp.MustCompile(`(?:^|_)(?:password|passwd|secret|token|api_key|apikey|access_key|private_key|client_secret|access_token|refresh_token|auth_token|session_id)$`)
	refAuthKey = regexp.MustCompile(`(?:^|_)authorization$`)
	refKeyRun  = regexp.MustCompile(`([A-Za-z0-9_.-]+)(\\?["'])?[ \t]*$`)
	refDQuoted = regexp.MustCompile(`^"((?:\\.|[^"\\])*)"`)
	refSQuoted = regexp.MustCompile(`^'((?:\\.|[^'\\])*)'`)
	refEscaped = regexp.MustCompile(`^\\"((?:[^\\]|\\[^"])*)\\"`)
	// 引用符なしの値: 停止(エスケープされた引用符・改行・タブ・&)、1 つの単位(\\ の対、\u、単独の \、普通の文字)
	refBareStop = regexp.MustCompile(`^\\(?:["'nrt]|u0026)`)
	refBareUnit = regexp.MustCompile(`^(?:\\\\|\\u|\\|[^ \t&,;}\])"'\\])`)
	refScheme   = regexp.MustCompile(`(?i)^(bearer|basic)[ \t]+`)
	// AWS の署名: 語(大文字・小文字を区別しない)+ `=` + 小文字の 16 進数 64 文字。前後の文字は、呼び出し側で確認する。
	refSignature = regexp.MustCompile(`^(?i:(?:x-amz-)?signature)=([0-9a-f]{64})`)
	refToken68   = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*`)
)

// refURLUserInfo は、URL のユーザー情報の形(仕様 4.1「URL のパスワード」)の正規表現。スキームの先頭に当てる。
// 1 つ目のグループがパスワード。スキームの前の文字の条件は、refURLPasswords で確かめる。
var refURLUserInfo = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^:` + refURLUserInfoStops + `]*:([^` + refURLUserInfoStops + `]+)@[A-Za-z0-9.\[-]`)

// refURLUserInfoStops は、ユーザー・パスワードに含まれない文字(文字クラスの中に書く形。仕様 4.1、Q60)。
var refURLUserInfoStops = " \t" + regexp.QuoteMeta("/?#@\"'`<>\\{}|^")

// refURLPasswords は、行のすべての位置で refURLUserInfo を試す参照実装。(パスワードの先頭, `@` の位置)の組を返す。
func refURLPasswords(line []byte) [][2]int {
	var out [][2]int
	for p := 0; p < len(line); p++ {
		if p > 0 {
			c := line[p-1]
			if refIsAlnum(c) || c == '+' || c == '.' || c == '-' || c == '_' { // `_` は Q64
				continue
			}
		}
		if loc := refURLUserInfo.FindSubmatchIndex(line[p:]); loc != nil {
			out = append(out, [2]int{p + loc[2], p + loc[3]})
		}
	}
	return out
}

func refIsAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func refNormKey(k string) string {
	k = refCamel1.ReplaceAllString(k, "${1}_${2}")
	k = refCamel2.ReplaceAllString(k, "${1}_${2}")
	return strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(k))
}

// refSecrets は、仕様と plans/v1.0.0.md(決定事項 15 を含む)の規則を、正規表現で書いた参照実装。
// 検出器と同じく、候補の範囲を、開始位置の順(同じなら終了位置の順)で返す。
func refSecrets(line []byte) [][2]int {
	var out [][2]int
	// 固定形式
	for p := 0; p < len(line); {
		if p > 0 && refIsAlnum(line[p-1]) {
			p++
			continue
		}
		loc := refFixed.FindIndex(line[p:])
		if loc == nil {
			p++
			continue
		}
		e := p + loc[1]
		if e < len(line) && refIsAlnum(line[e]) {
			p++
			continue
		}
		out = append(out, [2]int{p, e})
		p = e
	}
	// AWS の署名(前が英数字・`-`・`_` でなく、後ろが英数字でないこと)
	for p := 0; p < len(line); p++ {
		if p > 0 && (refIsAlnum(line[p-1]) || line[p-1] == '-' || line[p-1] == '_') {
			continue
		}
		loc := refSignature.FindSubmatchIndex(line[p:])
		if loc == nil || p+loc[1] < len(line) && refIsAlnum(line[p+loc[1]]) {
			continue
		}
		out = append(out, [2]int{p + loc[2], p + loc[3]})
	}
	// URL のパスワード(v1.2)
	out = append(out, refURLPasswords(line)...)
	// キー名ベース(Authorization と、方式名つきの値を含む)
	for i := 0; i < len(line); i++ {
		if line[i] != '=' && line[i] != ':' {
			continue
		}
		if line[i] == ':' && strings.HasPrefix(string(line[i+1:]), "//") {
			continue // `<キー名>://` は URL のスキーム(Q63)
		}
		km := refKeyRun.FindSubmatch(line[:i])
		if km == nil {
			continue
		}
		quotedKey := len(km[2]) > 0
		norm := refNormKey(string(km[1]))
		schemeOnly := false
		switch {
		case refKeyName.MatchString(norm):
		case refAuthKey.MatchString(norm):
			schemeOnly = true
		default:
			continue
		}
		vs := i + 1
		for vs < len(line) && (line[vs] == ' ' || line[vs] == '\t') {
			vs++
		}
		if vs >= len(line) {
			continue
		}
		// 値の内容の開始(引用符の内側なら、引用符の次)
		cs := vs
		var re *regexp.Regexp
		switch {
		case line[vs] == '"':
			re, cs = refDQuoted, vs+1
		case line[vs] == '\'':
			re, cs = refSQuoted, vs+1
		case line[vs] == '\\' && vs+1 < len(line) && line[vs+1] == '"':
			re, cs = refEscaped, vs+2
		}
		// 方式名(Bearer / Basic)。後ろが値として読めなければ、何も置換しない。
		if loc := refScheme.FindSubmatchIndex(line[cs:]); loc != nil {
			scheme := strings.ToLower(string(line[cs+loc[2] : cs+loc[3]]))
			q := cs + loc[1]
			if tl := refToken68.FindIndex(line[q:]); tl != nil {
				if e := q + tl[1]; scheme != "basic" || refBasicOK(line[q:e]) {
					out = append(out, [2]int{q, e})
				}
			}
			continue
		}
		if schemeOnly {
			continue
		}
		if refURLUserInfo.Match(line[cs:]) {
			continue // 値の先頭が URL のパスワードの形なら、URL のパスワードとして扱う(Q65)
		}
		var s, e int
		switch {
		case re != nil:
			if loc := re.FindSubmatchIndex(line[vs:]); loc != nil {
				s, e = vs+loc[2], vs+loc[3]
			} else {
				s, e = cs, len(line)
			}
		case quotedKey || line[vs] == '{' || line[vs] == '[':
			continue
		default:
			s, e = vs, refBareEnd(line, vs)
		}
		if e > s {
			out = append(out, [2]int{s, e})
		}
	}
	slices.SortFunc(out, func(a, b [2]int) int {
		if a[0] != b[0] {
			return a[0] - b[0]
		}
		return a[1] - b[1]
	})
	return out
}

// refBareEnd は、引用符なしの値の末尾の位置を、正規表現を使って返す。
func refBareEnd(line []byte, vs int) int {
	e := vs
	for e < len(line) {
		if refBareStop.Match(line[e:]) {
			break
		}
		loc := refBareUnit.FindIndex(line[e:])
		if loc == nil {
			break
		}
		e += loc[1]
	}
	return e
}

// refBasicOK は、Basic の値が、base64 として解読でき、結果に ':' を含むかどうか(末尾の '.' は外して再試行)。
func refBasicOK(v []byte) bool {
	try := func(s string) bool {
		for _, dec := range []func(string) ([]byte, error){
			base64StdDecode, base64RawStdDecode,
		} {
			if b, err := dec(s); err == nil && strings.Contains(string(b), ":") {
				return true
			}
		}
		return false
	}
	s := string(v)
	if try(s) {
		return true
	}
	return strings.HasSuffix(s, ".") && try(strings.TrimRight(s, "."))
}

func TestSecretFinderMatchesRegexpReference(t *testing.T) {
	alphabet := []string{
		"password", "Token", "SECRET", "api_key", "api-key", "apikey", "access.token", "session_id", "x_", "my-", "max_",
		"tokens", "count", "accessToken", "clientSecret", "APIKey", "sessionID", "maxTokens", "PGPASSWORD", "Authorization",
		"Proxy-Authorization", "=", "=", ":", ": ", " ", "\t", "\"", "'", "\\", "\\\"", "&", ",", ";", "}", "]", "[", "{", "(", ")",
		"<secret_1>", "abc", "123", "a b", "あ", "\xff", "Bearer ", "bearer\t", "Basic ", "dXNlcjpwYXNz", "dXNlcjpwYXNz.", "abc==",
		"AKIA", "IOSFODNN7EXAMPLE", "ASIA", "ghp_", rep("a", 36), "github_pat_", rep("b", 22), "xoxb-", rep("1", 10),
		"sk_live_", "rk_test_", rep("c", 24), "AIza", rep("d", 35), "sk-", rep("e", 20), "eyJ", ".", "eyJhbGci", "-", "_",
		"Signature", "signature", "SIGNATURE", "X-Amz-", "x-amz-", "Signature=", "X-Amz-Signature=", awsSig, awsSig,
		awsSig[:32], awsSig[32:], "0", "f", "F", "?", "%2F",
		"://", "://", "http", "postgres", "git+ssh", "user", "pw", "@", "@", "host.example.com", "/", "#", "+", "1x", "[::1]", "s3cret",
	}
	rng := rand.New(rand.NewPCG(21, 22))
	f := secretFinder{}
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, rng.IntN(10); i < n; i++ {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := []byte(sb.String())
		want := refSecrets(line)
		var got [][2]int
		for _, m := range f.find(line, nil) {
			got = append(got, [2]int{m.Start, m.End})
		}
		slices.SortFunc(got, func(a, b [2]int) int {
			if a[0] != b[0] {
				return a[0] - b[0]
			}
			return a[1] - b[1]
		})
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
	}
}

// AWS の署名の規則に絞った乱数テスト。語・前後の文字・16 進数の長さの組み合わせで、参照実装と一致すること。
// 行は「区切り + 語 + `=` + 16 進数(の変形)」の組と、雑多な文字列を、ランダムに並べて作る。
func TestSecretSignatureMatchesRegexpReference(t *testing.T) {
	around := []string{"", "", "&", "?", " ", ", ", ".", "-", "_", "a", "Z", "0", "g", "あ", "\xff", "token=", "password=", "%2F"}
	words := []string{"Signature", "signature", "SIGNATURE", "SigNature", "X-Amz-Signature", "x-amz-signature", "X-AMZ-Signature",
		"x-amz-x-amz-signature", "Signatures", "Foo-Signature", "X-Amz-SignedHeaders", "ignature", ""}
	hexes := []string{awsSig, awsSig, awsSig2, awsSig[:63], awsSig + "0", awsSig + "f", strings.ToUpper(awsSig),
		awsSig[:10] + "F" + awsSig[11:], awsSig[:32], "", "<secret_1>"}
	rng := rand.New(rand.NewPCG(23, 24))
	f := secretFinder{}
	signatures := 0
	for iter := 0; iter < 60000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(4); i < n; i++ {
			sb.WriteString(around[rng.IntN(len(around))])
			if rng.IntN(4) > 0 {
				sb.WriteString(words[rng.IntN(len(words))])
				if rng.IntN(8) > 0 {
					sb.WriteString("=")
				}
				sb.WriteString(hexes[rng.IntN(len(hexes))])
			}
			sb.WriteString(around[rng.IntN(len(around))])
		}
		line := []byte(sb.String())
		want := refSecrets(line)
		var got [][2]int
		for _, m := range f.find(line, nil) {
			got = append(got, [2]int{m.Start, m.End})
		}
		slices.SortFunc(got, func(a, b [2]int) int {
			if a[0] != b[0] {
				return a[0] - b[0]
			}
			return a[1] - b[1]
		})
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		signatures += len(f.signatures(line, nil))
	}
	if signatures < 3000 {
		t.Errorf("only %d signatures were found; the generator does not exercise the rule", signatures)
	}
}

// ---- JSON の文法を壊さない(仕様 4.1、決定事項 15) ----

// randomJSONValue は、ランダムな JSON の値(文字列、数値、真偽値、null、入れ子)を作る。
// 文字列には、キー名ベース・Authorization・固定形式・メールアドレス・IP アドレスの形を含める。
func randomJSONValue(rng *rand.Rand, depth int) any {
	strs := []string{
		"hello", "password=hunter2 ok", "token=abc123", "login password=abc123 user=x", "Bearer abc123", "Authorization: Bearer xyz",
		"AKIAIOSFODNN7EXAMPLE", "ghp_" + rep("a", 36), "user@example.com", "10.0.0.1", "from 2001:db8::1: refused",
		"api_key=\"quoted value\"", "it's a token='single'", "path=/a/b?token=zzz&x=1", "(password=abc)", jwt, "x=1;token=t;y",
		"back\\slash password=a\\b", "日本語 password=あいう", "",
	}
	keys := []string{
		"password", "token", "accessToken", "user", "message", "api_key", "n", "clientSecret", "pin", "authorization",
		"Authorization", "secret", "list", "nested", "msg", "session_id", "X-Api-Key",
	}
	pick := rng.IntN(10)
	if depth >= 3 && pick >= 6 {
		pick = rng.IntN(6)
	}
	switch pick {
	case 0, 1, 2:
		return strs[rng.IntN(len(strs))]
	case 3:
		return rng.IntN(100000)
	case 4:
		return []any{true, false, nil}[rng.IntN(3)]
	case 5:
		// ログに埋め込まれた JSON(文字列の中の JSON)
		inner, _ := json.Marshal(map[string]any{keys[rng.IntN(len(keys))]: strs[rng.IntN(len(strs))], "n": rng.IntN(100)})
		return string(inner)
	case 6, 7:
		m := map[string]any{}
		for i, n := 0, 1+rng.IntN(4); i < n; i++ {
			m[keys[rng.IntN(len(keys))]] = randomJSONValue(rng, depth+1)
		}
		return m
	default:
		var a []any
		for i, n := 0, rng.IntN(4); i < n; i++ {
			a = append(a, randomJSONValue(rng, depth+1))
		}
		return a
	}
}

// JSON の 1 行に対して、検出した範囲(email、IP、secret のすべて)を別の文字列に置き換えても、
// 結果は JSON として妥当なまま。置換が、文字列の外(引用符、区切り、数値)に及ばないことの確認。
func TestDetectedRangesKeepJSONValid(t *testing.T) {
	rng := rand.New(rand.NewPCG(31, 32))
	d, err := New(Options{Kinds: DefaultKinds})
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for iter := 0; iter < 4000; iter++ {
		doc := map[string]any{}
		for i, n := 0, 1+rng.IntN(5); i < n; i++ {
			k := []string{"password", "token", "accessToken", "msg", "headers", "data", "Authorization", "n"}[rng.IntN(8)]
			doc[k] = randomJSONValue(rng, 0)
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(raw) {
			t.Fatalf("generator produced invalid JSON: %s", raw)
		}
		got, _ := d.Find(raw, nil)
		var out []byte
		last := 0
		for _, m := range got {
			out = append(out, raw[last:m.Start]...)
			out = append(out, "<x_1>"...)
			last = m.End
			matched++
		}
		out = append(out, raw[last:]...)
		if !json.Valid(out) {
			t.Fatalf("iter %d: replacing the detected ranges made the JSON invalid\n in:  %s\n out: %s", iter, raw, out)
		}
	}
	if matched < 1000 {
		t.Errorf("only %d ranges were detected; the generator does not exercise the rules", matched)
	}
}

// ---- 長い行・性能 ----

func TestSecretFinderLongLines(t *testing.T) {
	for name, line := range map[string]string{
		"many keys":              rep("password=a ", 50000),
		"many unterminated":      rep(`password="`, 50000),
		"mixed quotes":           rep(`password="x password='y `, 20000),
		"key chars only":         rep("a", 1<<20) + "=" + rep("b", 1<<20),
		"many separators":        rep("a=b:c ", 100000),
		"hits without formats":   rep("gh sk rk xox eyJ AKIA AIza ", 30000),
		"many signature words":   rep("Signature=", 1<<17),
		"many signatures":        rep("Signature="+awsSig+"&", 1<<13),
		"many bearer":            rep("Bearer a ", 50000),
		"basic long":             "Basic " + rep("A", 1<<20),
		"escapes":                `password="` + rep(`\`, 1<<20),
		"token68 without scheme": rep("a.b-c_d", 1<<18),
		"repeated keys":          rep("token=", 1<<17),
	} {
		got := (secretFinder{}).find([]byte(line), nil)
		_ = got
		t.Logf("%s: %d matches", name, len(got))
	}
	if got := (secretFinder{}).find([]byte(rep("password=a ", 50000)), nil); len(got) != 50000 {
		t.Errorf("many keys: got %d matches, want 50000", len(got))
	}
	if got := (secretFinder{}).find([]byte(rep("Signature="+awsSig+"&", 1<<13)), nil); len(got) != 1<<13 {
		t.Errorf("many signatures: got %d matches, want %d", len(got), 1<<13)
	}
}

func BenchmarkSecretFinder(b *testing.B) {
	lines, size := benchCorpus(b)
	var dst []Match
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			dst = (secretFinder{}).find(line, dst[:0])
		}
	}
}

// ---- URL のパスワード(v1.2。仕様 4.1、9 章「URL のパスワード」) ----

func TestSecretURLPassword(t *testing.T) {
	sec := KindSet(0).With(KindSecret)
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"postgres", "postgres://app:s3cret@db.example.com:5432/app", []string{"secret=s3cret"}},
		{"rds host", "postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app", []string{"secret=s3cret"}},
		{"ip host", "https://user:pass@10.0.0.1/", []string{"secret=pass"}},
		{"empty user", "redis://:s3cret@10.0.0.5:6379", []string{"secret=s3cret"}},
		{"colon in password", "ftp://u:a:b@host", []string{"secret=a:b"}},
		{"colons only in password", "ftp://u::@host", []string{"secret=:"}},
		{"scheme chars", "git+ssh://git:tok@github.com/x/y.git", []string{"secret=tok"}},
		{"scheme with dot and dash", "jdbc.v-2://u:p@h", []string{"secret=p"}},
		{"scheme with digit and plus", "x1+://u:p@h", []string{"secret=p"}},
		{"ipv6 host", "http://u:p@[::1]:80/", []string{"secret=p"}},
		{"host starts with dash", "http://u:p@-x", []string{"secret=p"}},
		{"in quotes", `url="mysql://root:hunter2@db:3306/x"`, []string{"secret=hunter2"}},
		{"in json", `{"dsn":"postgres://a:b@c/d"}`, []string{"secret=b"}},
		{"two urls", "a://u:p1@h b://v:p2@i", []string{"secret=p1", "secret=p2"}},
		{"uppercase scheme", "HTTPS://U:P@H", []string{"secret=P"}},
		{"after non scheme chars", "(http://u:p@h) <ftp://u:q@h>", []string{"secret=p", "secret=q"}},
		{"at in password", "http://u:p@w@h", []string{"secret=p"}},
		// キー名と同じ語のスキーム(`<キー名>://`)は、キーと値の組として読まない(Q63)
		{"key name as scheme", "passwd://u:&x@db.example.com/", []string{"secret=&x"}},
		{"key name as scheme, fuzz", "passwd://:&@0", []string{"secret=&"}},
		{"password scheme", "password://app:s3cret@db/", []string{"secret=s3cret"}},
		{"quoted key name before slashes", `"token"://u:p@h`, nil}, // URL の形でもない(スキームの直後が `"`)
		{"key name scheme without password", "token://abc", nil},
		{"key name scheme without password, in json", `{"url":"secret://vault/path"}`, nil},
		// スキームの直前が `_` の形は、URL のパスワードとして扱わない(hash の出力の 16 進数を、スキームとして読まない。Q64)
		{"underscore before scheme", "x_https://u:p@h", nil},
		{"hash output before slashes", "email_fde789562e9a://:0@0", nil},
		{"other chars before scheme", "(https://u:p@h =ftp://u:q@h", []string{"secret=p", "secret=q"}},
		// 区切りの後ろに空白があるもの、`=` のものは、今までどおりキー名ベース
		{"space after colon", "password: //abc", []string{"secret=//abc"}},
		{"equals and slashes", "token=//abc", []string{"secret=//abc"}},
		{"single slash", "token:/abc", []string{"secret=/abc"}},
		// キー名ベースの値が URL のパスワードの形で始まるものは、パスワードだけ(Q65)
		{"keyed url, terminator in password", "password=https://u:p&q@db.example.com/", []string{"secret=p&q"}},
		{"keyed url, password starts with terminator", "password=https://u:&x@db.example.com/", []string{"secret=&x"}},
		{"keyed url, no terminator", "password=postgres://app:s3cret@db/app", []string{"secret=s3cret"}},
		{"keyed url, space after separator", "secret: \tredis://:pw@h", []string{"secret=pw"}},
		{"keyed url, quoted", `"password": "postgres://app:s3cret@db/"`, []string{"secret=s3cret"}},
		{"keyed url, single quoted", "password='https://u:p&q@h'", []string{"secret=p&q"}},
		{"keyed url, escaped quotes", `{"msg":"{\"password\":\"https://u:p@h\"}"}`, []string{"secret=p"}},
		{"keyed url, camel case key", "dbPassword=mysql://root:hunter2@db:3306", []string{"secret=hunter2"}},
		// 値の先頭が URL のパスワードの形でないものは、今までどおりキー名ベース
		{"keyed url in the middle", "password=x,https://u:p@h", []string{"secret=x", "secret=p"}},
		{"keyed url without userinfo", "token=https://hooks.example.com/T000/XXXX", []string{"secret=https://hooks.example.com/T000/XXXX"}},
		{"keyed url with user only", "token=https://u@h/x", []string{"secret=https://u@h/x"}},
		{"keyed url with empty password", "token=https://u:@h", []string{"secret=https://u:@h"}},
		{"keyed underscore before scheme", "token=_https://u:p@h", []string{"secret=_https://u:p@h"}},
		// 対象外
		{"user only", "https://taro@example.com/", nil},
		{"no scheme", "user:pass@host", nil},
		{"no slashes", "mailto:user:pass@host", nil},
		{"one slash", "http:/u:p@h", nil},
		{"empty password", "http://u:@h", nil},
		{"no host", "http://u:p@", nil},
		{"space after at", "http://u:p@ h", nil},
		{"host char is slash", "http://u:p@/x", nil},
		{"space in user", "http://u v:p@h", nil},
		{"space in password", "http://u:p w@h", nil},
		{"slash in password", "http://u:p/w@h", nil},
		{"question mark in password", "http://u:p?w@h", nil},
		{"hash in password", "http://u:p#w@h", nil},
		{"scheme starts with digit", "1http://u:p@h", nil},
		{"scheme starts with dash", "-http://u:p@h", nil},
		{"empty scheme", "://u:p@h", nil},
		{"path before userinfo", "http://host/path/u:p@h", nil},
		{"tab in user", "http://u\t:p@h", nil},
		// RFC 3986 で URL に使えない文字は、ユーザー情報に含めない(Q60)
		{"json after pathless url", `{"origin":"https://app.example.com","email":"bob@example.com"}`, nil},
		{"json after pathless url with colon", `{"u":"https://a.example.com","v":"x:y@h.example.com"}`, nil},
		{"double quote in password", `http://u:p"w@h`, nil},
		{"single quote in password", "http://u:p'w@h", nil},
		{"backquote in password", "http://u:p`w@h", nil},
		{"angle brackets in password", "http://u:<p>@h", nil},
		{"backslash in password", `http://u:p\w@h`, nil},
		{"braces in password", "http://u:{p}@h", nil},
		{"pipe in password", "http://u:p|w@h", nil},
		{"caret in password", "http://u:p^w@h", nil},
		{"double quote in user", `http://u"v:p@h`, nil},
		{"angle bracket in user", "http://u<v:p@h", nil},
		// RFC 3986 でユーザー情報に使える記号は、含める
		{"sub-delims in password", "http://u:a!$&()*+,;=~%41-._@h", []string{"secret=a!$&()*+,;=~%41-._"}},
		{"comma and semicolon in user", "http://a,b;c:p@h", []string{"secret=p"}},
	} {
		got := awsValues(t, sec, tc.line)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q: got %q, want %q", tc.name, tc.line, got, tc.want)
		}
	}
}

// ホスト名の部分は、通常どおり他の種別として検出される。メールアドレスとして扱われない(受け入れ基準)。
// キー名ベースの値が URL のパスワードの形で始まる場合(Q65)に絞った乱数テスト。参照実装と一致すること。
// 行は「キー名 + 区切り + 引用符 + URL の部品」の組と、雑多な文字列を、ランダムに並べて作る。
func TestSecretKeyedURLMatchesRegexpReference(t *testing.T) {
	keys := []string{"password", "token", "\"secret\"", "dbPassword", "authorization", "user", "x_token", ""}
	seps := []string{"=", ":", ": ", " =\t", "://", ""}
	quotes := []string{"", "", "\"", "'", "\\\""}
	urlParts := []string{
		"https", "postgres", "git+ssh", "_https", "1x", "://", "://", ":/", "u", "app", "", ":", ":", "p", "s3cret", "&", "&x", ",",
		";", ")", "}", "]", "\"", "'", "<", "<secret_1>", "@", "@", "db.example.com", "[::1]", " ", "/", "?", "#", "%41", "!$*+=~",
	}
	around := []string{"", "", " ", "&", ",", "{", "}", "x", "_", "\t", "あ"}
	rng := rand.New(rand.NewPCG(65, 66))
	f := secretFinder{}
	skipped := 0 // 区切り(`=`・`:`)の後ろの値の先頭が、URL のパスワードの形だった数(キー名の有無は問わない)
	for iter := 0; iter < 100000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			sb.WriteString(around[rng.IntN(len(around))])
			sb.WriteString(keys[rng.IntN(len(keys))])
			sb.WriteString(seps[rng.IntN(len(seps))])
			sb.WriteString(quotes[rng.IntN(len(quotes))])
			if rng.IntN(3) > 0 {
				// URL のパスワードの形になりやすい並び
				sb.WriteString(urlParts[rng.IntN(2)])
				sb.WriteString("://")
				for _, part := range []string{"u", ":", "p", "@", "db.example.com"} {
					if rng.IntN(5) == 0 {
						part = urlParts[rng.IntN(len(urlParts))]
					}
					sb.WriteString(part)
				}
			} else {
				for j, m := 0, rng.IntN(8); j < m; j++ {
					sb.WriteString(urlParts[rng.IntN(len(urlParts))])
				}
			}
			sb.WriteString(around[rng.IntN(len(around))])
		}
		line := []byte(sb.String())
		want := refSecrets(line)
		var got [][2]int
		for _, m := range f.find(line, nil) {
			got = append(got, [2]int{m.Start, m.End})
		}
		slices.SortFunc(got, func(a, b [2]int) int {
			if a[0] != b[0] {
				return a[0] - b[0]
			}
			return a[1] - b[1]
		})
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		for i := range line {
			if line[i] != '=' && line[i] != ':' {
				continue
			}
			cs := i + 1
			for cs < len(line) && (line[cs] == ' ' || line[cs] == '\t') {
				cs++
			}
			if strings.HasPrefix(string(line[cs:]), `\"`) {
				cs += 2
			} else if cs < len(line) && (line[cs] == '"' || line[cs] == '\'') {
				cs++
			}
			if f.startsWithURLPassword(line, cs) {
				skipped++
			}
		}
	}
	// 規則に当たる値が少なすぎると、比べた意味がない
	if skipped < 20000 {
		t.Errorf("only %d values started with a URL password", skipped)
	}
	t.Logf("%d values started with a URL password", skipped)
}

// 置換済みのラベルを含む URL の形(Q65)。置換後の出力を再度流しても、キー名ベースの値として読まないこと。
func TestSecretKeyedURLWithLabels(t *testing.T) {
	all := DefaultKinds.With(KindAWSAccount).With(KindAWSS3Bucket).With(KindAWSHost)
	for _, line := range []string{
		"password=https://u:<secret_1>@db.example.com/",
		"password=https://u:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app",
		"password=https://u:<secret_1>@<ipv4_private_1>/",
		"password=https://<ipv4_private_1>:<secret_1>@h",
		"password=redis://:<secret_1>@h",
		`"password": "postgres://app:<secret_1>@db/"`,
		"password=https://u:secret_0123456789ab@db.example.com/",
	} {
		if got := awsValues(t, all, line); got != nil {
			t.Errorf("%q: got %q, want nothing", line, got)
		}
	}
	// ラベルは、ユーザー・パスワード・ホスト名の部分の全体のときだけ。部分の一部なら、URL のパスワードの形ではない
	f := secretFinder{format: label.DefaultFormat}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"https://u:p@h", true},
		{"https://u:<secret_1>@h", true},
		{"https://<secret_2>:<secret_1>@h", true},
		{"https://:<secret_1>@h", true},
		{"https://u:<secret_1>@<aws_host_1>.x", true},
		{"https://u:<secret_1>:x@h", false}, // パスワードの一部
		{"https://u:x<secret_1>@h", false},
		{"https://u<secret_2>:p@h", false},
		{"https://u:<secret_1>", false},
		{"https://u:<secret_1>@", false},
		{"https://u:<secret_1>@ h", false},
		{"https://u:<secret_0>@h", false}, // ラベルの形でない
		{"https://u:<nope_1>@h", false},
		{"https://u:@h", false},
		{"https://u@h", false},
		{"https://<secret_1>@h", false},
	} {
		if got := f.startsWithURLPassword([]byte(tc.value), 0); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.value, got, tc.want)
		}
	}
	// 書式を指定しない(ゼロ値の)検出器は、ラベルを読まない
	if (secretFinder{}).startsWithURLPassword([]byte("https://u:<secret_1>@h"), 0) {
		t.Error("zero format must not read labels")
	}
	// 独自の書式(`{type}-{n}`)では、文字列の途中のラベルに似た部分を、ラベルとして読まない
	cf := secretFinder{format: mustFormat(t, "{type}-{n}")}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"https://u:secret-1@h", true},
		{"https://u:mysecret-1@h", true}, // ユーザー情報の文字として読む
		{"https://u:secret-1x<@h", false},
		{"https://u:p@aws_host-1.x", true},
	} {
		if got := cf.startsWithURLPassword([]byte(tc.value), 0); got != tc.want {
			t.Errorf("custom format: %q: got %v, want %v", tc.value, got, tc.want)
		}
	}
}

// キー名の直前が置換済みのラベルの終わりなら、キー名として扱わない(Q66)。
func TestSecretKeyAfterLabel(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		// ファズテストが見つけた形。1 回目は、キー名が `0.0.0.1passwd` で対象でない。2 回目も置換しない
		{"0.0.0.1passwd=0", []string{"ipv4_global=0.0.0.1"}},
		{"<ipv4_global_1>passwd=0", nil},
		// 1 回目から対象のキー名(`.` で切れる)のもの。2 回目は、値が置換済みのラベルなので、結果は同じ
		{"10.0.0.1.password=x", []string{"ipv4_private=10.0.0.1", "secret=x"}},
		{"<ipv4_private_1>.password=<secret_1>", nil},
		{"<email_1>password=abc", nil},
		{"<email_1>Token: abc", nil},
		{"<ipv4_global_12>passwd=0", nil},
		// ラベルとキー名の間に、キー名の文字でないもの(空白・引用符・区切り)があれば、今までどおり
		{"<email_1> password=abc", []string{"secret=abc"}},
		{`<email_1>"password":"abc"`, []string{"secret=abc"}},
		{"<email_1>,token=abc", []string{"secret=abc"}},
		// ラベルの形でないもの
		{"<email_0>password=abc", []string{"secret=abc"}},
		{"<nope_1>password=abc", []string{"secret=abc"}},
		{"email_1>password=abc", []string{"secret=abc"}},
		// hash の出力形は英数字で終わるので、後ろの語とつながり、1 回目と同じ単位で切れる
		{"ipv4_global_0123456789abpasswd=0", nil},
	} {
		if got := awsValues(t, DefaultKinds, tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, tc.want)
		}
	}
	// 書式を指定しない(ゼロ値の)検出器は、ラベルを見ない
	if got := (secretFinder{}).keyed([]byte("<email_1>password=abc"), nil); len(got) != 1 {
		t.Errorf("zero format: got %v", got)
	}
}

func TestSecretURLPasswordWithOtherKinds(t *testing.T) {
	all := DefaultKinds.With(KindAWSAccount).With(KindAWSS3Bucket).With(KindAWSHost)
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"https://user:pass@10.0.0.1/", []string{"secret=pass", "ipv4_private=10.0.0.1"}},
		{"postgres://app:s3cret@db.example.com:5432/app", []string{"secret=s3cret"}},
		{"postgres://app:s3cret@mydb.cluster-c9akciq32.ap-northeast-1.rds.amazonaws.com:5432/app", []string{"secret=s3cret", "aws_host=mydb.cluster-c9akciq32"}},
		{"redis://:s3cret@10.0.0.5:6379", []string{"secret=s3cret", "ipv4_private=10.0.0.5"}},
		{"ftp://u:a:b@host", []string{"secret=a:b"}},
		// ユーザーだけ、パスワードの形に当たらないものは、v1.1 と同じくメールアドレス
		{"https://taro@example.com/", []string{"email=taro@example.com"}},
		{"user:pass@example.com", []string{"email=pass@example.com"}},
		{"http://u:p@h@x.com", []string{"secret=p", "email=h@x.com"}},
		{"mail admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com", []string{"email=admin@mydb.c9akciq32.ap-northeast-1.rds.amazonaws.com"}},
		// パスのない URL の後ろの JSON の値は、ユーザー情報として読まない(Q60。読むと `"` が置換されて JSON が壊れ、
		// メールアドレスのドメインが残る)
		{`{"origin":"https://app.example.com","email":"bob@example.com"}`, []string{"email=bob@example.com"}},
		{`{"u":"https://a.example.com","v":"x:y@h.example.com"}`, []string{"email=y@h.example.com"}},
	} {
		if got := awsValues(t, all, tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.line, got, tc.want)
		}
	}
	// secret が無効でも、この形の `@` はメールアドレスとして扱わない(Q54)。パスワードは残る
	for _, line := range []string{"https://user:pass@example.com/", "postgres://app:s3cret@db.example.com:5432/app"} {
		if got := awsValues(t, KindSet(0).With(KindEmail), line); got != nil {
			t.Errorf("email only, %q: got %q, want nothing", line, got)
		}
	}
	if got := awsValues(t, KindSet(0).With(KindEmail), "https://taro@example.com/"); !slices.Equal(got, []string{"email=taro@example.com"}) {
		t.Errorf("email only, user only: %q", got)
	}
}

// 置換済みの形(mask のラベル、hash の出力)は、再度は置換されない(冪等性)。
func TestSecretURLPasswordAlreadyReplaced(t *testing.T) {
	d, err := New(Options{Kinds: DefaultKinds | KindSet(0).With(KindAWSHost)})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"postgres://app:<secret_1>@db.example.com:5432/app",
		"postgres://app:secret_3f9a1c0b7d2e@db.example.com:5432/app",
		"postgres://app:<secret_1>@<aws_host_1>.ap-northeast-1.rds.amazonaws.com:5432/app",
		"postgres://app:secret_3f9a1c0b7d2e@aws_host_3f9a1c0b7d2e.ap-northeast-1.rds.amazonaws.com:5432/app",
	} {
		got, _ := d.Find([]byte(line), nil)
		if len(got) != 0 {
			t.Errorf("Find(%q) = %+v, want nothing", line, got)
		}
	}
}

// urlPasswordStart と、正規表現の参照実装(スキームから前向きに調べる)が、`@` ごとに一致すること。
// secret(パスワードの範囲)と email(`@` を除く)は、どちらもこの関数を使う。
func TestURLPasswordMatchesRegexpReference(t *testing.T) {
	pieces := []string{"http", "postgres", "git+ssh", "1x", "x", "ftp", "://", "://", ":/", "//", "/", ":", ":", "@", "@", "user", "u", "", "pass", "p:q",
		"s3cret", "host.example.com", "h", "[::1]", ".", "-", "+", "_", "?", "#", " ", "\t", "あ", "\xff", "<secret_1>", "a@b.com", "10.0.0.1",
		`"`, `","k":"`, "'", "`", "<", ">", `\`, "{", "}", "|", "^", ",", ";", "!", "%41"}
	prefixes := []string{"", "", " ", "(", "\"", "=", "x", "1", "+", ".", "-", "_", "あ", "a://"}
	schemes := []string{"http", "https", "postgres", "git+ssh", "a.b-c", "x1+", "1x", "-x", "", "ふ"}
	seps := []string{"://", "://", "://", ":/", "//", ":///", "://:", ":"}
	users := []string{"", "u", "user", "a b", "a:b", "a/b", "a?b", "a#b", "a@b", "\t", "あ", `a"b`, "a,b", `h","k":"u`, "a{b", "a;b"}
	pws := []string{"p", "s3cret", "a:b", ":", "", "p w", "p/q", "p?q", "p#q", "p@q", "<secret_1>", "あ",
		`p"q`, "p'q", "p`q", "p\\q", "p|q", "p^q", "p,q", "p;q", "p!$&()*+=~%41"}
	hosts := []string{"h", "host.example.com", "[::1]", "-x", ".", "10.0.0.1", "", " h", "/x", "あ", "@h", "x@y.com"}
	suffixes := []string{"", "", "/", ":5432/app", " ", "\"", ")"}
	rng := rand.New(rand.NewPCG(31, 32))
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }
	found := 0
	for iter := 0; iter < 100000; iter++ {
		var sb strings.Builder
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			if rng.IntN(3) == 0 {
				for k, m := 0, 1+rng.IntN(8); k < m; k++ {
					sb.WriteString(pick(pieces))
				}
				continue
			}
			sb.WriteString(pick(prefixes) + pick(schemes) + pick(seps) + pick(users) + pick([]string{":", ":", ":", ""}) + pick(pws) +
				pick([]string{"@", "@", "@", ""}) + pick(hosts) + pick(suffixes))
		}
		line := []byte(sb.String())
		want := refURLPasswords(line)
		var got [][2]int
		for at := range line {
			if line[at] != '@' {
				continue
			}
			if s, ok := urlPasswordStart(line, at); ok {
				got = append(got, [2]int{s, at})
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("iter %d, line %q\n got  %v\n want %v", iter, line, got, want)
		}
		var fromFinder [][2]int
		for _, m := range (secretFinder{}).urlPasswords(line, nil) {
			fromFinder = append(fromFinder, [2]int{m.Start, m.End})
		}
		if !slices.Equal(fromFinder, want) {
			t.Fatalf("iter %d, line %q: finder %v, want %v", iter, line, fromFinder, want)
		}
		found += len(want)
	}
	if found < 3000 {
		t.Errorf("only %d URL passwords were found; the generator does not exercise the rules", found)
	}
}

// 手前へ遡る長さの合計が、行の長さ以内に収まること(長い行で遅くならない)。
func TestURLPasswordOnLongLines(t *testing.T) {
	for _, c := range []struct {
		name, line string
		want       int
	}{
		{"ats", strings.Repeat("@", 1<<20), 0},
		{"long user", "http://" + strings.Repeat("a", 1<<20) + ":p@h", 1},
		{"long password", "http://u:" + strings.Repeat("p", 1<<20) + "@h", 1},
		{"long scheme", strings.Repeat("a", 1<<20) + "://u:p@h", 1},
		{"colon runs", "http://" + strings.Repeat(":", 1<<20) + "@h", 1},
		{"repeated schemes", strings.Repeat("a://b:c@", 100000) + "h", 100000},
		{"repeated userinfo", "http://" + strings.Repeat("a:b@", 200000) + "h", 1},
		{"no scheme", strings.Repeat("u:p@h ", 150000), 0},
		{"scheme chars then at", strings.Repeat("a-", 500000) + "@h", 0},
		{"slashes", strings.Repeat("://", 300000) + "u:p@h", 0},
	} {
		start := time.Now()
		got := (secretFinder{}).urlPasswords([]byte(c.line), nil)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", c.name, d)
		}
		if len(got) != c.want {
			t.Errorf("%s: %d matches, want %d", c.name, len(got), c.want)
		}
		start = time.Now()
		_ = (emailFinder{hashLen: 12}).find([]byte(c.line), nil)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s (email): took %v", c.name, d)
		}
	}
}
