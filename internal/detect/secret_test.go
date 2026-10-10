package detect

import (
	"encoding/base64"
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"

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
		`xox[bparso]-[A-Za-z0-9-]{10,}`,
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
	refToken68  = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*`)
)

func refIsAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func refNormKey(k string) string {
	k = refCamel1.ReplaceAllString(k, "${1}_${2}")
	k = refCamel2.ReplaceAllString(k, "${1}_${2}")
	return strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(k))
}

// refSecrets は、仕様と PLAN(決定事項 15 を含む)の規則を、正規表現で書いた参照実装。
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
	// キー名ベース(Authorization と、方式名つきの値を含む)
	for i := 0; i < len(line); i++ {
		if line[i] != '=' && line[i] != ':' {
			continue
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
		// 方式名(Bearer / Basic)
		if loc := refScheme.FindSubmatchIndex(line[cs:]); loc != nil {
			scheme := strings.ToLower(string(line[cs+loc[2] : cs+loc[3]]))
			q := cs + loc[1]
			if tl := refToken68.FindIndex(line[q:]); tl != nil {
				if e := q + tl[1]; scheme != "basic" || refBasicOK(line[q:e]) {
					out = append(out, [2]int{q, e})
					continue
				}
			}
		}
		if schemeOnly {
			continue
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
		"many bearer":            rep("Bearer a ", 50000),
		"basic long":             "Basic " + rep("A", 1<<20),
		"escapes":                `password="` + rep(`\`, 1<<20),
		"token68 without scheme": rep("a.b-c_d", 1<<18),
	} {
		got := (secretFinder{}).find([]byte(line), nil)
		_ = got
		t.Logf("%s: %d matches", name, len(got))
	}
	if got := (secretFinder{}).find([]byte(rep("password=a ", 50000)), nil); len(got) != 50000 {
		t.Errorf("many keys: got %d matches, want 50000", len(got))
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
