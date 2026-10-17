package detect

import (
	"bytes"
	"regexp"
	"strings"
)

// AWS の値の形の定義(仕様 4.3「ホスト名に埋め込まれた IPv4」、4.4)。
//
// パーティション・ドメイン・エンドポイントなどの形は、表(スライスと正規表現の部品)として持つ。
// 将来のクラウドの追加や、v1.2 の aws_host のホストの表も、同じ形で書き足す(plans/v1.1.0.md 2.2)。

// awsPartitions は、対象のパーティション(ARN の 2 つ目の欄。仕様 4.4。AWS SDK の partitions.json で確認)。
var awsPartitions = []string{"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc"}

// awsDomains は、対象のドメイン(仕様 4.4)。長いほうから並べる
// (amazonaws.com.cn を、amazonaws.com + `.cn` と読まないため。Q41)。
var awsDomains = []string{"amazonaws.com.cn", "amazonaws.com", "amazonaws.eu"}

// awsDomainBytes は、awsDomains のバイト列(照合のたびに変換しないため)。
var awsDomainBytes = func() [][]byte {
	bs := make([][]byte, len(awsDomains))
	for i, d := range awsDomains {
		bs[i] = []byte(d)
	}
	return bs
}()

// awsRegionRe は、ホスト名の中のリージョン(英小文字・数字・`-` の 1 文字以上。Q40)。
const awsRegionRe = `[a-z0-9-]+`

// awsDomainRe は、awsDomains のどれかに一致する正規表現の部品(並びの順に試す)。
var awsDomainRe = alternation(awsDomains)

// awsPartitionRe は、awsPartitions のどれかに一致する正規表現の部品。
var awsPartitionRe = alternation(awsPartitions)

// alternation は、words のどれかに一致する正規表現の部品を返す(並びの順に試す)。
func alternation(words []string) string {
	qs := make([]string, len(words))
	for i, w := range words {
		qs[i] = regexp.QuoteMeta(w)
	}
	return `(?:` + strings.Join(qs, "|") + `)`
}

// isHostPrefixChar は、ホスト名の一部になる文字(英数字・`-`・`_`・`.`)。
// 決まった形(`ec2-`、`ip-` など)の前に、この文字があれば、別の名前の一部とみなす。
func isHostPrefixChar(c byte) bool {
	return isASCIIAlnum(c) || c == '-' || c == '_' || c == '.'
}

// isHostEnd は、line[e:] が、ホスト名の末尾の後ろとして読めるかを返す(Q41)。
// 後ろが英数字・`-`・`_` でなく、「`.` + 英数字」でもないこと(行末は可。文末の `.` と、FQDN の末尾の `.` は許す)。
func isHostEnd(line []byte, e int) bool {
	if e >= len(line) {
		return true
	}
	c := line[e]
	if isASCIIAlnum(c) || c == '-' || c == '_' {
		return false
	}
	return !(c == '.' && e+1 < len(line) && isASCIIAlnum(line[e+1]))
}

// ---- aws_account(仕様 4.4) ----

// awsAccountRe は、AWS アカウント ID(10 進数ちょうど 12 桁)。
const awsAccountRe = `([0-9]{12})`

var (
	// arnAccountRe は、`arn:<パーティション>:<サービス>:<リージョン>:<アカウント ID>:`。`arn:` の位置に当てる。
	// サービスは英小文字・数字・`-` の 1 文字以上、リージョンは 0 文字以上。どちらも、IAM ポリシーの
	// ワイルドカードの `*` を含んでよい(`arn:aws:ec2:*:…`)。
	arnAccountRe = regexp.MustCompile(`^arn:` + awsPartitionRe + `:[a-z0-9*-]+:[a-z0-9*-]*:` + awsAccountRe + `:`)
	// accountHostRe は、ECR・S3 Control のホストの、アカウント ID の後ろの部分。`.dkr.ecr` / `.s3-control` などの位置に当てる。
	accountHostRe = regexp.MustCompile(`^` + alternation(accountHostMarkers) + `\.` + awsRegionRe + `\.` + awsDomainRe)
	// sqsHostRe は、SQS のキュー URL の `sqs.<リージョン>.<ドメイン>/<アカウント ID>/`。`sqs.` の位置に当てる。
	sqsHostRe = regexp.MustCompile(`^sqs\.` + awsRegionRe + `\.` + awsDomainRe + `/` + awsAccountRe + `/`)
	// sqsPathRe は、SQS の旧形式のホスト(`queue.amazonaws.com`)の後ろの `/<アカウント ID>/`。
	sqsPathRe = regexp.MustCompile(`^/` + awsAccountRe + `/`)
)

// accountHostMarkers は、`<12 桁>` の直後に続く、アカウント ID を含むホストの語(仕様 4.4)。後ろに `.` + リージョン
// + `.` + 対象のドメインが続く。ECR と S3 Control(v1.2)。サービスの追加は、ここに行を足す。
var accountHostMarkers = []string{
	".dkr.ecr", ".dkr.ecr-fips",
	".s3-control", ".s3-control.dualstack", ".s3-control-fips", ".s3-control-fips.dualstack",
}

var accountHostMarkerBytes = func() [][]byte {
	bs := make([][]byte, len(accountHostMarkers))
	for i, m := range accountHostMarkers {
		bs[i] = []byte(m)
	}
	return bs
}()

var (
	arnPrefix    = []byte("arn:")
	arnWord      = []byte("arn")
	sqsWord      = []byte("sqs")
	sqsQueueHost = []byte("queue.amazonaws.com")
	queueWord    = []byte("queue")
)

// awsAccountFinder は、AWS アカウント ID の検出器(仕様 4.4)。決まった形の中に現れたものだけを検出する。
//
//   - ARN: `arn:aws:iam::123456789012:role/x`(アカウント ID の欄が 12 桁のときだけ)
//   - ECR: `123456789012.dkr.ecr.<リージョン>.<ドメイン>`
//   - S3 Control: `123456789012.s3-control.<リージョン>.<ドメイン>`(`.s3-control.dualstack.`、`.s3-control-fips.` などを含む)
//   - SQS: `sqs.<リージョン>.<ドメイン>/123456789012/`、`<リージョン>.queue.amazonaws.com/…`、`queue.amazonaws.com/…`
//
// 範囲は、12 桁の部分だけ。前処理: ARN は `:`、ECR と SQS は `.amazonaws.`(nextAmazonaws)を手がかりにし、
// なければすぐ戻る。正規表現は、手がかりから求めた形の先頭にだけ当てる。
type awsAccountFinder struct{}

func (awsAccountFinder) kind() Kind { return KindAWSAccount }

func (f awsAccountFinder) find(line []byte, dst []Match) []Match {
	dst = f.arn(line, dst)
	return f.hosts(line, dst)
}

func accountMatch(start int) Match {
	return Match{Start: start, End: start + 12, Kind: KindAWSAccount}
}

// arn は、ARN のアカウント ID を追記する。`arn:` の前が英数字でないこと。
//
// `arn:` を bytes.Index で探すと、先頭の `a` が文中に多く、遅い経路になる。`:` を bytes.IndexByte で探し、
// 手前が `arn` のときだけ、正規表現を当てる(段階 3 の `ec2-` / `ip-` と同じ工夫)。
func (awsAccountFinder) arn(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		j := bytes.IndexByte(line[pos:], ':')
		if j < 0 {
			return dst
		}
		i := pos + j // `:` の位置
		pos = i + 1
		p := i - len(arnWord) // `arn:` の位置
		if p < 0 || !bytes.Equal(line[p:i], arnWord) || p > 0 && isASCIIAlnum(line[p-1]) {
			continue
		}
		if loc := arnAccountRe.FindSubmatchIndex(line[p:]); loc != nil {
			dst = append(dst, accountMatch(p+loc[2]))
		}
	}
}

// hosts は、ECR のレジストリ・S3 Control のホストと、SQS のキュー URL のアカウント ID を追記する。
//
// どちらのホストも、対象のドメイン(`amazonaws.…`)で終わる。`.amazonaws.` を手がかりにし、手前のリージョン
// (`.` を含まない)を遡って、その手前が accountHostMarkers(ECR、S3 Control)、`sqs`(SQS)かを調べ、
// 形の先頭に正規表現を当てる。`queue.amazonaws.com`(SQS の旧形式)は、`.amazonaws.` の手前が `queue` の場合。
//   - ECR・S3 Control: 12 桁の前が、英数字・`-`・`_`・`.` でないこと。ドメインの後ろは、ホスト名の末尾の条件(isHostEnd。Q41)
//   - SQS: ホストの前が、英数字・`-`・`_`・`.` でないこと。ドメインの直後が `/` + 12 桁 + `/`
func (awsAccountFinder) hosts(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		a := nextAmazonaws(line, pos)
		if a < 0 {
			return dst
		}
		pos = a + amazonawsNext
		if q := a - len(queueWord); q >= 0 && bytes.Equal(line[q:a], queueWord) {
			dst = queueAccount(line, q, dst)
		}
		r := a // リージョンの先頭
		for r > 0 && isRegionChar(line[r-1]) {
			r--
		}
		if r == a || r == 0 || line[r-1] != '.' {
			continue
		}
		d := r - 1 // リージョンの手前の `.`
		for _, m := range accountHostMarkerBytes {
			p := d - len(m) // `.dkr.ecr` / `.s3-control` などの位置
			if p < 0 || !bytes.Equal(line[p:d], m) {
				continue
			}
			s := p - 12
			if s < 0 || !allDigits(line[s:p]) || s > 0 && isHostPrefixChar(line[s-1]) {
				continue
			}
			if loc := accountHostRe.FindIndex(line[p:]); loc != nil && isHostEnd(line, p+loc[1]) {
				dst = append(dst, accountMatch(s))
			}
			break
		}
		if p := d - len(sqsWord); p >= 0 && bytes.Equal(line[p:d], sqsWord) && (p == 0 || !isHostPrefixChar(line[p-1])) {
			if loc := sqsHostRe.FindSubmatchIndex(line[p:]); loc != nil {
				dst = append(dst, accountMatch(p+loc[2]))
			}
		}
	}
}

// queueAccount は、line[q:] から始まる `queue.amazonaws.com`(SQS の旧形式のホスト)の後ろのアカウント ID を追記する。
// ホストは `<リージョン>.queue.amazonaws.com` または `queue.amazonaws.com` で、その前が英数字・`-`・`_`・`.` でないこと。
func queueAccount(line []byte, q int, dst []Match) []Match {
	if !bytes.HasPrefix(line[q:], sqsQueueHost) {
		return dst
	}
	h := q // ホストの先頭
	if q > 0 && line[q-1] == '.' {
		h = q - 1
		for h > 0 && isRegionChar(line[h-1]) {
			h--
		}
		if h == q-1 {
			return dst // `.` の前にリージョンがない
		}
	}
	if h > 0 && isHostPrefixChar(line[h-1]) {
		return dst
	}
	e := q + len(sqsQueueHost)
	if loc := sqsPathRe.FindSubmatchIndex(line[e:]); loc != nil {
		dst = append(dst, accountMatch(e+loc[2]))
	}
	return dst
}

// amazonawsNext は、nextAmazonaws が返した位置 a から、次を探し始める位置までの距離(a の後ろの `z` の次)。
const amazonawsNext = 5

// nextAmazonaws は、line[pos:] の中の、次の `.amazonaws.` の位置(先頭の `.`)を返す。なければ -1。
// 次の呼び出しは、返した位置 + amazonawsNext から始める。
//
// `.amazonaws.` を bytes.Index で探すと、先頭の `.` が文中に多く(時刻、ロガー名など)、遅い経路になる。
// `amazonaws` の中の、文中に少ない `z` を bytes.IndexByte で探してから、前後を照合する。
func nextAmazonaws(line []byte, pos int) int {
	for {
		j := bytes.IndexByte(line[pos:], 'z')
		if j < 0 {
			return -1
		}
		z := pos + j
		pos = z + 1
		if a := z - 4; a >= 0 && bytes.HasPrefix(line[a:], amazonawsMarker) { // `.ama` + `z`
			return a
		}
	}
}

// isRegionChar は、ホスト名の中のリージョンの文字(英小文字・数字・`-`。Q40)。
func isRegionChar(c byte) bool {
	return c >= 'a' && c <= 'z' || isDigit(c) || c == '-'
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if !isDigit(c) {
			return false
		}
	}
	return true
}

// ---- aws_s3_bucket(仕様 4.4) ----

// s3Endpoints は、S3 のエンドポイント(バーチャルホスト形式・パス形式で共通。仕様 4.4)。
// {region} は、ホスト名の中のリージョン(awsRegionRe)。後ろに `.` + 対象のドメインが続く。
var s3Endpoints = []string{
	"s3", "s3.{region}", "s3-{region}", "s3.dualstack.{region}", "s3-fips.{region}", "s3-fips.dualstack.{region}",
	"s3-website-{region}", "s3-website.{region}", "s3-accelerate", "s3-accelerate.dualstack",
}

// s3EndpointRe は、文字列全体が S3 のエンドポイントのどれかかを調べる正規表現。
var s3EndpointRe = func() *regexp.Regexp {
	alts := make([]string, len(s3Endpoints))
	for i, e := range s3Endpoints {
		alts[i] = strings.ReplaceAll(regexp.QuoteMeta(e), regexp.QuoteMeta("{region}"), awsRegionRe)
	}
	return regexp.MustCompile(`^(?:` + strings.Join(alts, "|") + `)$`)
}()

// s3EndpointMaxDots は、S3 のエンドポイントに含まれる `.` の最大の数(リージョンは `.` を含まない)。
var s3EndpointMaxDots = func() int {
	n := 0
	for _, e := range s3Endpoints {
		n = max(n, strings.Count(e, "."))
	}
	return n
}()

// s3Schemes は、`s3://` 形式のスキーム(Hadoop・Spark の `s3a`、`s3n` を含む。Q37)。
var s3Schemes = [][]byte{[]byte("s3"), []byte("s3a"), []byte("s3n")}

// maxBucketLen は、バケット名の最大の長さ。
const maxBucketLen = 63

var (
	schemeSep       = []byte("://")
	amazonawsMarker = []byte(".amazonaws.")
	s3ARNMarker     = []byte(":s3:::")
)

// isBucketChar は、バケット名に使える文字(英小文字・数字・`.`・`-`)。
func isBucketChar(c byte) bool {
	return c >= 'a' && c <= 'z' || isDigit(c) || c == '.' || c == '-'
}

// validBucket は、b が、バケット名の規則に合うかを返す(仕様 4.4、Q45)。
// 英小文字・数字・`.`・`-` からなる 3〜63 文字。先頭と末尾が英小文字・数字。`.` が 2 つ続かない。IP アドレスの形でない。
func validBucket(b []byte) bool {
	if len(b) < 3 || len(b) > maxBucketLen {
		return false
	}
	for _, c := range b {
		if !isBucketChar(c) {
			return false
		}
	}
	first, last := b[0], b[len(b)-1]
	if first == '.' || first == '-' || last == '.' || last == '-' {
		return false
	}
	return !bytes.Contains(b, []byte("..")) && !looksLikeIPv4(b)
}

// looksLikeIPv4 は、b が、数字 1 文字以上の組 4 つを `.` で区切った形かを返す(値の範囲は問わない。Q45)。
func looksLikeIPv4(b []byte) bool {
	groups, digits := 1, 0
	for _, c := range b {
		switch {
		case isDigit(c):
			digits++
		case c == '.' && digits > 0:
			groups, digits = groups+1, 0
		default:
			return false
		}
	}
	return groups == 4 && digits > 0
}

// bucketAt は、line[s:] から始まるバケット名(`s3://`・パス形式・ARN の、決まった部分の直後)の末尾を返す。
//
// バケット名に使える文字を伸ばせるだけ伸ばし、後ろが英数字(英大文字を含む)・`_` なら、旧形式のバケット名の
// 一部とみなして、置換しない(Q44)。末尾の `.` 1 つは、文末の句点とみなして外す(Q44)。
func bucketAt(line []byte, s int) (int, bool) {
	e := s
	for e < len(line) && isBucketChar(line[e]) {
		if e-s > maxBucketLen { // 末尾の `.` を外しても、63 文字を超える
			return 0, false
		}
		e++
	}
	if e < len(line) && (isASCIIAlnum(line[e]) || line[e] == '_') {
		return 0, false
	}
	if e > s && line[e-1] == '.' {
		e--
	}
	if !validBucket(line[s:e]) {
		return 0, false
	}
	return e, true
}

// awsS3BucketFinder は、S3 のバケット名の検出器(仕様 4.4)。決まった形の中に現れたものだけを検出する。
//
//   - `s3://`(`s3a://`、`s3n://`)形式: `s3://my-bucket/…`
//   - バーチャルホスト形式: `my-bucket.<S3 のエンドポイント>.<ドメイン>`
//   - パス形式: `<S3 のエンドポイント>.<ドメイン>/my-bucket/…`
//   - ARN: `arn:<パーティション>:s3:::my-bucket/…`
//
// 範囲は、バケット名の部分だけ。前処理: 各形の手がかりを探し、なければすぐ戻る。`s3://` と ARN は `:` を
// bytes.IndexByte で探して前後を照合し(1 回の走査)、`.amazonaws.` は nextAmazonaws で探す。
type awsS3BucketFinder struct{}

func (awsS3BucketFinder) kind() Kind { return KindAWSS3Bucket }

func (f awsS3BucketFinder) find(line []byte, dst []Match) []Match {
	dst = f.colonForms(line, dst)
	return f.hosts(line, dst)
}

func bucketMatch(s, e int) Match {
	return Match{Start: s, End: e, Kind: KindAWSS3Bucket}
}

// colonForms は、`:` で始まる手がかりを持つ 2 つの形のバケット名を追記する。
//   - `s3://`(`s3a://`、`s3n://`)の直後。スキームの前が英数字でないこと
//   - `arn:<パーティション>:s3:::` の直後。`arn:` の前が英数字でないこと(Q46)
//
// `://`・`:s3:::` を bytes.Index で探すと、先頭の `:` が文中に多く(時刻、JSON のキーの区切りなど)、遅い経路になる
// (DEVELOPMENT.md 3.4 節)。`:` を bytes.IndexByte で 1 回だけ走査し、`:` ごとに後ろを照合する(plans/v1.2.0.md 段階 8)。
func (awsS3BucketFinder) colonForms(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		j := bytes.IndexByte(line[pos:], ':')
		if j < 0 {
			return dst
		}
		i := pos + j // `:` の位置
		pos = i + 1
		switch {
		case bytes.HasPrefix(line[i:], schemeSep):
			dst = s3SchemeBucket(line, i, dst)
		case bytes.HasPrefix(line[i:], s3ARNMarker):
			dst = s3ARNBucket(line, i, dst)
		}
	}
}

// s3SchemeBucket は、line[i:] から始まる `://` の手前が `s3`・`s3a`・`s3n` なら、直後のバケット名を追記する。
func s3SchemeBucket(line []byte, i int, dst []Match) []Match {
	for _, sch := range s3Schemes {
		p := i - len(sch)
		if p < 0 || !bytes.Equal(line[p:i], sch) || p > 0 && isASCIIAlnum(line[p-1]) {
			continue
		}
		if e, ok := bucketAt(line, i+len(schemeSep)); ok {
			dst = append(dst, bucketMatch(i+len(schemeSep), e))
		}
		break
	}
	return dst
}

// hosts は、バーチャルホスト形式とパス形式のバケット名を追記する。
//
// `.amazonaws.`(nextAmazonaws)を手がかりに、その後ろが対象のドメインかを確かめ、手前のラベル(`.` 区切り)を遡る。
// エンドポイントは `.` を s3EndpointMaxDots 個までしか含まないので、遡るのは、その数 + 1 個の `.` まで。
//   - パス形式: ホスト名全体(ドメインを除く)がエンドポイントで、ドメインの直後が `/`。その後ろがバケット名
//   - バーチャルホスト形式: ホスト名が「バケット名 + `.` + エンドポイント」。エンドポイントは、できるだけ後ろで取る
//     (バケット名を最も長く取る)。そのバケット名が規則に合わなければ、置換しない(Q43)。ドメインの後ろは isHostEnd(Q41)
func (awsS3BucketFinder) hosts(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		a := nextAmazonaws(line, pos) // ドメインの手前の `.` の位置
		if a < 0 {
			return dst
		}
		pos = a + amazonawsNext
		vhost, pathEnd := false, -1
		for _, d := range awsDomainBytes {
			if !bytes.HasPrefix(line[a+1:], d) {
				continue
			}
			end := a + 1 + len(d)
			if isHostEnd(line, end) {
				vhost = true
			}
			if end < len(line) && line[end] == '/' {
				pathEnd = end
			}
		}
		if !vhost && pathEnd < 0 {
			continue
		}
		// a の手前のラベルを遡る。dots は、見つけた `.` の位置(後ろから順)。
		// runStart は、ホスト名の先頭(遡りきった位置)。`.` が多すぎて遡りきらなかった場合は -1。
		// dotsBuf の大きさは、s3EndpointMaxDots+1(今は 3)以上にしておく(足りなくても append で広がるので、結果は変わらない)。
		var dotsBuf [4]int
		dots := dotsBuf[:0]
		runStart := a
		for runStart > 0 && isBucketChar(line[runStart-1]) {
			if line[runStart-1] == '.' {
				if len(dots) == s3EndpointMaxDots+1 {
					runStart = -1
					break
				}
				dots = append(dots, runStart-1)
			}
			runStart--
		}
		if pathEnd >= 0 && runStart >= 0 && (runStart == 0 || !isHostPrefixChar(line[runStart-1])) &&
			s3EndpointRe.Match(line[runStart:a]) {
			if e, ok := bucketAt(line, pathEnd+1); ok {
				dst = append(dst, bucketMatch(pathEnd+1, e))
			}
		}
		if !vhost {
			continue
		}
		for _, k := range dots {
			if !s3EndpointRe.Match(line[k+1 : a]) {
				continue
			}
			// バケット名は、k の手前から、ホスト名の先頭まで(最大 maxBucketLen 文字)
			h := k
			for h > 0 && isBucketChar(line[h-1]) && k-h <= maxBucketLen {
				h--
			}
			if k-h <= maxBucketLen && (h == 0 || !isHostPrefixChar(line[h-1])) && validBucket(line[h:k]) {
				dst = append(dst, bucketMatch(h, k))
			}
			break
		}
	}
}

// s3ARNBucket は、line[i:] から始まる `:s3:::` の手前が `arn:<パーティション>` なら、直後のバケット名を追記する。
func s3ARNBucket(line []byte, i int, dst []Match) []Match {
	for _, part := range awsPartitions {
		p := i - len(part) - len(arnPrefix)
		if p < 0 || !bytes.HasPrefix(line[p:], arnPrefix) || string(line[p+len(arnPrefix):i]) != part ||
			p > 0 && isASCIIAlnum(line[p-1]) {
			continue
		}
		s := i + len(s3ARNMarker)
		if e, ok := bucketAt(line, s); ok {
			dst = append(dst, bucketMatch(s, e))
		}
		break
	}
	return dst
}

// ---- aws_host(仕様 4.5) ----

// awsHostForm は、aws_host の表の 1 行(サービス 1 つ)。仕様 4.5 の表と同じ並び。
// サービスの追加は、この表に行を足すだけで済む(手がかり・照合の部品は、表から作る)。
type awsHostForm struct {
	service string
	// tails は、末尾の形。`.` で始まり、`{region}`(ホスト名の中のリージョン。awsRegionRe)と、
	// 末尾の `.{domain}`(awsDomains のどれか)を含められる。それ以外の部分は、小文字の決まった語(Q42)。
	// 後ろの条件は、どの形も isHostEnd(Q41)。
	tails []string
	// exclude は、利用者ごとの部分がこの名前そのものの場合は検出しない、という名前(AWS 共通のエンドポイント。Q57、Q61)。
	exclude []string
}

const (
	hostRegionPlaceholder = "{region}"
	hostDomainSuffix      = ".{domain}"
)

var awsHostForms = []awsHostForm{
	{service: "ELB (CLB, ALB)", tails: []string{".{region}.elb.{domain}"}},
	{service: "ELB (NLB, ALB)", tails: []string{".elb.{region}.{domain}"}},
	{service: "API Gateway", tails: []string{".execute-api.{region}.{domain}"}},
	{service: "Lambda function URL", tails: []string{".lambda-url.{region}.on.aws"}},
	{service: "CloudFront", tails: []string{".cloudfront.net"}},
	{service: "Global Accelerator", tails: []string{".awsglobalaccelerator.com"}},
	{service: "EKS", tails: []string{".{region}.eks.{domain}"}},
	{service: "RDS, Aurora, RDS Proxy", tails: []string{".{region}.rds.{domain}"}},
	{service: "Redshift", tails: []string{".{region}.redshift.{domain}", ".{region}.redshift-serverless.{domain}"}},
	{service: "OpenSearch", tails: []string{".{region}.es.{domain}", ".{region}.aoss.{domain}"}},
	{service: "MSK", tails: []string{".kafka.{region}.{domain}"}},
	{service: "Amazon MQ", tails: []string{".mq.{region}.{domain}", ".mq.{region}.on.aws"}},
	{service: "Transfer Family", tails: []string{".server.transfer.{region}.{domain}"}},
	{service: "AppSync", tails: []string{".appsync-api.{region}.{domain}", ".appsync-realtime-api.{region}.{domain}"}},
	{service: "Cognito domain", tails: []string{".auth.{region}.amazoncognito.com"}},
	{service: "IoT Core", tails: []string{".iot.{region}.{domain}"}, exclude: []string{"data-ats", "api.tunneling", "data.tunneling"}},
	{service: "App Runner", tails: []string{".{region}.awsapprunner.com"}},
	{service: "Amplify Hosting", tails: []string{".amplifyapp.com"}},
	{service: "Elastic Beanstalk", tails: []string{".{region}.elasticbeanstalk.com", ".elasticbeanstalk.com"}},
	{service: "EC2 public hostname (IPv6, dual-stack)", tails: []string{".{region}.ip.aws"}},
}

// hostElem は、末尾の形の部品。リージョン(region)か、決まった語(lit)。
type hostElem struct {
	region bool
	lit    []byte
}

// hostTail は、末尾の形のうち、手がかり(終端)より手前の部品を、前から順に並べたもの。
type hostTail struct {
	prefix  []hostElem
	exclude [][]byte
}

// hostTerminal は、決まった語で終わる形の終端(`.ip.aws` など)。hint は、終端の中の、文中に少ない 1 バイトの位置 off。
type hostTerminal struct {
	lit   []byte
	off   int
	tails []hostTail
}

// hostGroup は、同じ手がかりのバイト(hint)で探す終端のまとまり。amazonaws は、`.amazonaws.` で終わる形
// (`{domain}` で終わる形)も同じ走査で探すか。
type hostGroup struct {
	hint      byte
	terms     []hostTerminal
	amazonaws bool
}

// awsHostTable は、awsHostForms から作った照合の部品。
var awsHostTable = buildAWSHostTable(awsHostForms)

type awsHostParts struct {
	groups []hostGroup
	amazon []hostTail // `{domain}` で終わる形
}

// hostHintRank は、終端の中から手がかりのバイトを選ぶ順(文中に少ない文字から)。この順で最初に現れる文字を使う。
// 合成ログと文章(このリポジトリの資料)での文字の出現率と、BenchmarkAWSHostFinder の実測で決めた
// (plans/v1.2.0.md のベンチマーク記録)。`l` を `k` `y` `f` より前に置くのは、cloudfront.net・amplifyapp.com・
// elasticbeanstalk.com を 1 回の走査で探すため(走査の回数を減らすほうが、`l` の一致の増加より速かった)。
const hostHintRank = "zqxjvwlkybpgfmcudhrsnioate"

func buildAWSHostTable(forms []awsHostForm) awsHostParts {
	var t awsHostParts
	groupAt := func(hint byte) *hostGroup {
		for i := range t.groups {
			if t.groups[i].hint == hint {
				return &t.groups[i]
			}
		}
		t.groups = append(t.groups, hostGroup{hint: hint})
		return &t.groups[len(t.groups)-1]
	}
	// `.amazonaws.` は、nextAmazonaws と同じ `z` で探す。
	groupAt('z').amazonaws = true
	for _, f := range forms {
		var ex [][]byte
		for _, e := range f.exclude {
			ex = append(ex, []byte(e))
		}
		for _, spec := range f.tails {
			if !strings.HasPrefix(spec, ".") {
				panic("aws host tail must start with '.': " + spec)
			}
			if body, ok := strings.CutSuffix(spec, hostDomainSuffix); ok {
				t.amazon = append(t.amazon, hostTail{prefix: parseHostElems(body), exclude: ex})
				continue
			}
			i := strings.LastIndex(spec, "}")
			term, body := spec[i+1:], spec[:i+1] // i == -1 のとき、term は spec 全体
			if term == "" || term[0] != '.' || strings.ContainsAny(term, "{}") {
				panic("aws host tail must end with a fixed word: " + spec)
			}
			off := hintOffset(term)
			g := groupAt(term[off])
			ti := -1
			for k := range g.terms {
				if string(g.terms[k].lit) == term {
					ti = k
				}
			}
			if ti < 0 {
				g.terms = append(g.terms, hostTerminal{lit: []byte(term), off: off})
				ti = len(g.terms) - 1
			}
			g.terms[ti].tails = append(g.terms[ti].tails, hostTail{prefix: parseHostElems(body), exclude: ex})
		}
	}
	return t
}

// hintOffset は、term の中で、手がかりにするバイトの位置(hostHintRank の順で最初に現れる文字)を返す。
func hintOffset(term string) int {
	best, rank := -1, len(hostHintRank)+1
	for i := 0; i < len(term); i++ {
		r := strings.IndexByte(hostHintRank, term[i])
		if r < 0 {
			continue
		}
		if r < rank {
			best, rank = i, r
		}
	}
	if best < 0 {
		panic("aws host terminal has no hint letter: " + term)
	}
	return best
}

// parseHostElems は、`{region}` を含む文字列を、部品の列にする。
func parseHostElems(body string) []hostElem {
	var out []hostElem
	for body != "" {
		i := strings.Index(body, hostRegionPlaceholder)
		if i < 0 {
			if strings.ContainsAny(body, "{}") {
				panic("bad aws host tail: " + body)
			}
			return append(out, hostElem{lit: []byte(body)})
		}
		if i > 0 {
			out = append(out, hostElem{lit: []byte(body[:i])})
		}
		out = append(out, hostElem{region: true})
		body = body[i+len(hostRegionPlaceholder):]
	}
	return out
}

// matchBack は、line[:end] の末尾が、elems(前から順)に一致するかを調べ、一致した部分の先頭を返す。
// 後ろの部品から照合する(リージョンは、`.` を含まないので、遡れるだけ遡った長さが唯一の読み方になる)。
func matchBack(line []byte, end int, elems []hostElem) (int, bool) {
	pos := end
	for i := len(elems) - 1; i >= 0; i-- {
		e := elems[i]
		if e.region {
			n := pos
			for pos > 0 && isRegionChar(line[pos-1]) {
				pos--
			}
			if pos == n {
				return 0, false
			}
			continue
		}
		if pos < len(e.lit) || !bytes.Equal(line[pos-len(e.lit):pos], e.lit) {
			return 0, false
		}
		pos -= len(e.lit)
	}
	return pos, true
}

// isHostRunChar は、利用者ごとの部分に使える文字(英数字・`-`・`.`)。
func isHostRunChar(c byte) bool { return isASCIIAlnum(c) || c == '-' || c == '.' }

// hostRunCache は、利用者ごとの部分を求めるときに、手前へ遡った範囲を覚えておく(同じ範囲を何度も遡らないため)。
//
// [rs, hi) は、遡って調べた範囲で、すべて isHostRunChar の文字。rs の手前は、その文字でない(または行頭)。
// firstDD は、範囲の中の最初の `..` の 2 つ目の `.` の位置(なければ -1)。
// 検出器は、手がかりの位置が増える順に探す。次の問い合わせが範囲の上側に続くなら、範囲を伸ばすだけで、
// 遡る長さの合計は、行の長さ以内に収まる。
type hostRunCache struct{ rs, hi, firstDD int }

// userStart は、末尾の形の先頭 t の手前にある利用者ごとの部分の先頭を返す(仕様 4.5)。
// 英数字・`-`・`.` の続く範囲を遡れるだけ遡ったもので、先頭と末尾が英数字、`..` を含まず、手前が `_` でないこと。
func (c *hostRunCache) userStart(line []byte, t int) (int, bool) {
	if t == 0 || !isASCIIAlnum(line[t-1]) {
		return 0, false
	}
	last := t - 1
	var rs, dd int
	if c.hi > 0 && last >= c.rs && last < c.hi {
		rs, dd = c.rs, c.firstDD
		if dd >= t {
			dd = -1
		}
	} else {
		dd = -1
		i, joined := last, false
		for ; i >= 0 && isHostRunChar(line[i]); i-- {
			if i < last && line[i] == '.' && line[i+1] == '.' {
				dd = i + 1
			}
			if c.hi > 0 && i == c.hi-1 {
				joined = true
				break
			}
		}
		if joined {
			rs = c.rs
			if c.firstDD >= 0 {
				dd = c.firstDD
			}
		} else {
			rs = i + 1
		}
		*c = hostRunCache{rs: rs, hi: t, firstDD: dd}
	}
	if dd >= 0 || !isASCIIAlnum(line[rs]) || rs > 0 && line[rs-1] == '_' {
		return 0, false
	}
	return rs, true
}

// awsHostFinder は、AWS のサービスのホスト名の検出器(仕様 4.5)。表(awsHostForms)の末尾の形に一致するホスト名の、
// 利用者ごとの部分だけを検出する。
//
// 前処理: 終端ごとに、文中に少ない 1 バイト(hostHintRank。`.amazonaws.` は nextAmazonaws と同じ `z`)を
// bytes.IndexByte で探し、前後を照合する。手がかりが同じ終端は、1 回の走査でまとめて探す。
// 手前の部品は matchBack で遡る(リージョンは `.` を含まない)。利用者ごとの部分は hostRunCache で遡る。
type awsHostFinder struct{}

func (awsHostFinder) kind() Kind { return KindAWSHost }

func (f awsHostFinder) find(line []byte, dst []Match) []Match {
	for gi := range awsHostTable.groups {
		g := &awsHostTable.groups[gi]
		var cache hostRunCache
		for pos := 0; ; {
			j := bytes.IndexByte(line[pos:], g.hint)
			if j < 0 {
				break
			}
			p := pos + j
			pos = p + 1
			if g.amazonaws {
				if a := p - 4; a >= 0 && bytes.HasPrefix(line[a:], amazonawsMarker) {
					dst = hostAmazon(line, a, &cache, dst)
				}
			}
			for ti := range g.terms {
				term := &g.terms[ti]
				t0 := p - term.off
				if t0 < 0 || !bytes.HasPrefix(line[t0:], term.lit) || !isHostEnd(line, t0+len(term.lit)) {
					continue
				}
				dst = hostTails(line, t0, term.tails, &cache, dst)
			}
		}
	}
	return dst
}

// hostAmazon は、line[a:] から始まる `.amazonaws.<com / com.cn / eu>` で終わるホスト名を調べる。
func hostAmazon(line []byte, a int, cache *hostRunCache, dst []Match) []Match {
	for _, d := range awsDomainBytes {
		if bytes.HasPrefix(line[a+1:], d) && isHostEnd(line, a+1+len(d)) {
			return hostTails(line, a, awsHostTable.amazon, cache, dst)
		}
	}
	return dst
}

// hostCand は、終端の手前に一致した末尾の形(先頭の位置 start と、tails の中の番号)。
type hostCand struct{ start, tail int }

// hostTails は、終端の位置 end の手前が、tails のどれかの手前の部品に一致するか調べ、一致したもののうち
// 最も長い形(先頭が最も前)で、利用者ごとの部分が規則に合うものを追記する(仕様 4.5)。
func hostTails(line []byte, end int, tails []hostTail, cache *hostRunCache, dst []Match) []Match {
	var buf [4]hostCand
	cands := buf[:0]
	for i := range tails {
		if s, ok := matchBack(line, end, tails[i].prefix); ok {
			cands = append(cands, hostCand{start: s, tail: i})
		}
	}
	// 先頭が後ろのものから調べる(遡った範囲の覚えを、続けて使えるように)。残るのは、先頭が最も前の有効なもの
	for i := 1; i < len(cands); i++ {
		for k := i; k > 0 && cands[k].start > cands[k-1].start; k-- {
			cands[k], cands[k-1] = cands[k-1], cands[k]
		}
	}
	best := Match{Start: -1}
	for _, c := range cands {
		us, ok := cache.userStart(line, c.start)
		if !ok || hostExcluded(line[us:c.start], tails[c.tail].exclude) {
			continue
		}
		best = Match{Start: us, End: c.start, Kind: KindAWSHost}
	}
	if best.Start >= 0 {
		dst = append(dst, best)
	}
	return dst
}

func hostExcluded(user []byte, exclude [][]byte) bool {
	for _, e := range exclude {
		if bytes.Equal(user, e) {
			return true
		}
	}
	return false
}
