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
	// ecrHostRe は、ECR のレジストリのホストの、アカウント ID の後ろの部分。`.dkr.ecr` の位置に当てる。
	ecrHostRe = regexp.MustCompile(`^\.dkr\.ecr(?:-fips)?\.` + awsRegionRe + `\.` + awsDomainRe)
	// sqsHostRe は、SQS のキュー URL の `sqs.<リージョン>.<ドメイン>/<アカウント ID>/`。`sqs.` の位置に当てる。
	sqsHostRe = regexp.MustCompile(`^sqs\.` + awsRegionRe + `\.` + awsDomainRe + `/` + awsAccountRe + `/`)
	// sqsPathRe は、SQS の旧形式のホスト(`queue.amazonaws.com`)の後ろの `/<アカウント ID>/`。
	sqsPathRe = regexp.MustCompile(`^/` + awsAccountRe + `/`)
)

var (
	arnPrefix    = []byte("arn:")
	ecrMarker    = []byte(".dkr.ecr")
	sqsPrefix    = []byte("sqs.")
	sqsQueueHost = []byte("queue.amazonaws.com")
)

// awsAccountFinder は、AWS アカウント ID の検出器(仕様 4.4)。決まった形の中に現れたものだけを検出する。
//
//   - ARN: `arn:aws:iam::123456789012:role/x`(アカウント ID の欄が 12 桁のときだけ)
//   - ECR: `123456789012.dkr.ecr.<リージョン>.<ドメイン>`
//   - SQS: `sqs.<リージョン>.<ドメイン>/123456789012/`、`<リージョン>.queue.amazonaws.com/…`、`queue.amazonaws.com/…`
//
// 範囲は、12 桁の部分だけ。前処理: 各形の手がかり(`arn:`、`.dkr.ecr`、`sqs.`、`queue.amazonaws.com`)を
// bytes.Index で探し、なければすぐ戻る。正規表現は、手がかりの位置にだけ当てる。
type awsAccountFinder struct{}

func (awsAccountFinder) kind() Kind { return KindAWSAccount }

func (f awsAccountFinder) find(line []byte, dst []Match) []Match {
	dst = f.arn(line, dst)
	dst = f.ecr(line, dst)
	return f.sqs(line, dst)
}

func accountMatch(start int) Match {
	return Match{Start: start, End: start + 12, Kind: KindAWSAccount}
}

// arn は、ARN のアカウント ID を追記する。`arn:` の前が英数字でないこと。
func (awsAccountFinder) arn(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		j := bytes.Index(line[pos:], arnPrefix)
		if j < 0 {
			return dst
		}
		p := pos + j
		pos = p + 1
		if p > 0 && isASCIIAlnum(line[p-1]) {
			continue
		}
		if loc := arnAccountRe.FindSubmatchIndex(line[p:]); loc != nil {
			dst = append(dst, accountMatch(p+loc[2]))
		}
	}
}

// ecr は、ECR のレジストリのアカウント ID を追記する。12 桁の前が、英数字・`-`・`_`・`.` でないこと。
// ドメインの後ろは、ホスト名の末尾の条件(isHostEnd。Q41)を満たすこと。
func (awsAccountFinder) ecr(line []byte, dst []Match) []Match {
	for pos := 0; ; {
		j := bytes.Index(line[pos:], ecrMarker)
		if j < 0 {
			return dst
		}
		d := pos + j // `.dkr.ecr` の位置
		pos = d + 1
		s := d - 12
		if s < 0 || !allDigits(line[s:d]) || s > 0 && isHostPrefixChar(line[s-1]) {
			continue
		}
		if loc := ecrHostRe.FindIndex(line[d:]); loc != nil && isHostEnd(line, d+loc[1]) {
			dst = append(dst, accountMatch(s))
		}
	}
}

// sqs は、SQS のキュー URL のアカウント ID を追記する。ホストの前が、英数字・`-`・`_`・`.` でないこと。
func (awsAccountFinder) sqs(line []byte, dst []Match) []Match {
	// sqs.<リージョン>.<ドメイン>/<アカウント ID>/
	for pos := 0; ; {
		j := bytes.Index(line[pos:], sqsPrefix)
		if j < 0 {
			break
		}
		p := pos + j
		pos = p + 1
		if p > 0 && isHostPrefixChar(line[p-1]) {
			continue
		}
		if loc := sqsHostRe.FindSubmatchIndex(line[p:]); loc != nil {
			dst = append(dst, accountMatch(p+loc[2]))
		}
	}
	// <リージョン>.queue.amazonaws.com/<アカウント ID>/、queue.amazonaws.com/<アカウント ID>/
	for pos := 0; ; {
		j := bytes.Index(line[pos:], sqsQueueHost)
		if j < 0 {
			break
		}
		q := pos + j
		pos = q + 1
		h := q // ホストの先頭
		if q > 0 && line[q-1] == '.' {
			h = q - 1
			for h > 0 && isRegionChar(line[h-1]) {
				h--
			}
			if h == q-1 {
				continue // `.` の前にリージョンがない
			}
		}
		if h > 0 && isHostPrefixChar(line[h-1]) {
			continue
		}
		e := q + len(sqsQueueHost)
		if loc := sqsPathRe.FindSubmatchIndex(line[e:]); loc != nil {
			dst = append(dst, accountMatch(e+loc[2]))
		}
	}
	return dst
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
