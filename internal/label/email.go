package label

import "bytes"

// IsEmailLocalChar は、メールアドレスのローカルパートに使う文字(`[A-Za-z0-9._%+-]`)かどうかを返す。
// 非 ASCII のバイトは、英数字でない扱いで、ローカルパートの文字ではない。
func IsEmailLocalChar(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

// EmailDomainEnd は、b[i:] から始まるメールアドレスのドメイン
// (`([A-Za-z0-9-]+\.)+[A-Za-z]{2,}`)の末尾の位置を返す。ドメインでなければ -1。
//
// ドメインは、ラベルを `.` でつないだもので、最後のラベル(TLD)は英字 2 文字以上でなければならない。
// 末尾が英字だけのラベルで終わらない場合は、そこまでの最後の英字だけのラベル(2 文字以上)で終える。
// 末尾の `.` は含めない(文末の `user@example.com.` の `.` を範囲に入れない)。
//
// ScanHashed の `hash_<hex>@ドメイン` の範囲と、email 検出器(detect)の範囲が、
// 同じ位置で終わるよう、両方がこの関数を使う。
func EmailDomainEnd(b []byte, i int) int {
	end := -1
	j := i
	first := true // 最初のラベルは、TLD にならない
	for {
		k := j
		for k < len(b) && isLabelChar(b[k]) {
			k++
		}
		if k == j {
			break
		}
		if !first && isAlphaAtLeast2(b[j:k]) {
			end = k
		}
		if k < len(b) && b[k] == '.' {
			j = k + 1
			first = false
			continue
		}
		break
	}
	return end
}

// IsHashedLocalPart は、メールアドレスのローカルパート local が、hash モードの出力と同じ形かどうかを返す。
//
//   - `hash_` + 小文字の 16 進数 hexLen 桁(`--email-hash local` の出力。仕様 5.2)
//   - `<種別>_` + 小文字の 16 進数 hexLen 桁(`--email-hash full` などの出力。種別は Types のいずれか)
//
// この形のローカルパートを持つメールアドレスは、検出の対象外(仕様 5.2)。
// `user@example.com@bastion.example.org` の先頭だけがハッシュされた結果
// (`email_<hex>@bastion.example.org`)を、全体で 1 つのメールアドレスとして、再度ハッシュしないため。
func IsHashedLocalPart(local []byte, hexLen int) bool {
	return HashedAt(local, 0, hexLen) == len(local)
}

// HashedAt は、b[i:] が IsHashedLocalPart の形(`hash_<hex>`、`<種別>_<hex>`)で始まるなら、その終わりの位置を返す。
// でなければ -1。前後の文字は見ない(ローカルパートの先頭に続く置換済みの形を除くため。仕様 5.2。Q69)。
func HashedAt(b []byte, i, hexLen int) int {
	if hexLen <= 0 || i < 0 || i > len(b) {
		return -1
	}
	hashed := func(prefix []byte) int {
		n := i + len(prefix)
		e := n + 1 + hexLen
		if e > len(b) || !bytes.HasPrefix(b[i:], prefix) || b[n] != '_' || !isLowerHex(b[n+1:e]) {
			return -1
		}
		return e
	}
	if e := hashed(hashPrefix); e >= 0 {
		return e
	}
	for _, t := range typeBytes {
		if e := hashed(t); e >= 0 {
			return e
		}
	}
	return -1
}

var hashPrefix = []byte("hash")

// DomainEndBeforeHashed は、b[i:end] のメールアドレスのドメイン(EmailDomainEnd の結果)の末尾が、
// すぐ後ろに続く `hash_<hex>@` の `hash` に食い込むなら、その手前までで読み直したドメインの末尾を返す
// (ドメインにならなければ -1)。食い込まないなら end をそのまま返す(仕様 5.2。Q69)。
//
// `--email-hash local` の出力が続く形(`hash_<hex>@0.AAhash_<hex>@0.AA`)で、1 つ目のドメインを `0.AAhash` と
// 読まないため。ScanHashed の `hash_<hex>@ドメイン` の範囲と、email 検出器(detect)の範囲が、同じ位置で終わるよう、
// 両方がこの関数を使う。
func DomainEndBeforeHashed(b []byte, i, end, hexLen int) int {
	p := end - len(hashPrefix) // 食い込んだ `hash` の先頭
	e := end + 1 + hexLen      // `hash_<hex>` の終わり
	if hexLen <= 0 || p <= i || e >= len(b) || !bytes.HasPrefix(b[p:], hashPrefix) || b[end] != '_' ||
		!isLowerHex(b[end+1:e]) || b[e] != '@' {
		return end
	}
	return EmailDomainEnd(b[:p], i)
}

func isLabelChar(c byte) bool { return isAlnum(c) || c == '-' }

func isAlphaAtLeast2(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}
