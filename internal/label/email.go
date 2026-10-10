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
	if hexLen <= 0 {
		return false
	}
	hashed := func(prefix []byte) bool {
		n := len(prefix)
		return len(local) == n+1+hexLen && bytes.HasPrefix(local, prefix) && local[n] == '_' && isLowerHex(local[n+1:])
	}
	if hashed([]byte("hash")) {
		return true
	}
	for _, t := range typeBytes {
		if hashed(t) {
			return true
		}
	}
	return false
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
