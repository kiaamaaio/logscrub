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

// IsHashedLocalPart は、メールアドレスのローカルパート local が、
// `--email-hash local` の出力の形(`hash_` + 小文字の 16 進数 hexLen 桁)かどうかを返す。
// この形のローカルパートを持つメールアドレスは、検出の対象外(仕様 5.2)。
func IsHashedLocalPart(local []byte, hexLen int) bool {
	const prefix = "hash_"
	return hexLen > 0 && len(local) == len(prefix)+hexLen &&
		bytes.HasPrefix(local, []byte(prefix)) && isLowerHex(local[len(prefix):])
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
