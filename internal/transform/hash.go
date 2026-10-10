package transform

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/kiaamaaio/logscrub/internal/detect"
	"github.com/kiaamaaio/logscrub/internal/label"
)

// EmailHash は、メールアドレスのハッシュの形(`--email-hash`、仕様 5.2)。
type EmailHash uint8

const (
	// EmailHashFull は、メールアドレス全体をハッシュする(`email_<hex>`)。既定。
	EmailHashFull EmailHash = iota
	// EmailHashLocal は、ローカルパートだけをハッシュし、ドメインは残す(`hash_<hex>@ドメイン`)。
	EmailHashLocal
)

// Hasher は、値を、HMAC-SHA256(鍵つき)の先頭の桁に置き換える(仕様 5.2)。
//
//   - HMAC に渡すのは、値のバイト列だけ(`local` は、ローカルパートだけ。Q18)。正規化はしない(Q3)。
//     種別名は、入力に含めない
//   - 出力は、`<種別>_<小文字の 16 進数>`(種別は、IP アドレスの区別を含む。例: `ipv4_global_a1b2c3d4e5f6`)。
//     `local` のメールアドレスは、`hash_<16 進数>@ドメイン`
//   - 決定的(同じ鍵・同じ入力 → 同じ出力)。鍵が同じなら、別のマシンでも同じになる
//
// 出力の形は、検出器が置換済みとして認識する(label.ScanHashed、email の除外)ので、再度流しても変わらない。
// そのため、検出器の HashLen は、Hasher の桁数と同じにする。
type Hasher struct {
	mac     hash.Hash
	hashLen int
	email   EmailHash
	sum     [sha256.Size]byte
	hexBuf  [sha256.Size * 2]byte
}

// NewHasher は、鍵 key、16 進数の桁数 hashLen(8〜64。0 は既定の 12)、メールアドレスの形 email の
// Hasher を返す。鍵が空の場合、桁数が範囲外の場合は、エラー。
func NewHasher(key []byte, hashLen int, email EmailHash) (*Hasher, error) {
	if len(key) == 0 {
		return nil, errors.New("the hash key is empty")
	}
	if hashLen == 0 {
		hashLen = label.DefaultHashLen
	}
	if hashLen < label.MinHashLen || hashLen > label.MaxHashLen {
		return nil, fmt.Errorf("hash length must be between %d and %d", label.MinHashLen, label.MaxHashLen)
	}
	if email != EmailHashFull && email != EmailHashLocal {
		return nil, fmt.Errorf("unknown email hash mode %d", email)
	}
	return &Hasher{mac: hmac.New(sha256.New, key), hashLen: hashLen, email: email}, nil
}

// digest は、v の HMAC の先頭 hashLen 桁(小文字の 16 進数)を返す。返すスライスは、次の呼び出しまで有効。
func (h *Hasher) digest(v []byte) []byte {
	h.mac.Reset()
	h.mac.Write(v)
	sum := h.mac.Sum(h.sum[:0])
	hex.Encode(h.hexBuf[:], sum)
	return h.hexBuf[:h.hashLen]
}

// Append は、m の値のハッシュを、dst に追記して返す。
// 種別のない(置換しないはずの)範囲は、元のバイト列をそのまま追記する。
func (h *Hasher) Append(dst []byte, line []byte, m detect.Match) []byte {
	v := line[m.Start:m.End]
	typ := m.LabelType()
	if typ == "" {
		return append(dst, v...)
	}
	if h.email == EmailHashLocal && m.Kind == detect.KindEmail {
		if at := bytes.IndexByte(v, '@'); at > 0 {
			dst = append(dst, "hash_"...)
			dst = append(dst, h.digest(v[:at])...)
			return append(dst, v[at:]...)
		}
	}
	dst = append(dst, typ...)
	dst = append(dst, '_')
	return append(dst, h.digest(v)...)
}
