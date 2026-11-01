package stream

import (
	"bytes"
	"io"
	"slices"
)

const (
	// blockSize は、1 回の Read で読む大きさ。ブロックの大きさの目安にもなる。
	blockSize = 256 * 1024
	// maxEmptyReads は、データもエラーも返さない Read を続けて許す回数(bufio と同じ)。
	maxEmptyReads = 100
)

// BlockReader は入力を、完全な行だけを含むブロックに分けて読む。行の分け方は Reader と同じ。
// ブロックは行の途中で切れないので、複数の goroutine に分けて処理できる。
type BlockReader struct {
	r    io.Reader
	size int
	// carry は、前の Read の、最後の改行より後ろ。必ず 1 回の Read の大きさ以下。
	carry []byte
	err   error
}

// NewBlockReader は r を読む BlockReader を返す。
func NewBlockReader(r io.Reader) *BlockReader {
	return &BlockReader{r: r, size: blockSize}
}

// Next は次のブロックを、buf の領域を使い回して返す(足りなければ大きくする)。
//
// 返すブロックは 1 行以上の完全な行で、最後の行が改行で終わらないのは、入力の終わりだけ。
// Read の結果に改行があれば、ブロックが埋まるのを待たずに返す(データが少しずつ届く入力で、行を止めないため)。
// 長い行は、改行か入力の終わりまで連結する。行の長さに上限はない。
//
// 入力の終わりでは io.EOF を返す。読み込みエラーでは、エラーの前の完全な行を返してから、
// 次の呼び出しでエラーを返す。読みかけの行は返さない(Reader と同じ)。
func (b *BlockReader) Next(buf []byte) ([]byte, error) {
	if b.err != nil {
		return buf[:0], b.err
	}
	buf = append(buf[:0], b.carry...)
	b.carry = b.carry[:0]
	for empty := 0; ; {
		buf = slices.Grow(buf, b.size)
		start := len(buf)
		n, err := b.r.Read(buf[start : start+b.size])
		buf = buf[:start+n]
		// ここまでの buf に改行はないので、新しい部分だけを探す(長い行で 2 乗の時間にしない)。
		last := bytes.LastIndexByte(buf[start:], '\n')
		switch {
		case err == io.EOF:
			b.err = err
			if len(buf) == 0 {
				return buf, err
			}
			return buf, nil
		case err != nil:
			b.err = err
			if last < 0 {
				return buf[:0], err
			}
			return buf[:start+last+1], nil
		case last >= 0:
			b.carry = append(b.carry, buf[start+last+1:]...)
			return buf[:start+last+1], nil
		}
		if n > 0 {
			empty = 0
		} else if empty++; empty >= maxEmptyReads {
			b.err = io.ErrNoProgress
			return buf[:0], b.err
		}
	}
}

// NextLine は、block の先頭の 1 行を、中身と改行コードと残りに分けて返す。block は空でないこと。
func NextLine(block []byte) (content, eol, rest []byte) {
	i := bytes.IndexByte(block, '\n')
	if i < 0 {
		return block, nil, nil
	}
	content, eol = cutEOL(block[:i+1])
	return content, eol, block[i+1:]
}
