// Package stream は、行単位の入出力を提供する。
// 改行コード(LF / CRLF)と末尾改行の有無を保ち、行の長さに上限を設けない。
package stream

import (
	"bufio"
	"bytes"
	"io"
)

const bufferSize = 64 * 1024

var (
	eolLF   = []byte("\n")
	eolCRLF = []byte("\r\n")
)

// Reader は入力を 1 行ずつ返す。
type Reader struct {
	br *bufio.Reader
	// long は、バッファに収まらない行を連結するための作業領域。
	long []byte
}

// NewReader は r を読む Reader を返す。
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, bufferSize)}
}

// Next は次の 1 行を、中身と改行コードに分けて返す。
//
// 改行コードは "\n"、"\r\n"、またはファイル末尾で改行がない場合の nil のいずれか。
// 単独の '\r' は改行とみなさず、行の中身に含める。
// 入力のバイト列は一切変換しない(不正な UTF-8 もそのまま返す)。
//
// 返すスライスは、次に Next を呼ぶまでの間だけ有効であり、書き換えてはならない。
// 入力の終わりでは io.EOF を返す。読み込みエラー時は、読みかけの行を返さずにエラーを返す。
func (r *Reader) Next() (content, eol []byte, err error) {
	line, err := r.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// バッファより長い行。ここまでをコピーし、改行か入力の終わりまで連結する。
		r.long = append(r.long[:0], line...)
		for err == bufio.ErrBufferFull {
			line, err = r.br.ReadSlice('\n')
			r.long = append(r.long, line...)
		}
		line = r.long
	}
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	if len(line) == 0 {
		// err は必ず io.EOF(ReadSlice は、データなしでは err == nil を返さない)
		return nil, nil, io.EOF
	}
	// ここに来る時点で、err == nil(改行で終わる行)か、err == io.EOF(改行なしの最終行)。
	if line[len(line)-1] != '\n' {
		return line, nil, nil
	}
	line = line[:len(line)-1]
	if bytes.HasSuffix(line, eolCRLF[:1]) {
		return line[:len(line)-1], eolCRLF, nil
	}
	return line, eolLF, nil
}
