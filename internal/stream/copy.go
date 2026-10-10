package stream

import (
	"bufio"
	"io"
)

// ForEachLine は inputs を順に読み、1 行ごとに fn を呼ぶ。
//
// 行は入力ごとに区切る。末尾改行のない入力の最後の行と、次の入力の最初の行は
// 別の行になる。fn に渡すスライスは、fn から戻るまでの間だけ有効。
// fn がエラーを返したら、そこで止めてそのエラーを返す。
func ForEachLine(inputs []io.Reader, fn func(content, eol []byte) error) error {
	for _, in := range inputs {
		r := NewReader(in)
		for {
			content, eol, err := r.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := fn(content, eol); err != nil {
				return err
			}
		}
	}
	return nil
}

// Copy は inputs を順に読み、行を一切変えずに w へ書く。
// 出力は、各入力をそのままつないだものになる(入力の間に改行は足さない)。
func Copy(w io.Writer, inputs ...io.Reader) error {
	bw := bufio.NewWriterSize(w, bufferSize)
	err := ForEachLine(inputs, func(content, eol []byte) error {
		if _, err := bw.Write(content); err != nil {
			return err
		}
		_, err := bw.Write(eol)
		return err
	})
	if err != nil {
		return err
	}
	return bw.Flush()
}
