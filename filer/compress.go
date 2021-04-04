package filer

import (
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

func decompress(dstPath string, srcPath string) error {
	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return err
	}
	srcFile, err := os.OpenFile(srcPath, os.O_RDONLY, 0660)
	if err != nil {
		return err
	}

	dec, err := zstd.NewReader(srcFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(dstFile, dec)
	if err != nil {
		dec.Close()
		return err
	}
	dec.Close()
	return nil
}
