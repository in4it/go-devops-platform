//go:build !unix

package localstorage

import (
	"io/fs"
	"os"
)

func copyOwnership(file *os.File, existing fs.FileInfo) error {
	return nil
}
