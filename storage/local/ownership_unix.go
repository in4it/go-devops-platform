//go:build unix

package localstorage

import (
	"io/fs"
	"os"
	"syscall"
)

// copyOwnership gives file the same owner and group as existing
func copyOwnership(file *os.File, existing fs.FileInfo) error {
	stat, ok := existing.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) == os.Geteuid() && int(stat.Gid) == os.Getegid() {
		return nil // newly created file already has this owner/group
	}
	return file.Chown(int(stat.Uid), int(stat.Gid))
}
