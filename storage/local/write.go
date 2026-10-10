package localstorage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFile writes the data atomically: the data is written to a temporary file in the same directory,
// which is then renamed to name. A crash or a full disk can't leave a truncated file behind.
// New files are created with mode 0600. When the file already exists, its mode and ownership are kept
// (like os.WriteFile does). If that isn't possible (e.g. the directory isn't writable or the ownership
// can't be copied), the file is written in place.
func (l *LocalStorage) WriteFile(name string, data []byte) error {
	fullPath, err := l.fullPath(name)
	if err != nil {
		return err
	}
	return writeFileAtomic(fullPath, data, 0600)
}

func writeFileAtomic(filename string, data []byte, perm os.FileMode) error {
	existing, err := os.Lstat(filename)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if existing != nil && !existing.Mode().IsRegular() { // e.g. a symlink: write through it, like os.WriteFile
		return os.WriteFile(filename, data, perm)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(filename), "."+filepath.Base(filename)+".tmp-*")
	if err != nil { // directory not writable: fall back to writing in place
		return os.WriteFile(filename, data, perm)
	}
	tmpName := tmpFile.Name()
	renamed := false
	defer func() {
		if !renamed {
			tmpFile.Close()
			os.Remove(tmpName)
		}
	}()

	mode := perm
	if existing != nil {
		mode = existing.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		if err := copyOwnership(tmpFile, existing); err != nil { // can't keep ownership: write in place
			return os.WriteFile(filename, data, perm)
		}
	}
	if err := tmpFile.Chmod(mode); err != nil {
		return fmt.Errorf("chmod error: %s", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		return err
	}
	renamed = true
	syncDir(filepath.Dir(filename))
	return nil
}

// syncDir makes sure the rename is persisted (best effort)
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

func (l *LocalStorage) AppendFile(name string, data []byte) error {
	fullPath, err := l.fullPath(name)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

func (l *LocalStorage) OpenFileForWriting(name string) (io.WriteCloser, error) {
	fullPath, err := l.fullPath(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Create(fullPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open file (%s): %s", name, err)
	}
	return file, nil
}

func (l *LocalStorage) OpenFileForAppending(name string) (io.WriteCloser, error) {
	fullPath, err := l.fullPath(name)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		return nil, err
	}
	return file, nil
}
