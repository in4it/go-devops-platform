package localstorage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileNewFileMode(t *testing.T) {
	l, _ := newTestStorage(t)
	if err := l.WriteFile("new.json", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	info, err := os.Stat(filepath.Join(l.GetPath(), "new.json"))
	if err != nil {
		t.Fatalf("stat error: %s", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestWriteFileIsAtomic(t *testing.T) {
	l, _ := newTestStorage(t)
	filename := filepath.Join(l.GetPath(), "users.json")
	if err := l.WriteFile("users.json", []byte(`["old"]`)); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	// keep a handle to the old file: an in-place (truncating) write would modify its contents,
	// an atomic write (rename of a new file) keeps the old inode intact
	oldFile, err := os.Open(filename)
	if err != nil {
		t.Fatalf("open error: %s", err)
	}
	defer oldFile.Close()
	oldInfo, err := oldFile.Stat()
	if err != nil {
		t.Fatalf("stat error: %s", err)
	}

	if err := l.WriteFile("users.json", []byte(`["new"]`)); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	newInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("stat error: %s", err)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatalf("expected file to be replaced (written to a temp file and renamed), not written in place")
	}
	oldData := make([]byte, 64)
	n, _ := oldFile.ReadAt(oldData, 0)
	if string(oldData[:n]) != `["old"]` {
		t.Fatalf("old file contents were modified in place: %s", oldData[:n])
	}
	data, err := l.ReadFile("users.json")
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}
	if string(data) != `["new"]` {
		t.Fatalf("unexpected contents: %s", data)
	}
	// no temp files left behind
	files, err := l.ReadDir("")
	if err != nil {
		t.Fatalf("ReadDir error: %s", err)
	}
	for _, file := range files {
		if strings.Contains(file, ".tmp-") {
			t.Fatalf("temp file left behind: %s", file)
		}
	}
}

func TestWriteFileKeepsExistingMode(t *testing.T) {
	l, _ := newTestStorage(t)
	if err := l.WriteFile("client.conf", []byte("a")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	if err := l.EnsurePermissions("client.conf", 0640); err != nil {
		t.Fatalf("EnsurePermissions error: %s", err)
	}
	if err := l.WriteFile("client.conf", []byte("b")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	info, err := l.FileInfo("client.conf")
	if err != nil {
		t.Fatalf("FileInfo error: %s", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("expected existing mode 0640 to be kept, got %o", info.Mode().Perm())
	}
}

func TestWriteFileReadOnlyDirFallback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions are not enforced for root")
	}
	l, _ := newTestStorage(t)
	if err := l.EnsurePath("ro"); err != nil {
		t.Fatalf("EnsurePath error: %s", err)
	}
	if err := l.WriteFile("ro/file.txt", []byte("a")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	roDir := filepath.Join(l.GetPath(), "ro")
	if err := os.Chmod(roDir, 0500); err != nil {
		t.Fatalf("chmod error: %s", err)
	}
	t.Cleanup(func() { os.Chmod(roDir, 0700) })
	// the directory isn't writable, but the file is: like os.WriteFile, writing should still work
	if err := l.WriteFile("ro/file.txt", []byte("b")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	data, err := l.ReadFile("ro/file.txt")
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}
	if string(data) != "b" {
		t.Fatalf("unexpected contents: %s", data)
	}
}
