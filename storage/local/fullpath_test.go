package localstorage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStorage(t *testing.T) (*LocalStorage, string) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatalf("mkdir error: %s", err)
	}
	// a file outside of the storage path, that must not be reachable
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatalf("write error: %s", err)
	}
	l, err := NewWithPath(dataDir)
	if err != nil {
		t.Fatalf("NewWithPath error: %s", err)
	}
	return l, root
}

func TestFullPath(t *testing.T) {
	l := &LocalStorage{path: "/data/app"}
	valid := map[string]string{
		"config/users.json":             "/data/app/config/users.json",
		"./config/../config/users.json": "/data/app/config/users.json",
		"":                              "/data/app",
		"/data/app/config/users.json":   "/data/app/config/users.json", // already prefixed
		"/config/users.json":            "/data/app/config/users.json", // absolute names were always relative to the storage path
	}
	for name, expected := range valid {
		res, err := l.fullPath(name)
		if err != nil {
			t.Fatalf("%s: unexpected error: %s", name, err)
		}
		if res != expected {
			t.Fatalf("%s: expected %s, got %s", name, expected, res)
		}
	}
	invalid := []string{
		"../secret.txt",
		"config/../../secret.txt",
		"..",
		"/data/application/x",
	}
	for _, name := range invalid {
		res, err := l.fullPath(name)
		if name == "/data/application/x" { // not prefixed with the storage dir, so it's treated as relative
			if err != nil || res != "/data/app/data/application/x" {
				t.Fatalf("%s: unexpected result %s (err: %v)", name, res, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: expected error, got %s", name, res)
		}
	}
}

func TestPathTraversalRejected(t *testing.T) {
	l, root := newTestStorage(t)
	escape := "../secret.txt"

	if _, err := l.ReadFile(escape); err == nil {
		t.Fatalf("ReadFile: expected error")
	}
	if _, err := l.OpenFile(escape); err == nil {
		t.Fatalf("OpenFile: expected error")
	}
	if _, err := l.OpenFilesFromPos([]string{escape}, 0); err == nil {
		t.Fatalf("OpenFilesFromPos: expected error")
	}
	if l.FileExists(escape) {
		t.Fatalf("FileExists: expected false")
	}
	if _, err := l.FileInfo(escape); err == nil {
		t.Fatalf("FileInfo: expected error")
	}
	if _, err := l.ReadDir(".."); err == nil {
		t.Fatalf("ReadDir: expected error")
	}
	if err := l.WriteFile(escape, []byte("overwritten")); err == nil {
		t.Fatalf("WriteFile: expected error")
	}
	if err := l.AppendFile(escape, []byte("appended")); err == nil {
		t.Fatalf("AppendFile: expected error")
	}
	if _, err := l.OpenFileForWriting(escape); err == nil {
		t.Fatalf("OpenFileForWriting: expected error")
	}
	if _, err := l.OpenFileForAppending(escape); err == nil {
		t.Fatalf("OpenFileForAppending: expected error")
	}
	if err := l.EnsurePermissions(escape, 0644); err == nil {
		t.Fatalf("EnsurePermissions: expected error")
	}
	if err := l.EnsureOwnership(escape, "vpn"); err == nil {
		t.Fatalf("EnsureOwnership: expected error")
	}
	if err := l.EnsurePath("../newdir"); err == nil {
		t.Fatalf("EnsurePath: expected error")
	}
	if err := l.Rename(escape, "stolen.txt"); err == nil {
		t.Fatalf("Rename: expected error")
	}
	if err := l.WriteFile("x.txt", []byte("x")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	if err := l.Rename("x.txt", "../x.txt"); err == nil {
		t.Fatalf("Rename: expected error")
	}
	if err := l.Remove(escape); err == nil {
		t.Fatalf("Remove: expected error")
	}

	data, err := os.ReadFile(filepath.Join(root, "secret.txt"))
	if err != nil {
		t.Fatalf("secret file should still exist: %s", err)
	}
	if string(data) != "secret" {
		t.Fatalf("secret file was modified: %s", data)
	}
	if _, err := os.Stat(filepath.Join(root, "newdir")); err == nil {
		t.Fatalf("directory outside of storage path was created")
	}
	if _, err := os.Stat(filepath.Join(root, "x.txt")); err == nil {
		t.Fatalf("file was moved outside of storage path")
	}
}

func TestRelativeAndPrefixedPaths(t *testing.T) {
	l, _ := newTestStorage(t)
	if err := l.EnsurePath(CONFIG_PATH); err != nil {
		t.Fatalf("EnsurePath error: %s", err)
	}
	relative := l.ConfigPath("test.json")
	prefixed := filepath.Join(l.GetPath(), relative)

	if err := l.WriteFile(relative, []byte("one")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	for _, name := range []string{relative, prefixed} {
		data, err := l.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %s", name, err)
		}
		if string(data) != "one" {
			t.Fatalf("ReadFile(%s): unexpected data: %s", name, data)
		}
		if !l.FileExists(name) {
			t.Fatalf("FileExists(%s): expected true", name)
		}
	}
	if err := l.AppendFile(prefixed, []byte("two")); err != nil {
		t.Fatalf("AppendFile error: %s", err)
	}
	data, err := os.ReadFile(prefixed)
	if err != nil {
		t.Fatalf("read error: %s", err)
	}
	if string(data) != "onetwo" {
		t.Fatalf("unexpected data: %s", data)
	}
	files, err := l.ReadDir(CONFIG_PATH)
	if err != nil {
		t.Fatalf("ReadDir error: %s", err)
	}
	if len(files) != 1 || files[0] != "test.json" {
		t.Fatalf("unexpected dir contents: %s", strings.Join(files, ","))
	}
}

func TestFileInfoRelativeToStoragePath(t *testing.T) {
	l, _ := newTestStorage(t)
	if err := l.WriteFile("info.txt", []byte("12345")); err != nil {
		t.Fatalf("WriteFile error: %s", err)
	}
	// make sure the file doesn't exist relative to the working directory
	if _, err := os.Stat("info.txt"); err == nil {
		t.Skip("info.txt exists in working directory")
	}
	info, err := l.FileInfo("info.txt")
	if err != nil {
		t.Fatalf("FileInfo error: %s", err)
	}
	if info.Size() != 5 {
		t.Fatalf("unexpected size: %d", info.Size())
	}
}
