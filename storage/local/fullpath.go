package localstorage

import (
	"fmt"
	"path/filepath"
	"strings"
)

// fullPath returns the cleaned, absolute (storage path prefixed) path for name, and returns an error
// when the result would be outside of the storage path (e.g. by using ../).
// Names are relative to the storage path. For backwards compatibility, a name that is an absolute path which
// already starts with the storage path is also accepted.
func (l *LocalStorage) fullPath(name string) (string, error) {
	base := filepath.Clean(l.path)
	var full string
	if filepath.IsAbs(name) && isSubPath(base, filepath.Clean(name)) {
		full = filepath.Clean(name)
	} else {
		full = filepath.Join(base, name)
	}
	if !isSubPath(base, full) {
		return "", fmt.Errorf("path %s is outside of the storage path", name)
	}
	return full, nil
}

// isSubPath returns true if p equals base or is located under base. Both paths need to be cleaned.
func isSubPath(base, p string) bool {
	if p == base {
		return true
	}
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
