package v1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The API group is Hanzo's, and one version. A Hanzo cluster carrying a
// Lux-branded group violates the white-label rule, and a second version is the
// thing a migration exists to remove — so both are pinned here rather than left
// to whoever edits groupversion_info.go next.
func TestGroupIsHanzoAndSingleVersion(t *testing.T) {
	if GroupVersion.Group != "kms.hanzo.ai" {
		t.Errorf("group = %q, want kms.hanzo.ai", GroupVersion.Group)
	}
	if GroupVersion.Version != "v1" {
		t.Errorf("version = %q, want v1 — alpha is what the migration removed", GroupVersion.Version)
	}
}

// And nothing in the tree still names the old group. A rename that misses a
// manifest ships a CRD the operator has no RBAC for, which fails as "no
// permission" long after the commit that caused it.
func TestNoFileNamesTheOldGroup(t *testing.T) {
	root := filepath.Join("..", "..")
	var found []string
	err := filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
		if err != nil || i.IsDir() {
			if i != nil && i.IsDir() {
				for _, skip := range []string{".git", "vendor", "bin", "testbin"} {
					if i.Name() == skip {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		switch filepath.Ext(p) {
		case ".go", ".yaml", ".yml", ".md":
		default:
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		// Split so this file does not match its own check.
		if strings.Contains(string(b), "secrets.lux"+".network") {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Errorf("%d files still name the old group: %v", len(found), found[:min(5, len(found))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
