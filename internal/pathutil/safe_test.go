package pathutil

import (
	"path/filepath"
	"testing"
)

func TestSafePathNormal(t *testing.T) {
	base := filepath.Join("/", "base", "dir")
	full, err := SafePath(base, "images/photo.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(base, "images", "photo.png")
	if full != want {
		t.Fatalf("unexpected path: %s", full)
	}
}

func TestSafePathTraversal(t *testing.T) {
	base := filepath.Join("/", "base", "dir")
	cases := []string{
		"../secret.txt",
		"..\\secret.txt",
		"a/../b.txt",
		"a\\..\\b.txt",
		"/etc/passwd",
		"\\\\Windows\\system.ini",
		"",
		".",
	}

	for _, c := range cases {
		if _, err := SafePath(base, c); err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func TestSafePathEdge(t *testing.T) {
	base := filepath.Join("/", "base", "dir")
	full, err := SafePath(base, "a/./b/c.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(base, "a", "b", "c.txt")
	if full != want {
		t.Fatalf("unexpected path: %s", full)
	}
}

func TestSafeTemplateName(t *testing.T) {
	ok := []string{"welcome", "invoice_v2", "report-2024"}
	for _, name := range ok {
		if err := SafeTemplateName(name); err != nil {
			t.Fatalf("unexpected error for %q: %v", name, err)
		}
	}

	bad := []string{"", " ", "../a", "..\\a", "a/b", "a\\b", ".."}
	for _, name := range bad {
		if err := SafeTemplateName(name); err == nil {
			t.Fatalf("expected error for %q", name)
		}
	}
}
