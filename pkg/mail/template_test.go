package mail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderTemplate_Normal(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, defaultTemplateDir)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}
	templatePath := filepath.Join(templateDir, "welcome.html")
	if err := os.WriteFile(templatePath, []byte("<h1>{{.Name}}</h1>"), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(old)
	})

	out, err := RenderTemplate("welcome.html", map[string]any{"Name": "张三"})
	if err != nil {
		t.Fatalf("render template: %v", err)
	}
	if !strings.Contains(out, "张三") {
		t.Fatalf("expected rendered content, got: %q", out)
	}
}

func TestRenderTemplate_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, defaultTemplateDir)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(old)
	})

	if _, err := RenderTemplate("../secrets.html", map[string]any{}); err == nil {
		t.Fatalf("expected traversal error")
	} else if !strings.Contains(err.Error(), "模板名称非法") {
		t.Fatalf("unexpected error: %v", err)
	}
}
