package gin_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/mail"
)

func TestSendMail_Basic(t *testing.T) {
	cfg := mail.MailConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}
	if err := mail.InitDefaultMailer(cfg); err != nil {
		t.Fatalf("init mailer: %v", err)
	}
	if err := engine.SendMail("to@example.com", "标题", "内容"); err == nil {
		t.Fatalf("expected send error")
	}
}

func TestSendMailHTML(t *testing.T) {
	cfg := mail.MailConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}
	if err := mail.InitDefaultMailer(cfg); err != nil {
		t.Fatalf("init mailer: %v", err)
	}
	if err := engine.SendMailHTML("to@example.com", "标题", "<h1>内容</h1>"); err == nil {
		t.Fatalf("expected send error")
	}
}

func TestSendTemplate(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, "mail", "templates")
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

	if _, err := mail.RenderTemplate("welcome.html", map[string]any{"Name": "张三"}); err != nil {
		t.Fatalf("render template: %v", err)
	}
}

func TestSendMail_WithAttachment(t *testing.T) {
	cfg := mail.MailConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}
	if err := mail.InitDefaultMailer(cfg); err != nil {
		t.Fatalf("init mailer: %v", err)
	}

	attachment := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(attachment, []byte("report"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}
	if err := engine.SendMail("to@example.com", "标题", "内容", mail.WithMailAttachment(attachment)); err == nil {
		t.Fatalf("expected send error")
	}
}

func TestSendBatch(t *testing.T) {
	cfg := mail.MailConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}
	if err := mail.InitDefaultMailer(cfg); err != nil {
		t.Fatalf("init mailer: %v", err)
	}
	if _, err := engine.SendBatch([]string{"a@example.com", "b@example.com"}, "标题", "内容"); err == nil {
		t.Fatalf("expected send error")
	}
	if _, err := engine.SendBatch(nil, "标题", "内容"); !errors.Is(err, mail.ErrMailToMissing) {
		t.Fatalf("expected empty recipients error")
	}
}

func TestSendMail_TLS(t *testing.T) {
	cfg := mail.MailConfig{
		Host: "smtp.example.com",
		Port: 465,
		From: "noreply@example.com",
		TLS:  true,
	}
	if err := mail.InitDefaultMailer(cfg); err != nil {
		t.Fatalf("init mailer: %v", err)
	}
	if err := engine.SendMail("to@example.com", "标题", "内容"); err == nil {
		t.Fatalf("expected send error")
	}
}
