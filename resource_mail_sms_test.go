package gin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/mail"
	"github.com/darkit/gin/pkg/sms"
	_ "github.com/darkit/gin/pkg/sms/providers"
)

func TestEngineMailerRuntimePath(t *testing.T) {
	e := engine.New(
		engine.WithMail(mail.MailConfig{
			Host: "smtp.example.com",
			Port: 587,
			From: "noreply@example.com",
		}),
	)

	if _, err := e.Mailer(); !errors.Is(err, mail.ErrMailConfigMissing) {
		t.Fatalf("expected mailer unavailable before runtime ready, got %v", err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.TODO()) })

	e.GET("/send-mail", func(c *engine.Context) {
		if err := e.SendMail("to@example.com", "标题", "内容"); err == nil {
			c.InternalError("expected send error")
			return
		}
		c.Success(engine.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/send-mail", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestContextMailerAccessor(t *testing.T) {
	e := engine.New(
		engine.WithMail(mail.MailConfig{
			Host: "smtp.example.com",
			Port: 587,
			From: "noreply@example.com",
		}),
	)

	e.GET("/mail", func(c *engine.Context) {
		mailer, err := c.Mailer()
		if err != nil {
			c.InternalError(err.Error())
			return
		}
		if err := mailer.SendMail("to@example.com", "标题", "内容"); err == nil {
			c.InternalError("expected error")
			return
		}
		c.Success(engine.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mail", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestEngineSMSEngineScopedService(t *testing.T) {
	e := engine.New(
		engine.WithSMS(sms.SMSConfig{
			Provider:  "aliyun",
			AccessKey: "key",
			SecretKey: "secret",
			SignName:  "sign",
			Region:    "cn-hangzhou",
		}),
	)

	if _, err := e.SMS(); !errors.Is(err, sms.ErrSMSNotInitialized) {
		t.Fatalf("expected sms unavailable before runtime ready, got %v", err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.TODO()) })
	e.GET("/sms-code", func(c *engine.Context) {
		service, err := e.SMS()
		if err != nil {
			c.InternalError(err.Error())
			return
		}
		code, err := service.SendCode("13800138000")
		if err != nil {
			c.InternalError(err.Error())
			return
		}
		if code == "" || !service.VerifyCode("13800138000", code) {
			c.InternalError("expected verify success")
			return
		}
		c.Success(engine.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sms-code", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestEngineSendBatchAttachmentPath(t *testing.T) {
	e := engine.New(
		engine.WithMail(mail.MailConfig{
			Host: "smtp.example.com",
			Port: 587,
			From: "noreply@example.com",
		}),
	)
	t.Cleanup(func() { _ = e.Shutdown(context.TODO()) })

	attachment := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(attachment, []byte("report"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}
	e.GET("/batch", func(c *engine.Context) {
		if err := e.SendMail("to@example.com", "标题", "内容", mail.WithMailAttachment(attachment)); err == nil {
			c.InternalError("expected send error")
			return
		}
		if _, err := e.SendBatch(nil, "标题", "内容"); !errors.Is(err, mail.ErrMailToMissing) {
			c.InternalError("expected empty recipients error")
			return
		}
		c.Success(engine.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/batch", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
}
