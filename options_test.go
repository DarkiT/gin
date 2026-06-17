package gin_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/cache"
	"github.com/darkit/gin/pkg/logger"
	"github.com/darkit/gin/pkg/mail"
	"github.com/darkit/gin/pkg/sms"
)

type testLogger struct{}

func (t testLogger) Debug(msg string, args ...any) {}
func (t testLogger) Info(msg string, args ...any)  {}
func (t testLogger) Warn(msg string, args ...any)  {}
func (t testLogger) Error(msg string, args ...any) {}
func (t testLogger) WithContext(ctx context.Context) logger.Logger {
	return t
}
func (t testLogger) WithFields(fields map[string]any) logger.Logger { return t }

func TestOptionsSetters(t *testing.T) {
	e := engine.New()
	engine.WithAddr(":9090")(e)
	if readConfig(e).Addr != ":9090" {
		t.Fatalf("addr not set")
	}
	engine.WithReadTimeout(3 * time.Second)(e)
	if readConfig(e).ReadTimeout != 3*time.Second {
		t.Fatalf("read timeout not set")
	}
	engine.WithWriteTimeout(4 * time.Second)(e)
	if readConfig(e).WriteTimeout != 4*time.Second {
		t.Fatalf("write timeout not set")
	}
	engine.WithGracefulShutdown(5 * time.Second)(e)
	_ = e // only verify not panic; state is not a timer
	engine.WithStartupTimeout(6 * time.Second)(e)
	if readStartupTimeout(e) != 6*time.Second {
		t.Fatalf("startup timeout not set")
	}
	l := testLogger{}
	engine.WithLogger(l)(e)
	if readLogger(e) == nil {
		t.Fatalf("logger not set")
	}
	c := cache.NewMemory()
	engine.WithCache(c)(e)
	if readCache(e) == nil {
		t.Fatalf("cache not set")
	}
	engine.WithMail(mail.MailConfig{Host: "smtp.example.com", Port: 587, From: "noreply@example.com"})(e)
	if readMailConfig(e).Host != "smtp.example.com" {
		t.Fatalf("mail config not set")
	}
}

func TestOptionPresets(t *testing.T) {
	e := engine.New()
	engine.Development()(e)
	if readConfig(e).ReadTimeout != 30*time.Second {
		t.Fatalf("development read timeout")
	}
	e = engine.New()
	engine.Production()(e)
	if readConfig(e).ReadTimeout != 10*time.Second {
		t.Fatalf("production read timeout")
	}
	if readConfig(e).WriteTimeout != 10*time.Second {
		t.Fatalf("production write timeout")
	}
}

func TestWithTrustedProxiesPanicOnInvalidConfig(t *testing.T) {
	e := engine.New()
	assertPanics(t, func() {
		engine.WithTrustedProxies([]string{"not-a-valid-proxy"})(e)
	})
}

func TestWithMailPanicOnInvalidConfig(t *testing.T) {
	e := engine.New()
	assertPanics(t, func() {
		engine.WithMail(mail.MailConfig{})(e)
	})
}

func TestWithSMSPanicOnInvalidConfig(t *testing.T) {
	e := engine.New()
	assertPanics(t, func() {
		engine.WithSMS(sms.SMSConfig{})(e)
	})
}

func TestWithSMSValidatesWithoutCreatingService(t *testing.T) {
	called := false
	sms.RegisterProvider("options-no-side-effect", func(cfg sms.SMSConfig) (sms.SMSProvider, error) {
		called = true
		return nil, errors.New("provider factory should not run during option apply")
	})

	e := engine.New()
	engine.WithSMS(sms.SMSConfig{
		Provider:  "options-no-side-effect",
		AccessKey: "key",
		SecretKey: "secret",
		SignName:  "sign",
	})(e)

	if called {
		t.Fatalf("WithSMS should validate config without creating provider")
	}
}

func TestWithSMSTencentRequiresAppID(t *testing.T) {
	e := engine.New()
	assertPanics(t, func() {
		engine.WithSMS(sms.SMSConfig{
			Provider:  "tencent",
			AccessKey: "key",
			SecretKey: "secret",
			SignName:  "sign",
		})(e)
	})
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic but none occurred")
		}
	}()
	fn()
}

func readConfig(e *engine.Engine) *engine.Config {
	field := reflect.ValueOf(e).Elem().FieldByName("config")
	return *(**engine.Config)(unsafe.Pointer(field.UnsafeAddr()))
}

func readLogger(e *engine.Engine) logger.Logger {
	field := reflect.ValueOf(e).Elem().FieldByName("logger")
	return *(*logger.Logger)(unsafe.Pointer(field.UnsafeAddr()))
}

func readCache(e *engine.Engine) cache.Cache {
	field := reflect.ValueOf(e).Elem().FieldByName("cache")
	return *(*cache.Cache)(unsafe.Pointer(field.UnsafeAddr()))
}

func readMailConfig(e *engine.Engine) mail.MailConfig {
	field := reflect.ValueOf(e).Elem().FieldByName("mailConfig")
	return *(*mail.MailConfig)(unsafe.Pointer(field.UnsafeAddr()))
}

func readStartupTimeout(e *engine.Engine) time.Duration {
	field := reflect.ValueOf(e).Elem().FieldByName("startupTimeout")
	return *(*time.Duration)(unsafe.Pointer(field.UnsafeAddr()))
}

func TestWithCachePanicsOnNil(t *testing.T) {
	e := engine.New()
	assertPanics(t, func() {
		engine.WithCache(nil)(e)
	})
	assertPanics(t, func() {
		e.WithCache(nil)
	})
}
