package logger

import (
	"context"
	"reflect"
	"testing"
)

type testLogger struct{}

func (t *testLogger) Debug(msg string, args ...any)          {}
func (t *testLogger) Info(msg string, args ...any)           {}
func (t *testLogger) Warn(msg string, args ...any)           {}
func (t *testLogger) Error(msg string, args ...any)          {}
func (t *testLogger) WithContext(ctx context.Context) Logger { return t }
func (t *testLogger) WithFields(fields map[string]any) Logger {
	return t
}

func TestLevelConstants(t *testing.T) {
	if LevelDebug != 0 || LevelInfo != 1 || LevelWarn != 2 || LevelError != 3 {
		t.Fatalf("level constants mismatch: %d %d %d %d", LevelDebug, LevelInfo, LevelWarn, LevelError)
	}
}

func TestLoggerInterfaceSignature(t *testing.T) {
	var _ Logger = (*testLogger)(nil)

	iface := reflect.TypeFor[Logger]()
	impl := reflect.TypeFor[*testLogger]()

	if !impl.Implements(iface) {
		t.Fatalf("testLogger should implement Logger")
	}
}
