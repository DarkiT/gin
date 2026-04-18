package logger

import (
	"context"
	"testing"
)

func TestNewNoop(t *testing.T) {
	l := NewNoop()
	if l == nil {
		t.Fatalf("NewNoop returned nil")
	}
}

func TestNoopMethodsNoPanic(t *testing.T) {
	l := NewNoop()
	l.Debug("debug")
	l.Info("info")
	l.Warn("warn")
	l.Error("error")
}

func TestNoopWithContextAndFields(t *testing.T) {
	l := NewNoop()
	if l.WithContext(context.TODO()) != l {
		t.Fatalf("WithContext should return same instance")
	}
	if l.WithFields(map[string]any{"k": "v"}) != l {
		t.Fatalf("WithFields should return same instance")
	}
}
