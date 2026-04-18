package logger

import "context"

type noopLogger struct{}

func NewNoop() Logger {
	return &noopLogger{}
}

func (n *noopLogger) Debug(msg string, args ...any)          {}
func (n *noopLogger) Info(msg string, args ...any)           {}
func (n *noopLogger) Warn(msg string, args ...any)           {}
func (n *noopLogger) Error(msg string, args ...any)          {}
func (n *noopLogger) WithContext(ctx context.Context) Logger { return n }
func (n *noopLogger) WithFields(fields map[string]any) Logger {
	return n
}
