package gin

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
)

// Logger 定义统一的日志接口
type Logger interface {
	// Debug 记录调试信息
	Debug(format string, args ...any)

	// Info 记录信息日志
	Info(format string, args ...any)

	// Warn 记录警告日志
	Warn(format string, args ...any)

	// Error 记录错误日志
	Error(format string, args ...any)
}

// DefaultLogger 基于 log/slog 的默认日志实现
type DefaultLogger struct {
	logger *slog.Logger
	prefix string
}

// NewDefaultLogger 创建默认日志实例
func NewDefaultLogger(prefix string) *DefaultLogger {
	return &DefaultLogger{
		logger: slog.Default(),
		prefix: prefix,
	}
}

// Debug 记录调试信息（仅在调试模式下输出）
func (l *DefaultLogger) Debug(format string, args ...any) {
	if gin.Mode() == gin.DebugMode {
		message := fmt.Sprintf(format, args...)
		l.logger.Debug(fmt.Sprintf("[%s] DEBUG: %s", l.prefix, message))
	}
}

// Info 记录信息日志（仅在调试模式下输出）
func (l *DefaultLogger) Info(format string, args ...any) {
	if gin.Mode() == gin.DebugMode {
		message := fmt.Sprintf(format, args...)
		l.logger.Info(fmt.Sprintf("[%s] INFO: %s", l.prefix, message))
	}
}

// Warn 记录警告日志（在所有模式下输出）
func (l *DefaultLogger) Warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	l.logger.Warn(fmt.Sprintf("[%s] WARN: %s", l.prefix, message))
}

// Error 记录错误日志（在所有模式下输出）
func (l *DefaultLogger) Error(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	l.logger.Error(fmt.Sprintf("[%s] ERROR: %s", l.prefix, message))
}

// GinCompatLogger Gin兼容的日志实现，将日志输出到gin的标准输出
type GinCompatLogger struct {
	prefix string
}

func safeWriteLine(writer io.Writer, fallback io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(writer, format, args...); err != nil && fallback != nil {
		_, _ = fmt.Fprintf(fallback, "logger write error: %v\n", err)
	}
}

// NewGinCompatLogger 创建Gin兼容的日志实例
func NewGinCompatLogger(prefix string) *GinCompatLogger {
	return &GinCompatLogger{
		prefix: prefix,
	}
}

// Debug 记录调试信息（仅在调试模式下输出）
func (l *GinCompatLogger) Debug(format string, args ...any) {
	if gin.Mode() == gin.DebugMode {
		safeWriteLine(gin.DefaultWriter, gin.DefaultErrorWriter, "[%s] DEBUG: "+format+"\n", append([]any{l.prefix}, args...)...)
	}
}

// Info 记录信息日志（仅在调试模式下输出）
func (l *GinCompatLogger) Info(format string, args ...any) {
	if gin.Mode() == gin.DebugMode {
		safeWriteLine(gin.DefaultWriter, gin.DefaultErrorWriter, "[%s] INFO: "+format+"\n", append([]any{l.prefix}, args...)...)
	}
}

// Warn 记录警告日志（在所有模式下输出）
func (l *GinCompatLogger) Warn(format string, args ...any) {
	safeWriteLine(gin.DefaultWriter, gin.DefaultErrorWriter, "[%s] WARN: "+format+"\n", append([]any{l.prefix}, args...)...)
}

// Error 记录错误日志（在所有模式下输出）
func (l *GinCompatLogger) Error(format string, args ...any) {
	safeWriteLine(gin.DefaultErrorWriter, os.Stderr, "[%s] ERROR: "+format+"\n", append([]any{l.prefix}, args...)...)
}

// LoggerConfig 日志配置
type LoggerConfig struct {
	// UseDefaultLogger 是否使用默认的 slog 实现
	UseDefaultLogger bool

	// CustomLogger 自定义日志实现
	CustomLogger Logger
}

// DefaultLoggerConfig 返回默认日志配置
func DefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		UseDefaultLogger: false, // 默认使用Gin兼容的日志输出
		CustomLogger:     nil,
	}
}

// GetLogger 获取日志实例
func (config *LoggerConfig) GetLogger(prefix string) Logger {
	// 如果设置了自定义日志，优先使用
	if config.CustomLogger != nil {
		return config.CustomLogger
	}

	// 根据配置选择默认实现
	if config.UseDefaultLogger {
		return NewDefaultLogger(prefix)
	}

	// 默认使用Gin兼容的日志
	return NewGinCompatLogger(prefix)
}

// NoOpLogger 空操作日志实现（用于禁用日志）
type NoOpLogger struct{}

// NewNoOpLogger 创建空操作日志实例
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Debug 空操作
func (l *NoOpLogger) Debug(format string, args ...any) {}

// Info 空操作
func (l *NoOpLogger) Info(format string, args ...any) {}

// Warn 空操作
func (l *NoOpLogger) Warn(format string, args ...any) {}

// Error 空操作
func (l *NoOpLogger) Error(format string, args ...any) {}

// FileLogger 文件日志实现
type FileLogger struct {
	*DefaultLogger
	file *os.File
}

// NewFileLogger 创建文件日志实例
func NewFileLogger(prefix, filename string) (*FileLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return nil, fmt.Errorf("无法创建日志文件 %s: %v", filename, err)
	}

	logger := slog.New(slog.NewTextHandler(file, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	return &FileLogger{
		DefaultLogger: &DefaultLogger{
			logger: logger,
			prefix: prefix,
		},
		file: file,
	}, nil
}

// Close 关闭文件日志
func (l *FileLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
