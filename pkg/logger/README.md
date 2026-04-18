# pkg/logger

`pkg/logger` 定义框架依赖的最小日志接口，并提供空实现。

## 模块用途

- 为框架与业务层提供统一日志抽象。
- 避免强绑定具体日志库。
- 默认使用 `noop` 实现，保证未配置日志器时不报错。

## 关键类型与函数

- `type Level`
  - `LevelDebug`
  - `LevelInfo`
  - `LevelWarn`
  - `LevelError`
- `type Logger interface`
  - `Debug`
  - `Info`
  - `Warn`
  - `Error`
  - `WithContext(ctx)`
  - `WithFields(fields)`
- `NewNoop() Logger`
  - 返回空日志器，所有调用都会被忽略

## 配置项

本模块没有独立配置结构；通常由业务侧实现自己的 `Logger` 并注入。

## 使用示例

### 使用默认空实现

```go
log := logger.NewNoop()
log.Info("service started")
```

### 自定义实现

```go
type MyLogger struct{}

func (l *MyLogger) Debug(msg string, args ...any) {}
func (l *MyLogger) Info(msg string, args ...any) {}
func (l *MyLogger) Warn(msg string, args ...any) {}
func (l *MyLogger) Error(msg string, args ...any) {}
func (l *MyLogger) WithContext(ctx context.Context) logger.Logger { return l }
func (l *MyLogger) WithFields(fields map[string]any) logger.Logger { return l }
```

## 与 Engine 的集成

- `gin.New()` 默认注入 `logger.NewNoop()`。
- 可通过 `e.WithLogger(customLogger)` 替换为业务日志实现。

```go
e := gin.New()
e.WithLogger(&MyLogger{})
```
