# pkg/lifecycle

`pkg/lifecycle` 管理 HTTP 服务的启动、优雅关闭与生命周期回调。

## 模块用途

- 为 `http.Server` 提供统一的启动/停机状态机。
- 处理 `SIGINT` / `SIGTERM` / `SIGQUIT`。
- 支持启动前、关闭中、停止后回调。

## 关键类型与函数

- `type State`
  - `StateInit`
  - `StateStarting`
  - `StateRunning`
  - `StateShuttingDown`
  - `StateStopped`
- `type Hook func(ctx context.Context) error`
- `type Manager`
  - `NewManager()`
  - `SetShutdownTimeout(d)`
  - `OnStart(hooks...)`
  - `OnShutdown(hooks...)`
  - `OnStopped(hooks...)`
  - `Run(server, handler)`
  - `Shutdown(ctx)`
  - `State()`
  - `Wait()`

## 配置项

- 默认优雅关闭超时：`30s`
- `SetShutdownTimeout(d)`：修改停机超时
- `Run(server, handler)`：可传入自定义 `http.Handler` 覆盖 `server.Handler`
- `Shutdown(ctx)`：触发优雅关闭，并解阻塞正在等待退出的 `Run(server, handler)`；若关闭失败，错误由 `Shutdown(ctx)` 返回

## 使用示例

```go
mgr := lifecycle.NewManager()
mgr.SetShutdownTimeout(10 * time.Second)

mgr.OnStart(func(ctx context.Context) error {
    return nil
})
mgr.OnShutdown(func(ctx context.Context) error {
    return db.Close()
})

server := &http.Server{Addr: ":8080", Handler: mux}
if err := mgr.Run(server, nil); err != nil {
    panic(err)
}
```

## 与 Engine 的集成

- `gin.New()` 默认创建一个 `lifecycle.Manager`。
- `Engine.Run()` 内部委托给 `lifecycle.Manager.Run()`。
- `Engine.Shutdown(ctx)` 内部委托给 `lifecycle.Manager.Shutdown(ctx)`。
- `Engine.OnStart()` / `Engine.OnShutdown()` / `Engine.OnStopped()` 用于透传注册生命周期回调。

因此大多数应用无需直接操作该包，除非要自定义独立服务生命周期。
