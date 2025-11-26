# 基于Context的优雅停机设计

## 概述

我们改进了Gin框架的优雅停机机制，采用基于Go Context的设计模式，实现了更加灵活、统一且可测试的停机控制方案。

## 设计原理

### 传统问题
之前的优雅停机存在以下问题：
- 超时时间过短（5秒）
- SSE长连接未正确关闭
- 后台goroutine无法感知停机信号
- 资源清理不完整
- 不易测试和控制

### 新设计优势
1. **统一的上下文管理** - 通过Context统一控制所有组件生命周期
2. **灵活的触发方式** - 支持信号、API、定时器等多种停机方式
3. **完整的资源清理** - 确保所有资源被正确释放
4. **更好的可测试性** - 可以通过注入不同Context来测试
5. **更长的超时时间** - 默认30秒，给复杂应用足够的清理时间

## API设计

### 核心方法

#### 1. RunWithGracefulShutdown
```go
func (r *Router) RunWithGracefulShutdown(config ServerConfig) error
```
- 使用 `signal.NotifyContext` 监听系统信号
- 适合传统的服务器部署场景
- 自动处理 SIGINT/SIGTERM 信号

#### 2. RunWithContext
```go
func (r *Router) RunWithContext(ctx context.Context, config ServerConfig) error
```
- 接受任意Context，提供最大灵活性
- 当Context被取消时触发优雅停机
- 支持各种自定义停机策略

#### 3. RunWithContextSimple
```go
func (r *Router) RunWithContextSimple(ctx context.Context, addr ...string) error
```
- 简化版本，使用默认配置
- 适合快速原型和测试

## 使用场景

### 1. 传统信号控制（推荐）
```go
r := gin.Default()
// 自动监听SIGINT/SIGTERM信号
if err := r.Run(":8080"); err != nil {
    log.Fatal(err)
}
```

### 2. API控制停机
```go
appCtx, appCancel := context.WithCancel(context.Background())

r := gin.Default()
r.GET("/shutdown", func(c *gin.Context) {
    c.JSON(200, gin.H{"msg": "正在关闭..."})
    go func() {
        time.Sleep(100 * time.Millisecond)
        appCancel() // 触发停机
    }()
})

// 使用应用上下文启动
serverConfig := gin.DefaultServerConfig()
if err := r.RunWithContext(appCtx, serverConfig); err != nil {
    log.Fatal(err)
}
```

### 3. 定时自动停机
```go
// 30秒后自动停机
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

r := gin.Default()
if err := r.RunWithContext(ctx, gin.DefaultServerConfig()); err != nil {
    log.Fatal(err)
}
```

### 4. 测试场景
```go
func TestServer(t *testing.T) {
    testCtx, testCancel := context.WithCancel(context.Background())
    
    r := gin.Default()
    
    // 3秒后自动停机
    go func() {
        time.Sleep(3 * time.Second)
        testCancel()
    }()
    
    err := r.RunWithContext(testCtx, gin.DefaultServerConfig())
    assert.Equal(t, http.ErrServerClosed, err)
}
```

### 5. 混合控制（信号+API）
```go
// 创建信号上下文
signalCtx, signalStop := signal.NotifyContext(context.Background(), 
    syscall.SIGINT, syscall.SIGTERM)
defer signalStop()

// 创建应用上下文
appCtx, appCancel := context.WithCancel(context.Background())

// 创建组合上下文
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// 监听任一停机信号
go func() {
    select {
    case <-signalCtx.Done():
        fmt.Println("收到系统信号")
        cancel()
    case <-appCtx.Done():
        fmt.Println("收到API信号")
        cancel()
    }
}()

r := gin.Default()
r.GET("/shutdown", func(c *gin.Context) {
    appCancel() // 触发API停机
})

if err := r.RunWithContext(ctx, gin.DefaultServerConfig()); err != nil {
    log.Fatal(err)
}
```

## 后台任务管理

### Context传播模式
```go
func main() {
    // 创建应用级上下文
    appCtx, appCancel := context.WithCancel(context.Background())
    
    // 启动后台任务
    go backgroundTask(appCtx, "数据处理任务")
    go backgroundTask(appCtx, "日志清理任务")
    
    // 启动服务器
    r := gin.Default()
    if err := r.RunWithContext(appCtx, gin.DefaultServerConfig()); err != nil {
        log.Fatal(err)
    }
    
    // 清理资源
    appCancel()
    time.Sleep(1 * time.Second) // 等待goroutine退出
}

func backgroundTask(ctx context.Context, name string) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            fmt.Printf("[%s] 执行中...\n", name)
        case <-ctx.Done():
            fmt.Printf("[%s] 收到停机信号，正在退出...\n", name)
            return
        }
    }
}
```

## 配置选项

### ServerConfig
```go
type ServerConfig struct {
    Host            string        // 主机地址
    Port            string        // 端口
    ReadTimeout     time.Duration // 读取超时
    WriteTimeout    time.Duration // 写入超时
    MaxHeaderBytes  int           // 最大头部字节
    CertFile        string        // TLS证书文件
    KeyFile         string        // TLS密钥文件
    EnableHTTP2     bool          // 启用HTTP/2
    GracefulTimeout time.Duration // 优雅关闭超时（默认30秒）
}
```

### 推荐配置
```go
config := gin.DefaultServerConfig()
config.GracefulTimeout = 60 * time.Second  // 对于复杂应用
config.Port = "8080"

// 对于生产环境
config.ReadTimeout = 30 * time.Second
config.WriteTimeout = 30 * time.Second
```

## 优雅停机流程

### 停机顺序
1. **收到停机信号** - Context被取消
2. **关闭Router资源** - 调用 `r.Close()`
   - 关闭SSE Hub
   - 关闭缓存
   - 清理路由组
3. **停止HTTP服务器** - 调用 `server.Shutdown()`
   - 停止接受新连接
   - 等待现有请求完成
4. **通知后台任务** - 通过Context传播停机信号
5. **等待资源清理** - 所有goroutine正确退出

### 错误处理
```go
if err := server.Shutdown(shutdownCtx); err != nil {
    if err == context.DeadlineExceeded {
        log.Println("优雅停机超时，强制关闭")
    } else {
        log.Printf("停机过程出错: %v", err)
    }
}
```

## 最佳实践

### 1. 统一Context管理
```go
// 推荐：创建应用级Context
appCtx, appCancel := context.WithCancel(context.Background())

// 所有后台任务都使用这个Context
go task1(appCtx)
go task2(appCtx)
go task3(appCtx)

// 服务器也使用这个Context
r.RunWithContext(appCtx, config)
```

### 2. 合理设置超时时间
```go
config := gin.DefaultServerConfig()

// 根据应用复杂度调整
if hasLongRunningTasks() {
    config.GracefulTimeout = 60 * time.Second
} else {
    config.GracefulTimeout = 10 * time.Second
}
```

### 3. 添加停机日志
```go
go func() {
    <-ctx.Done()
    log.Println("收到停机信号，开始清理资源...")
    
    // 清理逻辑
    cleanup()
    
    log.Println("资源清理完成")
}()
```

### 4. 测试友好的设计
```go
func NewTestServer() (*gin.Router, context.CancelFunc) {
    ctx, cancel := context.WithCancel(context.Background())
    r := gin.Default()
    
    go func() {
        r.RunWithContext(ctx, gin.DefaultServerConfig())
    }()
    
    return r, cancel
}

func TestServerShutdown(t *testing.T) {
    r, cancel := NewTestServer()
    defer cancel()
    
    // 测试逻辑...
    
    cancel() // 触发停机
}
```

## 性能考量

### 内存使用
- Context树结构轻量级
- 取消信号传播高效
- 无额外goroutine开销

### 停机速度
- 并行关闭所有资源
- 避免顺序等待导致的延迟
- 合理的超时设置平衡安全性和响应速度

## 总结

基于Context的优雅停机设计提供了：
- ✅ **灵活性** - 支持多种停机触发方式
- ✅ **可靠性** - 确保资源完整清理
- ✅ **可测试性** - 易于编写单元测试
- ✅ **可维护性** - 清晰的代码结构和职责分离
- ✅ **生产就绪** - 经过充分测试的实现

这种设计模式已经成为Go语言中处理优雅停机的标准做法，值得在所有Go web应用中采用。 