# pkg/diagnostic

`pkg/diagnostic` 提供诊断辅助工具，用于检查和展示 Engine 的运行状态。

## 模块用途

- 获取服务运行状态
- 检查内存使用情况
- 列出所有注册的路由
- 提供运行时诊断信息

## 关键类型与函数

### Inspector

```go
inspector := diagnostic.NewInspector(e)
```

### 方法

| 方法 | 说明 |
|------|------|
| `GetStatus() *Status` | 获取完整状态信息 |
| `PrintRoutes()` | 打印所有路由到标准输出 |
| `Handler() engine.HandlerFunc` | 获取 HTTP 处理器 |

### Status 结构

```go
type Status struct {
    Uptime       string       // 运行时间
    Version      string       // Gin 版本
    GoVersion    string       // Go 版本
    NumGoroutine int          // Goroutine 数量
    Memory       *MemoryStats // 内存统计
    Routes       *RoutesInfo  // 路由信息
}
```

### MemoryStats 结构

```go
type MemoryStats struct {
    Alloc      uint64 // 当前分配字节数
    TotalAlloc uint64 // 累计分配字节数
    Sys        uint64 // 系统内存占用
    NumGC      uint32 // GC 次数
}
```

### RoutesInfo 结构

```go
type RoutesInfo struct {
    Count int      // 路由数量
    Items []string // 路由列表 (格式: "METHOD /path")
}
```

## 使用示例

### 基本用法

```go
package main

import (
	"fmt"

	gin "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/diagnostic"
)

func main() {
	app := gin.Default()

	r := app.Router()
	r.GET("/hello", func(c *gin.Context) {
		c.Success(gin.H{"message": "hello"})
	})

	// 创建诊断检查器
	inspector := diagnostic.NewInspector(app)

	// 获取状态
	status := inspector.GetStatus()
	fmt.Printf("Uptime: %s\n", status.Uptime)
	fmt.Printf("Go Version: %s\n", status.GoVersion)
	fmt.Printf("Goroutines: %d\n", status.NumGoroutine)
	fmt.Printf("Memory: Alloc=%d, Sys=%d\n", status.Memory.Alloc, status.Memory.Sys)
	fmt.Printf("Routes: %d\n", status.Routes.Count)
	for _, route := range status.Routes.Items {
		fmt.Println("  ", route)
	}
}
```

### 注册诊断路由

```go
app := gin.Default()

inspector := diagnostic.NewInspector(app)

// 注册诊断端点
r := app.Router()
r.GET("/diagnostic/status", inspector.Handler())
```

### 打印路由列表

```go
inspector := diagnostic.NewInspector(app)
inspector.PrintRoutes()
```

输出示例：

```
GET /hello
POST /users
GET /users/:id
PUT /users/:id
DELETE /users/:id
```

## 与 Engine 的集成

诊断包直接使用 `*engine.Engine` 获取路由信息：

```go
// 获取 Gin 路由信息
routes := engine.Routes()

for _, route := range routes {
    fmt.Printf("%s %s -> %s\n", route.Method, route.Path, route.Handler)
}
```

## 应用场景

1. **健康检查端点**：提供 `/diagnostic/status` 端点供监控或负载均衡器检查
2. **调试模式**：在开发环境打印路由列表帮助调试
3. **运维监控**：定期采集 goroutine 数量和内存使用情况
4. **服务自检**：在关闭前检查服务状态确保没有异常
