package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"time"

	"github.com/darkit/gin"
)

//go:embed sse.html
var content embed.FS

// 定义全局 SSE Hub
var hub *gin.SSEHub

// Message 定义消息结构体
type Message struct {
	Event   string `json:"event"`   // 事件类型
	Message string `json:"message"` // 消息内容
}

// BroadcastRequest 定义广播消息请求结构体
type BroadcastRequest struct {
	Event   string `json:"event"`   // 事件类型
	Message string `json:"message"` // 消息内容
}

// SendMessageRequest 定义发送消息请求结构体
type SendMessageRequest struct {
	Message string `json:"message"` // 消息内容
}

func main() {
	// 创建路由
	r := gin.Default()

	// 创建 SSE Hub，设置历史记录大小为 20
	hub = r.NewSSEHub(20)
	go hub.Run() // 启动 Hub

	// 注册路由
	setupRoutes(r)

	// 启动服务器
	log.Println("服务器启动在 http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

// setupRoutes 设置路由
func setupRoutes(r *gin.Router) {
	// 静态页面路由
	r.GET("/", handleIndex)

	// SSE 相关路由
	r.GET("/events", handleSSE)                   // SSE 连接
	r.GET("/clients", handleListClients)          // 获取客户端列表
	r.GET("/status", handleHubStatus)             // 获取 Hub 状态
	r.GET("/close", handleCloseHub)               // 关闭 Hub
	r.GET("/restart", handleRestartHub)           // 重启 Hub
	r.POST("/broadcast", handleBroadcast)         // 广播消息
	r.POST("/send/:clientID", handleSendToClient) // 发送消息到指定客户端

	// 模拟用户相关事件
	go simulateUserEvents()
}

// handleIndex 处理首页请求
func handleIndex(c *gin.Context) {
	// 读取并解析模板
	tmpl, err := template.ParseFS(content, "sse.html")
	if err != nil {
		c.Error(fmt.Sprintf("解析模板失败: %v", err))
		return
	}

	// 设置响应头
	c.Header("Content-Type", "text/html; charset=utf-8")

	// 执行模板
	if err := tmpl.Execute(c.Writer, nil); err != nil {
		c.Error(fmt.Sprintf("执行模板失败: %v", err))
		return
	}
}

// handleSSE 处理 SSE 连接请求
func handleSSE(c *gin.Context) {
	// 获取客户端ID
	clientID := c.Query("client_id")
	if clientID == "" {
		c.Fail("缺少客户端ID")
		return
	}

	// 创建新的 SSE 客户端连接
	// 订阅 user.created, user.updated, system.notice 和 ping 事件
	client := c.NewSSEClient(hub, "user.created", "user.updated", "system.notice", "ping")

	// 设置客户端ID
	client.ID = clientID

	// 发送连接成功事件
	hub.SendToClient(client.ID, &gin.SSEEvent{
		Event: "system.notice",
		Data: gin.H{
			"message":  "SSE 连接成功",
			"clientID": client.ID,
			"time":     time.Now().Format("2006-01-02 15:04:05"),
		},
	})

	// 等待连接断开
	<-client.Disconnected
}

// handleListClients 处理获取客户端列表请求
func handleListClients(c *gin.Context) {
	clients := hub.GetClients()
	c.Success(gin.H{
		"clients": clients,
		"count":   len(clients),
	})
}

// handleHubStatus 处理获取 Hub 状态请求
func handleHubStatus(c *gin.Context) {
	c.Success(gin.H{
		"running": hub.IsRunning(),
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	})
}

// handleCloseHub 处理关闭 Hub 请求
func handleCloseHub(c *gin.Context) {
	hub.Close()
	c.Success(gin.H{
		"message": "Hub 已关闭",
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	})
}

// handleRestartHub 处理重启 Hub 请求
func handleRestartHub(c *gin.Context) {
	if !hub.IsRunning() {
		hub.Restart()
		c.Success(gin.H{
			"message": "Hub 已重启",
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		})
	} else {
		c.Success(gin.H{
			"message": "Hub 正在运行中",
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		})
	}
}

// handleBroadcast 处理广播消息请求
func handleBroadcast(c *gin.Context) {
	var req BroadcastRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Fail("无效的请求数据")
		return
	}

	// 广播消息
	hub.BroadCast(&gin.SSEEvent{
		Event: req.Event,
		Data: gin.H{
			"message": req.Message,
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", time.Now().UnixNano()),
	})

	// 获取当前在线客户端数量
	clients := hub.GetClients()

	c.Success(gin.H{
		"message": "广播消息已发送",
		"clients": len(clients),
	})
}

// handleSendToClient 处理发送消息到指定客户端请求
func handleSendToClient(c *gin.Context) {
	clientID := c.Param("clientID")
	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Fail("无效的请求数据")
		return
	}

	// 发送消息到指定客户端
	success := hub.SendToClient(clientID, &gin.SSEEvent{
		Event: "system.notice",
		Data: gin.H{
			"message": req.Message,
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", time.Now().UnixNano()),
	})

	if success {
		c.Success("消息发送成功")
	} else {
		c.Fail("客户端不存在或已断开连接")
	}
}

// simulateUserEvents 模拟用户相关事件
func simulateUserEvents() {
	// 定义事件类型
	events := []string{"user.created", "user.updated"}
	// 定义用户操作
	actions := []string{"注册", "登录", "更新资料", "修改密码", "上传头像"}

	// 每 30 秒随机发送一个用户事件
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !hub.IsRunning() {
			continue
		}

		// 随机选择事件类型和操作
		event := events[time.Now().Unix()%2]
		action := actions[time.Now().Unix()%5]
		userID := fmt.Sprintf("user_%d", time.Now().Unix())

		// 广播事件
		hub.BroadCast(&gin.SSEEvent{
			Event: event,
			Data: gin.H{
				"user_id": userID,
				"action":  action,
				"message": fmt.Sprintf("用户 %s %s", userID, action),
				"time":    time.Now().Format("2006-01-02 15:04:05"),
			},
			ID: fmt.Sprintf("%d", time.Now().UnixNano()),
		})
	}
}
