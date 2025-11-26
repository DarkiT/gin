package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/sse"
	"github.com/go-playground/validator/v10"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static/*
var staticFiles embed.FS

// 定义全局 SSE Hub 和 缓存
var (
	hub       *sse.Hub
	cacheMap  = make(map[string]interface{})
	ginEngine *gin.Router // 保存gin引擎的引用
	hubMu     sync.RWMutex

	// 全局上下文，用于控制后台goroutine的生命周期
	appCtx, appCancel = context.WithCancel(context.Background())
)

func getHub() *sse.Hub {
	hubMu.RLock()
	defer hubMu.RUnlock()
	return hub
}

func setHub(h *sse.Hub) {
	hubMu.Lock()
	hub = h
	hubMu.Unlock()
}

// 常量定义
const (
	JWTSecretKey  = "your-secure-secret-key-for-jwt-authentication" // 实际应用中应该从环境变量或配置中读取
	CacheSavePath = "./cache_data.dat"                              // 缓存持久化路径
)

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

// UserForm 用户表单结构
type UserForm struct {
	Username string `form:"username" json:"username"`
	Email    string `form:"email" json:"email"`
	Age      int    `form:"age" json:"age"`
}

// Validate 验证表单数据
func (f UserForm) Validate() (bool, string) {
	if f.Username == "" {
		return false, "用户名不能为空"
	}
	if f.Email == "" {
		return false, "邮箱不能为空"
	}
	if !strings.Contains(f.Email, "@") {
		return false, "邮箱格式不正确"
	}
	if f.Age <= 0 || f.Age > 120 {
		return false, "年龄必须在 1-120 之间"
	}
	return true, ""
}

// FormValidateRequest 表单验证请求结构体
type FormValidateRequest struct {
	Username string `form:"username" json:"username" binding:"required" validate:"required"`
	Email    string `form:"email" json:"email" binding:"required,email" validate:"required,email"`
	Age      int    `form:"age" json:"age" binding:"required,gt=0,lt=121" validate:"required,gt=0,lt=121"`
	Phone    string `form:"phone" json:"phone" binding:"omitempty,len=11" validate:"omitempty,len=11"`
	Address  string `form:"address" json:"address" binding:"omitempty" validate:"omitempty"`
}

func main() {
	// 创建安全配置
	securityConfig := &gin.SecurityConfig{
		JWTSecretKey:      []byte(JWTSecretKey),
		JWTAlgorithm:      "HS256",
		JWTExpiration:     time.Hour,
		JWTRefreshEnabled: true,

		// CORS安全配置
		CORSAllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8080"},
		CORSAllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		CORSAllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With"},
		CORSMaxAge:           86400,
		CORSAllowCredentials: false,

		// 安全头和限流
		SecurityHeadersEnabled:     true,
		RateLimitEnabled:           true,
		RateLimitRequestsPerMinute: 60,
	}

	config := &gin.Config{
		SecurityConfig:      securityConfig,
		SSEEnabled:          true,
		ErrorHandlerEnabled: true,
		SensitiveFilter:     true,
	}

	// 使用兼容的gin.Default()方式，传入配置启用JWT
	r := gin.Default(config)

	// 将Router实例赋值给全局变量，供其他函数使用
	ginEngine = r

	// 启动SSE服务
	if err := r.StartSSE(); err != nil {
		log.Fatalf("启动SSE失败: %v", err)
	}
	setHub(r.GetSSEHub())

	// 设置信号监听，当收到系统信号时触发应用级取消
	go func() {
		// 创建信号监听通道
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// 等待信号
		sig := <-sigChan
		log.Printf("收到系统信号: %v，触发优雅停机...", sig)

		// 触发应用级取消，这将通知所有使用appCtx的组件
		appCancel()
	}()

	go func() {
		<-appCtx.Done()
		log.Println("ping定时任务收到停机信号，正在退出...")
	}()

	// 注册路由
	setupRoutes(r)

	// 添加服务器控制路由
	controlAPI := r.Group("/control")
	{
		// 显示当前服务器状态
		controlAPI.GET("/status", handleStatus)
		// 重启服务器
		controlAPI.GET("/restart", handleRestart)
		// 关闭服务器
		controlAPI.GET("/shutdown", handleShutdown)
	}

	// 服务器配置
	serverConfig := gin.DefaultServerConfig()
	serverConfig.Port = "8080"
	serverConfig.GracefulTimeout = 5 * time.Second

	// 启动服务器，使用全局上下文
	log.Println("服务器启动在 http://localhost:8080")
	if err := r.RunWithContext(appCtx, serverConfig); err != nil && err != http.ErrServerClosed {
		log.Fatal("服务器启动失败:", err)
	}

	// 服务器退出时清理资源
	log.Println("正在清理资源...")
	// 检查上下文是否已经被取消，如果没有则取消
	select {
	case <-appCtx.Done():
		// 上下文已经被取消，不需要再次调用appCancel
		log.Println("上下文已被取消，继续清理...")
	default:
		// 上下文尚未取消，调用appCancel
		appCancel() // 通知所有后台goroutine退出
	}

	// 等待一段时间确保所有goroutine正确退出
	time.Sleep(1 * time.Second)

	log.Println("服务器已优雅关闭")
}

// 服务器状态处理器
func handleStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "成功",
		"data": gin.H{
			"running":  true, // 简化：只要能响应就是运行中
			"time":     time.Now().Format("2006-01-02 15:04:05"),
			"uptime":   "服务器运行时间信息", // 可以添加更多运行时间信息
			"requests": "请求统计信息",    // 可以添加请求统计
		},
	})
}

func handleRestart(c *gin.Context) {
	// 在后台触发重启
	go func() {
		// 给客户端一点时间接收响应
		time.Sleep(100 * time.Millisecond)

		log.Println("正在重启服务器...")

		// 使用 ginEngine 的 Restart 方法
		if err := ginEngine.Restart(); err != nil {
			log.Printf("重启服务器出错: %v", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "服务器正在重启，请等待...",
	})
}

func handleShutdown(c *gin.Context) {
	// 在后台触发优雅停机
	go func() {
		// 给客户端一点时间接收响应
		time.Sleep(100 * time.Millisecond)
		// 调用取消函数触发优雅停机
		appCancel()
	}()

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "服务器正在优雅关闭，请等待...",
	})
}

// AuthMiddleware 认证中间件
func AuthMiddleware(c *gin.Context) {
	// 从增强的Context获取JWT令牌并验证
	jwt, ok := c.RequireJWT()
	if !ok {
		return // RequireJWT已经处理了错误响应
	}

	// 将用户信息设置到上下文中
	c.Set("jwt_payload", jwt)
	c.Set("user_id", jwt["user_id"])
	c.Set("username", jwt["username"])

	c.Next()
}

// setupRoutes 设置路由
func setupRoutes(r *gin.Router) {
	// 设置模板
	// 从嵌入式文件系统加载模板

	// 创建函数映射
	funcMap := template.FuncMap{
		"lower": strings.ToLower, // 小写转换函数
		"upper": strings.ToUpper, // 大写转换函数
		"slice": func(s string, i, j int) string { // 字符串切片函数
			runes := []rune(s)
			if i >= len(runes) {
				return ""
			}
			if j > len(runes) {
				j = len(runes)
			}
			return string(runes[i:j])
		},
		"replace": strings.ReplaceAll, // 字符串替换函数
	}

	// 使用函数映射创建模板
	tmpl := template.New("").Funcs(funcMap)
	tmpl = template.Must(tmpl.ParseFS(templates, "templates/*.html"))
	r.Engine().SetHTMLTemplate(tmpl)

	// 根路由 - 首页
	r.GET("/", handleIndex)

	// API文档
	r.GET("/docs", handleDocs)

	// 认证相关路由
	auth := r.Group("/auth")
	{
		auth.GET("/login", handleLogin)
		auth.POST("/login", handleLogin)
		auth.GET("/refresh", handleRefreshToken)
		auth.GET("/logout", handleLogout)
	}

	// 受保护的API路由组
	api := r.Group("/api")
	api.Use(AuthMiddleware)
	{
		// 用户相关API
		api.GET("/user/profile", handleUserProfile)
		api.POST("/user/update", handleUserUpdate)

		// 添加用户API的演示页面
		api.GET("/demo", handleAPIDemo)
	}

	// 缓存示例路由
	cacheRoutes := r.Group("/cache")
	{
		cacheRoutes.GET("/set", handleCacheSet)
		cacheRoutes.GET("/get", handleCacheGet)
		cacheRoutes.GET("/delete", handleCacheDelete)
		cacheRoutes.GET("/clear", handleCacheClear)
		cacheRoutes.GET("/list", handleCacheList)
		cacheRoutes.GET("/stats", handleCacheStats)
	}

	// 创建SSE路由组
	sseRoutes := r.Group("/sse-api")
	{
		// SSE 连接
		sseRoutes.GET("/events", handleSSE)
		// 获取客户端列表
		sseRoutes.GET("/clients", handleListClients)
		// 获取 Hub 状态
		sseRoutes.GET("/status", handleHubStatus)
		// 获取性能统计
		sseRoutes.GET("/stats", handleSSEStats)
		// 获取性能指标
		sseRoutes.GET("/metrics", handleSSEMetrics)
		// 关闭 Hub
		sseRoutes.GET("/close", handleCloseHub)
		// 重启 Hub
		sseRoutes.GET("/restart", handleRestartHub)
		// 广播消息API
		sseRoutes.POST("/broadcast", handleBroadcast)
		// 发送消息API
		sseRoutes.POST("/send/:clientID", handleSendToClient)
	}

	// 为了兼容旧链接，保留原来的路由
	r.GET("/events", handleSSE)
	r.GET("/clients", handleListClients)
	r.GET("/status", handleHubStatus)
	r.GET("/close", handleCloseHub)
	r.GET("/restart", handleRestartHub)
	r.GET("/broadcast", handleBroadcastPage)
	r.POST("/broadcast", handleBroadcast)
	r.GET("/send/:clientID", handleSendToClientPage)
	r.POST("/send/:clientID", handleSendToClient)

	// 表单验证示例
	r.GET("/form", handleShowForm)
	r.POST("/form/validate", handleFormValidate)

	// 工具示例
	r.GET("/utils/url-builder", handleURLBuilder)
	r.POST("/utils/url-builder", handleURLBuilder) // 添加POST方法支持
	r.GET("/url", handleURLBuilder)                // 兼容直接访问/url的情况
	r.POST("/url", handleURLBuilder)               // 支持表单提交到/url的情况
	r.GET("/utils/info", handleRequestInfo)

	// 安全示例
	r.GET("/security", handleSecurity)

	// 国际化示例
	r.GET("/i18n", handleI18n)

	// SSE演示页面
	r.GET("/sse", handleSSEPage)

	// SSE调试页面
	r.GET("/sse-debug", handleSSEDebugPage)

	// 设置静态文件服务（使用内嵌文件系统）
	r.Engine().StaticFS("/static", http.FS(staticFiles))

	// 模拟用户相关事件
	go simulateUserEvents()
}

// handleIndex 处理首页请求
func handleIndex(c *gin.Context) {
	// 获取当前服务器状态
	serverStatus := "运行中"
	if !ginEngine.IsRunning() {
		serverStatus = "已停止"
	}

	// 服务器控制相关API
	serverControls := []gin.H{
		{
			"name": "服务器状态",
			"url":  "/control/status",
			"desc": "查看当前服务器状态",
		},
		{
			"name": "优雅重启",
			"url":  "/control/restart",
			"desc": "重启服务器（等待现有请求处理完成）",
		},
		{
			"name": "优雅停机",
			"url":  "/control/shutdown",
			"desc": "停止服务器（等待现有请求处理完成）",
		},
	}

	c.HTML(200, "index.html", gin.H{
		"title":         "Gin框架扩展演示",
		"time":          time.Now().Format("2006-01-02 15:04:05"),
		"server_status": serverStatus,
		"controls":      serverControls,
	})
}

// handleDocs 显示API文档
func handleDocs(c *gin.Context) {
	c.HTML(200, "docs.html", gin.H{
		"title": "API文档",
	})
}

// handleLogin 处理登录
func handleLogin(c *gin.Context) {
	// 获取请求方法
	isPost := c.Request.Method == "POST"

	var username, password, redirect string

	if isPost {
		// 处理JSON或表单数据
		if c.ContentType() == "application/json" {
			// 绑定JSON
			var loginData struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Redirect string `json:"redirect"`
			}
			if err := c.ShouldBindJSON(&loginData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code": 400,
					"msg":  "无效的请求数据: " + err.Error(),
				})
				return
			}
			username = loginData.Username
			password = loginData.Password
			redirect = loginData.Redirect
			if redirect == "" {
				redirect = "/api/demo"
			}
		} else {
			// 绑定表单数据
			username = c.PostForm("username")
			password = c.PostForm("password")
			redirect = c.DefaultPostForm("redirect", "/api/demo")
		}
	} else {
		// 从GET参数获取
		username = c.DefaultQuery("username", "")
		password = c.DefaultQuery("password", "")
		redirect = c.DefaultQuery("redirect", "/api/demo")
	}

	// 如果没有提供用户名和密码，则显示登录页面
	if username == "" || password == "" {
		// 只有GET请求才显示登录页面
		if !isPost {
			c.HTML(200, "login.html", gin.H{
				"title":    "用户登录",
				"redirect": redirect,
			})
			return
		} else {
			// POST请求缺少参数返回错误
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "用户名和密码不能为空",
			})
			return
		}
	}

	// 从环境变量获取用户名和密码，如果不存在则使用默认值（仅用于开发环境）
	validUsername := os.Getenv("DEMO_USERNAME")
	validPassword := os.Getenv("DEMO_PASSWORD")

	// 如果环境变量未设置，使用默认值（仅用于开发环境）
	if validUsername == "" {
		validUsername = "demo"
	}
	if validPassword == "" {
		validPassword = "123456"
	}

	// 验证用户名和密码
	if username != validUsername || password != validPassword {
		if isPost {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": 401,
				"msg":  "用户名或密码错误",
			})
			return
		} else {
			c.HTML(200, "login.html", gin.H{
				"title":    "登录失败",
				"error":    "用户名或密码错误",
				"redirect": redirect,
			})
			return
		}
	}

	// 生成用户ID（实际应用中应该从数据库获取）
	userID := fmt.Sprintf("user_%d", time.Now().Unix())

	// 创建JWT payload并生成token
	payload := gin.H{
		"user_id":  userID,
		"username": username,
		"time":     time.Now().Unix(),
	}

	token, err := c.CreateJWTSession(JWTSecretKey, 1*time.Hour, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "生成token失败: " + err.Error(),
		})
		return
	}

	// 对于POST请求，返回JSON而不是重定向
	if isPost {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "登录成功",
			"data": gin.H{
				"token":      token,
				"user_id":    userID,
				"username":   username,
				"expires_in": 3600, // 1小时，单位秒
				"redirect":   redirect,
			},
		})
		return
	}

	// 对于GET请求，如果有重定向URL，则进行重定向
	if redirect != "/" {
		c.HTML(200, "redirect.html", gin.H{
			"redirect": redirect,
		})
		return
	}

	// 否则返回成功消息
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "登录成功",
		"data": gin.H{
			"token":      token,
			"user_id":    userID,
			"username":   username,
			"expires_in": 3600, // 1小时，单位秒
		},
	})
}

// handleRefreshToken 刷新JWT令牌
func handleRefreshToken(c *gin.Context) {
	token, err := c.RefreshJWTSession(JWTSecretKey, 1*time.Hour)
	if err != nil {
		c.Fail("刷新令牌失败: " + err.Error())
		return
	}

	c.Success(gin.H{
		"token":      token,
		"expires_in": 3600, // 1小时，单位秒
	})
}

// handleLogout 处理用户注销
func handleLogout(c *gin.Context) {
	c.ClearJWT()
	c.Success("用户已成功注销")
}

// handleUserProfile 获取用户资料
func handleUserProfile(c *gin.Context) {
	// 从会话中获取用户信息
	userID := c.SessionGetString("user_id")
	username := c.SessionGetString("username")

	// 模拟从数据库获取用户资料
	c.Success(gin.H{
		"user_id":     userID,
		"username":    username,
		"email":       fmt.Sprintf("%s@example.com", username),
		"role":        "user",
		"create_time": time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		"login_count": 42,
		"status":      "active",
	})
}

// handleUserUpdate 更新用户资料
func handleUserUpdate(c *gin.Context) {
	var form UserForm
	if !c.BindJSON(&form) {
		return
	}

	if !c.Validate(form) {
		return
	}

	// 模拟更新用户资料
	c.SuccessWithMsg("用户资料更新成功", gin.H{
		"username": form.Username,
		"email":    form.Email,
		"age":      form.Age,
	})
}

// handleCacheSet 设置缓存
func handleCacheSet(c *gin.Context) {
	key := c.Query("key")
	value := c.Query("value")
	ttl := c.DefaultQuery("ttl", "300") // 默认5分钟

	if key == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "key和value参数不能为空",
		})
		return
	}

	// 使用map模拟缓存设置
	cacheMap[key] = value

	// 设置一些额外的缓存演示
	cacheMap["counter"] = 1
	cacheMap["enabled"] = true
	cacheMap["score"] = 95.5
	cacheMap["user:profile"] = gin.H{
		"name":  "张三",
		"email": "zhangsan@example.com",
		"age":   30,
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "缓存设置成功",
		"data": gin.H{
			"key":   key,
			"value": value,
			"ttl":   ttl,
		},
	})
}

// handleCacheGet 获取缓存
func handleCacheGet(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "key参数不能为空",
		})
		return
	}

	// 从模拟缓存中获取
	value, exists := cacheMap[key]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 404,
			"msg":  fmt.Sprintf("缓存键 %s 不存在", key),
		})
		return
	}

	// 获取其他类型的缓存
	counter := cacheMap["counter"]
	enabled := cacheMap["enabled"]
	score := cacheMap["score"]

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取缓存成功",
		"data": gin.H{
			"key":      key,
			"value":    value,
			"counter":  counter,
			"enabled":  enabled,
			"score":    score,
			"examples": getMapKeys(cacheMap),
		},
	})
}

// handleCacheDelete 删除缓存
func handleCacheDelete(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "key参数不能为空",
		})
		return
	}

	// 从模拟缓存中删除
	delete(cacheMap, key)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "缓存删除成功",
		"data": gin.H{
			"key":     key,
			"deleted": true,
		},
	})
}

// handleCacheClear 清除所有缓存
func handleCacheClear(c *gin.Context) {
	// 清空模拟缓存
	cacheMap = make(map[string]interface{})

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "所有缓存已清除",
	})
}

// 获取map的所有键
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// handleCacheList 列表缓存操作演示
func handleCacheList(c *gin.Context) {
	// 使用全局缓存变量操作列表
	cacheKeyTasks := "tasks"

	// 创建一个列表缓存，设置5分钟过期
	c.GetCache().SetList(cacheKeyTasks, 5*time.Minute)

	// 添加任务到列表
	c.GetCache().LPush(cacheKeyTasks, "任务1", "任务2", "任务3")
	c.GetCache().RPush(cacheKeyTasks, "任务4", "任务5")

	// 获取所有任务
	allTasks := c.GetCache().LRange(cacheKeyTasks, 0, -1)

	// 弹出第一个和最后一个任务
	firstTask, _ := c.GetCache().LPop(cacheKeyTasks)
	lastTask, _ := c.GetCache().RPop(cacheKeyTasks)

	// 获取中间的任务
	middleTask, _ := c.GetCache().LIndex(cacheKeyTasks, 1)

	// 剩余的任务
	remainingTasks := c.GetCache().LRange(cacheKeyTasks, 0, -1)

	c.Success(gin.H{
		"all_tasks":       allTasks,
		"first_task":      firstTask,
		"last_task":       lastTask,
		"middle_task":     middleTask,
		"remaining_tasks": remainingTasks,
	})
}

// handleCacheStats 获取缓存统计信息
func handleCacheStats(c *gin.Context) {
	// 缓存实例有效，获取统计信息
	stats := c.GetCache().GetStats()

	c.Success(gin.H{
		"stats": stats,
	})
}

// handleSSE 处理 SSE 连接请求
func handleSSE(c *gin.Context) {
	// 获取客户端ID
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "缺少client_id参数",
		})
		return
	}

	// 获取事件过滤器
	filter := c.Query("filter")
	eventTypes := []string{"user.created", "user.updated", "system.notice", "ping"}

	// 如果请求中指定了过滤器，则使用指定的过滤器
	if filter != "" {
		eventTypes = strings.Split(filter, ",")
	}

	// 创建新的 SSE 客户端连接 - 在注册前指定 ID
	client := c.NewSSEClientWithOptions(eventTypes, sse.WithClientID(clientID))
	if client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "SSE服务未可用",
		})
		return
	}

	// 记录连接日志
	log.Printf("新的SSE客户端连接: %s, 订阅事件: %v\n", clientID, eventTypes)

	// 发送连接成功事件
	now := time.Now()
	h := getHub()
	if h == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": 503, "msg": "SSE服务不可用"})
		return
	}
	h.SendToClient(client.ID, &sse.Event{
		Event: "system.notice",
		Data: gin.H{
			"message":  "SSE 连接成功",
			"clientID": client.ID,
			"time":     now.Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", now.UnixNano()),
	})

	// 启动客户端消息监听 - 这是关键步骤！
	client.Listen()

	// 客户端断开连接后清理资源
	log.Printf("SSE客户端断开连接: %s\n", clientID)
}

// handleListClients 处理获取客户端列表请求
func handleListClients(c *gin.Context) {
	var clients []string
	if h := getHub(); h != nil {
		hubClients := h.GetClients()
		clients = append(clients, hubClients...)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取客户端列表成功",
		"data": gin.H{
			"clients": clients,
			"count":   len(clients),
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		},
	})
}

// handleHubStatus 处理获取 Hub 状态请求
func handleHubStatus(c *gin.Context) {
	var isRunning bool
	var clientCount int

	if h := getHub(); h != nil {
		isRunning = h.IsRunning()
		if isRunning {
			clients := h.GetClients()
			clientCount = len(clients)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取Hub状态成功",
		"data": gin.H{
			"running": isRunning,
			"clients": clientCount,
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		},
	})
}

// handleCloseHub 处理关闭 Hub 请求
func handleCloseHub(c *gin.Context) {
	h := getHub()
	if h != nil && h.IsRunning() {
		h.Close()
		setHub(nil)
		log.Println("SSE Hub已关闭")
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub已关闭",
			"data": gin.H{
				"time": time.Now().Format("2006-01-02 15:04:05"),
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub已经处于关闭状态",
			"data": gin.H{
				"time": time.Now().Format("2006-01-02 15:04:05"),
			},
		})
	}
}

// handleRestartHub 处理重启 Hub 请求
func handleRestartHub(c *gin.Context) {
	// 检查ginEngine是否已正确初始化
	if ginEngine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "服务器内部错误：Router未初始化",
		})
		return
	}

	// 关闭旧的Hub（如果存在）
	if h := getHub(); h != nil {
		log.Println("正在关闭旧的SSE Hub...")
		h.Close()
		setHub(nil)
		// 等待一点时间确保完全关闭
		time.Sleep(100 * time.Millisecond)
	}

	// 重新初始化Hub
	log.Println("正在创建新的SSE Hub...")
	newHub := ginEngine.NewSSEHub(20)
	setHub(newHub)
	if newHub == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "Hub创建失败",
		})
		return
	}

	// 在后台启动Hub
	go newHub.Run(context.Background())

	// 等待一点时间确保Hub启动
	time.Sleep(100 * time.Millisecond)

	log.Println("SSE Hub已重启")
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "Hub已重启",
		"data": gin.H{
			"time":    time.Now().Format("2006-01-02 15:04:05"),
			"running": newHub.IsRunning(),
		},
	})
}

// handleBroadcast 处理广播消息请求
func handleBroadcast(c *gin.Context) {
	// 检查hub是否可用
	h := getHub()
	if h == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code": 503,
			"msg":  "SSE服务不可用",
		})
		return
	}

	var req BroadcastRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "无效的请求数据: " + err.Error(),
		})
		return
	}

	// 广播消息
	now := time.Now()
	h.Broadcast(&sse.Event{
		Event: req.Event,
		Data: gin.H{
			"message": req.Message,
			"time":    now.Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", now.UnixNano()),
	})

	// 获取当前在线客户端数量
	hClients := h.GetClients()

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "广播消息已发送",
		"data": gin.H{
			"clients": len(hClients),
			"event":   req.Event,
			"message": req.Message,
		},
	})
}

// handleSendToClient 处理发送消息到指定客户端请求
func handleSendToClient(c *gin.Context) {
	// 检查hub是否可用
	h := getHub()
	if h == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code": 503,
			"msg":  "SSE服务不可用",
		})
		return
	}

	clientID := c.Param("clientID")
	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "无效的请求数据: " + err.Error(),
		})
		return
	}

	// 发送消息到指定客户端
	now := time.Now()
	success := h.SendToClient(clientID, &sse.Event{
		Event: "system.notice",
		Data: gin.H{
			"message": req.Message,
			"time":    now.Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", now.UnixNano()),
	})

	if success {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "消息发送成功",
			"data": gin.H{
				"clientID": clientID,
				"message":  req.Message,
			},
		})
	} else {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 404,
			"msg":  "客户端不存在或已断开连接",
		})
	}
}

// handleShowForm 显示表单
func handleShowForm(c *gin.Context) {
	c.HTML(200, "form.html", gin.H{
		"title": "表单验证示例",
	})
}

// handleFormValidate 处理表单验证
func handleFormValidate(c *gin.Context) {
	contentType := c.ContentType()
	var req FormValidateRequest
	var bindErr error

	// 根据内容类型绑定请求数据
	if strings.Contains(contentType, "application/json") {
		bindErr = c.ShouldBindJSON(&req)
	} else if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/x-www-form-urlencoded") {
		bindErr = c.ShouldBind(&req)
	} else {
		// 默认尝试从URL查询参数绑定
		bindErr = c.ShouldBindQuery(&req)
	}

	// 处理绑定错误
	if bindErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "表单数据绑定失败: " + bindErr.Error(),
		})
		return
	}

	// 验证请求参数
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		errors.As(err, &validationErrors)
		errorMessages := make([]string, 0)
		for _, e := range validationErrors {
			errorMessages = append(errorMessages, fmt.Sprintf("字段 '%s' 验证失败: %s", e.Field(), e.Tag()))
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "表单验证失败",
			"errors":  errorMessages,
		})
		return
	}

	// 验证通过，返回成功
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "表单验证成功",
		"data":    req,
	})
}

// handleURLBuilder URL构建工具示例
func handleURLBuilder(c *gin.Context) {
	// 从请求中获取URL参数
	var (
		path     = c.DefaultQuery("path", "/api/users")
		scheme   = c.DefaultQuery("scheme", "https")
		domain   = c.DefaultQuery("domain", "api.example.com")
		page     = c.DefaultQuery("page", "1")
		size     = c.DefaultQuery("size", "10")
		fragment = c.DefaultQuery("fragment", "")
	)

	// 如果是POST请求，优先使用POST表单数据
	if c.Request.Method == "POST" {
		path = c.DefaultPostForm("basePath", path)
		scheme = c.DefaultPostForm("scheme", scheme)
		domain = c.DefaultPostForm("domain", domain)
		fragment = c.DefaultPostForm("fragment", fragment)
		hasFragment := c.DefaultPostForm("hasFragment", "0")
		if hasFragment == "0" {
			fragment = ""
		}
	}

	// 创建URL构建器并链式调用相关方法
	urlBuilder := c.BuildURL(path).
		Set("page", page).
		Set("size", size).
		Domain(domain).
		Scheme(scheme)

	// 如果有片段，则添加片段
	if fragment != "" {
		urlBuilder.Set("fragment", fragment)
	}

	url := urlBuilder.Build()

	// 渲染URL构建工具页面
	c.HTML(200, "url.html", gin.H{
		"title":      "URL构建工具",
		"result":     url,
		"showResult": true,
		"path":       path,
		"scheme":     scheme,
		"domain":     domain,
		"page":       page,
		"size":       size,
		"fragment":   fragment,
	})
}

// handleRequestInfo 请求信息获取示例
func handleRequestInfo(c *gin.Context) {
	// 获取请求信息
	method := c.Method()
	path := c.Request.URL.Path
	fullUrl := c.Request.URL.String()
	host := c.Host()
	domain := c.Domain()
	scheme := c.Scheme()
	port := c.Port()
	isSSL := c.IsSSL()
	isAjax := c.IsAjax()
	contentType := c.ContentType()
	userAgent := c.Request.UserAgent()
	ip := c.ClientIP()

	// 获取所有请求头
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// 获取所有查询参数
	queryParams := make(map[string]string)
	hasQueryParams := false
	for key, values := range c.Request.URL.Query() {
		queryParams[key] = values[0]
		hasQueryParams = true
	}

	// 获取所有Cookie
	cookies := make(map[string]string)
	hasCookies := false
	for _, cookie := range c.Request.Cookies() {
		cookies[cookie.Name] = cookie.Value
		hasCookies = true
	}

	// 渲染请求信息页面
	c.HTML(200, "request.html", gin.H{
		"title":          "请求信息详情",
		"method":         method,
		"path":           path,
		"fullUrl":        fullUrl,
		"host":           host,
		"domain":         domain,
		"scheme":         scheme,
		"port":           port,
		"isSSL":          isSSL,
		"isAjax":         isAjax,
		"contentType":    contentType,
		"userAgent":      userAgent,
		"ip":             ip,
		"time":           time.Now().Format("2006-01-02 15:04:05"),
		"headers":        headers,
		"queryParams":    queryParams,
		"hasQueryParams": hasQueryParams,
		"cookies":        cookies,
		"hasCookies":     hasCookies,
	})
}

// handleSecurity 安全示例
func handleSecurity(c *gin.Context) {
	// 设置常用安全头
	c.SetSecureHeaders()

	// 设置内容安全策略
	c.SetCSP("default-src 'self'; script-src 'self' https://trusted.cdn.com;")

	// 设置X-Frame-Options以防止点击劫持
	c.SetXFrameOptions("DENY")

	c.HTML(200, "security.html", gin.H{
		"title": "安全增强示例",
		"headers": []gin.H{
			{"name": "Content-Security-Policy", "description": "控制允许的资源来源"},
			{"name": "X-Frame-Options", "description": "防止点击劫持"},
			{"name": "X-XSS-Protection", "description": "启用XSS过滤"},
			{"name": "X-Content-Type-Options", "description": "防止MIME类型嗅探"},
			{"name": "Strict-Transport-Security", "description": "强制使用HTTPS"},
		},
	})
}

// handleI18n 国际化支持示例
func handleI18n(c *gin.Context) {
	// 获取客户端请求的语言参数，默认为中文
	lang := c.DefaultQuery("lang", "zh-CN")

	// 定义支持的语言列表
	supportedLangs := []string{"zh-CN", "en-US", "ja-JP", "fr-FR"}

	// 验证语言是否支持
	langValid := false
	for _, l := range supportedLangs {
		if l == lang {
			langValid = true
			break
		}
	}

	// 如果不支持，则使用默认语言
	if !langValid {
		lang = "zh-CN"
	}

	// 根据语言提供不同的问候语和消息
	var greeting, message, langInfo string

	switch lang {
	case "zh-CN":
		greeting = "你好，世界！"
		message = "欢迎使用多语言支持功能"
		langInfo = "当前语言：简体中文 (zh-CN)"
	case "en-US":
		greeting = "Hello, World!"
		message = "Welcome to the multilingual support feature"
		langInfo = "Current language: English (en-US)"
	case "ja-JP":
		greeting = "こんにちは、世界！"
		message = "多言語サポート機能へようこそ"
		langInfo = "現在の言語：日本語 (ja-JP)"
	case "fr-FR":
		greeting = "Bonjour le monde !"
		message = "Bienvenue dans la fonctionnalité de support multilingue"
		langInfo = "Langue actuelle : Français (fr-FR)"
	}

	c.HTML(200, "i18n.html", gin.H{
		"title":       "国际化支持示例",
		"currentLang": lang,
		"greeting":    greeting,
		"message":     message,
		"langInfo":    langInfo,
	})
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

	for {
		select {
		case <-ticker.C:
			h := getHub()
			if h == nil || !h.IsRunning() {
				continue
			}

			// 随机选择事件类型和操作
			event := events[time.Now().Unix()%2]
			action := actions[time.Now().Unix()%5]
			userID := fmt.Sprintf("user_%d", time.Now().Unix())

			// 广播事件
			h.Broadcast(&sse.Event{
				Event: event,
				Data: gin.H{
					"user_id": userID,
					"action":  action,
					"message": fmt.Sprintf("用户 %s %s", userID, action),
					"time":    time.Now().Format("2006-01-02 15:04:05"),
				},
				ID: fmt.Sprintf("%d", time.Now().UnixNano()),
			})
		case <-appCtx.Done():
			// 收到停机信号，退出goroutine
			log.Println("收到停机信号，正在退出...")
			return
		}
	}
}

// handleBroadcastPage 显示广播消息页面
func handleBroadcastPage(c *gin.Context) {
	var clients []string
	if h := getHub(); h != nil {
		clients = h.GetClients()
	}
	c.HTML(200, "sse.html", gin.H{
		"title":   "广播消息",
		"clients": clients,
		"count":   len(clients),
		"mode":    "broadcast",
	})
}

// handleSendToClientPage 显示发送消息页面
func handleSendToClientPage(c *gin.Context) {
	clientID := c.Param("clientID")
	var clients []string
	if h := getHub(); h != nil {
		clients = h.GetClients()
	}
	c.HTML(200, "sse.html", gin.H{
		"title":     "发送消息",
		"clients":   clients,
		"count":     len(clients),
		"mode":      "send",
		"target_id": clientID,
	})
}

// handleSSEPage 显示SSE演示页面
func handleSSEPage(c *gin.Context) {
	var clients []string
	if h := getHub(); h != nil {
		clients = h.GetClients()
	}
	c.HTML(200, "sse.html", gin.H{
		"title":   "服务器发送事件(SSE)演示",
		"clients": clients,
		"count":   len(clients),
	})
}

// handleSSEDebugPage 显示SSE调试页面
func handleSSEDebugPage(c *gin.Context) {
	c.HTML(200, "sse_debug.html", gin.H{
		"title": "SSE调试页面",
	})
}

// handleSSEStats 处理获取SSE统计信息请求
func handleSSEStats(c *gin.Context) {
	h := getHub()
	if h == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code": 503,
			"msg":  "SSE服务不可用",
		})
		return
	}

	stats := h.GetStats()
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取SSE统计信息成功",
		"data": stats,
	})
}

// handleSSEMetrics 处理获取SSE性能指标请求
func handleSSEMetrics(c *gin.Context) {
	h := getHub()
	if h == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code": 503,
			"msg":  "SSE服务不可用",
		})
		return
	}

	metrics := h.GetPerformanceMetrics()
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取SSE性能指标成功",
		"data": metrics,
	})
}

// handleAPIDemo 显示API演示页面
func handleAPIDemo(c *gin.Context) {
	// 从上下文中获取用户信息
	userInfo, exists := c.RequireJWT()
	if !exists {
		// 重定向到登录页面
		c.HTML(302, "login.html", gin.H{
			"title":    "请先登录",
			"redirect": "/api/demo",
		})
		return
	}

	username := c.GetString("username")

	c.HTML(200, "api.html", gin.H{
		"title":     "API演示",
		"user_info": userInfo,
		"username":  username,
		"endpoints": []gin.H{
			{"path": "/api/user/profile", "method": "GET", "desc": "获取用户资料"},
			{"path": "/api/user/update", "method": "POST", "desc": "更新用户资料"},
		},
	})
}
