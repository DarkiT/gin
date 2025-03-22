package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/darkit/gin"
	"github.com/go-playground/validator/v10"
)

//go:embed templates/*.html
var content embed.FS

// 定义全局 SSE Hub 和 缓存
var (
	hub       *gin.SSEHub
	cache     *gin.Cache[string, any]
	cacheMap  = make(map[string]interface{})
	ginEngine *gin.Router // 保存gin引擎的引用
)

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
	// 创建路由
	r := gin.Default()
	ginEngine = r // 保存gin引擎的引用

	// 初始化缓存系统
	cache = gin.SetGlobalCacheWithPersistence(
		10*time.Minute, // 默认过期时间
		30*time.Second, // 清理间隔
		CacheSavePath,  // 持久化文件路径
		5*time.Minute,  // 自动保存间隔
	)

	// 创建 SSE Hub，设置历史记录大小为 20
	hub = r.NewSSEHub(20)
	go hub.Run() // 启动 Hub

	// 添加一个定时任务，每30秒发送ping事件，确保连接保持活跃
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if hub.IsRunning() {
				hub.BroadCast(&gin.SSEEvent{
					Event: "ping",
					Data:  gin.H{"message": "ping", "time": time.Now().Format("2006-01-02 15:04:05")},
					ID:    fmt.Sprintf("%d", time.Now().UnixNano()),
				})
			}
		}
	}()

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
	tmpl = template.Must(tmpl.ParseFS(content, "templates/*.html"))
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
	api := r.Group("/api", AuthMiddleware)
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

	// 静态文件服务（如果需要）
	// 使用标准库http.FileServer提供静态文件服务
	r.GET("/static/*filepath", func(c *gin.Context) {
		// TODO: 实现静态文件服务
	})

	// 模拟用户相关事件
	go simulateUserEvents()
}

// AuthMiddleware 认证中间件
func AuthMiddleware(c *gin.Context) {
	// 从请求头获取Token
	token := c.GetHeader("Authorization")
	if token == "" {
		// 尝试从Cookie中获取
		token, _ = c.Cookie("jwt_token")
	}

	// 如果没有token，则尝试从查询参数获取
	if token == "" {
		token = c.Query("token")
	}

	// 如果仍然没有token，则视为未授权
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code": 401,
			"msg":  "未授权访问，请先登录",
		})
		c.Abort()
		return
	}

	// 这里简化处理，实际应用中需要验证JWT令牌
	// 模拟查询用户信息
	userID := "user_123"
	username := "demo"

	// 将用户信息设置到上下文中
	c.Set("user_id", userID)
	c.Set("username", username)

	c.Next()
}

// handleIndex 处理首页请求
func handleIndex(c *gin.Context) {
	c.HTML(200, "index.html", gin.H{
		"title": "Gin框架扩展演示",
		"time":  time.Now().Format("2006-01-02 15:04:05"),
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

	// 简单验证，实际应用中需要更复杂的验证逻辑
	if username != "demo" || password != "123456" {
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

	// 生成简单的token（实际应用中应该使用JWT）
	token := fmt.Sprintf("token_%s_%d", username, time.Now().Unix())

	// 设置Cookie
	c.SetCookie("jwt_token", token, 3600, "/", "", false, false)

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
	// 使用全局缓存实例而不是从上下文获取
	if cache == nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 500,
			"msg":  "缓存系统未初始化或不可用",
		})
		return
	}

	// 使用全局缓存变量操作列表
	cacheKeyTasks := "tasks"

	// 创建一个列表缓存，设置5分钟过期
	cache.SetList(cacheKeyTasks, 5*time.Minute)

	// 添加任务到列表
	cache.LPush(cacheKeyTasks, "任务1", "任务2", "任务3")
	cache.RPush(cacheKeyTasks, "任务4", "任务5")

	// 获取所有任务
	allTasks := cache.LRange(cacheKeyTasks, 0, -1)

	// 弹出第一个和最后一个任务
	firstTask, _ := cache.LPop(cacheKeyTasks)
	lastTask, _ := cache.RPop(cacheKeyTasks)

	// 获取中间的任务
	middleTask, _ := cache.LIndex(cacheKeyTasks, 1)

	// 剩余的任务
	remainingTasks := cache.LRange(cacheKeyTasks, 0, -1)

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
	// 使用全局缓存实例而不是从上下文获取
	if cache == nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 500,
			"msg":  "缓存系统未初始化或不可用",
			"data": gin.H{
				"stats": nil,
			},
		})
		return
	}

	// 缓存实例有效，获取统计信息
	stats := cache.GetStats()

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

	// 创建新的 SSE 客户端连接
	client := c.NewSSEClient(hub, eventTypes...)

	// 设置客户端ID
	client.ID = clientID

	// 记录连接日志
	log.Printf("新的SSE客户端连接: %s, 订阅事件: %v\n", clientID, eventTypes)

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
	log.Printf("SSE客户端断开连接: %s\n", clientID)
}

// handleListClients 处理获取客户端列表请求
func handleListClients(c *gin.Context) {
	clients := hub.GetClients()
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取客户端列表成功",
		"data": gin.H{
			"clients": clients,
			"count":   len(clients),
		},
	})
}

// handleHubStatus 处理获取 Hub 状态请求
func handleHubStatus(c *gin.Context) {
	isRunning := hub.IsRunning()
	clientCount := 0
	if isRunning {
		clientCount = len(hub.GetClients())
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "获取Hub状态成功",
		"data": gin.H{
			"running":     isRunning,
			"time":        time.Now().Format("2006-01-02 15:04:05"),
			"clientCount": clientCount,
		},
	})
}

// handleCloseHub 处理关闭 Hub 请求
func handleCloseHub(c *gin.Context) {
	if hub.IsRunning() {
		hub.Close()
		log.Println("SSE Hub已关闭")
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub已关闭",
			"data": gin.H{
				"time":    time.Now().Format("2006-01-02 15:04:05"),
				"running": false,
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub已经处于关闭状态",
			"data": gin.H{
				"time":    time.Now().Format("2006-01-02 15:04:05"),
				"running": false,
			},
		})
	}
}

// handleRestartHub 处理重启 Hub 请求
func handleRestartHub(c *gin.Context) {
	if !hub.IsRunning() {
		// 关闭旧的Hub
		if hub != nil {
			hub.Close()
		}

		// 重新初始化Hub
		hub = ginEngine.NewSSEHub(20)
		go hub.Run()

		log.Println("SSE Hub已重启")
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub已重启",
			"data": gin.H{
				"time":    time.Now().Format("2006-01-02 15:04:05"),
				"running": true,
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "Hub正在运行中，无需重启",
			"data": gin.H{
				"time":    time.Now().Format("2006-01-02 15:04:05"),
				"running": true,
			},
		})
	}
}

// handleBroadcast 处理广播消息请求
func handleBroadcast(c *gin.Context) {
	var req BroadcastRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "无效的请求数据: " + err.Error(),
		})
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

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "广播消息已发送",
		"data": gin.H{
			"clients": len(clients),
			"event":   req.Event,
			"message": req.Message,
		},
	})
}

// handleSendToClient 处理发送消息到指定客户端请求
func handleSendToClient(c *gin.Context) {
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
	success := hub.SendToClient(clientID, &gin.SSEEvent{
		Event: "system.notice",
		Data: gin.H{
			"message": req.Message,
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		},
		ID: fmt.Sprintf("%d", time.Now().UnixNano()),
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
		validationErrors := err.(validator.ValidationErrors)
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
	urlBuilder := c.BuildUrl(path).
		Set("page", page).
		Set("size", size).
		Domain(domain).
		Scheme(scheme)

	// 如果有片段，则添加片段
	if fragment != "" {
		urlBuilder.Set("fragment", fragment)
	}

	url := urlBuilder.Builder()

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
	isSSL := c.IsSsl()
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

	// 禁止缓存
	c.NoCache()

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

// handleBroadcastPage 显示广播消息页面
func handleBroadcastPage(c *gin.Context) {
	clients := hub.GetClients()
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
	clients := hub.GetClients()
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
	clients := hub.GetClients()
	c.HTML(200, "sse.html", gin.H{
		"title":   "服务器发送事件(SSE)演示",
		"clients": clients,
		"count":   len(clients),
	})
}

// handleAPIDemo 显示API演示页面
func handleAPIDemo(c *gin.Context) {
	// 从上下文中获取用户信息
	userID, exists := c.Get("user_id")
	if !exists {
		// 重定向到登录页面
		c.HTML(302, "login.html", gin.H{
			"title":    "请先登录",
			"redirect": "/api/demo",
		})
		return
	}

	username, _ := c.Get("username")
	usernameStr, ok := username.(string)
	if !ok {
		usernameStr = "未知用户"
	}

	c.HTML(200, "api.html", gin.H{
		"title":    "API演示",
		"user_id":  userID,
		"username": usernameStr,
		"endpoints": []gin.H{
			{"path": "/api/user/profile", "method": "GET", "desc": "获取用户资料"},
			{"path": "/api/user/update", "method": "POST", "desc": "更新用户资料"},
		},
	})
}
