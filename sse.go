package gin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SSEEvent SSE 事件结构体
type SSEEvent struct {
	Event string `json:"event"` // 事件名称
	Data  any    `json:"data"`  // 事件数据
	ID    string `json:"id"`    // 事件ID
	Retry int    `json:"retry"` // 重试时间（毫秒）
}

// SSE 客户端结构体
type _SSEClient struct {
	ID           string         // 客户端唯一标识
	Connection   *Context       // 客户端连接上下文
	MessageChan  chan *SSEEvent // 消息通道
	Disconnected chan struct{}  // 断开连接信号
	CloseOnce    sync.Once      // 确保只关闭一次
	LastEventID  string         // 最后接收的事件ID
	EventFilters []string       // 事件过滤器，只接收指定事件
	done         chan struct{}  // 用于优雅关闭
}

// SSEHub SSE 连接管理中心
type SSEHub struct {
	sync.RWMutex
	clients    map[string]*_SSEClient // 所有已连接的客户端
	register   chan *_SSEClient       // 注册通道
	unregister chan *_SSEClient       // 注销通道
	broadcast  chan *SSEEvent         // 广播通道
	done       chan struct{}          // 用于优雅关闭
	running    bool                   // Hub 运行状态

	// 事件历史记录，用于断线重连时的消息补发
	eventHistory []*SSEEvent          // 历史事件缓存
	historySize  int                  // 历史记录大小
	historyMutex sync.RWMutex         // 历史记录锁
	lastPing     map[string]time.Time // 记录每个客户端最后一次心跳时间
	pingTimeout  time.Duration        // 心跳超时时间
}

const (
	defaultHistorySize   = 50               // 默认历史记录大小
	defaultBufferSize    = 512              // 默认缓冲区大小
	defaultRetryInterval = 3000             // 默认重试间隔（毫秒）
	defaultPingInterval  = 10 * time.Second // 默认心跳间隔
	defaultPingTimeout   = 30 * time.Second // 默认心跳超时时间
)

// NewSSEHub 创建新的 SSE Hub
//
// size 设置历史记录大小
func (r *Router) NewSSEHub(size ...int) *SSEHub {
	hub := &SSEHub{
		clients:      make(map[string]*_SSEClient),
		lastPing:     make(map[string]time.Time),
		register:     make(chan *_SSEClient, defaultBufferSize),
		unregister:   make(chan *_SSEClient, defaultBufferSize),
		broadcast:    make(chan *SSEEvent, defaultBufferSize),
		done:         make(chan struct{}),
		historySize:  defaultHistorySize,
		eventHistory: make([]*SSEEvent, 0, defaultHistorySize),
		pingTimeout:  defaultPingTimeout,
	}

	if len(size) > 0 {
		hub.historySize = size[0]
		hub.eventHistory = make([]*SSEEvent, 0, hub.historySize)
	}

	return hub
}

// Run 运行 SSE Hub
func (h *SSEHub) Run() {
	h.Lock()
	if h.running {
		h.Unlock()
		return
	}

	// 重新初始化通道
	h.register = make(chan *_SSEClient, defaultBufferSize)
	h.unregister = make(chan *_SSEClient, defaultBufferSize)
	h.broadcast = make(chan *SSEEvent, defaultBufferSize)
	h.done = make(chan struct{})
	h.running = true
	h.Unlock()

	ticker := time.NewTicker(defaultPingInterval)
	defer ticker.Stop()

	// 调整清理定时器间隔为 5 秒
	cleanupTicker := time.NewTicker(5 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case client := <-h.register:
			h.Lock()
			h.clients[client.ID] = client
			h.lastPing[client.ID] = time.Now() // 记录初始心跳时间
			h.Unlock()
			// 发送历史消息
			h.sendHistoryEvents(client)
		case client := <-h.unregister:
			h.removeClient(client.ID)
		case event := <-h.broadcast:
			// 保存到历史记录
			h.saveToHistory(event)
			// 广播消息
			h.broadcastEvent(event)
		case <-ticker.C:
			// 发送心跳
			h.sendPing()
		case <-cleanupTicker.C:
			// 清理不活跃的客户端
			h.cleanupInactiveClients()
		case <-h.done:
			// 优雅关闭
			h.shutdown()
			return
		}
	}
}

// 保存事件到历史记录
func (h *SSEHub) saveToHistory(event *SSEEvent) {
	h.historyMutex.Lock()
	defer h.historyMutex.Unlock()

	h.eventHistory = append(h.eventHistory, event)
	if len(h.eventHistory) > h.historySize {
		h.eventHistory = h.eventHistory[1:]
	}
}

// 发送历史事件
func (h *SSEHub) sendHistoryEvents(client *_SSEClient) {
	h.historyMutex.RLock()
	defer h.historyMutex.RUnlock()

	// 找到上次接收的位置
	startIdx := 0
	if client.LastEventID != "" {
		for i, event := range h.eventHistory {
			if event.ID == client.LastEventID {
				startIdx = i + 1
				break
			}
		}
	}

	// 发送错过的消息
	for i := startIdx; i < len(h.eventHistory); i++ {
		event := h.eventHistory[i]
		if client.shouldReceiveEvent(event) {
			select {
			case client.MessageChan <- event:
			default:
				// 如果客户端接收太慢，跳过
				continue
			}
		}
	}
}

// 广播事件到所有客户端
func (h *SSEHub) broadcastEvent(event *SSEEvent) {
	h.RLock()
	defer h.RUnlock()

	for _, client := range h.clients {
		if client.shouldReceiveEvent(event) {
			select {
			case client.MessageChan <- event:
			default:
				// 如果客户端接收太慢，跳过
				continue
			}
		}
	}
}

// 发送心跳
func (h *SSEHub) sendPing() {
	pingEvent := &SSEEvent{
		Event: "ping",
		Data:  time.Now().Unix(),
		ID:    fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	h.Lock()
	now := time.Now()
	for clientID, client := range h.clients {
		if client.shouldReceiveEvent(pingEvent) {
			select {
			case client.MessageChan <- pingEvent:
				h.lastPing[clientID] = now // 更新心跳时间
			default:
				// 如果客户端接收太慢，跳过或考虑移除
				h.removeClient(clientID)
				// continue
			}
		}
	}
	h.Unlock()
}

// 优雅关闭
func (h *SSEHub) shutdown() {
	h.Lock()
	defer h.Unlock()

	for _, client := range h.clients {
		close(client.MessageChan)
		client.CloseOnce.Do(func() {
			close(client.Disconnected)
		})
	}
	h.clients = make(map[string]*_SSEClient)
}

// Broadcast 广播消息
func (h *SSEHub) BroadCast(event *SSEEvent) {
	h.broadcast <- event
}

// Close 关闭 Hub
func (h *SSEHub) Close() {
	h.Lock()
	if !h.running {
		h.Unlock()
		return
	}
	h.running = false

	// 安全地关闭通道
	select {
	case <-h.done: // 检查通道是否已关闭
		// 通道已关闭，不需要再次关闭
	default:
		close(h.done)
	}

	h.Unlock()

	// 等待所有操作完成
	time.Sleep(200 * time.Millisecond)
}

// IsRunning 检查 Hub 是否正在运行
func (h *SSEHub) IsRunning() bool {
	h.RLock()
	defer h.RUnlock()
	return h.running
}

// Restart 重启 Hub
func (h *SSEHub) Restart() {
	h.Close()
	// 等待旧的 hub 完全关闭
	time.Sleep(100 * time.Millisecond)
	go h.Run()
}

// NewSSEClient 创建新的 SSE 客户端连接
func (c *Context) NewSSEClient(hub *SSEHub, filters ...string) *_SSEClient {
	// 设置 SSE 相关的 HTTP 头
	c.Writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // 禁用 Nginx 缓冲

	// 设置 hub
	c.hub = hub

	client := &_SSEClient{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Connection:   c,
		MessageChan:  make(chan *SSEEvent, defaultBufferSize),
		Disconnected: make(chan struct{}),
		LastEventID:  c.GetHeader("Last-Event-ID"),
		EventFilters: filters,
		done:         make(chan struct{}),
	}

	// 注册客户端
	hub.register <- client

	// 启动消息处理
	go client.listen()

	return client
}

// Close 关闭客户端连接
func (c *_SSEClient) Close() {
	close(c.done)
}

// SendToClient 发送消息到指定客户端
func (h *SSEHub) SendToClient(clientID string, event *SSEEvent) bool {
	h.RLock()
	client, exists := h.clients[clientID]
	if exists {
		h.RUnlock()
		h.Lock()
		h.lastPing[clientID] = time.Now() // 更新心跳时间
		h.Unlock()
	} else {
		h.RUnlock()
		return false
	}

	if client.shouldReceiveEvent(event) {
		select {
		case client.MessageChan <- event:
			return true
		default:
			return false
		}
	}
	return false
}

// GetClients 获取所有在线客户端ID
func (h *SSEHub) GetClients() []string {
	h.RLock()
	defer h.RUnlock()

	clients := make([]string, 0, len(h.clients))
	for id := range h.clients {
		clients = append(clients, id)
	}
	return clients
}

// shouldReceiveEvent 检查客户端是否应该接收该事件
func (c *_SSEClient) shouldReceiveEvent(event *SSEEvent) bool {
	if len(c.EventFilters) == 0 {
		return true
	}
	for _, filter := range c.EventFilters {
		if filter == event.Event {
			return true
		}
	}
	return false
}

// listen 监听并处理客户端消息
func (c *_SSEClient) listen() {
	defer func() {
		// 在连接结束时注销客户端
		if c.Connection != nil && c.Connection.hub != nil {
			c.Connection.hub.unregister <- c
		}
		c.CloseOnce.Do(func() {
			close(c.Disconnected)
		})
	}()

	flusher, ok := c.Connection.Writer.(http.Flusher)
	if !ok {
		c.Connection.Error("不支持 SSE")
		return
	}

	// 设置初始重试时间
	fmt.Fprintf(c.Connection.Writer, "retry: %d\n\n", defaultRetryInterval)
	flusher.Flush()

	for {
		select {
		case <-c.Connection.Request.Context().Done():
			return
		case <-c.done:
			return
		case event, ok := <-c.MessageChan:
			if !ok {
				return
			}
			if err := c.sendEvent(event, flusher); err != nil {
				c.Connection.Error(fmt.Sprintf("发送事件失败: %v", err))
				return
			}
		}
	}
}

// sendEvent 发送 SSE 事件
func (c *_SSEClient) sendEvent(event *SSEEvent, flusher http.Flusher) error {
	// 检查连接是否已关闭
	select {
	case <-c.Connection.Request.Context().Done():
		return fmt.Errorf("连接已关闭")
	default:
		// 连接仍然活跃，继续处理
	}

	if event.ID != "" {
		fmt.Fprintf(c.Connection.Writer, "id: %s\n", event.ID)
		c.LastEventID = event.ID
	}

	if event.Event != "" {
		fmt.Fprintf(c.Connection.Writer, "event: %s\n", event.Event)
	}

	if event.Retry > 0 {
		fmt.Fprintf(c.Connection.Writer, "retry: %d\n", event.Retry)
	}

	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("序列化事件数据失败: %v", err)
	}

	// 写入数据
	if _, err := fmt.Fprintf(c.Connection.Writer, "data: %s\n\n", data); err != nil {
		return fmt.Errorf("写入数据失败: %v", err)
	}

	// 刷新连接
	flusher.Flush()
	return nil
}

// 清理不活跃的客户端
func (h *SSEHub) cleanupInactiveClients() {
	now := time.Now()
	for clientID, lastPing := range h.lastPing {
		if now.Sub(lastPing) > h.pingTimeout {
			// 客户端超时，清理相关资源
			h.removeClient(clientID)
		}
	}
}

// 移除客户端
func (h *SSEHub) removeClient(clientID string) {
	h.Lock()
	defer h.Unlock()

	if client, exists := h.clients[clientID]; exists {
		// 安全地关闭通道
		select {
		case <-client.MessageChan: // 检查通道是否已关闭
			// 通道已关闭，不需要再次关闭
		default:
			close(client.MessageChan)
		}

		// 安全地关闭断开连接通道
		client.CloseOnce.Do(func() {
			close(client.Disconnected)
		})

		delete(h.clients, clientID)
		delete(h.lastPing, clientID)
	}
}
