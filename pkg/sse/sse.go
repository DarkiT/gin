// Package sse 提供基于Server-Sent Events的实时通信功能
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultHistorySize 默认历史记录大小
	DefaultHistorySize = 50
	// DefaultBufferSize 默认缓冲区大小
	DefaultBufferSize = 512
	// DefaultRetryInterval 默认重试间隔（毫秒）
	DefaultRetryInterval = 3000
	// DefaultPingInterval 默认心跳间隔
	DefaultPingInterval = 10 * time.Second
	// DefaultPingTimeout 默认心跳超时时间
	DefaultPingTimeout = 30 * time.Second
)

// 事件对象池 - 减少GC压力
var eventPool = sync.Pool{
	New: func() interface{} {
		return &Event{}
	},
}

// GetEvent 从对象池获取事件对象
func GetEvent() *Event {
	return eventPool.Get().(*Event)
}

// PutEvent 将事件对象放回对象池
func PutEvent(event *Event) {
	// 清理事件数据
	event.Event = ""
	event.Data = nil
	event.ID = ""
	event.Retry = 0
	eventPool.Put(event)
}

// Event SSE 事件结构体
type Event struct {
	// Event 事件名称
	Event string `json:"event"`
	// Data 事件数据
	Data any `json:"data"`
	// ID 事件ID
	ID string `json:"id"`
	// Retry 重试时间（毫秒）
	Retry int `json:"retry"`
}

// Client SSE 客户端结构体
type Client struct {
	// ID 客户端唯一标识
	ID string
	// ResponseWriter 客户端连接的响应写入器
	ResponseWriter http.ResponseWriter
	// Request 客户端请求
	Request *http.Request
	// MessageChan 消息通道
	MessageChan chan *Event
	// Disconnected 断开连接信号
	Disconnected chan struct{}
	// CloseOnce 确保只关闭一次
	CloseOnce sync.Once
	// LastEventID 最后接收的事件ID
	LastEventID string
	// EventFilters 事件过滤器，只接收指定事件
	EventFilters []string
	// done 用于优雅关闭
	done chan struct{}
	// firstEvent 标记是否是第一个事件
	firstEvent bool

	metaMu sync.RWMutex
}

// ClientOption 自定义客户端属性
type ClientOption func(*Client)

// Hub SSE 连接管理中心
type Hub struct {
	// 互斥锁
	mu sync.RWMutex
	// 所有已连接的客户端
	clients map[string]*Client
	// 注册通道
	register chan *Client
	// 注销通道
	unregister chan *Client
	// 广播通道
	broadcast chan *Event
	// 用于优雅关闭
	done chan struct{}
	// Hub 运行状态
	running bool

	// 历史事件锁
	historyMu sync.RWMutex
	// 历史事件缓存
	eventHistory []*Event
	// 历史记录大小
	historySize int

	// 客户端心跳时间锁
	pingMu sync.RWMutex
	// 记录每个客户端最后一次心跳时间
	lastPing map[string]time.Time
	// 心跳超时时间
	pingTimeout time.Duration
	// 心跳间隔
	pingInterval time.Duration
	// 重试间隔（毫秒）
	retryInterval int

	// 性能统计
	statsMu          sync.RWMutex
	totalMessages    int64
	totalBroadcasts  int64
	totalConnections int64
	startTime        time.Time
}

// Config Hub配置
type Config struct {
	// HistorySize 历史记录大小
	HistorySize int
	// PingTimeout 心跳超时时间
	PingTimeout time.Duration
	// PingInterval 心跳间隔
	PingInterval time.Duration
	// RetryInterval 重试间隔（毫秒）
	RetryInterval int
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		HistorySize:   DefaultHistorySize,
		PingTimeout:   DefaultPingTimeout,
		PingInterval:  DefaultPingInterval,
		RetryInterval: DefaultRetryInterval,
	}
}

// NewHub 创建新的 SSE Hub
func NewHub(config *Config) *Hub {
	if config == nil {
		config = DefaultConfig()
	}

	// 确保配置项有有效的默认值
	historySize := config.HistorySize
	if historySize <= 0 {
		historySize = DefaultHistorySize
	}

	pingTimeout := config.PingTimeout
	if pingTimeout <= 0 {
		pingTimeout = DefaultPingTimeout
	}

	pingInterval := config.PingInterval
	if pingInterval <= 0 {
		pingInterval = DefaultPingInterval
	}

	retryInterval := config.RetryInterval
	if retryInterval <= 0 {
		retryInterval = DefaultRetryInterval
	}

	return &Hub{
		clients:       make(map[string]*Client),
		register:      make(chan *Client, DefaultBufferSize),
		unregister:    make(chan *Client, DefaultBufferSize),
		broadcast:     make(chan *Event, DefaultBufferSize),
		done:          make(chan struct{}),
		historySize:   historySize,
		eventHistory:  make([]*Event, 0, historySize),
		lastPing:      make(map[string]time.Time),
		pingTimeout:   pingTimeout,
		pingInterval:  pingInterval,
		retryInterval: retryInterval,
		startTime:     time.Now(),
	}
}

// Run 运行 SSE Hub
func (h *Hub) Run(ctx context.Context) {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}

	// 重新初始化通道
	h.register = make(chan *Client, DefaultBufferSize)
	h.unregister = make(chan *Client, DefaultBufferSize)
	h.broadcast = make(chan *Event, DefaultBufferSize)
	h.done = make(chan struct{})
	h.running = true
	h.mu.Unlock()

	ticker := time.NewTicker(h.pingInterval)
	defer ticker.Stop()

	// 调整清理定时器间隔为 5 秒
	cleanupTicker := time.NewTicker(5 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case client := <-h.register:
			h.registerClient(client)
		case client := <-h.unregister:
			if client != nil {
				h.removeClient(client.getID())
			}
		case event := <-h.broadcast:
			// 保存到历史记录
			h.saveToHistory(event)
			// 广播消息
			h.broadcastEvent(event)
			// 更新统计
			h.statsMu.Lock()
			h.totalBroadcasts++
			h.statsMu.Unlock()
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
		case <-ctx.Done():
			// 外部上下文结束，优雅关闭
			h.shutdown()
			return
		}
	}
}

// 注册客户端
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	clientID := client.getID()
	h.clients[clientID] = client
	h.mu.Unlock()

	h.pingMu.Lock()
	h.lastPing[clientID] = time.Now() // 记录初始心跳时间
	h.pingMu.Unlock()

	// 更新统计信息
	h.statsMu.Lock()
	h.totalConnections++
	h.statsMu.Unlock()

	// 发送历史消息
	h.sendHistoryEvents(client)
}

// 保存事件到历史记录
func (h *Hub) saveToHistory(event *Event) {
	h.historyMu.Lock()
	defer h.historyMu.Unlock()

	h.eventHistory = append(h.eventHistory, event)
	if len(h.eventHistory) > h.historySize {
		h.eventHistory = h.eventHistory[1:]
	}
}

// 发送历史事件
func (h *Hub) sendHistoryEvents(client *Client) {
	if !h.IsRunning() {
		return
	}

	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	// 找到上次接收的位置
	startIdx := 0
	lastEventID := client.getLastEventID()
	if lastEventID != "" {
		for i, event := range h.eventHistory {
			if event.ID == lastEventID {
				startIdx = i + 1
				break
			}
		}
	}

	// 发送错过的消息
	for i := startIdx; i < len(h.eventHistory); i++ {
		// 检查客户端是否已关闭
		select {
		case <-client.done:
			// 客户端已关闭，停止发送
			return
		default:
			// 客户端仍然活跃
		}

		event := h.eventHistory[i]
		if client.shouldReceiveEvent(event) {
			select {
			case client.MessageChan <- event:
				// 消息发送成功，更新统计
				h.statsMu.Lock()
				h.totalMessages++
				h.statsMu.Unlock()
			case <-client.done:
				// 客户端已关闭
				return
			default:
				// 如果客户端接收太慢，跳过
				continue
			}
		}
	}
}

// 广播事件到所有客户端
func (h *Hub) broadcastEvent(event *Event) {
	if !h.IsRunning() {
		return
	}

	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()

	for _, client := range clients {
		if _, backpressure := h.pushEventToClient(client, event, false, true); backpressure {
			// 慢客户端直接移除，避免堵塞
			go h.removeClient(client.getID())
		}
	}
}

// 发送心跳
func (h *Hub) sendPing() {
	if !h.IsRunning() {
		return
	}

	now := time.Now()
	pingEvent := &Event{
		Event: "ping",
		Data:  now.Unix(),
		ID:    generateEventID(),
	}

	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()

	for _, client := range clients {
		if _, backpressure := h.pushEventToClient(client, pingEvent, true, false); backpressure {
			go h.removeClient(client.getID())
		}
	}
}

// pushEventToClient 封装统一的非阻塞事件发送逻辑
func (h *Hub) pushEventToClient(client *Client, event *Event, updatePing bool, countStats bool) (sent bool, backpressure bool) {
	if !client.shouldReceiveEvent(event) {
		return false, false
	}

	clientID := client.getID()
	defer func() {
		if r := recover(); r != nil {
			h.removeClient(clientID)
			sent = false
			backpressure = false
		}
	}()
	select {
	case <-client.done:
		h.removeClient(clientID)
		return false, false
	default:
	}

	select {
	case client.MessageChan <- event:
		if updatePing {
			h.pingMu.Lock()
			h.lastPing[clientID] = time.Now()
			h.pingMu.Unlock()
		}
		if countStats {
			h.statsMu.Lock()
			h.totalMessages++
			h.statsMu.Unlock()
		}
		return true, false
	case <-client.done:
		h.removeClient(clientID)
		return false, false
	default:
		return false, true
	}
}

// 优雅关闭
func (h *Hub) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, client := range h.clients {
		h.closeClient(client)
	}
	h.clients = make(map[string]*Client)

	h.pingMu.Lock()
	h.lastPing = make(map[string]time.Time)
	h.pingMu.Unlock()
}

// closeClient 安全地关闭客户端
func (h *Hub) closeClient(client *Client) {
	client.CloseOnce.Do(func() {
		close(client.MessageChan)
		close(client.Disconnected)
		close(client.done)
	})
}

// Broadcast 广播消息
func (h *Hub) Broadcast(event *Event) {
	if !h.IsRunning() {
		return
	}
	h.broadcast <- event
}

// Close 关闭 Hub
func (h *Hub) Close() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	h.mu.Unlock()

	// 安全地关闭通道
	select {
	case <-h.done:
		// 通道已关闭，无需再次关闭
	default:
		close(h.done)
	}

	// 立即关闭所有客户端并清理状态
	h.shutdown()
}

// IsRunning 检查 Hub 是否正在运行
func (h *Hub) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// 清理不活跃的客户端
func (h *Hub) cleanupInactiveClients() {
	// 使用写锁确保在检查和修改过程中不会有竞争条件
	h.pingMu.Lock()
	now := time.Now()
	inactiveClients := make([]string, 0)

	for clientID, lastPing := range h.lastPing {
		if now.Sub(lastPing) > h.pingTimeout {
			inactiveClients = append(inactiveClients, clientID)
		}
	}
	h.pingMu.Unlock()

	// 移除不活跃的客户端
	if len(inactiveClients) > 0 {
		for _, clientID := range inactiveClients {
			// 确保立即移除，不通过通道
			h.removeClient(clientID)
		}
	}
}

// removeClient 移除客户端
func (h *Hub) removeClient(clientID string) {
	h.mu.Lock()
	client, exists := h.clients[clientID]
	if exists {
		h.closeClient(client)
		delete(h.clients, clientID)
	}
	h.mu.Unlock()

	h.pingMu.Lock()
	delete(h.lastPing, clientID)
	h.pingMu.Unlock()
}

// SendToClient 发送消息到指定客户端
func (h *Hub) SendToClient(clientID string, event *Event) bool {
	if !h.IsRunning() {
		return false
	}

	h.mu.RLock()
	client, exists := h.clients[clientID]
	h.mu.RUnlock()

	if !exists {
		return false
	}

	// 检查客户端是否已关闭
	select {
	case <-client.done:
		// 客户端已关闭
		h.removeClient(clientID)
		return false
	default:
		// 客户端仍然活跃
	}

	h.pingMu.Lock()
	h.lastPing[clientID] = time.Now() // 更新心跳时间
	h.pingMu.Unlock()

	if client.shouldReceiveEvent(event) {
		select {
		case client.MessageChan <- event:
			// 消息发送成功，更新统计
			h.statsMu.Lock()
			h.totalMessages++
			h.statsMu.Unlock()
			return true
		case <-client.done:
			// 客户端已关闭
			h.removeClient(clientID)
			return false
		default:
			return false
		}
	}
	return false
}

// GetClients 获取所有在线客户端ID
func (h *Hub) GetClients() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]string, 0, len(h.clients))
	for id := range h.clients {
		clients = append(clients, id)
	}
	return clients
}

// shouldReceiveEvent 检查客户端是否应该接收该事件
func (c *Client) shouldReceiveEvent(event *Event) bool {
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

func (c *Client) getID() string {
	c.metaMu.RLock()
	defer c.metaMu.RUnlock()
	return c.ID
}

func (c *Client) setLastEventID(id string) {
	c.metaMu.Lock()
	c.LastEventID = id
	c.metaMu.Unlock()
}

func (c *Client) getLastEventID() string {
	c.metaMu.RLock()
	defer c.metaMu.RUnlock()
	return c.LastEventID
}

func (c *Client) consumeFirstEvent() bool {
	c.metaMu.Lock()
	defer c.metaMu.Unlock()
	if c.firstEvent {
		c.firstEvent = false
		return true
	}
	return false
}

// Listen 监听并处理客户端消息
func (c *Client) Listen() {
	defer func() {
		c.CloseOnce.Do(func() {
			close(c.Disconnected)
		})
	}()

	flusher, ok := c.ResponseWriter.(http.Flusher)
	if !ok {
		http.Error(c.ResponseWriter, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-c.done:
			return
		case event, ok := <-c.MessageChan:
			if !ok {
				return
			}
			if err := c.sendEvent(event, flusher); err != nil {
				return
			}
		}
	}
}

// sendEvent 发送 SSE 事件
func (c *Client) sendEvent(event *Event, flusher http.Flusher) error {
	// 检查连接是否已关闭
	select {
	case <-c.Request.Context().Done():
		return fmt.Errorf("连接已关闭")
	default:
		// 连接仍然活跃，继续处理
	}

	if event.ID != "" {
		if _, err := fmt.Fprintf(c.ResponseWriter, "id: %s\n", event.ID); err != nil {
			return fmt.Errorf("写入事件ID失败: %v", err)
		}
		c.setLastEventID(event.ID)
	}

	if event.Event != "" {
		if _, err := fmt.Fprintf(c.ResponseWriter, "event: %s\n", event.Event); err != nil {
			return fmt.Errorf("写入事件名称失败: %v", err)
		}
	}

	// 如果是第一个事件，设置默认重试间隔
	if c.consumeFirstEvent() {
		if _, err := fmt.Fprintf(c.ResponseWriter, "retry: %d\n", DefaultRetryInterval); err != nil {
			return fmt.Errorf("写入默认重试间隔失败: %v", err)
		}
	}

	if event.Retry > 0 {
		if _, err := fmt.Fprintf(c.ResponseWriter, "retry: %d\n", event.Retry); err != nil {
			return fmt.Errorf("写入重试间隔失败: %v", err)
		}
	}

	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("序列化事件数据失败: %v", err)
	}

	// 写入数据
	if _, err := fmt.Fprintf(c.ResponseWriter, "data: %s\n\n", data); err != nil {
		return fmt.Errorf("写入数据失败: %v", err)
	}

	// 刷新连接
	flusher.Flush()
	return nil
}

// NewClient 创建新的 SSE 客户端连接
func NewClient(w http.ResponseWriter, r *http.Request, filters ...string) *Client {
	// 设置 SSE 相关的 HTTP 头
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no") // 禁用 Nginx 缓冲

	client := &Client{
		ID:             generateEventID(),
		ResponseWriter: w,
		Request:        r,
		MessageChan:    make(chan *Event, DefaultBufferSize),
		Disconnected:   make(chan struct{}),
		LastEventID:    r.Header.Get("Last-Event-ID"),
		EventFilters:   filters,
		done:           make(chan struct{}),
		firstEvent:     true,
	}

	return client
}

// ApplyClientOptions 在注册前应用客户端配置
func ApplyClientOptions(client *Client, opts ...ClientOption) {
	if client == nil {
		return
	}
	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}
}

// WithClientID 指定客户端 ID
func WithClientID(id string) ClientOption {
	return func(c *Client) {
		if id == "" {
			return
		}
		c.metaMu.Lock()
		c.ID = id
		c.metaMu.Unlock()
	}
}

// Close 关闭客户端连接
func (c *Client) Close() {
	c.CloseOnce.Do(func() {
		close(c.done)
	})
}

// RegisterClient 注册客户端到Hub
func (h *Hub) RegisterClient(client *Client) {
	h.mu.RLock()
	running := h.running
	h.mu.RUnlock()

	if !running {
		// 如果Hub未运行，直接注册客户端
		h.registerClient(client)
		return
	}

	// 使用非阻塞发送，避免在测试中导致死锁
	select {
	case h.register <- client:
		// 发送成功
	default:
		// 通道已满或关闭，直接调用注册方法
		h.registerClient(client)
	}
}

// UnregisterClient 从Hub注销客户端
func (h *Hub) UnregisterClient(client *Client) {
	h.mu.RLock()
	running := h.running
	h.mu.RUnlock()

	if !running {
		// 如果Hub未运行，直接移除客户端
		h.removeClient(client.getID())
		return
	}

	// 使用非阻塞发送，避免在测试中导致死锁
	select {
	case h.unregister <- client:
		// 发送成功
	default:
		// 通道已满或关闭，直接调用移除方法
		h.removeClient(client.getID())
	}
}

// generateEventID 生成统一格式的事件ID
func generateEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// GetStats 获取Hub性能统计信息
func (h *Hub) GetStats() map[string]interface{} {
	h.statsMu.RLock()
	h.mu.RLock()

	stats := map[string]interface{}{
		"total_messages":    h.totalMessages,
		"total_broadcasts":  h.totalBroadcasts,
		"total_connections": h.totalConnections,
		"current_clients":   len(h.clients),
		"uptime_seconds":    time.Since(h.startTime).Seconds(),
		"running":           h.running,
		"history_size":      len(h.eventHistory),
		"max_history_size":  h.historySize,
	}

	h.mu.RUnlock()
	h.statsMu.RUnlock()

	return stats
}

// GetPerformanceMetrics 获取性能指标
func (h *Hub) GetPerformanceMetrics() map[string]interface{} {
	stats := h.GetStats()
	uptime := stats["uptime_seconds"].(float64)

	metrics := map[string]interface{}{
		"messages_per_second":   0.0,
		"broadcasts_per_second": 0.0,
		"connections_per_hour":  0.0,
	}

	if uptime > 0 {
		h.statsMu.RLock()
		metrics["messages_per_second"] = float64(h.totalMessages) / uptime
		metrics["broadcasts_per_second"] = float64(h.totalBroadcasts) / uptime
		metrics["connections_per_hour"] = float64(h.totalConnections) / (uptime / 3600)
		h.statsMu.RUnlock()
	}

	// 合并基础统计和性能指标
	for k, v := range stats {
		metrics[k] = v
	}

	return metrics
}
