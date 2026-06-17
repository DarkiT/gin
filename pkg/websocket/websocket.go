package websocket

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WebSocket WebSocket 连接封装
type WebSocket struct {
	conn    *websocket.Conn
	id      string
	userID  string
	readMu  sync.Mutex
	writeMu sync.Mutex
	stateMu sync.RWMutex
	closed  bool
	closeMu sync.Mutex
	opts    *wsOptions
}

// NewWebSocket 创建 WebSocket 连接
func NewWebSocket(conn *websocket.Conn, userID string, opts *wsOptions) *WebSocket {
	if opts == nil {
		opts = defaultWSOptions()
	}
	ws := &WebSocket{
		conn:   conn,
		id:     uuid.New().String(),
		userID: userID,
		opts:   opts,
	}

	// 设置读取限制
	ws.conn.SetReadLimit(opts.maxMessageSize)

	// 设置 Pong 处理器
	_ = ws.conn.SetReadDeadline(time.Now().Add(opts.pongTimeout))
	ws.conn.SetPongHandler(func(string) error {
		_ = ws.conn.SetReadDeadline(time.Now().Add(opts.pongTimeout))
		return nil
	})

	return ws
}

// ID 获取连接 ID
func (ws *WebSocket) ID() string {
	return ws.id
}

// UserID 获取用户 ID
func (ws *WebSocket) UserID() string {
	return ws.userID
}

// Read 读取消息
// 返回消息类型、数据和错误
func (ws *WebSocket) Read() (messageType int, data []byte, err error) {
	ws.readMu.Lock()
	defer ws.readMu.Unlock()

	if ws.isClosed() {
		return 0, nil, websocket.ErrCloseSent
	}

	return ws.conn.ReadMessage()
}

// ReadText 读取文本消息
func (ws *WebSocket) ReadText() (string, error) {
	messageType, data, err := ws.Read()
	if err != nil {
		return "", err
	}

	if messageType != websocket.TextMessage {
		return "", websocket.ErrBadHandshake
	}

	return string(data), nil
}

// ReadJSON 读取 JSON 消息
func (ws *WebSocket) ReadJSON(v any) error {
	ws.readMu.Lock()
	defer ws.readMu.Unlock()

	if ws.isClosed() {
		return websocket.ErrCloseSent
	}

	return ws.conn.ReadJSON(v)
}

// Write 写入消息
func (ws *WebSocket) Write(messageType int, data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	if ws.isClosed() {
		return websocket.ErrCloseSent
	}

	return ws.conn.WriteMessage(messageType, data)
}

// WriteText 写入文本消息
func (ws *WebSocket) WriteText(text string) error {
	return ws.Write(websocket.TextMessage, []byte(text))
}

// WriteJSON 写入 JSON 消息
func (ws *WebSocket) WriteJSON(v any) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	if ws.isClosed() {
		return websocket.ErrCloseSent
	}

	return ws.conn.WriteJSON(v)
}

// WriteBinary 写入二进制消息
func (ws *WebSocket) WriteBinary(data []byte) error {
	return ws.Write(websocket.BinaryMessage, data)
}

// Ping 发送 Ping 消息
func (ws *WebSocket) Ping() error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	if ws.isClosed() {
		return websocket.ErrCloseSent
	}

	return ws.conn.WriteMessage(websocket.PingMessage, nil)
}

// Close 关闭连接
func (ws *WebSocket) Close() error {
	ws.closeMu.Lock()
	defer ws.closeMu.Unlock()

	ws.stateMu.Lock()
	if ws.closed {
		ws.stateMu.Unlock()
		return nil
	}
	ws.closed = true
	ws.stateMu.Unlock()

	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	// 发送关闭消息
	_ = ws.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return ws.conn.Close()
}

// IsClosed 检查连接是否已关闭
func (ws *WebSocket) IsClosed() bool {
	return ws.isClosed()
}

func (ws *WebSocket) isClosed() bool {
	ws.stateMu.RLock()
	defer ws.stateMu.RUnlock()
	return ws.closed
}

// StartPingPong 启动心跳检测（在单独的 goroutine 中运行）
func (ws *WebSocket) StartPingPong() {
	ticker := time.NewTicker(ws.opts.pingInterval)
	defer ticker.Stop()

	for range ticker.C {
		if ws.IsClosed() {
			return
		}

		if err := ws.Ping(); err != nil {
			_ = ws.Close()
			return
		}
	}
}

// Message WebSocket 消息结构
type Message struct {
	// Type 消息类型
	Type string `json:"type"`
	// Data 消息数据
	Data json.RawMessage `json:"data"`
}

// NewTextMessage 创建文本消息
func NewTextMessage(msgType string, data any) (*Message, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return &Message{
		Type: msgType,
		Data: jsonData,
	}, nil
}
