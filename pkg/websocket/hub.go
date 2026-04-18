package websocket

import (
	"sync"
)

// WebSocketHub WebSocket 连接管理中心
type WebSocketHub struct {
	// connections 所有活跃连接，key 为用户 ID
	connections map[string]*WebSocket
	// rooms 房间管理，第一层 key 为房间 ID，第二层 key 为用户 ID
	rooms map[string]map[string]*WebSocket
	// mu 读写锁
	mu sync.RWMutex
}

// NewWebSocketHub 创建连接管理中心
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		connections: make(map[string]*WebSocket),
		rooms:       make(map[string]map[string]*WebSocket),
	}
}

// Register 注册连接
func (h *WebSocketHub) Register(ws *WebSocket) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 如果用户已存在连接，先关闭旧连接
	if oldWS, exists := h.connections[ws.userID]; exists {
		_ = oldWS.Close()
	}

	h.connections[ws.userID] = ws
}

// Unregister 注销连接
func (h *WebSocketHub) Unregister(ws *WebSocket) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 从连接池中删除
	delete(h.connections, ws.userID)

	// 从所有房间中删除
	for roomID := range h.rooms {
		delete(h.rooms[roomID], ws.userID)
		// 如果房间为空，删除房间
		if len(h.rooms[roomID]) == 0 {
			delete(h.rooms, roomID)
		}
	}

	// 关闭连接
	_ = ws.Close()
}

// Get 获取指定用户的连接
func (h *WebSocketHub) Get(userID string) (*WebSocket, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ws, exists := h.connections[userID]
	return ws, exists
}

// GetAll 获取所有连接
func (h *WebSocketHub) GetAll() []*WebSocket {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]*WebSocket, 0, len(h.connections))
	for _, ws := range h.connections {
		result = append(result, ws)
	}
	return result
}

// Count 获取连接总数
func (h *WebSocketHub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.connections)
}

// Broadcast 广播消息给所有连接
func (h *WebSocketHub) Broadcast(message any) error {
	h.mu.RLock()
	connections := make([]*WebSocket, 0, len(h.connections))
	for _, ws := range h.connections {
		connections = append(connections, ws)
	}
	h.mu.RUnlock()

	var lastErr error
	for _, ws := range connections {
		if err := ws.WriteJSON(message); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// BroadcastText 广播文本消息给所有连接
func (h *WebSocketHub) BroadcastText(text string) error {
	h.mu.RLock()
	connections := make([]*WebSocket, 0, len(h.connections))
	for _, ws := range h.connections {
		connections = append(connections, ws)
	}
	h.mu.RUnlock()

	var lastErr error
	for _, ws := range connections {
		if err := ws.WriteText(text); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Send 发送消息给指定用户
func (h *WebSocketHub) Send(userID string, message any) error {
	h.mu.RLock()
	ws, exists := h.connections[userID]
	h.mu.RUnlock()

	if !exists {
		return ErrConnectionNotFound
	}

	return ws.WriteJSON(message)
}

// SendText 发送文本消息给指定用户
func (h *WebSocketHub) SendText(userID string, text string) error {
	h.mu.RLock()
	ws, exists := h.connections[userID]
	h.mu.RUnlock()

	if !exists {
		return ErrConnectionNotFound
	}

	return ws.WriteText(text)
}

// JoinRoom 加入房间
func (h *WebSocketHub) JoinRoom(userID, roomID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ws, exists := h.connections[userID]
	if !exists {
		return ErrConnectionNotFound
	}

	// 创建房间（如果不存在）
	if _, exists := h.rooms[roomID]; !exists {
		h.rooms[roomID] = make(map[string]*WebSocket)
	}

	h.rooms[roomID][userID] = ws
	return nil
}

// LeaveRoom 离开房间
func (h *WebSocketHub) LeaveRoom(userID, roomID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	room, exists := h.rooms[roomID]
	if !exists {
		return ErrRoomNotFound
	}

	delete(room, userID)

	// 如果房间为空，删除房间
	if len(room) == 0 {
		delete(h.rooms, roomID)
	}

	return nil
}

// BroadcastToRoom 广播消息给房间内所有用户
func (h *WebSocketHub) BroadcastToRoom(roomID string, message any) error {
	h.mu.RLock()
	room, exists := h.rooms[roomID]
	if !exists {
		h.mu.RUnlock()
		return ErrRoomNotFound
	}

	// 复制房间连接列表
	connections := make([]*WebSocket, 0, len(room))
	for _, ws := range room {
		connections = append(connections, ws)
	}
	h.mu.RUnlock()

	var lastErr error
	for _, ws := range connections {
		if err := ws.WriteJSON(message); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// BroadcastTextToRoom 广播文本消息给房间内所有用户
func (h *WebSocketHub) BroadcastTextToRoom(roomID string, text string) error {
	h.mu.RLock()
	room, exists := h.rooms[roomID]
	if !exists {
		h.mu.RUnlock()
		return ErrRoomNotFound
	}

	// 复制房间连接列表
	connections := make([]*WebSocket, 0, len(room))
	for _, ws := range room {
		connections = append(connections, ws)
	}
	h.mu.RUnlock()

	var lastErr error
	for _, ws := range connections {
		if err := ws.WriteText(text); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// GetRoomMembers 获取房间成员列表
func (h *WebSocketHub) GetRoomMembers(roomID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	room, exists := h.rooms[roomID]
	if !exists {
		return nil
	}

	members := make([]string, 0, len(room))
	for userID := range room {
		members = append(members, userID)
	}
	return members
}

// RoomCount 获取房间成员数量
func (h *WebSocketHub) RoomCount(roomID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	room, exists := h.rooms[roomID]
	if !exists {
		return 0
	}
	return len(room)
}

// GetRooms 获取所有房间 ID 列表
func (h *WebSocketHub) GetRooms() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rooms := make([]string, 0, len(h.rooms))
	for roomID := range h.rooms {
		rooms = append(rooms, roomID)
	}
	return rooms
}

// IsInRoom 检查用户是否在房间中
func (h *WebSocketHub) IsInRoom(userID, roomID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	room, exists := h.rooms[roomID]
	if !exists {
		return false
	}

	_, inRoom := room[userID]
	return inRoom
}
