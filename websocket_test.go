package gin

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/darkit/gin/pkg/websocket"
	ws "github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpgradeWebSocket 测试升级连接
func TestUpgradeWebSocket(t *testing.T) {
	engine := Default()

	// 测试升级成功
	engine.GET("/ws", func(c *Context) {
		wsConn, err := c.UpgradeWebSocket("user123")
		require.NoError(t, err)
		assert.NotNil(t, wsConn)
		assert.Equal(t, "user123", wsConn.UserID())
		defer func() {
			if closeErr := wsConn.Close(); closeErr != nil {
				t.Errorf("close ws connection: %v", closeErr)
			}
		}()
	})

	// 创建测试服务器
	server := httptest.NewServer(engine)
	defer server.Close()

	// 将 http:// 替换为 ws://
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// 连接 WebSocket
	conn, _, err := ws.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close client connection: %v", closeErr)
		}
	}()

	// 验证连接成功
	assert.NotNil(t, conn)
}

// TestWebSocket_ReadWrite 测试读写消息
func TestWebSocket_ReadWrite(t *testing.T) {
	engine := Default()
	done := make(chan bool)

	engine.GET("/ws", func(c *Context) {
		wsConn, err := c.UpgradeWebSocket("user123")
		require.NoError(t, err)
		defer func() {
			if closeErr := wsConn.Close(); closeErr != nil {
				t.Errorf("close ws connection: %v", closeErr)
			}
		}()

		// 读取消息
		messageType, data, err := wsConn.Read()
		require.NoError(t, err)
		assert.Equal(t, ws.TextMessage, messageType)
		assert.Equal(t, "hello", string(data))

		// 写入响应
		err = wsConn.WriteText("world")
		require.NoError(t, err)

		done <- true
	})

	server := httptest.NewServer(engine)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := ws.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close client connection: %v", closeErr)
		}
	}()

	// 发送消息
	err = conn.WriteMessage(ws.TextMessage, []byte("hello"))
	require.NoError(t, err)

	// 读取响应
	messageType, data, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, ws.TextMessage, messageType)
	assert.Equal(t, "world", string(data))

	<-done
}

// TestWebSocket_JSON 测试 JSON 消息
func TestWebSocket_JSON(t *testing.T) {
	engine := Default()
	done := make(chan bool)

	type TestMessage struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}

	engine.GET("/ws", func(c *Context) {
		wsConn, err := c.UpgradeWebSocket("user123")
		require.NoError(t, err)
		defer func() {
			if closeErr := wsConn.Close(); closeErr != nil {
				t.Errorf("close ws connection: %v", closeErr)
			}
		}()

		// 读取 JSON 消息
		var msg TestMessage
		err = wsConn.ReadJSON(&msg)
		require.NoError(t, err)
		assert.Equal(t, "greeting", msg.Type)
		assert.Equal(t, "hello", msg.Text)

		// 写入 JSON 响应
		response := TestMessage{
			Type: "greeting",
			Text: "world",
		}
		err = wsConn.WriteJSON(response)
		require.NoError(t, err)

		done <- true
	})

	server := httptest.NewServer(engine)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := ws.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close client connection: %v", closeErr)
		}
	}()

	// 发送 JSON 消息
	msg := TestMessage{
		Type: "greeting",
		Text: "hello",
	}
	err = conn.WriteJSON(msg)
	require.NoError(t, err)

	// 读取 JSON 响应
	var response TestMessage
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "greeting", response.Type)
	assert.Equal(t, "world", response.Text)

	<-done
}

// TestWebSocketHub_Broadcast 测试广播
func TestWebSocketHub_Broadcast(t *testing.T) {
	hub := websocket.NewWebSocketHub()
	engine := Default()

	// 创建多个连接的通道
	ready := make(chan bool, 2)
	done := make(chan bool, 2)

	// 创建处理器
	handler := func(c *Context) {
		userID := c.Query("user")
		wsConn, err := c.UpgradeWebSocket(userID)
		require.NoError(t, err)

		// 注册到 Hub
		hub.Register(wsConn)
		ready <- true

		// 等待测试完成信号
		<-done

		hub.Unregister(wsConn)
		if err := wsConn.Close(); err != nil {
			t.Errorf("close hub connection: %v", err)
		}
	}

	engine.GET("/ws", handler)

	server := httptest.NewServer(engine)
	defer server.Close()

	// 创建两个客户端连接
	wsURL1 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user1"
	conn1, _, err := ws.DefaultDialer.Dial(wsURL1, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn1.Close(); closeErr != nil {
			t.Errorf("close user1 connection: %v", closeErr)
		}
	}()

	wsURL2 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user2"
	conn2, _, err := ws.DefaultDialer.Dial(wsURL2, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn2.Close(); closeErr != nil {
			t.Errorf("close user2 connection: %v", closeErr)
		}
	}()

	// 等待两个连接都就绪
	<-ready
	<-ready
	time.Sleep(100 * time.Millisecond)

	// 广播消息
	err = hub.Broadcast(map[string]string{"text": "broadcast message"})
	require.NoError(t, err)

	// 验证两个客户端都收到消息
	var msg1 map[string]string
	err = conn1.ReadJSON(&msg1)
	require.NoError(t, err)
	assert.Equal(t, "broadcast message", msg1["text"])

	var msg2 map[string]string
	err = conn2.ReadJSON(&msg2)
	require.NoError(t, err)
	assert.Equal(t, "broadcast message", msg2["text"])

	// 通知处理器测试完成
	done <- true
	done <- true
}

// TestWebSocketHub_Room 测试房间功能
func TestWebSocketHub_Room(t *testing.T) {
	hub := websocket.NewWebSocketHub()
	engine := Default()

	ready := make(chan bool, 3)
	done := make(chan bool, 3)

	handler := func(c *Context) {
		userID := c.Query("user")
		wsConn, err := c.UpgradeWebSocket(userID)
		require.NoError(t, err)

		hub.Register(wsConn)
		ready <- true

		// 等待测试完成信号
		<-done

		hub.Unregister(wsConn)
		if err := wsConn.Close(); err != nil {
			t.Errorf("close room connection: %v", err)
		}
	}

	engine.GET("/ws", handler)

	server := httptest.NewServer(engine)
	defer server.Close()

	// 创建三个客户端
	wsURL1 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user1"
	conn1, _, err := ws.DefaultDialer.Dial(wsURL1, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn1.Close(); closeErr != nil {
			t.Errorf("close user1 connection: %v", closeErr)
		}
	}()

	wsURL2 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user2"
	conn2, _, err := ws.DefaultDialer.Dial(wsURL2, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn2.Close(); closeErr != nil {
			t.Errorf("close user2 connection: %v", closeErr)
		}
	}()

	wsURL3 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user3"
	conn3, _, err := ws.DefaultDialer.Dial(wsURL3, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn3.Close(); closeErr != nil {
			t.Errorf("close user3 connection: %v", closeErr)
		}
	}()

	// 等待连接就绪
	<-ready
	<-ready
	<-ready
	time.Sleep(100 * time.Millisecond)

	// user1 和 user2 加入 room1
	err = hub.JoinRoom("user1", "room1")
	require.NoError(t, err)
	err = hub.JoinRoom("user2", "room1")
	require.NoError(t, err)

	// 验证房间成员
	members := hub.GetRoomMembers("room1")
	assert.Equal(t, 2, len(members))
	assert.True(t, hub.IsInRoom("user1", "room1"))
	assert.True(t, hub.IsInRoom("user2", "room1"))
	assert.False(t, hub.IsInRoom("user3", "room1"))

	// 向 room1 广播消息
	err = hub.BroadcastToRoom("room1", map[string]string{"text": "room message"})
	require.NoError(t, err)

	// 只有 user1 和 user2 应该收到消息
	var msg1 map[string]string
	err = conn1.ReadJSON(&msg1)
	require.NoError(t, err)
	assert.Equal(t, "room message", msg1["text"])

	var msg2 map[string]string
	err = conn2.ReadJSON(&msg2)
	require.NoError(t, err)
	assert.Equal(t, "room message", msg2["text"])

	// user3 不应该收到消息（设置读取超时）
	require.NoError(t, conn3.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	var msg3 map[string]string
	err = conn3.ReadJSON(&msg3)
	assert.Error(t, err) // 应该超时

	// user1 离开房间
	err = hub.LeaveRoom("user1", "room1")
	require.NoError(t, err)
	assert.False(t, hub.IsInRoom("user1", "room1"))
	assert.Equal(t, 1, hub.RoomCount("room1"))

	// 通知处理器测试完成
	done <- true
	done <- true
	done <- true
}

// TestWebSocketHub_Send 测试定向发送
func TestWebSocketHub_Send(t *testing.T) {
	hub := websocket.NewWebSocketHub()
	engine := Default()

	ready := make(chan bool, 2)
	done := make(chan bool, 2)

	handler := func(c *Context) {
		userID := c.Query("user")
		wsConn, err := c.UpgradeWebSocket(userID)
		require.NoError(t, err)

		hub.Register(wsConn)
		ready <- true

		// 等待测试完成信号
		<-done

		hub.Unregister(wsConn)
		if err := wsConn.Close(); err != nil {
			t.Errorf("close send connection: %v", err)
		}
	}

	engine.GET("/ws", handler)

	server := httptest.NewServer(engine)
	defer server.Close()

	// 创建两个客户端
	wsURL1 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user1"
	conn1, _, err := ws.DefaultDialer.Dial(wsURL1, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn1.Close(); closeErr != nil {
			t.Errorf("close user1 connection: %v", closeErr)
		}
	}()

	wsURL2 := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?user=user2"
	conn2, _, err := ws.DefaultDialer.Dial(wsURL2, nil)
	require.NoError(t, err)
	defer func() {
		if closeErr := conn2.Close(); closeErr != nil {
			t.Errorf("close user2 connection: %v", closeErr)
		}
	}()

	// 等待连接就绪
	<-ready
	<-ready
	time.Sleep(100 * time.Millisecond)

	// 只向 user1 发送消息
	err = hub.Send("user1", map[string]string{"text": "private message"})
	require.NoError(t, err)

	// 验证只有 user1 收到消息
	var msg1 map[string]string
	err = conn1.ReadJSON(&msg1)
	require.NoError(t, err)
	assert.Equal(t, "private message", msg1["text"])

	// 验证 user2 没有收到消息（设置读取超时）
	require.NoError(t, conn2.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	var msg2 map[string]string
	err = conn2.ReadJSON(&msg2)
	assert.Error(t, err) // 应该超时

	// 测试向不存在的用户发送消息
	err = hub.Send("user999", map[string]string{"text": "test"})
	assert.Error(t, err)
	assert.Equal(t, websocket.ErrConnectionNotFound, err)

	// 通知处理器测试完成
	done <- true
	done <- true
}
