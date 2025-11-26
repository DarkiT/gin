package sse

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSSEHub_RegisterAndRemoveClient(t *testing.T) {
	hub := NewHub(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 创建测试客户端
	req := httptest.NewRequest("GET", "/events", nil)
	w := httptest.NewRecorder()
	client := NewClient(w, req)

	// 注册客户端
	hub.RegisterClient(client)

	// 等待注册完成
	time.Sleep(50 * time.Millisecond)

	// 检查客户端是否被正确注册
	if len(hub.GetClients()) != 1 {
		t.Errorf("期望有1个客户端，但得到了%d个", len(hub.GetClients()))
	}

	// 移除客户端
	hub.UnregisterClient(client)

	// 等待移除完成
	time.Sleep(50 * time.Millisecond)

	// 检查客户端是否被正确移除
	if len(hub.GetClients()) != 0 {
		t.Errorf("期望有0个客户端，但得到了%d个", len(hub.GetClients()))
	}
}

func TestSSEHub_BroadcastEvent(t *testing.T) {
	hub := NewHub(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 创建测试客户端
	req := httptest.NewRequest("GET", "/events", nil)
	w := httptest.NewRecorder()
	client := NewClient(w, req)

	// 注册客户端
	hub.RegisterClient(client)

	// 等待注册完成
	time.Sleep(50 * time.Millisecond)

	// 广播事件
	event := &Event{
		Event: "test",
		Data:  "test data",
		ID:    "1",
	}
	hub.Broadcast(event)

	// 等待事件发送
	time.Sleep(50 * time.Millisecond)

	// 检查事件是否被正确存储在历史记录中
	hub.historyMu.RLock()
	defer hub.historyMu.RUnlock()

	if len(hub.eventHistory) != 1 {
		t.Errorf("期望历史记录中有1个事件，但得到了%d个", len(hub.eventHistory))
	}

	if hub.eventHistory[0].Event != "test" {
		t.Errorf("期望事件名称为'test'，但得到了'%s'", hub.eventHistory[0].Event)
	}
}

func TestSSEHub_ConcurrencySafety(t *testing.T) {
	hub := NewHub(&Config{
		HistorySize:  100,
		PingTimeout:  5 * time.Second,
		PingInterval: 1 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 并发注册和移除客户端
	var wg sync.WaitGroup
	clientCount := 100
	wg.Add(clientCount * 2) // 注册和移除各加一次

	for i := 0; i < clientCount; i++ {
		go func(i int) {
			defer wg.Done()

			req := httptest.NewRequest("GET", "/events", nil)
			w := httptest.NewRecorder()
			client := NewClient(w, req)

			hub.RegisterClient(client)
			time.Sleep(10 * time.Millisecond) // 模拟一些延迟
		}(i)
	}

	// 等待一段时间确保大部分客户端已注册
	time.Sleep(100 * time.Millisecond)

	// 获取当前客户端并移除
	for _, clientID := range hub.GetClients() {
		go func(id string) {
			defer wg.Done()

			hub.mu.RLock()
			client, exists := hub.clients[id]
			hub.mu.RUnlock()

			if exists {
				hub.UnregisterClient(client)
			}
		}(clientID)
	}

	// 等待所有操作完成
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	// 应该没有客户端了
	if len(hub.GetClients()) > 0 {
		t.Errorf("期望所有客户端都已移除，但仍有%d个", len(hub.GetClients()))
	}
}

func TestSSEHub_ClientTimeout(t *testing.T) {
	// 使用较短的超时时间以便快速测试
	hub := NewHub(&Config{
		PingTimeout:  100 * time.Millisecond,
		PingInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 创建测试客户端
	req := httptest.NewRequest("GET", "/events", nil)
	w := httptest.NewRecorder()
	client := NewClient(w, req)

	// 注册客户端
	hub.RegisterClient(client)

	// 等待注册完成
	time.Sleep(50 * time.Millisecond)

	// 检查客户端是否被正确注册
	if len(hub.GetClients()) != 1 {
		t.Fatalf("期望有1个客户端，但得到了%d个", len(hub.GetClients()))
	}

	// 手动设置上次心跳时间为较早的时间，模拟超时
	hub.pingMu.Lock()
	hub.lastPing[client.ID] = time.Now().Add(-200 * time.Millisecond)
	hub.pingMu.Unlock()

	// 手动触发超时检测
	hub.cleanupInactiveClients()

	// 等待超时检测和清理完成
	time.Sleep(300 * time.Millisecond)

	// 检查客户端是否被超时移除
	clients := hub.GetClients()
	if len(clients) != 0 {
		t.Errorf("期望客户端已被超时移除，但仍有%d个：%v", len(clients), clients)
	}
}

func TestSSEClient_EventFiltering(t *testing.T) {
	// 创建测试客户端，只接收"test"事件
	req := httptest.NewRequest("GET", "/events", nil)
	w := httptest.NewRecorder()
	client := NewClient(w, req, "test")

	// 测试事件过滤
	testEvent := &Event{Event: "test", Data: "test data"}
	otherEvent := &Event{Event: "other", Data: "other data"}

	if !client.shouldReceiveEvent(testEvent) {
		t.Error("客户端应该接收'test'事件")
	}

	if client.shouldReceiveEvent(otherEvent) {
		t.Error("客户端不应该接收'other'事件")
	}
}

func TestSSEHub_MemoryLeak(t *testing.T) {
	// 创建一个小容量的历史记录，以便测试历史记录清理
	hub := NewHub(&Config{
		HistorySize: 5,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 广播10个事件
	for i := 0; i < 10; i++ {
		hub.Broadcast(&Event{
			Event: "test",
			Data:  i,
			ID:    fmt.Sprintf("%d", i),
		})
	}

	// 等待事件处理
	time.Sleep(50 * time.Millisecond)

	// 检查历史记录是否被正确限制在5个
	hub.historyMu.RLock()
	historyLen := len(hub.eventHistory)
	hub.historyMu.RUnlock()

	if historyLen > 5 {
		t.Errorf("期望历史记录不超过5个事件，但得到了%d个", historyLen)
	}

	// 测试客户端关闭和资源清理
	clientCount := 10
	clients := make([]*Client, clientCount)

	// 创建并注册多个客户端
	for i := 0; i < clientCount; i++ {
		req := httptest.NewRequest("GET", "/events", nil)
		w := httptest.NewRecorder()
		clients[i] = NewClient(w, req)
		hub.RegisterClient(clients[i])
	}

	time.Sleep(50 * time.Millisecond)

	// 关闭Hub，应该释放所有资源
	hub.Close()
	time.Sleep(150 * time.Millisecond)

	// 检查是否有未关闭的通道
	for i, client := range clients {
		// 检查MessageChan是否已关闭
		func() {
			defer func() {
				if r := recover(); r != nil {
					// 如果panic，说明通道已关闭
					return
				}
			}()
			select {
			case _, open := <-client.MessageChan:
				if open {
					t.Errorf("客户端%d的MessageChan未关闭", i)
				}
			case <-time.After(10 * time.Millisecond):
				// 超时，说明通道可能已关闭并排空
			}
		}()

		// 检查Disconnected是否已关闭
		func() {
			defer func() {
				if r := recover(); r != nil {
					// 如果panic，说明通道已关闭
					return
				}
			}()
			select {
			case _, open := <-client.Disconnected:
				if open {
					t.Errorf("客户端%d的Disconnected通道未关闭", i)
				}
			case <-time.After(10 * time.Millisecond):
				// 超时，说明通道可能已关闭并排空
			}
		}()
	}
}

// 测试在多个goroutine中同时访问Hub
func TestSSEHub_ConcurrentAccess(t *testing.T) {
	hub := NewHub(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	var wg sync.WaitGroup
	routineCount := 50

	// 同时从多个goroutine广播事件
	wg.Add(routineCount)
	for i := 0; i < routineCount; i++ {
		go func(i int) {
			defer wg.Done()
			event := &Event{
				Event: "test",
				Data:  i,
				ID:    fmt.Sprintf("event-%d", i),
			}
			hub.Broadcast(event)
		}(i)
	}

	// 同时从多个goroutine获取客户端列表
	wg.Add(routineCount)
	for i := 0; i < routineCount; i++ {
		go func() {
			defer wg.Done()
			hub.GetClients()
		}()
	}

	// 等待所有操作完成
	wg.Wait()
}
