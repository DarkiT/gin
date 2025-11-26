package sse

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkBroadcast(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 创建测试事件
	event := &Event{
		Event: "benchmark",
		Data:  "benchmark data",
		ID:    "1",
	}

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		hub.Broadcast(event)
	}
}

func BenchmarkClientRegistration(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		// 创建测试客户端
		req := httptest.NewRequest("GET", "/events", nil)
		w := httptest.NewRecorder()
		client := NewClient(w, req)

		// 注册客户端
		hub.RegisterClient(client)
	}
}

func BenchmarkClientUnregistration(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 准备测试数据
	clients := make([]*Client, b.N)
	for i := 0; i < b.N; i++ {
		// 创建测试客户端
		req := httptest.NewRequest("GET", "/events", nil)
		w := httptest.NewRecorder()
		client := NewClient(w, req)

		// 注册客户端
		hub.RegisterClient(client)
		clients[i] = client
	}

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		hub.UnregisterClient(clients[i])
	}
}

func BenchmarkSendToClient(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
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

	// 创建测试事件
	event := &Event{
		Event: "benchmark",
		Data:  "benchmark data",
		ID:    "1",
	}

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		hub.SendToClient(client.ID, event)
	}
}

func BenchmarkConcurrentBroadcast(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 创建多个客户端
	clientCount := 100
	for i := 0; i < clientCount; i++ {
		req := httptest.NewRequest("GET", "/events", nil)
		w := httptest.NewRecorder()
		client := NewClient(w, req)
		hub.RegisterClient(client)
	}

	// 等待注册完成
	time.Sleep(50 * time.Millisecond)

	// 创建测试事件
	event := &Event{
		Event: "benchmark",
		Data:  "benchmark data",
		ID:    "1",
	}

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		hub.Broadcast(event)
	}
}

func BenchmarkHistoryEvents(b *testing.B) {
	// 创建Hub
	hub := NewHub(&Config{
		HistorySize:  100,
		PingInterval: 5 * time.Second,
		PingTimeout:  10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)
	defer hub.Close()

	// 生成历史事件
	for i := 0; i < 50; i++ {
		event := &Event{
			Event: "history",
			Data:  "history data",
			ID:    GenerateEventID(),
		}
		hub.Broadcast(event)
	}

	// 等待事件处理完成
	time.Sleep(50 * time.Millisecond)

	// 重置计时器
	b.ResetTimer()

	// 运行基准测试
	for i := 0; i < b.N; i++ {
		// 创建测试客户端
		req := httptest.NewRequest("GET", "/events", nil)
		w := httptest.NewRecorder()
		client := NewClient(w, req)

		// 注册客户端，这将触发历史事件发送
		hub.RegisterClient(client)

		// 注销客户端以避免内存泄漏
		hub.UnregisterClient(client)
	}
}

// 生成唯一的事件ID
func GenerateEventID() string {
	return time.Now().Format(time.RFC3339Nano)
}
