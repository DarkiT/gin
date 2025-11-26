package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/darkit/gin/pkg/sse"
)

func main() {
	// 创建SSE Hub
	hub := sse.NewHub(nil) // 使用默认配置

	// 创建退出信号监听
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动Hub
	go hub.Run(ctx)

	// 每秒广播一条消息
	go func() {
		count := 0
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				count++
				event := &sse.Event{
					Event: "message",
					Data:  fmt.Sprintf("这是第 %d 条消息", count),
					ID:    fmt.Sprintf("%d", time.Now().UnixNano()),
				}
				hub.Broadcast(event)
				log.Printf("广播消息: %v", event.Data)
			case <-ctx.Done():
				return
			}
		}
	}()

	// 设置路由
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		// 创建新客户端
		client := sse.NewClient(w, r)

		// 向Hub注册客户端
		hub.RegisterClient(client)

		// 启动客户端消息监听
		client.Listen()

		// 客户端断开连接后清理资源
		log.Printf("客户端 %s 断开连接", client.ID)
	})

	// 提供HTML页面用于测试
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <meta charSet="utf-8"/>
	<title>SSE 测试</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        #messages { border: 1px solid #ccc; padding: 10px; height: 300px; overflow-y: scroll; }
        .message { margin: 5px 0; padding: 5px; background-color: #f0f0f0; }
    </style>
</head>
<body>
    <h1>SSE 测试页面</h1>
    <div id="messages"></div>
    <script>
        const messagesDiv = document.getElementById('messages');
        
        function addMessage(text) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            messageDiv.textContent = text;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        // 连接SSE
        const eventSource = new EventSource('/events');
        
        // 监听消息事件
        eventSource.addEventListener('message', function(e) {
            addMessage(e.data);
        });
        
        // 监听连接打开事件
        eventSource.onopen = function() {
            addMessage('SSE 连接已建立');
        };
        
        // 监听错误事件
        eventSource.onerror = function() {
            addMessage('SSE 连接错误，尝试重新连接...');
        };
    </script>
</body>
</html>
	`); err != nil {
			log.Printf("write error: %v", err)
		}
	})

	// 获取客户端列表的API
	http.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(w, `{"clients": %q}`, hub.GetClients()); err != nil {
			log.Printf("write error: %v", err)
		}
	})

	// 启动HTTP服务器
	server := &http.Server{
		Addr: ":8080",
	}

	// 优雅关闭
	go func() {
		// 监听终止信号
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		log.Println("正在关闭服务器...")
		cancel() // 通知所有goroutine退出

		// 设置5秒超时强制关闭
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("服务器关闭错误: %v", err)
		}
	}()

	log.Println("SSE 服务器启动在 http://localhost:8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务器错误: %v", err)
	}

	log.Println("服务器已关闭")
}
