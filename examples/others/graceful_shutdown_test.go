package others

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/darkit/gin"
)

// TestGracefulShutdownWithSignal 测试基于信号的优雅停机功能
func TestGracefulShutdownWithSignal(t *testing.T) {
	// 创建测试用的上下文（模拟appCtx）
	testCtx, testCancel := context.WithCancel(context.Background())

	// 模拟信号监听（类似于main.go中的实现）
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// 在测试中，我们不等真正的信号，而是在1秒后模拟信号
		time.Sleep(1 * time.Second)
		log.Println("模拟收到系统信号，触发优雅停机...")
		testCancel()
	}()

	config := &gin.Config{
		SSEEnabled:          true,
		ErrorHandlerEnabled: true,
		SensitiveFilter:     true,
	}

	r := gin.Default(config)

	// 启动SSE服务
	if err := r.StartSSE(); err != nil {
		t.Fatalf("启动SSE失败: %v", err)
	}

	// 启动测试用的后台任务
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				log.Println("测试后台任务运行中...")
			case <-testCtx.Done():
				log.Println("测试后台任务收到停机信号，正在退出...")
				return
			}
		}
	}()

	// 使用测试上下文启动服务器
	serverConfig := gin.DefaultServerConfig()
	serverConfig.Port = "8082"
	serverConfig.GracefulTimeout = 2 * time.Second

	log.Println("测试服务器启动在 http://localhost:8082")
	start := time.Now()
	if err := r.RunWithContext(testCtx, serverConfig); err != nil && err != http.ErrServerClosed {
		t.Fatalf("服务器启动失败: %v", err)
	}

	duration := time.Since(start)
	log.Printf("优雅停机测试完成！服务器运行了 %.2f 秒", duration.Seconds())

	// 验证运行时间应该在1-3秒之间（1秒等待 + 停机时间）
	if duration < 1*time.Second || duration > 3*time.Second {
		t.Errorf("停机时间异常: %v，期望在1-3秒之间", duration)
	}
}
