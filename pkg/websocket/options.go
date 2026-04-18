package websocket

import (
	"net/http"
	"time"
)

// wsOptions WebSocket 选项配置
type wsOptions struct {
	// PingInterval Ping 消息发送间隔
	pingInterval time.Duration
	// PongTimeout 等待 Pong 响应的超时时间
	pongTimeout time.Duration
	// MaxMessageSize 最大消息大小（字节）
	maxMessageSize int64
	// ReadBufferSize 读缓冲区大小
	readBufferSize int
	// WriteBufferSize 写缓冲区大小
	writeBufferSize int
	// CheckOrigin 自定义来源校验（可选）
	checkOrigin func(r *http.Request) bool
}

// WSOption WebSocket 选项函数
type WSOption func(*wsOptions)

// defaultWSOptions 返回默认选项
func defaultWSOptions() *wsOptions {
	return &wsOptions{
		pingInterval:    54 * time.Second, // 54秒发送一次 Ping
		pongTimeout:     60 * time.Second, // 60秒 Pong 超时
		maxMessageSize:  512 * 1024,       // 512KB
		readBufferSize:  1024,             // 1KB
		writeBufferSize: 1024,             // 1KB
	}
}

// DefaultWSOptions 返回默认选项（导出）
func DefaultWSOptions() *wsOptions {
	return defaultWSOptions()
}

// ReadBufferSize 获取读缓冲区大小
func (opts *wsOptions) ReadBufferSize() int {
	return opts.readBufferSize
}

// WriteBufferSize 获取写缓冲区大小
func (opts *wsOptions) WriteBufferSize() int {
	return opts.writeBufferSize
}

// CheckOrigin 获取来源校验函数
func (opts *wsOptions) CheckOrigin() func(r *http.Request) bool {
	return opts.checkOrigin
}

// WithWSPingInterval 设置 Ping 消息发送间隔
func WithWSPingInterval(interval time.Duration) WSOption {
	return func(opts *wsOptions) {
		if interval > 0 {
			opts.pingInterval = interval
		}
	}
}

// WithWSPongTimeout 设置等待 Pong 响应的超时时间
func WithWSPongTimeout(timeout time.Duration) WSOption {
	return func(opts *wsOptions) {
		if timeout > 0 {
			opts.pongTimeout = timeout
		}
	}
}

// WithWSMaxMessageSize 设置最大消息大小
func WithWSMaxMessageSize(size int64) WSOption {
	return func(opts *wsOptions) {
		if size > 0 {
			opts.maxMessageSize = size
		}
	}
}

// WithWSReadBufferSize 设置读缓冲区大小
func WithWSReadBufferSize(size int) WSOption {
	return func(opts *wsOptions) {
		if size > 0 {
			opts.readBufferSize = size
		}
	}
}

// WithWSWriteBufferSize 设置写缓冲区大小
func WithWSWriteBufferSize(size int) WSOption {
	return func(opts *wsOptions) {
		if size > 0 {
			opts.writeBufferSize = size
		}
	}
}

// WithWSCheckOrigin 设置来源校验函数。
func WithWSCheckOrigin(fn func(r *http.Request) bool) WSOption {
	return func(opts *wsOptions) {
		opts.checkOrigin = fn
	}
}

// WithWSAllowAllOrigins 允许所有来源（不建议生产环境使用）。
func WithWSAllowAllOrigins() WSOption {
	return func(opts *wsOptions) {
		opts.checkOrigin = func(r *http.Request) bool {
			return true
		}
	}
}
