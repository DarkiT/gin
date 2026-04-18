package websocket

import original "github.com/gorilla/websocket"

// Conn 复用底层 gorilla 连接类型，供兼容层按需显式引用。
type Conn = original.Conn

// Upgrader 复用底层 gorilla 升级器类型，供兼容层按需显式引用。
type Upgrader = original.Upgrader

const (
	// TextMessage 表示文本消息帧。
	TextMessage = original.TextMessage
	// BinaryMessage 表示二进制消息帧。
	BinaryMessage = original.BinaryMessage
	// CloseMessage 表示关闭消息帧。
	CloseMessage = original.CloseMessage
	// PingMessage 表示 ping 控制帧。
	PingMessage = original.PingMessage
	// CloseNormalClosure 表示正常关闭状态码。
	CloseNormalClosure = original.CloseNormalClosure
	// CloseGoingAway 表示连接离开状态码。
	CloseGoingAway = original.CloseGoingAway
	// CloseAbnormalClosure 表示异常关闭状态码。
	CloseAbnormalClosure = original.CloseAbnormalClosure
)

var (
	// ErrCloseSent 表示关闭帧已发送。
	ErrCloseSent = original.ErrCloseSent
	// ErrBadHandshake 表示握手异常。
	ErrBadHandshake = original.ErrBadHandshake
	// DefaultDialer 复用底层默认拨号器，供测试与客户端回放使用。
	DefaultDialer = original.DefaultDialer
	// FormatCloseMessage 复用底层关闭消息格式化函数。
	FormatCloseMessage = original.FormatCloseMessage
	// IsUnexpectedCloseError 复用底层异常关闭判断函数。
	IsUnexpectedCloseError = original.IsUnexpectedCloseError
)
