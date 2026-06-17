// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"github.com/darkit/gin/pkg/websocket"
	ws "github.com/gorilla/websocket"
)

// UpgradeWebSocket 升级 HTTP 连接为 WebSocket，userID 为连接标识。
// opts 为 WebSocket 选项配置。
func (c *Context) UpgradeWebSocket(userID string, opts ...websocket.WSOption) (*websocket.WebSocket, error) {
	// 合并选项
	options := websocket.DefaultWSOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	// 创建 upgrader
	upgrader := ws.Upgrader{
		ReadBufferSize:  options.ReadBufferSize(),
		WriteBufferSize: options.WriteBufferSize(),
	}
	if options.CheckOrigin() != nil {
		upgrader.CheckOrigin = options.CheckOrigin()
	}

	// 升级连接
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return nil, err
	}

	// 创建 WebSocket 包装
	return websocket.NewWebSocket(conn, userID, options), nil
}
