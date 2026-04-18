package websocket

import "errors"

var (
	// ErrConnectionNotFound 连接不存在
	ErrConnectionNotFound = errors.New("连接不存在")

	// ErrRoomNotFound 房间不存在
	ErrRoomNotFound = errors.New("房间不存在")

	// ErrInvalidMessageType 无效的消息类型
	ErrInvalidMessageType = errors.New("无效的消息类型")
)
