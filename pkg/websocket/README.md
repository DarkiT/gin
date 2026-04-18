# pkg/websocket

`pkg/websocket` 封装 `gorilla/websocket`，提供连接对象、心跳管理与 Hub/房间广播能力。

## 模块用途

- 为单个 WebSocket 连接提供统一读写接口。
- 管理连接 ID、用户 ID、Ping/Pong 心跳。
- 通过 `WebSocketHub` 管理连接、私发、广播与房间。

## 关键类型与函数

### 连接对象

- `type WebSocket`
  - `ID()` / `UserID()`
  - `Read` / `ReadText` / `ReadJSON`
  - `Write` / `WriteText` / `WriteJSON` / `WriteBinary`
  - `Ping()` / `Close()` / `IsClosed()`
  - `StartPingPong()`

### Hub 管理器

- `type WebSocketHub`
  - `NewWebSocketHub()`
  - `Register` / `Unregister`
  - `Get` / `GetAll` / `Count`
  - `Broadcast` / `BroadcastText`
  - `Send` / `SendText`
  - `JoinRoom` / `LeaveRoom`
  - `BroadcastToRoom` / `BroadcastTextToRoom`
  - `GetRoomMembers` / `RoomCount` / `GetRooms` / `IsInRoom`

### 配套类型

- `type WSOption`
- `type Message`
- `NewTextMessage(msgType, data)`

### 错误

- `ErrConnectionNotFound`
- `ErrRoomNotFound`
- `ErrInvalidMessageType`

## 配置项

- `WithWSPingInterval(interval)`：默认 `54s`
- `WithWSPongTimeout(timeout)`：默认 `60s`
- `WithWSMaxMessageSize(size)`：默认 `512KB`
- `WithWSReadBufferSize(size)`：默认 `1024`
- `WithWSWriteBufferSize(size)`：默认 `1024`
- `WithWSCheckOrigin(fn)`：自定义来源校验
- `WithWSAllowAllOrigins()`：允许所有来源，不建议生产环境使用

## 使用示例

### 基础连接

```go
ws, err := c.UpgradeWebSocket("user-1")
if err != nil {
    return
}
defer ws.Close()

go ws.StartPingPong()

for {
    msg, err := ws.ReadText()
    if err != nil {
        break
    }
    _ = ws.WriteText("echo: " + msg)
}
```

### Hub 广播与房间

```go
hub := websocket.NewWebSocketHub()
hub.Register(ws)
defer hub.Unregister(ws)

_ = hub.JoinRoom(ws.UserID(), "room-1")
_ = hub.BroadcastToRoom("room-1", map[string]any{"type": "notice"})
```

## 与 Engine 的集成

- `Context.UpgradeWebSocket(userID, opts...)` 直接完成 HTTP → WebSocket 升级。
- 常见模式是在路由中升级连接，再把结果交给 `WebSocketHub` 管理。

```go
r.GET("/ws", func(c *gin.Context) {
    ws, err := c.UpgradeWebSocket("user-1", websocket.WithWSPongTimeout(30*time.Second))
    if err != nil {
        return
    }
    hub.Register(ws)
})
```
