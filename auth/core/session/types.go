package session

// Session type constants for token vs account session | 会话类型（token 级 / 账号级）
const (
	TypeAccount = "Account-Session"
	TypeToken   = "Token-Session"
	TypeAnon    = "Anon-Token-Session"
	TypeCustom  = "Custom-Session"
)

// Storage key prefixes to namespace session kinds | 各类 Session 存储 key 前缀
const (
	AccountSessionKeyPrefix = "session:"
	TokenSessionKeyPrefix   = "token-session:"
	CustomSessionKeyPrefix  = "custom-session:"
)
