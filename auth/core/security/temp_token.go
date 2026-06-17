package security

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/errs"
	"github.com/darkit/gin/auth/core/utils"
)

// TempTokenInfo stores temporary token metadata | 临时Token信息
type TempTokenInfo struct {
	Token      string `json:"token"`
	LoginID    string `json:"loginId"`
	CreateTime int64  `json:"createTime"`
	ExpireTime int64  `json:"expireTime"`
	Used       bool   `json:"used,omitempty"`
	Extra      string `json:"extra,omitempty"`
}

// TempTokenManager manages short-lived one-time tokens | 临时Token管理器
type TempTokenManager struct {
	storage   adapter.Storage
	keyPrefix string
	// mu 保护 VerifyTempToken 的 read-check-write，避免一次性 token 被并发消费两次（TOCTOU）。
	// 多实例部署仍需后端 CAS，此处保证单实例并发安全。
	mu sync.Mutex
}

// NewTempTokenManager creates a new temp token manager | 创建临时Token管理器
func NewTempTokenManager(storage adapter.Storage, prefix string) *TempTokenManager {
	return &TempTokenManager{
		storage:   storage,
		keyPrefix: prefix + "temp:",
	}
}

// CreateTempToken creates a new one-time temporary token | 创建一次性临时Token
func (m *TempTokenManager) CreateTempToken(loginID string, expireSeconds int64, extra string) (*TempTokenInfo, error) {
	if expireSeconds <= 0 {
		expireSeconds = 300 // default 5 minutes
	}

	token := utils.RandomString(32)
	now := time.Now().Unix()

	info := &TempTokenInfo{
		Token:      token,
		LoginID:    loginID,
		CreateTime: now,
		ExpireTime: now + expireSeconds,
		Extra:      extra,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal temp token: %w", err)
	}

	ttl := time.Duration(expireSeconds) * time.Second
	if err := m.storage.Set(m.keyPrefix+token, string(data), ttl); err != nil {
		return nil, fmt.Errorf("failed to store temp token: %w", err)
	}

	return info, nil
}

// GetTempTokenInfo retrieves temp token info without consuming | 获取临时Token信息（不消费）
func (m *TempTokenManager) GetTempTokenInfo(token string) (*TempTokenInfo, error) {
	data, err := m.storage.Get(m.keyPrefix + token)
	if err != nil || data == nil {
		return nil, errs.ErrTempTokenNotFound
	}

	var info TempTokenInfo
	var bytes []byte
	switch v := data.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return nil, fmt.Errorf("unexpected type for temp token data")
	}

	if err := json.Unmarshal(bytes, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal temp token: %w", err)
	}

	return &info, nil
}

// VerifyTempToken verifies and consumes a one-time temp token | 验证并消费一次性临时Token
//
// 全流程在进程内互斥下完成 read-check-write，避免一次性 token 被「先读 Used 再写回」的并发窗口
// 重放消费。多实例部署需后端 CAS（已知限制）。
func (m *TempTokenManager) VerifyTempToken(token string) (*TempTokenInfo, error) {
	if token == "" {
		return nil, errs.ErrTempTokenNotFound
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	info, err := m.GetTempTokenInfo(token)
	if err != nil {
		return nil, err
	}

	if info.Used {
		return nil, errs.ErrTempTokenUsed
	}

	if time.Now().Unix() > info.ExpireTime {
		return nil, errs.ErrTempTokenExpired
	}

	// Mark as used
	info.Used = true
	data, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}

	remaining := info.ExpireTime - time.Now().Unix()
	ttl := time.Duration(remaining) * time.Second
	if ttl <= 0 {
		ttl = time.Second
	}
	_ = m.storage.Set(m.keyPrefix+token, string(data), ttl)

	return info, nil
}

// DeleteTempToken deletes a temp token | 删除临时Token
func (m *TempTokenManager) DeleteTempToken(token string) error {
	return m.storage.Delete(m.keyPrefix + token)
}
