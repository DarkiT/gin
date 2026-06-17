package security

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/config"
	"github.com/darkit/gin/auth/core/token"
	"github.com/darkit/gin/auth/core/utils"
)

// Refresh Token Implementation
// 刷新令牌实现
//
// Flow | 流程:
// 1. GenerateTokenPair() - Create access token + refresh token | 创建访问令牌 + 刷新令牌
// 2. Access token expires (short-lived, e.g. 2h) | 访问令牌过期（短期，如2小时）
// 3. RefreshAccessToken() - Use refresh token to get new access token | 使用刷新令牌获取新访问令牌
// 4. Refresh token expires (long-lived, 30 days) | 刷新令牌过期（长期，30天）
//
// Usage | 用法:
//   tokenInfo, _ := manager.LoginWithRefreshToken(loginID, "web")
//   // ... access token expires ...
//   newInfo, _ := manager.RefreshAccessToken(tokenInfo.RefreshToken)

// Constants for refresh token | 刷新令牌常量
const (
	DefaultRefreshTTL  = 30 * 24 * time.Hour // 30 days | 30天
	DefaultAccessTTL   = 2 * time.Hour       // 2 hours | 2小时
	RefreshTokenLength = 32                  // Refresh token byte length | 刷新令牌字节长度
	RefreshKeySuffix   = "refresh:"          // Key suffix after prefix | 前缀后的键后缀
	accountKeySuffix   = "account:"          // Account mapping key suffix | 账号映射键后缀
	deviceSeparator    = ":"                 // Device separator | 设备分隔符
)

// Error variables | 错误变量
var (
	ErrInvalidRefreshToken = fmt.Errorf("invalid refresh token")
	ErrRefreshTokenExpired = fmt.Errorf("refresh token expired")
	ErrInvalidRefreshData  = fmt.Errorf("invalid refresh token data")
)

// RefreshTokenInfo refresh token information | 刷新令牌信息
type RefreshTokenInfo struct {
	RefreshToken string `json:"refreshToken"` // Refresh token (long-lived) | 刷新令牌（长期有效）
	AccessToken  string `json:"accessToken"`  // Access token (short-lived) | 访问令牌（短期有效）
	LoginID      string `json:"loginID"`      // User login ID | 用户登录ID
	Device       string `json:"device"`       // Device type | 设备类型
	CreateTime   int64  `json:"createTime"`   // Creation timestamp | 创建时间戳
	ExpireTime   int64  `json:"expireTime"`   // Expiration timestamp | 过期时间戳
}

// MarshalBinary implements encoding.BinaryMarshaler for Redis storage | 实现encoding.BinaryMarshaler接口用于Redis存储
func (r *RefreshTokenInfo) MarshalBinary() ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Redis storage | 实现encoding.BinaryUnmarshaler接口用于Redis存储
func (r *RefreshTokenInfo) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, r)
}

// RefreshTokenManager Refresh token manager | 刷新令牌管理器
type RefreshTokenManager struct {
	storage        adapter.Storage
	keyPrefix      string // Configurable prefix | 可配置的前缀
	tokenKeyPrefix string // Token key prefix | 令牌键前缀
	tokenGen       *token.Generator
	refreshTTL     time.Duration // Refresh token TTL (30 days) | 刷新令牌有效期（30天）
	accessTTL      time.Duration // Access token TTL (configurable) | 访问令牌有效期（可配置）
}

// NewRefreshTokenManager Creates a new refresh token manager | 创建新的刷新令牌管理器
// prefix: key prefix (e.g., "satoken:" or "" for Java compatibility) | 键前缀（如："satoken:" 或 "" 兼容Java）
// cfg: configuration, uses Timeout for access token TTL | 配置，使用Timeout作为访问令牌有效期
func NewRefreshTokenManager(storage adapter.Storage, prefix, keyPrefix string, cfg *config.Config) *RefreshTokenManager {
	accessTTL := time.Duration(cfg.Timeout) * time.Second
	refreshTTL := time.Duration(cfg.RefreshTimeout) * time.Second

	if accessTTL == 0 {
		accessTTL = DefaultAccessTTL
	}
	if refreshTTL == 0 {
		refreshTTL = DefaultRefreshTTL
	}

	return &RefreshTokenManager{
		storage:        storage,
		keyPrefix:      prefix,
		tokenKeyPrefix: keyPrefix,
		tokenGen:       token.NewGenerator(cfg),
		refreshTTL:     refreshTTL,
		accessTTL:      accessTTL,
	}
}

// GenerateTokenPair Generates access token and refresh token pair | 生成访问令牌和刷新令牌对
func (rtm *RefreshTokenManager) GenerateTokenPair(loginID, device string, accessTokenOverride ...string) (*RefreshTokenInfo, error) {
	if loginID == "" {
		return nil, fmt.Errorf("loginID cannot be empty")
	}

	// Generate access token | 生成访问令牌
	var accessToken string
	if len(accessTokenOverride) > 0 && accessTokenOverride[0] != "" {
		accessToken = accessTokenOverride[0]
	} else {
		var err error
		accessToken, err = rtm.tokenGen.Generate(loginID, device)
		if err != nil {
			return nil, fmt.Errorf("failed to generate access token: %w", err)
		}
	}

	// Generate refresh token | 生成刷新令牌
	refreshTokenBytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := hex.EncodeToString(refreshTokenBytes)

	now := time.Now()
	info := &RefreshTokenInfo{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		LoginID:      loginID,
		Device:       device,
		CreateTime:   now.Unix(),
		ExpireTime:   now.Add(rtm.refreshTTL).Unix(),
	}

	key := rtm.getRefreshKey(refreshToken)
	payload, err := info.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode refresh token: %w", err)
	}
	if err := rtm.storage.Set(key, payload, rtm.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return info, nil
}

// RefreshAccessToken Generates new access token using refresh token | 使用刷新令牌生成新的访问令牌
func (rtm *RefreshTokenManager) RefreshAccessToken(refreshToken string) (*RefreshTokenInfo, error) {
	if refreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	// Get refresh token info | 获取刷新令牌信息
	key := rtm.getRefreshKey(refreshToken)

	// Get refresh token info | 获取刷新令牌信息
	data, err := rtm.storage.Get(key)
	if err != nil || data == nil {
		return nil, ErrInvalidRefreshToken
	}

	// Convert to RefreshTokenInfo | 转换为 RefreshTokenInfo
	oldInfo, err := decodeRefreshTokenInfo(data)
	if err != nil {
		return nil, ErrInvalidRefreshData
	}

	// Check expiration | 检查是否过期
	if time.Now().Unix() > oldInfo.ExpireTime {
		if err := rtm.storage.Delete(key); err != nil {
			return nil, fmt.Errorf("failed to delete expired refresh token: %w", err)
		}
		return nil, ErrRefreshTokenExpired
	}

	// Generate new access token | 生成新的访问令牌
	newAccessToken, err := rtm.tokenGen.Generate(oldInfo.LoginID, oldInfo.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	oldAccessToken := oldInfo.AccessToken

	// Update access token info | 更新访问令牌信息
	oldInfo.AccessToken = newAccessToken

	// Copy original token storage value to new access token key, to keep JSON TokenInfo format
	// 复制原 access token 的存储值到新的 access token 键，保持 JSON TokenInfo 格式，避免破坏 IsLogin/CheckLogin
	oldTokenKey := rtm.getTokenKey(oldAccessToken)
	if data, err := rtm.storage.Get(oldTokenKey); err == nil && data != nil {
		newTokenKey := rtm.getTokenKey(newAccessToken)
		if err := rtm.storage.Set(newTokenKey, data, rtm.accessTTL); err != nil {
			return nil, fmt.Errorf("failed to save new access token: %w", err)
		}
	}
	if newAccessToken != oldAccessToken {
		_ = rtm.storage.Delete(oldTokenKey)
	}

	accountKey := rtm.getAccountKey(oldInfo.LoginID, oldInfo.Device)
	if err := rtm.storage.Set(accountKey, newAccessToken, rtm.accessTTL); err != nil {
		return nil, fmt.Errorf("failed to update account mapping: %w", err)
	}

	// Update storage | 更新存储
	payload, err := oldInfo.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode refresh token: %w", err)
	}
	if err := rtm.storage.Set(key, payload, rtm.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", err)
	}

	return oldInfo, nil
}

// RevokeRefreshToken Revokes a refresh token | 撤销刷新令牌
func (rtm *RefreshTokenManager) RevokeRefreshToken(refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	key := rtm.getRefreshKey(refreshToken)
	return rtm.storage.Delete(key)
}

// GetRefreshTokenInfo Gets refresh token information | 获取刷新令牌信息
func (rtm *RefreshTokenManager) GetRefreshTokenInfo(refreshToken string) (*RefreshTokenInfo, error) {
	if refreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	key := rtm.getRefreshKey(refreshToken)

	data, err := rtm.storage.Get(key)
	if err != nil || data == nil {
		return nil, ErrInvalidRefreshToken
	}

	info, err := decodeRefreshTokenInfo(data)
	if err != nil {
		return nil, ErrInvalidRefreshData
	}

	return info, nil
}

// IsValid Checks if refresh token is valid | 检查刷新令牌是否有效
func (rtm *RefreshTokenManager) IsValid(refreshToken string) bool {
	info, err := rtm.GetRefreshTokenInfo(refreshToken)
	if err != nil {
		return false
	}

	return time.Now().Unix() <= info.ExpireTime
}

// getRefreshKey Gets storage key for refresh token | 获取刷新令牌的存储键
func (rtm *RefreshTokenManager) getRefreshKey(refreshToken string) string {
	return rtm.keyPrefix + RefreshKeySuffix + refreshToken
}

// getTokenKey Gets token storage key | 获取Token存储键
func (rtm *RefreshTokenManager) getTokenKey(tokenValue string) string {
	return rtm.keyPrefix + rtm.tokenKeyPrefix + tokenValue
}

// getAccountKey Gets storage key for account mapping | 获取账号映射存储键
func (rtm *RefreshTokenManager) getAccountKey(loginID, device string) string {
	return rtm.keyPrefix + accountKeySuffix + loginID + deviceSeparator + device
}

func decodeRefreshTokenInfo(data any) (*RefreshTokenInfo, error) {
	switch v := data.(type) {
	case *RefreshTokenInfo:
		if v == nil {
			return nil, nil
		}
		info := *v
		return &info, nil
	case RefreshTokenInfo:
		info := v
		return &info, nil
	default:
		dataBytes, err := utils.ToBytes(data)
		if err != nil {
			return nil, err
		}
		info := &RefreshTokenInfo{}
		if err := info.UnmarshalBinary(dataBytes); err != nil {
			return nil, err
		}
		return info, nil
	}
}
