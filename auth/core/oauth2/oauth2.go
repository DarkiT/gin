package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/utils"
)

// OAuth2 Authorization Code Flow Implementation
// OAuth2 授权码模式实现
//
// Flow | 流程:
// 1. RegisterClient() - Register OAuth2 client | 注册OAuth2客户端
// 2. GenerateAuthorizationCode() - User authorizes, get code | 用户授权，获取授权码
// 3. ExchangeCodeForToken() - Exchange code for access token | 用授权码换取访问令牌
// 4. ValidateAccessToken() - Validate access token | 验证访问令牌
// 5. RefreshAccessToken() - Use refresh token to get new token | 用刷新令牌获取新令牌
//
// Usage | 用法:
//   server := oauth2.NewOAuth2Server(storage)
//   server.RegisterClient(&oauth2.Client{...})
//   authCode, _ := server.GenerateAuthorizationCode(...)
//   token, _ := server.ExchangeCodeForToken(...)

// Constants for OAuth2 | OAuth2常量
const (
	DefaultCodeExpiration  = 10 * time.Minute    // Authorization code expiration | 授权码过期时间
	DefaultTokenExpiration = 2 * time.Hour       // Access token expiration | 访问令牌过期时间
	DefaultRefreshTTL      = 30 * 24 * time.Hour // Refresh token expiration | 刷新令牌过期时间
	DefaultLockTTL         = 5 * time.Second     // Operation lock expiration | 操作锁过期时间
	DefaultLockWait        = 2 * time.Second     // Operation lock wait timeout | 操作锁等待超时

	CodeLength         = 32 // Authorization code byte length | 授权码字节长度
	AccessTokenLength  = 32 // Access token byte length | 访问令牌字节长度
	RefreshTokenLength = 32 // Refresh token byte length | 刷新令牌字节长度

	CodeKeySuffix    = "oauth2:code:"    // Code key suffix after prefix | 授权码键后缀
	TokenKeySuffix   = "oauth2:token:"   // Token key suffix after prefix | 令牌键后缀
	RefreshKeySuffix = "oauth2:refresh:" // Refresh key suffix after prefix | 刷新令牌键后缀
	ClientKeySuffix  = "oauth2:client:"  // Client key suffix after prefix | 客户端键后缀
	LockKeySuffix    = "oauth2:lock:"    // Lock key suffix after prefix | 锁键后缀

	TokenTypeBearer = "Bearer" // Token type | 令牌类型
)

// Error variables | 错误变量
var (
	ErrClientNotFound           = fmt.Errorf("client not found")
	ErrInvalidRedirectURI       = fmt.Errorf("invalid redirect_uri")
	ErrInvalidClientCredentials = fmt.Errorf("invalid client credentials")
	ErrInvalidAuthCode          = fmt.Errorf("invalid authorization code")
	ErrAuthCodeUsed             = fmt.Errorf("authorization code already used")
	ErrAuthCodeExpired          = fmt.Errorf("authorization code expired")
	ErrClientMismatch           = fmt.Errorf("client mismatch")
	ErrRedirectURIMismatch      = fmt.Errorf("redirect_uri mismatch")
	ErrInvalidAccessToken       = fmt.Errorf("invalid access token")
	ErrInvalidRefreshToken      = fmt.Errorf("invalid refresh token")
	ErrInvalidClientData        = fmt.Errorf("invalid client data")
	ErrInvalidTokenData         = fmt.Errorf("invalid token data")
)

// GrantType OAuth2 grant type | OAuth2授权类型
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code" // Authorization code flow | 授权码模式
	GrantTypeRefreshToken      GrantType = "refresh_token"      // Refresh token flow | 刷新令牌模式
	GrantTypeClientCredentials GrantType = "client_credentials" // Client credentials flow | 客户端凭证模式
	GrantTypePassword          GrantType = "password"           // Password flow | 密码模式
)

// Client OAuth2 client configuration | OAuth2客户端配置
type Client struct {
	ClientID     string      // Client ID | 客户端ID
	ClientSecret string      // Client secret | 客户端密钥
	RedirectURIs []string    // Allowed redirect URIs | 允许的回调URI
	GrantTypes   []GrantType // Allowed grant types | 允许的授权类型
	Scopes       []string    // Allowed scopes | 允许的权限范围
}

// MarshalBinary implements encoding.BinaryMarshaler for cross-storage compatibility.
func (c *Client) MarshalBinary() ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for cross-storage compatibility.
func (c *Client) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, c)
}

// AuthorizationCode authorization code information | 授权码信息
type AuthorizationCode struct {
	Code        string   // Authorization code | 授权码
	ClientID    string   // Client ID | 客户端ID
	RedirectURI string   // Redirect URI | 回调URI
	UserID      string   // User ID | 用户ID
	Scopes      []string // Requested scopes | 请求的权限范围
	CreateTime  int64    // Creation time | 创建时间
	ExpiresIn   int64    // Expiration time in seconds | 过期时间（秒）
	Used        bool     // Whether used | 是否已使用
}

// MarshalBinary implements encoding.BinaryMarshaler for cross-storage compatibility.
func (a *AuthorizationCode) MarshalBinary() ([]byte, error) {
	return json.Marshal(a)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for cross-storage compatibility.
func (a *AuthorizationCode) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, a)
}

// AccessToken access token information | 访问令牌信息
type AccessToken struct {
	Token        string   // Access token | 访问令牌
	TokenType    string   // Token type (Bearer) | 令牌类型（Bearer）
	ExpiresIn    int64    // Expiration time in seconds | 过期时间（秒）
	RefreshToken string   // Refresh token | 刷新令牌
	Scopes       []string // Granted scopes | 授予的权限范围
	UserID       string   // User ID | 用户ID
	ClientID     string   // Client ID | 客户端ID
}

// MarshalBinary implements encoding.BinaryMarshaler for cross-storage compatibility.
func (a *AccessToken) MarshalBinary() ([]byte, error) {
	return json.Marshal(a)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for cross-storage compatibility.
func (a *AccessToken) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, a)
}

// OAuth2Server OAuth2 authorization server | OAuth2授权服务器
type OAuth2Server struct {
	storage         adapter.Storage
	keyPrefix       string // Configurable prefix | 可配置的前缀
	codeMu          sync.Mutex
	refreshMu       sync.Mutex
	codeExpiration  time.Duration // Authorization code expiration (10min) | 授权码过期时间（10分钟）
	tokenExpiration time.Duration // Access token expiration (2h) | 访问令牌过期时间（2小时）
}

type setNXStorage interface {
	SetNX(key string, value any, expiration time.Duration) (bool, error)
}

// NewOAuth2Server Creates a new OAuth2 server | 创建新的OAuth2服务器
// prefix: key prefix (e.g., "satoken:" or "" for Java compatibility) | 键前缀（如："satoken:" 或 "" 兼容Java）
func NewOAuth2Server(storage adapter.Storage, prefix string) *OAuth2Server {
	return &OAuth2Server{
		storage:         storage,
		keyPrefix:       prefix,
		codeExpiration:  DefaultCodeExpiration,
		tokenExpiration: DefaultTokenExpiration,
	}
}

// RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func (s *OAuth2Server) RegisterClient(client *Client) error {
	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client: clientID is required")
	}
	payload, err := client.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode client: %w", err)
	}
	return s.storage.Set(s.getClientKey(client.ClientID), payload, 0)
}

// UnregisterClient Unregisters an OAuth2 client | 注销OAuth2客户端
func (s *OAuth2Server) UnregisterClient(clientID string) {
	_ = s.storage.Delete(s.getClientKey(clientID))
}

// GetClient Gets client by ID | 根据ID获取客户端
func (s *OAuth2Server) GetClient(clientID string) (*Client, error) {
	data, err := s.storage.Get(s.getClientKey(clientID))
	if err != nil || data == nil {
		return nil, ErrClientNotFound
	}
	return decodeClient(data)
}

// GenerateAuthorizationCode Generates authorization code | 生成授权码
func (s *OAuth2Server) GenerateAuthorizationCode(clientID, redirectURI, userID string, scopes []string) (*AuthorizationCode, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// Validate redirect URI | 验证回调URI
	if !s.isValidRedirectURI(client, redirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	// Generate code | 生成授权码
	codeBytes := make([]byte, CodeLength)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}
	code := hex.EncodeToString(codeBytes)

	authCode := &AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      userID,
		Scopes:      scopes,
		CreateTime:  time.Now().Unix(),
		ExpiresIn:   int64(s.codeExpiration.Seconds()),
		Used:        false,
	}

	key := s.getCodeKey(code)
	payload, err := authCode.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode authorization code: %w", err)
	}
	if err := s.storage.Set(key, payload, s.codeExpiration); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return authCode, nil
}

// isValidRedirectURI Checks if redirect URI is valid for client | 检查回调URI是否有效
func (s *OAuth2Server) isValidRedirectURI(client *Client, redirectURI string) bool {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// ExchangeCodeForToken Exchanges authorization code for access token | 用授权码换取访问令牌
func (s *OAuth2Server) ExchangeCodeForToken(code, clientID, clientSecret, redirectURI string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, ErrInvalidClientCredentials
	}

	var token *AccessToken
	err = s.withOperationLock("code:"+code, &s.codeMu, func() error {
		// Get authorization code | 获取授权码
		key := s.getCodeKey(code)
		data, err := s.storage.Get(key)
		if err != nil || data == nil {
			return ErrInvalidAuthCode
		}

		authCode, err := decodeAuthorizationCode(data)
		if err != nil {
			return err
		}

		// Validate authorization code | 验证授权码
		if authCode.Used {
			return ErrAuthCodeUsed
		}

		if authCode.ClientID != clientID {
			return ErrClientMismatch
		}

		if authCode.RedirectURI != redirectURI {
			return ErrRedirectURIMismatch
		}

		if time.Now().Unix() > authCode.CreateTime+authCode.ExpiresIn {
			_ = s.storage.Delete(key)
			return ErrAuthCodeExpired
		}

		token, err = s.newAccessToken(authCode.UserID, authCode.ClientID, authCode.Scopes)
		if err != nil {
			return err
		}

		if err := s.storeToken(token); err != nil {
			return err
		}

		// Mark code as used only after token pair has been persisted, and roll back on failure.
		authCode.Used = true
		payload, err := authCode.MarshalBinary()
		if err != nil {
			s.rollbackToken(token)
			return fmt.Errorf("failed to encode authorization code: %w", err)
		}
		if err := s.storage.Set(key, payload, time.Minute); err != nil {
			s.rollbackToken(token)
			return fmt.Errorf("failed to store used authorization code: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

// newAccessToken Generates access token payload without persisting it | 生成访问令牌对象但暂不持久化
func (s *OAuth2Server) newAccessToken(userID, clientID string, scopes []string) (*AccessToken, error) {
	// Generate access token | 生成访问令牌
	tokenBytes := make([]byte, AccessTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	accessToken := hex.EncodeToString(tokenBytes)

	// Generate refresh token | 生成刷新令牌
	refreshBytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	token := &AccessToken{
		Token:        accessToken,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    int64(s.tokenExpiration.Seconds()),
		RefreshToken: refreshToken,
		Scopes:       scopes,
		UserID:       userID,
		ClientID:     clientID,
	}
	return token, nil
}

func (s *OAuth2Server) storeToken(token *AccessToken) error {
	payload, err := token.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode access token: %w", err)
	}

	tokenKey := s.getTokenKey(token.Token)
	refreshKey := s.getRefreshKey(token.RefreshToken)

	if err := s.storage.Set(tokenKey, payload, s.tokenExpiration); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}
	if err := s.storage.Set(refreshKey, payload, DefaultRefreshTTL); err != nil {
		_ = s.storage.Delete(tokenKey)
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

func (s *OAuth2Server) rollbackToken(token *AccessToken) {
	if token == nil {
		return
	}
	_ = s.storage.Delete(s.getTokenKey(token.Token), s.getRefreshKey(token.RefreshToken))
}

// ValidateAccessToken Validates access token | 验证访问令牌
func (s *OAuth2Server) ValidateAccessToken(tokenString string) (*AccessToken, error) {
	if tokenString == "" {
		return nil, ErrInvalidAccessToken
	}

	key := s.getTokenKey(tokenString)
	data, err := s.storage.Get(key)
	if err != nil || data == nil {
		return nil, ErrInvalidAccessToken
	}

	token, err := decodeAccessToken(data)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func (s *OAuth2Server) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, ErrInvalidClientCredentials
	}

	var newToken *AccessToken
	err = s.withOperationLock("refresh:"+refreshToken, &s.refreshMu, func() error {
		// Get refresh token | 获取刷新令牌
		key := s.getRefreshKey(refreshToken)
		data, err := s.storage.Get(key)
		if err != nil || data == nil {
			return ErrInvalidRefreshToken
		}

		oldToken, err := decodeAccessToken(data)
		if err != nil {
			return fmt.Errorf("invalid refresh token data: %w", err)
		}

		if oldToken.ClientID != clientID {
			return ErrClientMismatch
		}
		if oldToken.RefreshToken != refreshToken {
			return ErrInvalidRefreshToken
		}

		newToken, err = s.newAccessToken(oldToken.UserID, oldToken.ClientID, oldToken.Scopes)
		if err != nil {
			return err
		}
		if err := s.storeToken(newToken); err != nil {
			return err
		}

		// Rotate both old access token and old refresh token atomically from the caller perspective.
		oldTokenKey := s.getTokenKey(oldToken.Token)
		if err := s.storage.Delete(oldTokenKey, key); err != nil {
			s.rollbackToken(newToken)
			return fmt.Errorf("failed to rotate refresh token: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func (s *OAuth2Server) RevokeToken(tokenString string) error {
	if tokenString == "" {
		return nil
	}

	key := s.getTokenKey(tokenString)
	data, err := s.storage.Get(key)
	if err != nil {
		return err
	}

	// Revoke refresh token if exists | 如果存在则撤销刷新令牌
	token, err := decodeAccessToken(data)
	if err == nil && token.RefreshToken != "" {
		refreshKey := s.getRefreshKey(token.RefreshToken)
		_ = s.storage.Delete(refreshKey)
	}

	return s.storage.Delete(key)
}

// ============ Helper Methods | 辅助方法 ============

// getCodeKey Gets storage key for authorization code | 获取授权码的存储键
func (s *OAuth2Server) getCodeKey(code string) string {
	return s.keyPrefix + CodeKeySuffix + code
}

// getTokenKey Gets storage key for access token | 获取访问令牌的存储键
func (s *OAuth2Server) getTokenKey(token string) string {
	return s.keyPrefix + TokenKeySuffix + token
}

// getRefreshKey Gets storage key for refresh token | 获取刷新令牌的存储键
func (s *OAuth2Server) getRefreshKey(refreshToken string) string {
	return s.keyPrefix + RefreshKeySuffix + refreshToken
}

func (s *OAuth2Server) getClientKey(clientID string) string {
	return s.keyPrefix + ClientKeySuffix + clientID
}

func (s *OAuth2Server) getLockKey(operation string) string {
	return s.keyPrefix + LockKeySuffix + operation
}

func (s *OAuth2Server) withOperationLock(operation string, fallback *sync.Mutex, fn func() error) error {
	if locker, ok := s.storage.(setNXStorage); ok {
		lockKey := s.getLockKey(operation)
		deadline := time.Now().Add(DefaultLockWait)
		for {
			acquired, err := locker.SetNX(lockKey, "1", DefaultLockTTL)
			if err != nil {
				return fmt.Errorf("acquire oauth2 lock %q: %w", operation, err)
			}
			if acquired {
				defer func() { _ = s.storage.Delete(lockKey) }()
				return fn()
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("acquire oauth2 lock %q: timeout", operation)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	fallback.Lock()
	defer fallback.Unlock()
	return fn()
}

func decodeAuthorizationCode(data any) (*AuthorizationCode, error) {
	switch v := data.(type) {
	case *AuthorizationCode:
		return v, nil
	case AuthorizationCode:
		code := v
		return &code, nil
	default:
		dataBytes, err := utils.ToBytes(data)
		if err != nil {
			return nil, fmt.Errorf("invalid code data")
		}
		var code AuthorizationCode
		if err := code.UnmarshalBinary(dataBytes); err != nil {
			return nil, fmt.Errorf("invalid code data: %w", err)
		}
		return &code, nil
	}
}

func decodeAccessToken(data any) (*AccessToken, error) {
	switch v := data.(type) {
	case *AccessToken:
		return v, nil
	case AccessToken:
		token := v
		return &token, nil
	default:
		dataBytes, err := utils.ToBytes(data)
		if err != nil {
			return nil, ErrInvalidTokenData
		}
		var token AccessToken
		if err := token.UnmarshalBinary(dataBytes); err != nil {
			return nil, ErrInvalidTokenData
		}
		return &token, nil
	}
}

func decodeClient(data any) (*Client, error) {
	switch v := data.(type) {
	case *Client:
		return v, nil
	case Client:
		client := v
		return &client, nil
	default:
		dataBytes, err := utils.ToBytes(data)
		if err != nil {
			return nil, ErrInvalidClientData
		}
		var client Client
		if err := client.UnmarshalBinary(dataBytes); err != nil {
			return nil, ErrInvalidClientData
		}
		return &client, nil
	}
}
