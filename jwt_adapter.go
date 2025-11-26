package gin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	stdjwt "github.com/golang-jwt/jwt/v5"
)

const (
	ClaimIss   = "iss"
	ClaimSub   = "sub"
	ClaimAud   = "aud"
	ClaimExp   = "exp"
	ClaimNbf   = "nbf"
	ClaimIat   = "iat"
	ClaimJti   = "jti"
	ClaimType  = "typ"
	ClaimScope = "scp"

	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
)

// JWTPayload 通用载荷
type JWTPayload map[string]any

// Payload 兼容别名
type Payload = JWTPayload

// GetClaim 获取声明
func (p JWTPayload) GetClaim(key string) (any, bool) {
	v, ok := p[key]
	return v, ok
}

// JWTAdapter 最简 JWT 适配器（HS256）
type JWTAdapter struct {
	secret        []byte
	timeout       time.Duration
	revoked       map[string]time.Time
	mu            sync.RWMutex
	signingMethod *stdjwt.SigningMethodHMAC
}

func newJWTAdapter(secret []byte, alg string, timeout time.Duration) *JWTAdapter {
	if len(secret) == 0 {
		secret = randomBytes(32)
	}
	if timeout <= 0 {
		timeout = time.Hour
	}

	sm := stdjwt.GetSigningMethod(alg)
	hmacMethod, ok := sm.(*stdjwt.SigningMethodHMAC)
	if !ok || hmacMethod == nil {
		hmacMethod = stdjwt.SigningMethodHS256
	}

	return &JWTAdapter{
		secret:        secret,
		timeout:       timeout,
		revoked:       make(map[string]time.Time),
		signingMethod: hmacMethod,
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// GenerateToken 生成 HS256 JWT
func (a *JWTAdapter) GenerateToken(payload JWTPayload) (string, error) {
	claims := stdjwt.MapClaims{}
	for k, v := range payload {
		claims[k] = v
	}
	now := time.Now()
	if _, ok := claims[ClaimIat]; !ok {
		claims[ClaimIat] = now.Unix()
	}
	if _, ok := claims[ClaimExp]; !ok && a.timeout > 0 {
		claims[ClaimExp] = now.Add(a.timeout).Unix()
	}
	if _, ok := claims[ClaimJti]; !ok {
		claims[ClaimJti] = base64.RawURLEncoding.EncodeToString(randomBytes(8))
	}

	token := stdjwt.NewWithClaims(a.signingMethod, claims)
	return token.SignedString(a.secret)
}

// ValidateToken 验证并返回载荷
func (a *JWTAdapter) ValidateToken(tokenStr string) (JWTPayload, error) {
	if tokenStr == "" {
		return nil, errors.New("empty token")
	}
	token, err := stdjwt.Parse(tokenStr, func(token *stdjwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != a.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(stdjwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if jtiVal, ok := claims[ClaimJti]; ok {
		if jtiStr, ok := jtiVal.(string); ok && a.IsTokenRevoked(jtiStr) {
			return nil, errors.New("token revoked")
		}
	}

	p := JWTPayload{}
	for k, v := range claims {
		p[k] = v
	}
	return p, nil
}

// RevokeToken 撤销
func (a *JWTAdapter) RevokeToken(jti string, exp time.Time) error {
	if jti == "" {
		return errors.New("empty jti")
	}
	if exp.IsZero() {
		exp = time.Now().Add(7 * 24 * time.Hour)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked[jti] = exp
	return nil
}

// IsTokenRevoked 判断撤销
func (a *JWTAdapter) IsTokenRevoked(jti string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.revoked[jti]
	if !ok {
		return false
	}
	if exp.Before(time.Now()) {
		delete(a.revoked, jti)
		return false
	}
	return true
}

func (a *JWTAdapter) WithTimeout(d time.Duration) *JWTAdapter {
	if d > 0 {
		a.timeout = d
	}
	return a
}

func (a *JWTAdapter) Close() error { return nil }
