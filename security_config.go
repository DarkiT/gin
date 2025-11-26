package gin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SecurityConfig 安全配置结构体
type SecurityConfig struct {
	// JWT配置
	JWTSecretKey      []byte        `json:"-"` // 不序列化密钥
	JWTAlgorithm      string        `json:"jwt_algorithm"`
	JWTExpiration     time.Duration `json:"jwt_expiration"`
	JWTRefreshEnabled bool          `json:"jwt_refresh_enabled"`

	// CORS配置
	CORSAllowedOrigins   []string `json:"cors_allowed_origins"`
	CORSAllowedMethods   []string `json:"cors_allowed_methods"`
	CORSAllowedHeaders   []string `json:"cors_allowed_headers"`
	CORSMaxAge           int      `json:"cors_max_age"`
	CORSAllowCredentials bool     `json:"cors_allow_credentials"`

	// 安全头配置
	SecurityHeadersEnabled bool `json:"security_headers_enabled"`

	// 限流配置
	RateLimitEnabled           bool `json:"rate_limit_enabled"`
	RateLimitRequestsPerMinute int  `json:"rate_limit_requests_per_minute"`
}

// DefaultSecurityConfig 返回默认安全配置
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		// JWT默认配置
		JWTAlgorithm:      "HS256",
		JWTExpiration:     2 * time.Hour,
		JWTRefreshEnabled: true,

		// CORS安全默认配置
		CORSAllowedOrigins:   []string{}, // 空数组表示不允许任何源，必须明确配置
		CORSAllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		CORSAllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With"},
		CORSMaxAge:           86400, // 24小时
		CORSAllowCredentials: false, // 默认不允许凭据

		// 安全头默认启用
		SecurityHeadersEnabled: true,

		// 限流默认配置
		RateLimitEnabled:           true,
		RateLimitRequestsPerMinute: 60, // 每分钟60请求
	}
}

// LoadSecurityConfig 从环境变量加载安全配置
func LoadSecurityConfig() (*SecurityConfig, error) {
	config := DefaultSecurityConfig()

	// 加载JWT密钥（必需）
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		// 如果没有设置环境变量，生成一个随机密钥（仅用于开发）
		if os.Getenv("GO_ENV") == "development" {
			randomKey, err := generateRandomKey(32)
			if err != nil {
				return nil, fmt.Errorf("生成随机JWT密钥失败: %v", err)
			}
			config.JWTSecretKey = randomKey
			fmt.Printf("[GIN-SECURITY] WARNING: 使用随机生成的JWT密钥（仅用于开发环境）\n")
		} else {
			return nil, fmt.Errorf("生产环境必须设置JWT_SECRET_KEY环境变量")
		}
	} else {
		config.JWTSecretKey = []byte(jwtSecret)
	}

	// 加载JWT算法
	if alg := os.Getenv("JWT_ALGORITHM"); alg != "" {
		// 验证算法安全性
		allowedAlgorithms := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
		isValid := false
		for _, validAlg := range allowedAlgorithms {
			if alg == validAlg {
				isValid = true
				break
			}
		}
		if !isValid {
			return nil, fmt.Errorf("不安全的JWT算法: %s", alg)
		}
		config.JWTAlgorithm = alg
	}

	// 加载JWT过期时间
	if expStr := os.Getenv("JWT_EXPIRATION"); expStr != "" {
		exp, err := time.ParseDuration(expStr)
		if err != nil {
			return nil, fmt.Errorf("无效的JWT过期时间格式: %v", err)
		}
		if exp < 5*time.Minute {
			return nil, fmt.Errorf("JWT过期时间不能少于5分钟")
		}
		if exp > 24*time.Hour {
			return nil, fmt.Errorf("JWT过期时间不能超过24小时")
		}
		config.JWTExpiration = exp
	}

	// 加载CORS配置
	if origins := os.Getenv("CORS_ALLOWED_ORIGINS"); origins != "" {
		config.CORSAllowedOrigins = parseCommaSeparated(origins)
	} else {
		// 生产环境必须明确配置允许的源
		if os.Getenv("GO_ENV") != "development" {
			return nil, fmt.Errorf("生产环境必须设置CORS_ALLOWED_ORIGINS环境变量")
		}
		config.CORSAllowedOrigins = []string{"http://localhost:3000", "http://localhost:8080"}
	}

	// 加载限流配置
	if rpmStr := os.Getenv("RATE_LIMIT_RPM"); rpmStr != "" {
		rpm, err := strconv.Atoi(rpmStr)
		if err != nil {
			return nil, fmt.Errorf("无效的限流配置: %v", err)
		}
		if rpm < 1 || rpm > 10000 {
			return nil, fmt.Errorf("限流配置必须在1-10000之间")
		}
		config.RateLimitRequestsPerMinute = rpm
	}

	// 安全头配置
	if secHeadersStr := os.Getenv("SECURITY_HEADERS_ENABLED"); secHeadersStr != "" {
		enabled, _ := strconv.ParseBool(secHeadersStr)
		config.SecurityHeadersEnabled = enabled
	}

	return config, nil
}

// generateRandomKey 生成随机密钥
func generateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateSecureJWTKey 生成安全的JWT密钥（用于部署脚本）
func GenerateSecureJWTKey() (string, error) {
	key, err := generateRandomKey(32) // 256位密钥
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// parseCommaSeparated 解析逗号分隔的字符串
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := make([]string, 0)
	for _, part := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// ValidateSecurityConfig 验证安全配置
func (c *SecurityConfig) Validate() error {
	// 验证JWT密钥长度
	if len(c.JWTSecretKey) < 32 {
		return fmt.Errorf("JWT密钥长度至少需要32字节")
	}

	// 验证CORS配置
	if len(c.CORSAllowedOrigins) == 0 {
		return fmt.Errorf("必须配置至少一个允许的CORS源")
	}

	// 检查是否存在不安全的CORS配置
	for _, origin := range c.CORSAllowedOrigins {
		if origin == "*" && c.CORSAllowCredentials {
			return fmt.Errorf("不能同时设置CORS允许所有源(*)和凭据(credentials)")
		}
	}

	return nil
}

// BuildJWTAdapter 构建 JWT 适配器（目前仅支持 HS256 系列）
func (c *SecurityConfig) BuildJWTAdapter() (*JWTAdapter, error) {
	if len(c.JWTSecretKey) == 0 {
		return nil, fmt.Errorf("JWTSecretKey is required")
	}
	// 仅支持 HS256/384/512，默认 HS256
	if c.JWTAlgorithm == "" {
		c.JWTAlgorithm = "HS256"
	}
	if !strings.HasPrefix(c.JWTAlgorithm, "HS") {
		return nil, fmt.Errorf("algorithm %s not supported (only HS256/384/512)", c.JWTAlgorithm)
	}

	adapter := newJWTAdapter(c.JWTSecretKey, c.JWTAlgorithm, c.JWTExpiration)
	return adapter, nil
}
