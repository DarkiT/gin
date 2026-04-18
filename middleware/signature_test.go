package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/darkit/gin"
	"github.com/stretchr/testify/assert"
)

func mustGenerateNonce(t *testing.T) string {
	t.Helper()

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	return nonce
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	assert.NoError(t, err)
	assert.Len(t, nonce, 32)
}

func TestSignatureVerify_Valid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置密钥
	secret := "test-secret-key"

	// 创建路由
	router := gin.New()
	router.Use(SignatureVerify(WithSignatureSecret(secret)))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 准备请求数据
	body := `{"name":"test"}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)

	// 生成签名
	signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, "HMAC-SHA256", nil)

	// 创建请求
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)

	// 执行请求
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

func TestSignatureVerify_Invalid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置密钥
	secret := "test-secret-key"

	// 创建路由
	router := gin.New()
	router.Use(SignatureVerify(WithSignatureSecret(secret)))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 准备请求数据
	body := `{"name":"test"}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)

	// 使用错误的签名
	invalidSignature := "invalid-signature-12345"

	// 创建请求
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", invalidSignature)

	// 执行请求
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid signature")
}

func TestSignatureVerify_Expired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置密钥和过期时间（10秒）
	secret := "test-secret-key"
	expiry := int64(10)

	// 创建路由
	router := gin.New()
	router.Use(SignatureVerify(
		WithSignatureSecret(secret),
		WithSignatureExpiry(expiry),
	))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 准备过期的时间戳（15秒前）
	body := `{"name":"test"}`
	expiredTimestamp := fmt.Sprintf("%d", time.Now().Unix()-15)
	nonce := mustGenerateNonce(t)

	// 生成签名（即使签名正确，但时间戳过期）
	signature := GenerateSignature("POST", "/api/test", body, expiredTimestamp, nonce, secret, "HMAC-SHA256", nil)

	// 创建请求
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", expiredTimestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)

	// 执行请求
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "timestamp expired or invalid")
}

func TestSignatureVerify_ReplayAttack(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置密钥
	secret := "test-secret-key"

	// 创建共享的 NonceStore
	nonceStore := NewMemoryNonceStore()

	// 创建路由
	router := gin.New()
	router.Use(SignatureVerify(
		WithSignatureSecret(secret),
		WithSignatureNonceStore(nonceStore),
	))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 准备请求数据
	body := `{"name":"test"}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)

	// 生成签名
	signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, "HMAC-SHA256", nil)

	// 第一次请求（应该成功）
	req1 := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Timestamp", timestamp)
	req1.Header.Set("X-Nonce", nonce)
	req1.Header.Set("X-Signature", signature)

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	// 验证第一次请求成功
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Contains(t, w1.Body.String(), "success")

	// 第二次请求（使用相同的 nonce，应该被拒绝）
	req2 := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Timestamp", timestamp)
	req2.Header.Set("X-Nonce", nonce) // 相同的 nonce
	req2.Header.Set("X-Signature", signature)

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	// 验证第二次请求被拒绝（检测到重放攻击）
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	assert.Contains(t, w2.Body.String(), "nonce already used")
}

func TestSignatureVerify_MissingHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置密钥
	secret := "test-secret-key"

	// 创建路由
	router := gin.New()
	router.Use(SignatureVerify(WithSignatureSecret(secret)))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	tests := []struct {
		name          string
		timestamp     string
		nonce         string
		signature     string
		expectedError string
	}{
		{
			name:          "缺少所有头",
			timestamp:     "",
			nonce:         "",
			signature:     "",
			expectedError: "missing required headers",
		},
		{
			name:          "缺少 X-Timestamp",
			timestamp:     "",
			nonce:         "test-nonce",
			signature:     "test-signature",
			expectedError: "missing required headers",
		},
		{
			name:          "缺少 X-Nonce",
			timestamp:     strconv.FormatInt(time.Now().Unix(), 10),
			nonce:         "",
			signature:     "test-signature",
			expectedError: "missing required headers",
		},
		{
			name:          "缺少 X-Signature",
			timestamp:     strconv.FormatInt(time.Now().Unix(), 10),
			nonce:         "test-nonce",
			signature:     "",
			expectedError: "missing required headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建请求
			req := httptest.NewRequest("POST", "/api/test", strings.NewReader(`{"name":"test"}`))
			req.Header.Set("Content-Type", "application/json")

			if tt.timestamp != "" {
				req.Header.Set("X-Timestamp", tt.timestamp)
			}
			if tt.nonce != "" {
				req.Header.Set("X-Nonce", tt.nonce)
			}
			if tt.signature != "" {
				req.Header.Set("X-Signature", tt.signature)
			}

			// 执行请求
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// 额外测试：测试不同的签名算法
func TestSignatureVerify_DifferentAlgorithms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := "test-secret-key"

	tests := []struct {
		name      string
		algorithm string
	}{
		{
			name:      "HMAC-SHA256",
			algorithm: "HMAC-SHA256",
		},
		{
			name:      "HMAC-SHA1",
			algorithm: "HMAC-SHA1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建路由
			router := gin.New()
			router.Use(SignatureVerify(
				WithSignatureSecret(secret),
				WithSignatureAlgorithm(tt.algorithm),
			))
			router.POST("/api/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// 准备请求数据
			body := `{"name":"test"}`
			timestamp := fmt.Sprintf("%d", time.Now().Unix())
			nonce := mustGenerateNonce(t)

			// 生成签名
			signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, tt.algorithm, nil)

			// 创建请求
			req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Timestamp", timestamp)
			req.Header.Set("X-Nonce", nonce)
			req.Header.Set("X-Signature", signature)

			// 执行请求
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// 验证响应
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), "success")
		})
	}
}

// 额外测试：测试自定义 header 参与签名
func TestSignatureVerify_WithCustomHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := "test-secret-key"

	// 创建路由，指定额外的 header 参与签名
	router := gin.New()
	router.Use(SignatureVerify(
		WithSignatureSecret(secret),
		WithSignatureHeaders("X-App-ID", "X-User-ID"),
	))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 准备请求数据
	body := `{"name":"test"}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)

	// 生成签名（包含自定义 header）
	headers := map[string]string{
		"X-App-ID":  "app-123",
		"X-User-ID": "user-456",
	}
	signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, "HMAC-SHA256", headers)

	// 创建请求
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-App-ID", "app-123")
	req.Header.Set("X-User-ID", "user-456")

	// 执行请求
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

func TestGenerateSignature_HeaderOrderConsistency(t *testing.T) {
	secret := "test-secret-key"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	method := "POST"
	path := "/api/test"
	body := `{"name":"test"}`

	headersA := map[string]string{
		"X-App-ID":  "app-123",
		"X-User-ID": "user-456",
	}
	headersB := map[string]string{
		"X-User-ID": "user-456",
		"X-App-ID":  "app-123",
	}

	signA := GenerateSignature(method, path, body, timestamp, nonce, secret, "HMAC-SHA256", headersA)
	signB := GenerateSignature(method, path, body, timestamp, nonce, secret, "HMAC-SHA256", headersB)

	assert.Equal(t, signA, signB)
}

func TestBuildSignString_HeaderOrderConsistency(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/test", nil)
	c.Request.Header.Set("X-App-ID", "app-123")
	c.Request.Header.Set("X-User-ID", "user-456")

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	body := `{"name":"test"}`

	ordered := []string{"X-App-ID", "X-User-ID"}
	reversed := []string{"X-User-ID", "X-App-ID"}

	signA := buildSignString(c, timestamp, nonce, body, ordered)
	signB := buildSignString(c, timestamp, nonce, body, reversed)

	assert.Equal(t, signA, signB)
}

func TestBuildSignString_EmptyHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/test", nil)

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	body := `{"name":"test"}`

	sign := buildSignString(c, timestamp, nonce, body, nil)

	assert.NotEmpty(t, sign)
}

func TestBuildSignString_SingleHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/test", nil)
	c.Request.Header.Set("X-App-ID", "app-123")

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	body := `{"name":"test"}`

	sign := buildSignString(c, timestamp, nonce, body, []string{"X-App-ID"})

	assert.Contains(t, sign, "app-123")
}

func TestSignatureVerify_BodySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := "test-secret-key"

	router := gin.New()
	router.Use(SignatureVerify(WithSignatureSecret(secret)))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	body := strings.Repeat("a", int(DefaultMaxBodySize)+1)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, "HMAC-SHA256", nil)

	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "request body too large")
}

func TestSignatureVerify_CustomBodySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := "test-secret-key"
	maxBodySize := int64(1024)

	router := gin.New()
	router.Use(SignatureVerify(
		WithSignatureSecret(secret),
		WithSignatureMaxBodySize(maxBodySize),
	))
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	body := strings.Repeat("a", int(maxBodySize)+1)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := mustGenerateNonce(t)
	signature := GenerateSignature("POST", "/api/test", body, timestamp, nonce, secret, "HMAC-SHA256", nil)

	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "request body too large")
}

// 测试 MemoryNonceStore
func TestMemoryNonceStore(t *testing.T) {
	store := NewMemoryNonceStore()

	nonce := "test-nonce-12345"

	// 初始不存在
	assert.False(t, store.Exists(nonce))

	// 设置 nonce
	err := store.Set(nonce, 5*time.Second)
	assert.NoError(t, err)

	// 现在应该存在
	assert.True(t, store.Exists(nonce))

	// 等待过期
	time.Sleep(6 * time.Second)

	// 过期后应该不存在
	assert.False(t, store.Exists(nonce))
}
