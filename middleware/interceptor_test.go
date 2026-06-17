package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/darkit/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestInterceptor_RequestInterceptor 测试请求拦截器
func TestInterceptor_RequestInterceptor(t *testing.T) {
	r := gin.New()

	// 添加请求拦截器
	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			// 检查请求头
			if c.GetHeader("X-API-Key") == "" {
				return errors.New("missing API key")
			}
			// 记录请求
			c.Set("intercepted", true)
			return nil
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		if c.GetBool("intercepted") {
			c.JSON(200, gin.H{"status": "ok"})
		}
	})

	// 测试缺少 API key
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "missing API key", resp["error"])

	// 测试正常请求
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "valid-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp["status"])
}

// TestInterceptor_ResponseInterceptor 测试响应拦截器
func TestInterceptor_ResponseInterceptor(t *testing.T) {
	r := gin.New()

	// 添加响应拦截器
	r.Use(Interceptor(InterceptorConfig{
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			// 修改响应：添加签名
			var data map[string]any
			if err := json.Unmarshal(body, &data); err != nil {
				return body, nil
			}
			data["signature"] = "test-signature"
			return json.Marshal(data)
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "hello"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "hello", resp["message"])
	assert.Equal(t, "test-signature", resp["signature"])
}

// TestInterceptor_ResponseError 测试响应拦截器错误处理
func TestInterceptor_ResponseError(t *testing.T) {
	r := gin.New()

	// 添加会失败的响应拦截器
	r.Use(Interceptor(InterceptorConfig{
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			return nil, errors.New("processing failed")
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "hello"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "响应处理失败", resp["error"])
}

// TestInterceptor_ChainExecution 测试拦截器链执行顺序
func TestInterceptor_ChainExecution(t *testing.T) {
	r := gin.New()

	var executionOrder []string

	// 第一个拦截器
	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			executionOrder = append(executionOrder, "request-1")
			return nil
		},
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			executionOrder = append(executionOrder, "response-1")
			return body, nil
		},
	}))

	// 第二个拦截器
	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			executionOrder = append(executionOrder, "request-2")
			return nil
		},
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			executionOrder = append(executionOrder, "response-2")
			return body, nil
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		executionOrder = append(executionOrder, "handler")
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	// 验证执行顺序：request-1 → request-2 → handler → response-2 → response-1
	expected := []string{"request-1", "request-2", "handler", "response-2", "response-1"}
	assert.Equal(t, expected, executionOrder)
}

// TestInterceptor_BodyModification 测试响应体修改
func TestInterceptor_BodyModification(t *testing.T) {
	r := gin.New()

	r.Use(Interceptor(InterceptorConfig{
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			// 将所有响应转为大写
			return bytes.ToUpper(body), nil
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "hello world"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "HELLO WORLD"))
}

// TestInterceptor_ConcurrentRequests 测试并发请求处理
func TestInterceptor_ConcurrentRequests(t *testing.T) {
	r := gin.New()

	var counter int
	var mu sync.Mutex

	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			mu.Lock()
			counter++
			mu.Unlock()
			return nil
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 并发发送100个请求
	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for range concurrency {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}()
	}

	wg.Wait()

	// 验证所有请求都被拦截
	assert.Equal(t, concurrency, counter)
}

// TestInterceptor_ErrorPropagation 测试错误传播
func TestInterceptor_ErrorPropagation(t *testing.T) {
	r := gin.New()

	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			// 模拟认证失败
			if c.GetHeader("Authorization") != "Bearer valid-token" {
				return errors.New("unauthorized")
			}
			return nil
		},
	}))

	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": "secret"})
	})

	// 测试未授权请求
	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "unauthorized", resp["error"])

	// 测试授权请求
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "secret", resp["data"])
}

// TestInterceptor_NoInterceptor 测试无拦截器配置
func TestInterceptor_NoInterceptor(t *testing.T) {
	r := gin.New()

	// 空配置，不应影响请求
	r.Use(Interceptor(InterceptorConfig{}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp["status"])
}

// TestInterceptor_OnlyRequestInterceptor 测试仅请求拦截器
func TestInterceptor_OnlyRequestInterceptor(t *testing.T) {
	r := gin.New()

	r.Use(Interceptor(InterceptorConfig{
		OnRequest: func(c *gin.Context) error {
			c.Set("request_time", "2024-01-01")
			return nil
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"request_time": c.GetString("request_time"),
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "2024-01-01", resp["request_time"])
}

// TestInterceptor_OnlyResponseInterceptor 测试仅响应拦截器
func TestInterceptor_OnlyResponseInterceptor(t *testing.T) {
	r := gin.New()

	r.Use(Interceptor(InterceptorConfig{
		OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
			var data map[string]any
			if err := json.Unmarshal(body, &data); err != nil {
				return body, nil
			}
			data["timestamp"] = "2024-01-01"
			return json.Marshal(data)
		},
	}))

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "test", resp["message"])
	assert.Equal(t, "2024-01-01", resp["timestamp"])
}
