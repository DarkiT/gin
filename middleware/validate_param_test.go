package middleware

import (
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/darkit/gin"
)

func TestValidateParam(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		pattern       *regexp.Regexp
		paramValue    string
		expectedCode  int
		expectedError bool
	}{
		{
			name:          "valid numeric",
			pattern:       PatternNumeric,
			paramValue:    "12345",
			expectedCode:  200,
			expectedError: false,
		},
		{
			name:          "invalid numeric",
			pattern:       PatternNumeric,
			paramValue:    "abc123",
			expectedCode:  400,
			expectedError: true,
		},
		{
			name:          "valid uuid",
			pattern:       PatternUUID,
			paramValue:    "550e8400-e29b-41d4-a716-446655440000",
			expectedCode:  200,
			expectedError: false,
		},
		{
			name:          "invalid uuid",
			pattern:       PatternUUID,
			paramValue:    "not-a-uuid",
			expectedCode:  400,
			expectedError: true,
		},
		{
			name:          "valid slug",
			pattern:       PatternSlug,
			paramValue:    "my-article-title",
			expectedCode:  200,
			expectedError: false,
		},
		{
			name:          "invalid slug - uppercase",
			pattern:       PatternSlug,
			paramValue:    "My-Article",
			expectedCode:  400,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test/:id", ValidateParam("id", tt.pattern), func(c *gin.Context) {
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test/"+tt.paramValue, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}

			if tt.expectedError && w.Body.String() == "ok" {
				t.Error("expected validation error, but handler was executed")
			}
		})
	}
}

func TestValidateParam_AllPredefinedPatterns(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		pattern    *regexp.Regexp
		validValue string
	}{
		{"PatternNumeric", PatternNumeric, "123456"},
		{"PatternAlpha", PatternAlpha, "abcXYZ"},
		{"PatternAlphanumeric", PatternAlphanumeric, "abc123XYZ"},
		{"PatternUUID", PatternUUID, "550e8400-e29b-41d4-a716-446655440000"},
		{"PatternSlug", PatternSlug, "my-article-title"},
		{"PatternEmail", PatternEmail, "test@example.com"},
		// Note: PatternURL skipped - URLs contain ':' which conflicts with Gin's param syntax
		{"PatternHex", PatternHex, "a1b2c3"},
		{"PatternBase64", PatternBase64, "YWJjMTIz"},
		{"PatternDate", PatternDate, "2024-12-22"},
		{"PatternTime", PatternTime, "14:30:00"},
		{"PatternIPv4", PatternIPv4, "192.168.1.1"},
		{"PatternPhone", PatternPhone, "13812345678"},
		{"PatternUsername", PatternUsername, "user_name123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test/:value", ValidateParam("value", tt.pattern), func(c *gin.Context) {
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test/"+tt.validValue, nil)
			router.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Errorf("%s: status code = %d, want 200", tt.name, w.Code)
			}
		})
	}
}

func TestValidateParam_CustomPattern(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 自定义模式: 3个大写字母 + 连字符 + 4个数字
	customPattern := regexp.MustCompile(`^[A-Z]{3}-\d{4}$`)

	router := gin.New()
	router.GET("/items/:code", ValidateParam("code", customPattern), func(c *gin.Context) {
		c.String(200, "ok")
	})

	tests := []struct {
		name         string
		code         string
		expectedCode int
	}{
		{
			name:         "valid custom pattern",
			code:         "ABC-1234",
			expectedCode: 200,
		},
		{
			name:         "invalid - lowercase",
			code:         "abc-1234",
			expectedCode: 400,
		},
		{
			name:         "invalid - wrong number length",
			code:         "ABC-123",
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/items/"+tt.code, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}
		})
	}
}

func TestValidateParamFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/page/:num", ValidateParamFunc("num", func(value string) (bool, string) {
		num, err := strconv.Atoi(value)
		if err != nil {
			return false, "must be a number"
		}
		if num < 1 || num > 100 {
			return false, "must be between 1 and 100"
		}
		return true, ""
	}), func(c *gin.Context) {
		c.String(200, "ok")
	})

	tests := []struct {
		name          string
		pageNum       string
		expectedCode  int
		expectedError string
	}{
		{
			name:          "valid page number",
			pageNum:       "50",
			expectedCode:  200,
			expectedError: "",
		},
		{
			name:          "page number too low",
			pageNum:       "0",
			expectedCode:  400,
			expectedError: "must be between 1 and 100",
		},
		{
			name:          "page number too high",
			pageNum:       "101",
			expectedCode:  400,
			expectedError: "must be between 1 and 100",
		},
		{
			name:          "not a number",
			pageNum:       "abc",
			expectedCode:  400,
			expectedError: "must be a number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/page/"+tt.pageNum, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}

			if tt.expectedError != "" && w.Body.String() == "ok" {
				t.Errorf("expected error message containing %q", tt.expectedError)
			}
		})
	}
}

func TestValidateParam_EmptyParameter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	// 路由定义中 :id 是必需的，但中间件应该处理空值情况
	router.GET("/test/:id", ValidateParam("id", PatternNumeric), func(c *gin.Context) {
		c.String(200, "ok")
	})

	// 测试空参数（虽然在实际路由中很难产生，但中间件应该处理）
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/", nil)
	router.ServeHTTP(w, req)

	// 路由本身会 404，这是预期的
	if w.Code != 404 {
		t.Logf("Empty param resulted in: %d (expected 404 from router)", w.Code)
	}
}

func TestValidateParam_Abort(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var handlerExecuted bool

	router := gin.New()
	router.GET("/test/:id", ValidateParam("id", PatternNumeric), func(c *gin.Context) {
		handlerExecuted = true
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/abc", nil)
	router.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status code = %d, want 400", w.Code)
	}

	if handlerExecuted {
		t.Error("handler should not be executed after validation failure")
	}
}

func TestValidateParam_MultipleParameters(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/users/:userId/posts/:postId",
		ValidateParam("userId", PatternNumeric),
		ValidateParam("postId", PatternNumeric),
		func(c *gin.Context) {
			c.JSON(200, gin.H{
				"userId": c.Param("userId"),
				"postId": c.Param("postId"),
			})
		})

	tests := []struct {
		name         string
		userId       string
		postId       string
		expectedCode int
	}{
		{
			name:         "both valid",
			userId:       "123",
			postId:       "456",
			expectedCode: 200,
		},
		{
			name:         "invalid userId",
			userId:       "abc",
			postId:       "456",
			expectedCode: 400,
		},
		{
			name:         "invalid postId",
			userId:       "123",
			postId:       "xyz",
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/users/"+tt.userId+"/posts/"+tt.postId, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}
		})
	}
}

// BenchmarkValidateParam 性能基准测试
func BenchmarkValidateParam(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test/:id", ValidateParam("id", PatternNumeric), func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/12345", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkValidateParamFunc 自定义验证函数性能测试
func BenchmarkValidateParamFunc(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/page/:num", ValidateParamFunc("num", func(value string) (bool, string) {
		num, err := strconv.Atoi(value)
		if err != nil {
			return false, "must be a number"
		}
		if num < 1 || num > 100 {
			return false, "must be between 1 and 100"
		}
		return true, ""
	}), func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/page/50", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}
