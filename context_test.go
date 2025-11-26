package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin/cache"
	"github.com/gin-gonic/gin"
)

// TestContextOptimization 测试Context优化功能
func TestContextOptimization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("对象池功能测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// 创建Context
		ctx1 := newContext(c)
		if !ctx1.IsPooled() {
			t.Error("Context应该标记为来自对象池")
		}

		// 设置缓存
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx1.SetCache(cacheInstance)
		ctx1.CacheSet("test", "value")

		if !ctx1.HasComponents() {
			t.Error("Context应该有组件")
		}

		// 释放到池中
		releaseContext(ctx1)

		// 再次获取Context
		ctx2 := newContext(c)

		// 验证状态已重置
		if ctx2.HasComponents() {
			t.Error("从池中获取的Context应该没有组件")
		}

		releaseContext(ctx2)
	})

	t.Run("延迟初始化测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)

		// 初始状态不应该有组件
		if ctx.HasComponents() {
			t.Error("新创建的Context不应该有组件")
		}

		// 设置缓存应该触发组件初始化
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)

		if !ctx.HasComponents() {
			t.Error("设置缓存后应该初始化组件")
		}

		if ctx.ComponentsCount() != 1 {
			t.Errorf("设置缓存后应该有1个组件，实际有%d个", ctx.ComponentsCount())
		}

		releaseContext(ctx)
	})

	t.Run("组件访问优化测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)

		// 测试缓存访问
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)

		// 设置和获取缓存值
		ctx.CacheSet("key1", "value1", time.Minute)
		if val, ok := ctx.CacheGet("key1"); !ok || val != "value1" {
			t.Error("缓存设置和获取失败")
		}

		// 测试缓存检查
		if !ctx.CacheHas("key1") {
			t.Error("缓存检查失败")
		}

		// 测试缓存删除
		ctx.CacheDelete("key1")
		if ctx.CacheHas("key1") {
			t.Error("缓存删除失败")
		}

		releaseContext(ctx)
	})

	t.Run("Context克隆测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)
		ctx.CacheSet("test", "value")

		// 克隆Context
		clone := ctx.Clone()

		// 验证克隆的Context不是来自池
		if clone.IsPooled() {
			t.Error("克隆的Context不应该标记为来自对象池")
		}

		// 验证组件是共享的
		if val, ok := clone.CacheGet("test"); !ok || val != "value" {
			t.Error("克隆的Context应该共享组件")
		}

		releaseContext(ctx)
	})

	t.Run("链式组件设置测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())

		// 测试链式调用
		result := ctx.WithComponents(cacheInstance, nil, nil, nil)

		if result != ctx {
			t.Error("WithComponents应该返回同一个Context实例")
		}

		if ctx.ComponentsCount() != 1 {
			t.Errorf("应该有1个组件，实际有%d个", ctx.ComponentsCount())
		}

		releaseContext(ctx)
	})
}

// BenchmarkContextCreationOptimized 优化后的Context创建性能测试
func BenchmarkContextCreationOptimized(b *testing.B) {
	gin.SetMode(gin.TestMode)

	b.Run("对象池创建", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)
			releaseContext(ctx)
		}
	})

	b.Run("带组件创建", func(b *testing.B) {
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := NewContextWithComponents(c, cacheInstance, nil, nil, nil)
			releaseContext(ctx)
		}
	})
}

// BenchmarkContextComponentAccess 组件访问性能测试
func BenchmarkContextComponentAccess(b *testing.B) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ctx := newContext(c)
	cacheInstance := cache.New[string, any](*cache.DefaultConfig())
	ctx.SetCache(cacheInstance)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx.CacheSet("test", "value")
		_, _ = ctx.CacheGet("test")
	}

	releaseContext(ctx)
}

// TestContextType 测试Type方法使用标准库mime解析
func TestContextType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		accept   string
		expected string
	}{
		{"JSON请求", "application/json", "json"},
		{"JSON请求带参数", "application/json; charset=utf-8", "json"},
		{"JSON请求带权重", "application/json;q=0.9, text/html;q=0.8", "json"},
		{"文本JSON", "text/json", "json"},
		{"XML请求", "application/xml", "xml"},
		{"文本XML", "text/xml", "xml"},
		{"HTML请求", "text/html", "html"},
		{"XHTML请求", "application/xhtml+xml", "html"},
		{"纯文本", "text/plain", "text"},
		{"JavaScript", "application/javascript", "js"},
		{"文本JavaScript", "text/javascript", "js"},
		{"CSS", "text/css", "css"},
		{"PDF", "application/pdf", "pdf"},
		{"CSV", "text/csv", "csv"},
		{"RSS", "application/rss+xml", "rss"},
		{"Atom", "application/atom+xml", "atom"},
		{"YAML", "application/x-yaml", "yaml"},
		{"文本YAML", "text/yaml", "yaml"},
		{"图片PNG", "image/png", "image"},
		{"图片JPEG", "image/jpeg", "image"},
		{"图片通配", "image/*", "image"},
		{"通配符", "*/*", "html"},
		{"空字符串", "", ""},
		{"浏览器Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "html"},
		{"API Accept", "application/json,text/plain,*/*", "json"},
		{"不支持的类型", "application/octet-stream", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)
			result := ctx.Type()

			if result != tt.expected {
				t.Errorf("Type() = %q, 期望 %q (Accept: %q)", result, tt.expected, tt.accept)
			}

			releaseContext(ctx)
		})
	}
}

// TestContextIsJSON 测试IsJSON方法
func TestContextIsJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		accept   string
		expected bool
	}{
		{"JSON请求", "application/json", true},
		{"JSON带参数", "application/json; charset=utf-8", true},
		{"文本JSON", "text/json", true},
		{"HTML请求", "text/html", false},
		{"XML请求", "application/xml", false},
		{"空Accept", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)
			result := ctx.IsJSON()

			if result != tt.expected {
				t.Errorf("IsJSON() = %v, 期望 %v (Accept: %q)", result, tt.expected, tt.accept)
			}

			releaseContext(ctx)
		})
	}
}

// BenchmarkContextType 性能测试Type方法
func BenchmarkContextType(b *testing.B) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name   string
		accept string
	}{
		{"JSON", "application/json"},
		{"JSON带参数", "application/json; charset=utf-8"},
		{"浏览器Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"复杂Accept", "application/json,text/plain,text/html,application/xml;q=0.9,*/*;q=0.8"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Accept", tc.accept)

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = ctx.Type()
			}

			releaseContext(ctx)
		})
	}
}

// TestContextRootDomain 测试RootDomain方法使用publicsuffix
func TestContextRootDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		host     string
		expected string
	}{
		// 标准域名
		{"二级域名", "example.com", "example.com"},
		{"三级域名", "www.example.com", "example.com"},
		{"四级域名", "api.www.example.com", "example.com"},
		{"带端口的域名", "example.com:8080", "example.com"},
		{"带端口的子域名", "www.example.com:8080", "example.com"},

		// 特殊公共后缀
		{"英国域名", "example.co.uk", "example.co.uk"},
		{"英国子域名", "www.example.co.uk", "example.co.uk"},
		{"中国域名", "example.com.cn", "example.com.cn"},
		{"中国子域名", "www.example.com.cn", "example.com.cn"},
		{"日本域名", "example.co.jp", "example.co.jp"},
		{"澳大利亚域名", "example.com.au", "example.com.au"},

		// 新顶级域名
		{"app域名", "example.app", "example.app"},
		{"dev域名", "example.dev", "example.dev"},
		{"io域名", "example.io", "example.io"},

		// 边界情况
		{"空字符串", "", ""},
		{"单级域名", "localhost", "localhost"},
		{"IP地址", "192.168.1.1", ""},
		{"IPv6", "[::1]", ""},
		{"带端口的IP", "192.168.1.1:8080", ""},

		// 真实案例
		{"GitHub", "github.com", "github.com"},
		{"GitHub子域名", "api.github.com", "github.com"},
		{"Google", "www.google.com", "google.com"},
		{"Google UK", "www.google.co.uk", "google.co.uk"},
		{"淘宝", "www.taobao.com", "taobao.com"},
		{"百度", "www.baidu.com", "baidu.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Host = tt.host

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)
			result := ctx.RootDomain()

			if result != tt.expected {
				t.Errorf("RootDomain() = %q, 期望 %q (Host: %q)", result, tt.expected, tt.host)
			}

			releaseContext(ctx)
		})
	}
}

// BenchmarkContextRootDomain 性能测试RootDomain方法
func BenchmarkContextRootDomain(b *testing.B) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name string
		host string
	}{
		{"简单域名", "example.com"},
		{"子域名", "www.example.com"},
		{"带端口", "www.example.com:8080"},
		{"英国域名", "www.example.co.uk"},
		{"中国域名", "www.example.com.cn"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Host = tc.host

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = ctx.RootDomain()
			}

			releaseContext(ctx)
		})
	}
}

// TestContextLanguage 测试 Language 方法优化
func TestContextLanguage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		acceptLanguage string
		expected       string
	}{
		{
			name:           "简体中文",
			acceptLanguage: "zh-CN,zh;q=0.9,en;q=0.8",
			expected:       "zh-CN",
		},
		{
			name:           "繁体中文",
			acceptLanguage: "zh-TW,zh;q=0.9",
			expected:       "zh-TW",
		},
		{
			name:           "英语美国",
			acceptLanguage: "en-US,en;q=0.9",
			expected:       "en-US",
		},
		{
			name:           "英语英国",
			acceptLanguage: "en-GB,en;q=0.9",
			expected:       "en-GB",
		},
		{
			name:           "日语",
			acceptLanguage: "ja-JP,ja;q=0.9,en;q=0.8",
			expected:       "ja-JP",
		},
		{
			name:           "韩语",
			acceptLanguage: "ko-KR,ko;q=0.9",
			expected:       "ko-KR",
		},
		{
			name:           "法语",
			acceptLanguage: "fr-FR,fr;q=0.9",
			expected:       "fr-FR",
		},
		{
			name:           "德语",
			acceptLanguage: "de-DE,de;q=0.9",
			expected:       "de-DE",
		},
		{
			name:           "复杂权重",
			acceptLanguage: "en-US;q=0.7,zh-CN;q=0.9,ja;q=0.8",
			expected:       "zh-CN", // 权重最高
		},
		{
			name:           "空字符串",
			acceptLanguage: "",
			expected:       "zh-CN", // 默认值
		},
		{
			name:           "无效格式",
			acceptLanguage: "invalid-header",
			expected:       "zh-CN", // 解析失败返回默认值
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.acceptLanguage != "" {
				req.Header.Set("Accept-Language", tt.acceptLanguage)
			}
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)
			got := ctx.Language()

			if got != tt.expected {
				t.Errorf("Language() = %v, expected %v", got, tt.expected)
			}

			releaseContext(ctx)
		})
	}
}

// TestContextGetIntSlice 测试 GetIntSlice 方法优化
func TestContextGetIntSlice(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		queryKey  string
		queryVal  string
		separator string
		expected  []int
	}{
		{
			name:      "逗号分隔",
			queryKey:  "ids",
			queryVal:  "1,2,3,4,5",
			separator: ",",
			expected:  []int{1, 2, 3, 4, 5},
		},
		{
			name:      "带空格",
			queryKey:  "ids",
			queryVal:  "1, 2, 3, 4, 5",
			separator: ",",
			expected:  []int{1, 2, 3, 4, 5},
		},
		{
			name:      "连续空值",
			queryKey:  "ids",
			queryVal:  "10,,,20,,,30",
			separator: ",",
			expected:  []int{10, 20, 30},
		},
		{
			name:      "管道符分隔",
			queryKey:  "ids",
			queryVal:  "100|200|300",
			separator: "|",
			expected:  []int{100, 200, 300},
		},
		{
			name:      "包含非数字",
			queryKey:  "ids",
			queryVal:  "1,abc,3,def,5",
			separator: ",",
			expected:  []int{1, 3, 5}, // 自动过滤非数字
		},
		{
			name:      "空值处理",
			queryKey:  "ids",
			queryVal:  "1,,3,,5",
			separator: ",",
			expected:  []int{1, 3, 5}, // FieldsFunc自动过滤空值
		},
		{
			name:      "单个值",
			queryKey:  "ids",
			queryVal:  "42",
			separator: ",",
			expected:  []int{42},
		},
		{
			name:      "空字符串",
			queryKey:  "ids",
			queryVal:  "",
			separator: ",",
			expected:  []int{},
		},
		{
			name:      "默认分隔符",
			queryKey:  "ids",
			queryVal:  "7,8,9",
			separator: "", // 使用默认逗号
			expected:  []int{7, 8, 9},
		},
		{
			name:      "负数支持",
			queryKey:  "ids",
			queryVal:  "-1,0,1",
			separator: ",",
			expected:  []int{-1, 0, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			url := "/test"
			if tt.queryVal != "" {
				url += "?" + tt.queryKey + "=" + tt.queryVal
			}
			req, _ := http.NewRequest("GET", url, nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)

			var got []int
			if tt.separator == "" {
				got = ctx.GetIntSlice(tt.queryKey)
			} else {
				got = ctx.GetIntSlice(tt.queryKey, tt.separator)
			}

			if len(got) != len(tt.expected) {
				t.Errorf("GetIntSlice() length = %v, expected %v", len(got), len(tt.expected))
				return
			}

			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("GetIntSlice()[%d] = %v, expected %v", i, got[i], tt.expected[i])
				}
			}

			releaseContext(ctx)
		})
	}
}
