package gin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/swagger"
)

// TestSwagger_Integration 集成测试
func TestSwagger_Integration(t *testing.T) {
	// 创建带 Swagger 的引擎
	e := gin.New(
		gin.EnableSwagger(swagger.SwaggerConfig{
			Title:       "测试 API",
			Description: "Swagger 集成测试",
			Version:     "1.0.0",
			BasePath:    "/api",
			Host:        "localhost:8080",
			Schemes:     []string{"http"},
		}),
	)

	// 注册路由并添加文档注解
	e.Router().GETDoc("/users", func(c *gin.Context) {
		c.Success(gin.H{"users": []string{"user1", "user2"}})
	}).
		Doc("获取用户列表").
		Description("分页获取所有用户信息").
		Param("page", "query", "integer", "页码", false).
		Param("per_page", "query", "integer", "每页数量", false).
		Response(200, "成功", []gin.H{}).
		Tag("用户管理")

	e.Router().POSTDoc("/users", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"id": 1, "name": "test"})
	}).
		Doc("创建用户").
		Param("body", "body", "object", "用户信息", true).
		Response(201, "创建成功", gin.H{}).
		Response(400, "参数错误", gin.H{}).
		Tag("用户管理")

	e.Router().GETDoc("/users/:id", func(c *gin.Context) {
		c.Success(gin.H{"id": c.Param("id"), "name": "test"})
	}).
		Doc("获取用户详情").
		Param("id", "path", "integer", "用户ID", true).
		Response(200, "成功", gin.H{}).
		Response(404, "用户不存在", gin.H{}).
		Tag("用户管理")

	api := e.Router().Group("/api")
	api.GETDoc("/teams/:id", func(c *gin.Context) {
		c.Success(gin.H{"id": c.Param("id")})
	}).
		Doc("获取团队详情").
		Response(200, "成功", gin.H{}).
		Tag("团队管理")

	e.RegexRouter().GET("/orders/{id:[0-9]+}", func(c *gin.Context) {
		c.Success(gin.H{"id": c.Param("id")})
	})

	// 测试 Swagger UI 页面
	t.Run("SwaggerUI", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/swagger", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		body := w.Body.String()
		if body == "" {
			t.Error("Expected non-empty response body")
		}

		// 验证 HTML 包含 Swagger UI
		if !contains(body, "swagger-ui") {
			t.Error("Expected HTML to contain swagger-ui")
		}
	})

	// 测试 Swagger JSON 文档
	t.Run("SwaggerJSON", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/swagger/doc.json", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// 解析 JSON
		var spec swagger.OpenAPI
		if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
			t.Fatalf("Failed to decode JSON: %v", err)
		}

		// 验证基本信息
		if spec.Info.Title != "测试 API" {
			t.Errorf("Expected title '测试 API', got %s", spec.Info.Title)
		}

		// 验证路径
		if _, exists := spec.Paths["/users"]; !exists {
			t.Error("Expected path /users to exist")
		}

		if _, exists := spec.Paths["/users/{id}"]; !exists {
			t.Error("Expected path /users/{id} to exist")
		}

		if _, exists := spec.Paths["/api/teams/{id}"]; !exists {
			t.Error("Expected path /api/teams/{id} to exist")
		}

		if _, exists := spec.Paths["/orders/{id}"]; !exists {
			t.Error("Expected path /orders/{id} to exist")
		}

		// 验证操作
		usersPath := spec.Paths["/users"]
		if usersPath.Get == nil {
			t.Error("Expected GET operation on /users")
		}

		if usersPath.Post == nil {
			t.Error("Expected POST operation on /users")
		}

		// 验证参数
		if usersPath.Get != nil {
			params := usersPath.Get.Parameters
			if len(params) != 2 {
				t.Errorf("Expected 2 parameters, got %d", len(params))
			}
		}

		teamsPath := spec.Paths["/api/teams/{id}"]
		if teamsPath.Get == nil {
			t.Error("Expected GET operation on /api/teams/{id}")
		}
		if teamsPath.Get != nil && len(teamsPath.Get.Parameters) != 1 {
			t.Errorf("Expected 1 inferred path parameter for /api/teams/{id}, got %d", len(teamsPath.Get.Parameters))
		}

		ordersPath := spec.Paths["/orders/{id}"]
		if ordersPath.Get == nil {
			t.Error("Expected GET operation on /orders/{id}")
		}
		if ordersPath.Get != nil {
			if len(ordersPath.Get.Parameters) != 1 {
				t.Errorf("Expected 1 inferred path parameter for /orders/{id}, got %d", len(ordersPath.Get.Parameters))
			}
			if _, ok := ordersPath.Get.Responses["200"]; !ok {
				t.Error("Expected default 200 response on regex fallback route")
			}
		}

		// 验证标签
		if len(spec.Tags) == 0 {
			t.Error("Expected at least one tag")
		}
	})

	// 测试实际 API 调用
	t.Run("APICall", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/users", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

// TestSwagger_WithoutEnable 测试未启用 Swagger 的情况
func TestSwagger_WithoutEnable(t *testing.T) {
	e := gin.New()

	// 注册路由（但不启用 Swagger）
	e.Router().GET("/test", func(c *gin.Context) {
		c.Success(gin.H{"message": "test"})
	})

	// Swagger UI 应该返回 404
	req := httptest.NewRequest("GET", "/swagger", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
