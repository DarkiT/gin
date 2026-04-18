package swagger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// User 测试用的用户模型
type User struct {
	ID    int64  `json:"id" description:"用户ID"`
	Name  string `json:"name" binding:"required" description:"用户名"`
	Email string `json:"email" description:"邮箱"`
	Age   int    `json:"age" description:"年龄"`
}

// ErrorResponse 测试用的错误响应模型
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Node struct {
	Value int   `json:"value"`
	Next  *Node `json:"next"`
}

type A struct {
	B *B `json:"b"`
}

type B struct {
	A *A `json:"a"`
}

// TestSwagger_Generation 测试文档生成
func TestSwagger_Generation(t *testing.T) {
	cfg := SwaggerConfig{
		Title:       "测试 API",
		Description: "这是一个测试 API",
		Version:     "1.0.0",
		BasePath:    "/api",
		Host:        "localhost:8080",
		Schemes:     []string{"http", "https"},
	}

	gen := NewGenerator(cfg)

	// 添加一个路由
	route := &RouteInfo{
		Path:        "/users",
		Method:      "GET",
		Summary:     "获取用户列表",
		Description: "分页获取所有用户信息",
		Tags:        []string{"用户管理"},
		Params: []ParamDoc{
			{Name: "page", In: "query", Type: "integer", Description: "页码", Required: false},
			{Name: "per_page", In: "query", Type: "integer", Description: "每页数量", Required: false},
		},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功", Model: []User{}},
		},
	}
	gen.AddRoute(route)

	// 生成文档
	spec := gen.Generate()

	// 验证基本信息
	if spec.OpenAPI != "3.0.0" {
		t.Errorf("Expected OpenAPI version 3.0.0, got %s", spec.OpenAPI)
	}

	if spec.Info.Title != cfg.Title {
		t.Errorf("Expected title %s, got %s", cfg.Title, spec.Info.Title)
	}

	if spec.Info.Version != cfg.Version {
		t.Errorf("Expected version %s, got %s", cfg.Version, spec.Info.Version)
	}

	// 验证服务器信息
	if len(spec.Servers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(spec.Servers))
	}

	// 验证路径
	if _, exists := spec.Paths["/users"]; !exists {
		t.Error("Expected path /users to exist")
	}

	pathItem := spec.Paths["/users"]
	if pathItem.Get == nil {
		t.Error("Expected GET operation to exist")
	}

	if pathItem.Get.Summary != route.Summary {
		t.Errorf("Expected summary %s, got %s", route.Summary, pathItem.Get.Summary)
	}
}

// TestSwagger_RouteAnnotation 测试路由注解
func TestSwagger_RouteAnnotation(t *testing.T) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)

	// 创建路由信息并链式添加注解
	route := &RouteInfo{
		Path:   "/users/:id",
		Method: "GET",
		Params: []ParamDoc{
			{Name: "id", In: "path", Type: "integer", Description: "用户ID", Required: true},
		},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功", Model: User{}},
			404: {Description: "用户不存在", Model: ErrorResponse{}},
		},
		Tags:       []string{"用户管理"},
		Summary:    "获取用户详情",
		Deprecated: false,
	}

	gen.AddRoute(route)
	spec := gen.Generate()

	// 验证路径参数
	pathItem := spec.Paths["/users/{id}"]
	if pathItem.Get == nil {
		t.Fatal("Expected GET operation to exist")
	}

	if len(pathItem.Get.Parameters) != 1 {
		t.Errorf("Expected 1 parameter, got %d", len(pathItem.Get.Parameters))
	}

	param := pathItem.Get.Parameters[0]
	if param.Name != "id" || param.In != "path" {
		t.Errorf("Expected path parameter 'id', got %s in %s", param.Name, param.In)
	}

	// 验证响应
	if len(pathItem.Get.Responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(pathItem.Get.Responses))
	}
}

// TestSwagger_Parameters 测试参数定义
func TestSwagger_Parameters(t *testing.T) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)

	// 测试各种参数类型
	route := &RouteInfo{
		Path:   "/search",
		Method: "GET",
		Params: []ParamDoc{
			{Name: "q", In: "query", Type: "string", Description: "搜索关键词", Required: true},
			{Name: "page", In: "query", Type: "integer", Description: "页码", Required: false},
			{Name: "X-API-Key", In: "header", Type: "string", Description: "API密钥", Required: true},
		},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	}

	gen.AddRoute(route)
	spec := gen.Generate()

	pathItem := spec.Paths["/search"]
	if pathItem.Get == nil {
		t.Fatal("Expected GET operation to exist")
	}

	params := pathItem.Get.Parameters
	if len(params) != 3 {
		t.Fatalf("Expected 3 parameters, got %d", len(params))
	}

	// 验证查询参数
	queryParam := params[0]
	if queryParam.Name != "q" || queryParam.In != "query" || !queryParam.Required {
		t.Errorf("Query parameter validation failed: %+v", queryParam)
	}

	// 验证头参数
	headerParam := params[2]
	if headerParam.Name != "X-API-Key" || headerParam.In != "header" {
		t.Errorf("Header parameter validation failed: %+v", headerParam)
	}
}

// TestSwagger_Responses 测试响应定义
func TestSwagger_Responses(t *testing.T) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)

	route := &RouteInfo{
		Path:   "/users",
		Method: "POST",
		Params: []ParamDoc{
			{Name: "body", In: "body", Type: "object", Description: "用户信息", Required: true, Model: User{}},
		},
		Responses: map[int]ResponseDoc{
			201: {Description: "创建成功", Model: User{}},
			400: {Description: "参数错误", Model: ErrorResponse{}},
			500: {Description: "服务器错误"},
		},
	}

	gen.AddRoute(route)
	spec := gen.Generate()

	pathItem := spec.Paths["/users"]
	if pathItem.Post == nil {
		t.Fatal("Expected POST operation to exist")
	}

	responses := pathItem.Post.Responses
	if len(responses) != 3 {
		t.Errorf("Expected 3 responses, got %d", len(responses))
	}

	// 验证 201 响应
	if resp, exists := responses["201"]; !exists {
		t.Error("Expected 201 response to exist")
	} else if resp.Description != "创建成功" {
		t.Errorf("Expected description '创建成功', got %s", resp.Description)
	}

	// 验证 400 响应
	if resp, exists := responses["400"]; !exists {
		t.Error("Expected 400 response to exist")
	} else {
		if resp.Content == nil {
			t.Error("Expected response content to exist")
		}
	}
}

// TestSwagger_UI 测试 UI 服务
func TestSwagger_UI(t *testing.T) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)
	uiHandler := NewUIHandler(gen)

	// 测试 UI 页面
	t.Run("ServeUI", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/swagger", nil)
		w := httptest.NewRecorder()

		uiHandler.ServeUI(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "text/html; charset=utf-8" {
			t.Errorf("Expected Content-Type text/html, got %s", contentType)
		}

		body := w.Body.String()
		if body == "" {
			t.Error("Expected non-empty response body")
		}

		// 验证 HTML 包含必要元素
		if indexOf(body, "swagger-ui") < 0 {
			t.Error("Expected HTML to contain swagger-ui")
		}
	})

	// 测试文档 JSON
	t.Run("ServeDoc", func(t *testing.T) {
		// 添加一个测试路由
		gen.AddRoute(&RouteInfo{
			Path:    "/test",
			Method:  "GET",
			Summary: "测试路由",
			Responses: map[int]ResponseDoc{
				200: {Description: "成功"},
			},
		})

		req := httptest.NewRequest("GET", "/swagger/doc.json", nil)
		w := httptest.NewRecorder()

		uiHandler.ServeDoc(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json; charset=utf-8" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}

		// 验证 JSON 格式
		var spec OpenAPI
		if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
			t.Errorf("Failed to decode JSON: %v", err)
		}

		if spec.OpenAPI != "3.0.0" {
			t.Errorf("Expected OpenAPI version 3.0.0, got %s", spec.OpenAPI)
		}
	})
}

// TestSwagger_Tags 测试标签
func TestSwagger_Tags(t *testing.T) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)

	// 添加多个路由，使用不同标签
	gen.AddRoute(&RouteInfo{
		Path:    "/users",
		Method:  "GET",
		Summary: "获取用户列表",
		Tags:    []string{"用户管理"},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	})

	gen.AddRoute(&RouteInfo{
		Path:    "/orders",
		Method:  "GET",
		Summary: "获取订单列表",
		Tags:    []string{"订单管理"},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	})

	gen.AddRoute(&RouteInfo{
		Path:    "/users/:id",
		Method:  "GET",
		Summary: "获取用户详情",
		Tags:    []string{"用户管理"},
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	})

	spec := gen.Generate()

	// 验证标签数量
	if len(spec.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(spec.Tags))
	}

	// 验证标签名称
	tagNames := make(map[string]bool)
	for _, tag := range spec.Tags {
		tagNames[tag.Name] = true
	}

	if !tagNames["用户管理"] || !tagNames["订单管理"] {
		t.Error("Expected tags '用户管理' and '订单管理'")
	}
}

// TestSwagger_StructSchema 测试结构体 Schema 生成
func TestSwagger_StructSchema(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	schema := gen.buildSchemaFromModel(User{}, "test")

	if schema.Type != "object" {
		t.Errorf("Expected type object, got %s", schema.Type)
	}

	if schema.Properties == nil {
		t.Fatal("Expected properties to exist")
	}

	// 验证字段
	if _, exists := schema.Properties["id"]; !exists {
		t.Error("Expected field 'id' to exist")
	}

	if _, exists := schema.Properties["name"]; !exists {
		t.Error("Expected field 'name' to exist")
	}

	// 验证必需字段
	hasRequired := false
	for _, req := range schema.Required {
		if req == "name" {
			hasRequired = true
			break
		}
	}
	if !hasRequired {
		t.Error("Expected 'name' to be required")
	}
}

func TestSwagger_CircularReferences(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	schema := gen.buildSchemaFromModel(Node{}, "test")
	if schema.Type != "object" {
		t.Fatalf("Expected type object, got %s", schema.Type)
	}

	nextSchema := schema.Properties["next"]
	if nextSchema == nil {
		t.Fatal("Expected next schema to exist")
	}
	if nextSchema.Ref == "" {
		t.Fatal("Expected next schema to use $ref")
	}

	mutualSchema := gen.buildSchemaFromModel(A{}, "test")
	if mutualSchema.Properties["b"] == nil {
		t.Fatal("Expected b schema to exist")
	}
	if mutualSchema.Properties["b"].Properties["a"] == nil {
		t.Fatal("Expected mutual nested reference to exist")
	}
	if mutualSchema.Properties["b"].Properties["a"].Ref == "" {
		t.Fatal("Expected mutual reference to use $ref")
	}
}

// TestSwagger_ArraySchema 测试数组 Schema 生成
func TestSwagger_ArraySchema(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	schema := gen.buildSchemaFromModel([]User{}, "test")

	if schema.Type != "array" {
		t.Errorf("Expected type array, got %s", schema.Type)
	}

	if schema.Items == nil {
		t.Fatal("Expected items schema to exist")
	}

	if schema.Items.Type != "object" {
		t.Errorf("Expected items type object, got %s", schema.Items.Type)
	}
}

// BenchmarkGenerate 基准测试文档生成
func BenchmarkGenerate(b *testing.B) {
	cfg := SwaggerConfig{
		Title:   "测试 API",
		Version: "1.0.0",
	}

	gen := NewGenerator(cfg)

	// 添加多个路由
	for i := 0; i < 10; i++ {
		gen.AddRoute(&RouteInfo{
			Path:    "/test",
			Method:  "GET",
			Summary: "测试",
			Responses: map[int]ResponseDoc{
				200: {Description: "成功"},
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gen.Generate()
	}
}

// TestSwagger_TypeMapping 测试类型映射
func TestSwagger_TypeMapping(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	tests := []struct {
		typeName string
		expected string
	}{
		{"string", "string"},
		{"str", "string"},
		{"integer", "integer"},
		{"int", "integer"},
		{"int32", "integer"},
		{"int64", "integer"},
		{"long", "integer"},
		{"number", "number"},
		{"float", "number"},
		{"double", "number"},
		{"float32", "number"},
		{"float64", "number"},
		{"boolean", "boolean"},
		{"bool", "boolean"},
		{"array", "array"},
		{"object", "object"},
		{"unknown", "string"}, // 默认值
	}

	for _, tt := range tests {
		result := gen.mapType(tt.typeName)
		if result != tt.expected {
			t.Errorf("mapType(%s) = %s, expected %s", tt.typeName, result, tt.expected)
		}
	}
}

// TestSwagger_SchemaFormat 测试 Schema 格式
func TestSwagger_SchemaFormat(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	tests := []struct {
		typeName       string
		expectedType   string
		expectedFormat string
	}{
		{"integer", "integer", "int32"},
		{"long", "integer", "int64"},
		{"float", "number", "float"},
		{"double", "number", "double"},
		{"date", "string", "date"},
		{"datetime", "string", "date-time"},
	}

	for _, tt := range tests {
		schema := gen.buildSchema(tt.typeName, nil, "test")
		if schema.Type != tt.expectedType {
			t.Errorf("buildSchema(%s).Type = %s, expected %s", tt.typeName, schema.Type, tt.expectedType)
		}
		if schema.Format != tt.expectedFormat {
			t.Errorf("buildSchema(%s).Format = %s, expected %s", tt.typeName, schema.Format, tt.expectedFormat)
		}
	}
}

// TestSwagger_AddRoutes 测试批量添加路由
func TestSwagger_AddRoutes(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	routes := []*RouteInfo{
		{Path: "/test1", Method: "GET", Responses: map[int]ResponseDoc{200: {Description: "成功"}}},
		{Path: "/test2", Method: "POST", Responses: map[int]ResponseDoc{201: {Description: "创建成功"}}},
		{Path: "/test3", Method: "DELETE", Responses: map[int]ResponseDoc{204: {Description: "删除成功"}}},
	}

	gen.AddRoutes(routes)

	spec := gen.Generate()

	if len(spec.Paths) != 3 {
		t.Errorf("Expected 3 paths, got %d", len(spec.Paths))
	}
}

// TestSwagger_NormalizeRegexAndWildcardRoutes 测试 regex 与 wildcard 路径规范化。
func TestSwagger_NormalizeRegexAndWildcardRoutes(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	gen.AddRoute(&RouteInfo{
		Path:   "/orders/{id:[0-9]+}",
		Method: "GET",
	})
	gen.AddRoute(&RouteInfo{
		Path:   "/files/*",
		Method: "GET",
	})

	spec := gen.Generate()

	ordersPath := spec.Paths["/orders/{id}"]
	if ordersPath.Get == nil {
		t.Fatal("Expected GET operation on /orders/{id}")
	}
	if len(ordersPath.Get.Parameters) != 1 || ordersPath.Get.Parameters[0].Name != "id" {
		t.Fatalf("Expected inferred id path parameter, got %+v", ordersPath.Get.Parameters)
	}
	if _, ok := ordersPath.Get.Responses["200"]; !ok {
		t.Fatal("Expected default 200 response on regex route")
	}

	filesPath := spec.Paths["/files/{_wildcard}"]
	if filesPath.Get == nil {
		t.Fatal("Expected GET operation on /files/{_wildcard}")
	}
	if len(filesPath.Get.Parameters) != 1 || filesPath.Get.Parameters[0].Name != "_wildcard" {
		t.Fatalf("Expected inferred wildcard path parameter, got %+v", filesPath.Get.Parameters)
	}
}

// TestSwagger_TraceOperation 测试 TRACE 方法文档生成。
func TestSwagger_TraceOperation(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	gen.AddRoute(&RouteInfo{
		Path:   "/trace/{id:[0-9]+}",
		Method: "TRACE",
	})

	spec := gen.Generate()
	tracePath := spec.Paths["/trace/{id}"]
	if tracePath.Trace == nil {
		t.Fatal("Expected TRACE operation on /trace/{id}")
	}
	if len(tracePath.Trace.Parameters) != 1 || tracePath.Trace.Parameters[0].Name != "id" {
		t.Fatalf("Expected inferred id path parameter, got %+v", tracePath.Trace.Parameters)
	}
}

// TestSwagger_EmptyConfig 测试空配置
func TestSwagger_EmptyConfig(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	spec := gen.Generate()

	if spec.OpenAPI != "3.0.0" {
		t.Errorf("Expected OpenAPI version 3.0.0, got %s", spec.OpenAPI)
	}

	if spec.Info.Version != "1.0.0" {
		t.Errorf("Expected default version 1.0.0, got %s", spec.Info.Version)
	}

	// 空配置下，服务器列表应该为空
	if len(spec.Servers) != 0 {
		t.Errorf("Expected empty servers list, got %d servers", len(spec.Servers))
	}
}

// TestSwagger_SecurityRequirement 测试安全要求
func TestSwagger_SecurityRequirement(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	route := &RouteInfo{
		Path:     "/secure",
		Method:   "GET",
		Security: "bearer",
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	}

	gen.AddRoute(route)
	spec := gen.Generate()

	pathItem := spec.Paths["/secure"]
	if pathItem.Get == nil {
		t.Fatal("Expected GET operation to exist")
	}

	if len(pathItem.Get.Security) == 0 {
		t.Error("Expected security requirement to exist")
	}

	if pathItem.Get.Security[0]["bearer"] == nil {
		t.Error("Expected bearer security requirement")
	}
}

// TestSwagger_DeprecatedRoute 测试废弃路由
func TestSwagger_DeprecatedRoute(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	route := &RouteInfo{
		Path:       "/old-api",
		Method:     "GET",
		Deprecated: true,
		Responses: map[int]ResponseDoc{
			200: {Description: "成功"},
		},
	}

	gen.AddRoute(route)
	spec := gen.Generate()

	pathItem := spec.Paths["/old-api"]
	if pathItem.Get == nil {
		t.Fatal("Expected GET operation to exist")
	}

	if !pathItem.Get.Deprecated {
		t.Error("Expected route to be marked as deprecated")
	}
}

// TestSwagger_ComplexModel 测试复杂模型
func TestSwagger_ComplexModel(t *testing.T) {
	type Address struct {
		Street string `json:"street"`
		City   string `json:"city"`
	}

	type ComplexUser struct {
		ID      int64   `json:"id"`
		Name    string  `json:"name" binding:"required"`
		Address Address `json:"address"`
	}

	gen := NewGenerator(SwaggerConfig{})
	schema := gen.buildSchemaFromModel(ComplexUser{}, "test")

	if schema.Type != "object" {
		t.Errorf("Expected type object, got %s", schema.Type)
	}

	if _, exists := schema.Properties["address"]; !exists {
		t.Error("Expected nested address field to exist")
	}

	addressSchema := schema.Properties["address"]
	if addressSchema.Type != "object" {
		t.Errorf("Expected address type object, got %s", addressSchema.Type)
	}
}

// TestSwagger_StringHelpers 测试字符串辅助函数
func TestSwagger_StringHelpers(t *testing.T) {
	// 测试 replaceString
	input := "Hello {{name}}, welcome to {{place}}!"
	result := replaceString(input, "{{name}}", "World")
	expected := "Hello World, welcome to {{place}}!"
	if result != expected {
		t.Errorf("replaceString failed: got %s, expected %s", result, expected)
	}

	// 测试 indexOf
	if indexOf("hello world", "world") != 6 {
		t.Error("indexOf failed for existing substring")
	}

	if indexOf("hello", "xyz") != -1 {
		t.Error("indexOf should return -1 for non-existing substring")
	}
}

// TestSwagger_IntToString 测试整数转字符串
func TestSwagger_IntToString(t *testing.T) {
	for i := 100; i <= 599; i++ {
		result := intToString(i)
		expected := strconv.Itoa(i)
		if result != expected {
			t.Fatalf("intToString(%d) = %s, expected %s", i, result, expected)
		}
	}

	negativeAndZero := []int{0, -1, -100}
	for _, input := range negativeAndZero {
		result := intToString(input)
		expected := strconv.Itoa(input)
		if result != expected {
			t.Errorf("intToString(%d) = %s, expected %s", input, result, expected)
		}
	}
}

// TestSwagger_MultipleHTTPMethods 测试多个 HTTP 方法
func TestSwagger_MultipleHTTPMethods(t *testing.T) {
	gen := NewGenerator(SwaggerConfig{})

	// 同一个路径，不同方法
	gen.AddRoute(&RouteInfo{
		Path:      "/resource",
		Method:    "GET",
		Summary:   "获取资源",
		Responses: map[int]ResponseDoc{200: {Description: "成功"}},
	})

	gen.AddRoute(&RouteInfo{
		Path:      "/resource",
		Method:    "POST",
		Summary:   "创建资源",
		Responses: map[int]ResponseDoc{201: {Description: "创建成功"}},
	})

	gen.AddRoute(&RouteInfo{
		Path:      "/resource",
		Method:    "PUT",
		Summary:   "更新资源",
		Responses: map[int]ResponseDoc{200: {Description: "更新成功"}},
	})

	gen.AddRoute(&RouteInfo{
		Path:      "/resource",
		Method:    "DELETE",
		Summary:   "删除资源",
		Responses: map[int]ResponseDoc{204: {Description: "删除成功"}},
	})

	spec := gen.Generate()

	pathItem := spec.Paths["/resource"]
	if pathItem.Get == nil {
		t.Error("Expected GET operation")
	}
	if pathItem.Post == nil {
		t.Error("Expected POST operation")
	}
	if pathItem.Put == nil {
		t.Error("Expected PUT operation")
	}
	if pathItem.Delete == nil {
		t.Error("Expected DELETE operation")
	}
}
