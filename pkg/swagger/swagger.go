package swagger

import (
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// SwaggerConfig Swagger 配置
type SwaggerConfig struct {
	Title       string   // API 标题
	Description string   // API 描述
	Version     string   // API 版本
	BasePath    string   // 基础路径
	Host        string   // 主机地址
	Schemes     []string // 协议: http, https
	Contact     Contact  // 联系信息
}

// Generator Swagger 文档生成器
type Generator struct {
	config     SwaggerConfig
	routeInfos []*RouteInfo
}

var (
	chiPathParamPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(:[^{}]+)?\}`)
	openAPIParamPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// RouteInfo 路由信息
type RouteInfo struct {
	Path        string              // 路径
	Method      string              // HTTP 方法
	Summary     string              // 简要说明
	Description string              // 详细描述
	OperationID string              // 操作 ID
	Params      []ParamDoc          // 参数列表
	Responses   map[int]ResponseDoc // 响应定义
	Tags        []string            // 标签
	Deprecated  bool                // 是否废弃
	Security    string              // 安全方案名称
}

// ParamDoc 参数文档
type ParamDoc struct {
	Name        string      // 参数名称
	In          string      // 位置: query, header, path, body
	Type        string      // 类型: string, integer, boolean, object, array
	Description string      // 描述
	Required    bool        // 是否必需
	ContentType string      // 请求体内容类型，仅 body 生效
	Example     interface{} // 示例值
	Examples    map[string]Example
	Model       interface{} // 模型（用于 body 参数）
}

// ResponseDoc 响应文档
type ResponseDoc struct {
	Description string      // 响应描述
	ContentType string      // 响应内容类型
	Example     interface{} // 示例值
	Examples    map[string]Example
	Model       interface{} // 响应模型
}

// NewGenerator 创建 Swagger 文档生成器
func NewGenerator(cfg SwaggerConfig) *Generator {
	// 设置默认值
	if cfg.Version == "" {
		cfg.Version = "1.0.0"
	}
	if len(cfg.Schemes) == 0 {
		cfg.Schemes = []string{"http"}
	}

	return &Generator{
		config:     cfg,
		routeInfos: make([]*RouteInfo, 0),
	}
}

// AddRoute 添加路由信息
func (g *Generator) AddRoute(route *RouteInfo) {
	if route != nil {
		g.routeInfos = append(g.routeInfos, normalizeRouteInfo(route))
	}
}

// AddRoutes 批量添加路由信息
func (g *Generator) AddRoutes(routes []*RouteInfo) {
	for _, route := range routes {
		g.AddRoute(route)
	}
}

// CollectFromGinRoutes 从 Gin 路由收集信息
func (g *Generator) CollectFromGinRoutes(routes gin.RoutesInfo) {
	for _, route := range routes {
		// 过滤 Swagger 自己的路由
		if strings.HasPrefix(route.Path, "/swagger") {
			continue
		}

		routeInfo := &RouteInfo{
			Path:      route.Path,
			Method:    route.Method,
			Responses: make(map[int]ResponseDoc),
		}

		// 添加默认 200 响应
		if route.Method != "DELETE" {
			routeInfo.Responses[200] = ResponseDoc{
				Description: "成功",
			}
		} else {
			routeInfo.Responses[204] = ResponseDoc{
				Description: "删除成功",
			}
		}

		g.AddRoute(routeInfo)
	}
}

// Generate 生成 OpenAPI 规范
func (g *Generator) Generate() *OpenAPI {
	spec := &OpenAPI{
		OpenAPI: "3.0.0",
		Info: Info{
			Title:       g.config.Title,
			Description: g.config.Description,
			Version:     g.config.Version,
			Contact:     g.config.Contact,
		},
		Paths: make(map[string]PathItem),
		Tags:  g.collectTags(),
	}

	// 添加服务器信息
	if g.config.Host != "" {
		for _, scheme := range g.config.Schemes {
			spec.Servers = append(spec.Servers, Server{
				URL:         scheme + "://" + g.config.Host + g.config.BasePath,
				Description: strings.ToUpper(scheme) + " 服务器",
			})
		}
	}

	// 生成路径文档
	for _, route := range g.routeInfos {
		g.addPathItem(spec, route)
	}

	return spec
}

// collectTags 收集所有标签
func (g *Generator) collectTags() []Tag {
	tagMap := make(map[string]bool)
	tags := make([]Tag, 0)

	for _, route := range g.routeInfos {
		for _, tagName := range route.Tags {
			if !tagMap[tagName] {
				tagMap[tagName] = true
				tags = append(tags, Tag{
					Name: tagName,
				})
			}
		}
	}

	return tags
}

// addPathItem 添加路径项
func (g *Generator) addPathItem(spec *OpenAPI, route *RouteInfo) {
	pathItem, exists := spec.Paths[route.Path]
	if !exists {
		pathItem = PathItem{}
	}

	operation := g.buildOperation(route)

	// 根据 HTTP 方法设置操作
	switch strings.ToUpper(route.Method) {
	case "GET":
		pathItem.Get = operation
	case "POST":
		pathItem.Post = operation
	case "PUT":
		pathItem.Put = operation
	case "DELETE":
		pathItem.Delete = operation
	case "PATCH":
		pathItem.Patch = operation
	case "HEAD":
		pathItem.Head = operation
	case "OPTIONS":
		pathItem.Options = operation
	case "TRACE":
		pathItem.Trace = operation
	}

	spec.Paths[route.Path] = pathItem
}

// buildOperation 构建操作定义
func (g *Generator) buildOperation(route *RouteInfo) *Operation {
	op := &Operation{
		Summary:     route.Summary,
		Description: route.Description,
		Tags:        route.Tags,
		OperationID: route.OperationID,
		Parameters:  make([]Parameter, 0),
		Responses:   make(map[string]Response),
		Deprecated:  route.Deprecated,
	}

	// 添加参数
	for _, param := range route.Params {
		if param.In == "body" {
			// Body 参数转为 RequestBody
			op.RequestBody = g.buildRequestBody(param)
		} else {
			op.Parameters = append(op.Parameters, g.buildParameter(param))
		}
	}

	// 添加响应
	for code, resp := range route.Responses {
		op.Responses[intToString(code)] = g.buildResponse(resp)
	}

	// 添加安全要求
	if route.Security != "" {
		op.Security = []SecurityRequirement{
			{route.Security: []string{}},
		}
	}

	return op
}

// buildParameter 构建参数定义
func (g *Generator) buildParameter(param ParamDoc) Parameter {
	schema := g.buildSchema(param.Type, param.Model, "parameter")
	if param.Example != nil && schema != nil {
		schema.Example = param.Example
	}
	return Parameter{
		Name:        param.Name,
		In:          param.In,
		Description: param.Description,
		Required:    param.Required,
		Schema:      schema,
	}
}

// buildRequestBody 构建请求体定义
func (g *Generator) buildRequestBody(param ParamDoc) *RequestBody {
	contentType := param.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	mediaType := MediaType{
		Schema: g.buildSchemaFromModel(param.Model, "request_body"),
	}
	if param.Example != nil {
		mediaType.Example = param.Example
	}
	if len(param.Examples) > 0 {
		mediaType.Examples = cloneExamples(param.Examples)
	}
	return &RequestBody{
		Description: param.Description,
		Required:    param.Required,
		Content: map[string]MediaType{
			contentType: mediaType,
		},
	}
}

// buildResponse 构建响应定义
func (g *Generator) buildResponse(resp ResponseDoc) Response {
	response := Response{
		Description: resp.Description,
	}

	if resp.Model != nil {
		contentType := resp.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		mediaType := MediaType{
			Schema: g.buildSchemaFromModel(resp.Model, "response"),
		}
		if resp.Example != nil {
			mediaType.Example = resp.Example
		}
		if len(resp.Examples) > 0 {
			mediaType.Examples = cloneExamples(resp.Examples)
		}
		response.Content = map[string]MediaType{
			contentType: mediaType,
		}
	}

	return response
}

func normalizeRouteInfo(route *RouteInfo) *RouteInfo {
	if route == nil {
		return nil
	}

	normalizedPath := normalizeOpenAPIPath(route.Path)
	params := mergePathParams(normalizedPath, route.Params)
	responses := cloneResponses(route.Responses)
	if len(responses) == 0 {
		responses = defaultResponses(route.Method)
	}

	return &RouteInfo{
		Path:        normalizedPath,
		Method:      route.Method,
		Summary:     route.Summary,
		Description: route.Description,
		OperationID: route.OperationID,
		Params:      params,
		Responses:   responses,
		Tags:        append([]string(nil), route.Tags...),
		Deprecated:  route.Deprecated,
		Security:    route.Security,
	}
}

func normalizeOpenAPIPath(routePath string) string {
	normalized := chiPathParamPattern.ReplaceAllString(routePath, "{$1}")
	segments := strings.Split(normalized, "/")
	for idx, segment := range segments {
		switch {
		case segment == "*":
			segments[idx] = "{_wildcard}"
		case strings.HasPrefix(segment, ":") && len(segment) > 1:
			segments[idx] = "{" + segment[1:] + "}"
		case strings.HasPrefix(segment, "*") && len(segment) > 1:
			segments[idx] = "{" + segment[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

func mergePathParams(routePath string, existing []ParamDoc) []ParamDoc {
	params := append([]ParamDoc(nil), existing...)
	seen := make(map[string]struct{}, len(params))

	for idx := range params {
		if strings.EqualFold(params[idx].In, "path") {
			params[idx].Required = true
			seen[params[idx].Name] = struct{}{}
		}
	}

	for _, name := range extractPathParamNames(routePath) {
		if _, exists := seen[name]; exists {
			continue
		}
		params = append(params, ParamDoc{
			Name:        name,
			In:          "path",
			Type:        "string",
			Description: name + " 路径参数",
			Required:    true,
		})
	}

	return params
}

func extractPathParamNames(routePath string) []string {
	matches := openAPIParamPattern.FindAllStringSubmatch(routePath, -1)
	if len(matches) == 0 {
		return nil
	}

	names := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := match[1]
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func cloneResponses(responses map[int]ResponseDoc) map[int]ResponseDoc {
	if len(responses) == 0 {
		return nil
	}

	cloned := make(map[int]ResponseDoc, len(responses))
	for code, resp := range responses {
		resp.Examples = cloneExamples(resp.Examples)
		cloned[code] = resp
	}
	return cloned
}

func cloneExamples(examples map[string]Example) map[string]Example {
	if len(examples) == 0 {
		return nil
	}

	cloned := make(map[string]Example, len(examples))
	for name, example := range examples {
		cloned[name] = example
	}
	return cloned
}

func defaultResponses(method string) map[int]ResponseDoc {
	if strings.EqualFold(method, "DELETE") {
		return map[int]ResponseDoc{
			204: {Description: "删除成功"},
		}
	}
	return map[int]ResponseDoc{
		200: {Description: "成功"},
	}
}

// buildSchema 构建基础 Schema
func (g *Generator) buildSchema(typeName string, model interface{}, path string) *Schema {
	if model != nil {
		return g.buildSchemaFromModel(model, path)
	}

	schema := &Schema{
		Type: g.mapType(typeName),
	}

	// 设置格式
	switch typeName {
	case "integer":
		schema.Format = "int32"
	case "long":
		schema.Type = "integer"
		schema.Format = "int64"
	case "float":
		schema.Type = "number"
		schema.Format = "float"
	case "double":
		schema.Type = "number"
		schema.Format = "double"
	case "date":
		schema.Type = "string"
		schema.Format = "date"
	case "datetime":
		schema.Type = "string"
		schema.Format = "date-time"
	}

	return schema
}

// buildSchemaFromModel 从模型构建 Schema
func (g *Generator) buildSchemaFromModel(model interface{}, path string) *Schema {
	if model == nil {
		return &Schema{Type: "object"}
	}

	t := reflect.TypeOf(model)
	return g.buildSchemaFromType(t, make(map[string]bool), path)
}

func (g *Generator) buildSchemaFromType(t reflect.Type, visited map[string]bool, path string) *Schema {
	// 解引用指针
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	currentPath := t.String()
	if path != "" {
		currentPath = path + "." + currentPath
	}

	if t.Kind() == reflect.Struct {
		typeKey := g.schemaTypeKey(t)
		if visited[typeKey] {
			log.Printf("swagger: 检测到循环引用: %s", currentPath)
			if t.Name() != "" {
				return &Schema{Ref: "#/components/schemas/" + t.Name()}
			}
			return &Schema{Type: "object"}
		}
		visited[typeKey] = true
		defer delete(visited, typeKey)
	}

	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return &Schema{
			Type:  "array",
			Items: g.buildSchemaFromType(t.Elem(), visited, currentPath),
		}
	case reflect.Struct:
		return g.buildStructSchemaWithVisited(t, visited, currentPath)
	default:
		return &Schema{
			Type: g.mapGoType(t),
		}
	}
}

func (g *Generator) buildStructSchemaWithVisited(t reflect.Type, visited map[string]bool, path string) *Schema {
	schema := &Schema{
		Type:       "object",
		Properties: make(map[string]*Schema),
		Required:   make([]string, 0),
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// 跳过未导出字段
		if !field.IsExported() {
			continue
		}

		// 获取 json 标签
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		fieldName := field.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		// 构建字段 Schema
		fieldSchema := g.buildSchemaFromType(field.Type, visited, path+"."+fieldName)

		// 添加描述
		if desc := field.Tag.Get("description"); desc != "" {
			fieldSchema.Description = desc
		}

		schema.Properties[fieldName] = fieldSchema

		// 检查是否必需
		if strings.Contains(field.Tag.Get("binding"), "required") {
			schema.Required = append(schema.Required, fieldName)
		}
	}

	return schema
}

func (g *Generator) schemaTypeKey(t reflect.Type) string {
	if t.PkgPath() == "" {
		return t.String()
	}
	return t.PkgPath() + "." + t.Name()
}

// mapType 映射类型名称到 JSON Schema 类型
func (g *Generator) mapType(typeName string) string {
	switch strings.ToLower(typeName) {
	case "string", "str":
		return "string"
	case "integer", "int", "int32", "int64", "long":
		return "integer"
	case "number", "float", "double", "float32", "float64":
		return "number"
	case "boolean", "bool":
		return "boolean"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return "string"
	}
}

// mapGoType 映射 Go 类型到 JSON Schema 类型
func (g *Generator) mapGoType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Struct, reflect.Map:
		return "object"
	default:
		return "string"
	}
}

// intToString 将整数转为字符串
func intToString(i int) string {
	return strconv.Itoa(i)
}
