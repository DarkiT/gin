package gin

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	Int      = "int"
	Int64    = "int64"
	Float    = "float"
	DateTime = "date-time"
	Date     = "date"
	UUID     = "uuid"
	Bool     = "bool"
	String   = "string"
)

// RouteOption 定义一个修改APIRoute文档属性的函数类型
type RouteOption func(*APIRoute)

// OpenAPI 包含生成OpenAPI/Swagger文档的配置。
// 包含API的元数据和文档信息。
type OpenAPI struct {
	Title   string  // API标题
	Version string  // API版本
	Servers Servers // API托管服务器URL列表
	License License // API许可证信息
	Contact Contact // API维护者联系信息
	// SecuritySchemes 为OpenAPI规范定义安全方案。
	SecuritySchemes SecuritySchemes
	ExternalDocs    *ExternalDocs
}
type SecuritySchemes []SecurityScheme

type SecurityScheme struct {
	Name         string // Type string // "http", "oauth2", "apiKey"
	Type         string // Scheme string // "basic", "bearer", etc.
	Scheme       string
	BearerFormat string
	Flows        *OAuthFlows
	Description  string
}
type ExternalDocs struct {
	Extensions map[string]any `json:"-" yaml:"-"`
	Origin     *Origin        `json:"__origin__,omitempty" yaml:"__origin__,omitempty"`

	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
}

type Origin struct {
	Key    *Location           `json:"key,omitempty" yaml:"key,omitempty"`
	Fields map[string]Location `json:"fields,omitempty" yaml:"fields,omitempty"`
}

type Location struct {
	Line   int `json:"line,omitempty" yaml:"line,omitempty"`
	Column int `json:"column,omitempty" yaml:"column,omitempty"`
}

type OAuthFlow struct {
	AuthorizationURL string
	TokenURL         string
	RefreshURL       string
	Scopes           map[string]string
}
type OAuthFlows struct {
	Implicit          *OAuthFlow
	Password          *OAuthFlow
	ClientCredentials *OAuthFlow
	AuthorizationCode *OAuthFlow
}
type SecurityRequirement map[string][]string // SchemeName -> Scopes

// License 包含API的许可证信息。
// 遵循OpenAPI规范格式。
type License struct {
	Extensions map[string]any `json:"-" yaml:"-"`                         // OpenAPI规范之外的自定义扩展
	Name       string         `json:"name" yaml:"name"`                   // 必需的许可证名称（例如："MIT"）
	URL        string         `json:"url,omitempty" yaml:"url,omitempty"` // 可选的许可证URL
}

// Servers 是代表API服务器位置的Server对象列表
type Servers []Server

// Server 代表API托管的服务器位置
type Server struct {
	Extensions map[string]any `json:"-" yaml:"-"`
	// 服务器URL（例如："https://api.example.com/v1"）
	URL string `json:"url" yaml:"url"`
	// 可选的服务器描述
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Contact 包含API维护者的联系信息
type Contact struct {
	Extensions map[string]any `json:"-" yaml:"-"`                             // OpenAPI规范之外的自定义扩展
	Name       string         `json:"name,omitempty" yaml:"name,omitempty"`   // 可选的联系人姓名
	URL        string         `json:"url,omitempty" yaml:"url,omitempty"`     // Optional contact URL
	Email      string         `json:"email,omitempty" yaml:"email,omitempty"` // Optional contact email
}

// ToOpenAPI 将License转换为openapi3.License。
// 将自定义License类型转换为openapi3包期望的格式。
func (l License) ToOpenAPI() *openapi3.License {
	license := &openapi3.License{
		Name: l.Name,
		URL:  l.URL,
	}
	// 复制所有扩展到目标许可证对象
	if len(l.Extensions) > 0 {
		if license.Extensions == nil {
			license.Extensions = make(map[string]any)
		}
		for k, v := range l.Extensions {
			license.Extensions[k] = v
		}
	}
	return license
}

// ToOpenAPI 将Servers转换为openapi3.Servers。
// 将自定义Servers类型转换为openapi3包期望的格式。
func (s Servers) ToOpenAPI() openapi3.Servers {
	var servers openapi3.Servers
	for _, srv := range s {
		server := &openapi3.Server{
			URL:         srv.URL,
			Description: srv.Description,
		}
		if len(srv.Extensions) > 0 {
			if server.Extensions == nil {
				server.Extensions = make(map[string]any)
			}
			for k, v := range srv.Extensions {
				server.Extensions[k] = v
			}
		}
		servers = append(servers, server)
	}
	return servers
}

// ToOpenAPISpec 将OpenAPI转换为*openapi3.T。
// 将自定义OpenAPI配置转换为完整的OpenAPI规范对象。
func (o OpenAPI) ToOpenAPISpec() *openapi3.T {
	return &openapi3.T{
		Info: &openapi3.Info{
			Title:   o.Title,
			Version: o.Version,
			License: o.License.ToOpenAPI(),
			Contact: o.Contact.ToOpenAPI(),
		},
		Servers: o.Servers.ToOpenAPI(),
		Components: &openapi3.Components{
			SecuritySchemes: o.SecuritySchemes.ToOpenAPI(),
		},
	}
}

func (ss SecuritySchemes) ToOpenAPI() openapi3.SecuritySchemes {
	result := make(openapi3.SecuritySchemes)
	for _, s := range ss {
		result[s.Name] = &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:         s.Type,
				Scheme:       s.Scheme,
				BearerFormat: s.BearerFormat,
				Flows:        s.Flows.ToOpenAPI(),
				Description:  s.Description,
			},
		}
	}
	return result
}

func (e *ExternalDocs) ToOpenAPI() *openapi3.ExternalDocs {
	if e == nil {
		return nil
	}
	doc := &openapi3.ExternalDocs{
		Description: e.Description,
		URL:         e.URL,
	}
	if len(e.Extensions) > 0 {
		if doc.Extensions == nil {
			doc.Extensions = make(map[string]any)
		}
		for k, v := range e.Extensions {
			doc.Extensions[k] = v
		}
	}
	return doc
}

func (f *OAuthFlow) ToOpenAPI() *openapi3.OAuthFlow {
	if f == nil {
		return nil
	}
	return &openapi3.OAuthFlow{
		AuthorizationURL: f.AuthorizationURL,
		TokenURL:         f.TokenURL,
		RefreshURL:       f.RefreshURL,
		Scopes:           f.Scopes,
	}
}

func (flows *OAuthFlows) ToOpenAPI() *openapi3.OAuthFlows {
	if flows == nil {
		return nil
	}
	return &openapi3.OAuthFlows{
		Implicit:          flows.Implicit.ToOpenAPI(),
		Password:          flows.Password.ToOpenAPI(),
		ClientCredentials: flows.ClientCredentials.ToOpenAPI(),
		AuthorizationCode: flows.AuthorizationCode.ToOpenAPI(),
	}
}

// ToOpenAPI 将Contact转换为openapi3.Contact。
// 将自定义Contact类型转换为openapi3包期望的格式。
func (c Contact) ToOpenAPI() *openapi3.Contact {
	contact := &openapi3.Contact{
		Name:  c.Name,
		URL:   c.URL,
		Email: c.Email,
	}
	if len(c.Extensions) > 0 {
		if contact.Extensions == nil {
			contact.Extensions = make(map[string]any)
		}
		for k, v := range c.Extensions {
			contact.Extensions[k] = v
		}
	}
	return contact
}

// SchemaInfo 保存架构的额外信息以便更好地命名。
// 在从Bo类型生成OpenAPI架构时使用。
type SchemaInfo struct {
	Schema   *openapi3.SchemaRef
	TypeName string
	Package  string
}

// Doc 创建并返回一个用于链式文档选项的新DocBuilder实例。
func Doc() *DocBuilder {
	return &DocBuilder{}
}

// DocBuilder 帮助以流畅、可链式的方式构建 RouteOption 函数列表。
type DocBuilder struct {
	options []RouteOption
}

// RequestBody 使用提供的值将请求体架构添加到路由文档中。
func (b *DocBuilder) RequestBody(v any) *DocBuilder {
	b.options = append(b.options, DocRequestBody(v))
	return b
}

// Response 为路由的OpenAPI文档注册响应架构。
// 可以用两种方式使用：
//  1. DocResponse(status int, value any) - 为指定HTTP状态码定义响应架构（例如：200、1、01、4００）。
//  2. DocResponse(value any) - DocResponse(200, value)的简写形式。
//
// 示例：
//
//	DocResponse(201, CreatedResponse{})   // 201 Created响应
//	DocResponse(400, ErrorResponse{})     // 400 Bad Request响应
//	DocResponse(Response{})               // 响应：默认状态200
func (b *DocBuilder) Response(statusOrValue any, vOptional ...any) *DocBuilder {
	b.options = append(b.options, DocResponse(statusOrValue, vOptional...))
	return b
}

// ErrorResponse 为特定HTTP状态码定义错误响应架构
// 在路由的OpenAPI文档中。
// 已弃用：此函数已弃用，请使用Response(status, v)。
//
// 参数：
//   - status: HTTP状态码（例如：400、404、500）
//   - v: Go值（例如：结构体实例），其类型将用于生成
//     错误响应的OpenAPI架构
func (b *DocBuilder) ErrorResponse(status int, v any) *DocBuilder {
	b.options = append(b.options, DocErrorResponse(status, v))
	return b
}

// Summary 为路由文档添加简短的摘要描述。
func (b *DocBuilder) Summary(summary string) *DocBuilder {
	b.options = append(b.options, DocSummary(summary))
	return b
}

// OperationID 为OpenAPI文档中的操作设置唯一标识符。
func (b *DocBuilder) OperationID(operationID string) *DocBuilder {
	b.options = append(b.options, DocOperationID(operationID))
	return b
}

// Description 为路由文档添加描述。
func (b *DocBuilder) Description(description string) *DocBuilder {
	b.options = append(b.options, DocDescription(description))
	return b
}

// Tags 为路由文档添加一个或多个标签以进行分类。
func (b *DocBuilder) Tags(tags ...string) *DocBuilder {
	b.options = append(b.options, DocTags(tags...))
	return b
}

// BearerAuth 将路由标记为需要Bearer令牌身份验证。
func (b *DocBuilder) BearerAuth() *DocBuilder {
	b.options = append(b.options, DocBearerAuth())
	return b
}

// Deprecated 将路由标记为已弃用
func (b *DocBuilder) Deprecated() *DocBuilder {
	b.options = append(b.options, DocDeprecated())
	return b
}

// PathParam 为路由添加文档化的路径参数。
// name: 参数名称
// typ: 参数类型（例如："string", "int"）
// desc: 参数描述
func (b *DocBuilder) PathParam(name, typ, desc string) *DocBuilder {
	b.options = append(b.options, DocPathParam(name, typ, desc))
	return b
}

// QueryParam 为路由添加文档化的查询参数。
// name: 参数名称
// typ: 参数类型（例如："string", "int"）
// desc: 参数描述
// required: 参数是否为必需
func (b *DocBuilder) QueryParam(name, typ, desc string, required bool) *DocBuilder {
	b.options = append(b.options, DocQueryParam(name, typ, desc, required))
	return b
}

// Header 为路由添加文档化的请求头。
// name: 请求头名称
// typ: 请求头值类型（例如："string", "int"）
// desc: 请求头描述
// required: 请求头是否为必需
func (b *DocBuilder) Header(name, typ, desc string, required bool) *DocBuilder {
	b.options = append(b.options, DocHeader(name, typ, desc, required))
	return b
}

// ResponseHeader 为路由文档添加响应头
// name: 响应头名称
// typ: 响应头值类型（例如："string", "int"）
// desc: 响应头描述，可选
func (b *DocBuilder) ResponseHeader(name, typ string, desc ...string) *DocBuilder {
	b.options = append(b.options, DocResponseHeader(name, typ, desc...))
	return b
}

// Hide 将路由标记为从 OpenAPI 文档中排除。
func (b *DocBuilder) Hide() *DocBuilder {
	b.options = append(b.options, DocHide())
	return b
}

// Build 返回由所有累积的文档选项组成的单个 RouteOption。
// 此方法旨在直接传递给路由注册函数。
//
// 示例：
//
//	okapi.Get("/books", handler, okapi.Doc().response(Book{}).Summary("获取书籍列表").Build())
func (b *DocBuilder) Build() RouteOption {
	return b.AsOption()
}

// AsOption 通过合并所有累积的文档选项返回单个 RouteOption。
// 这在功能上等同于 Build()，存在是为了命名的灵活性和可读性。
//
// 您可以使用 Build() 或 AsOption()，取决于哪种更符合您的代码风格。
//
// 示例：
//
//	okapi.Get("/books", handler, okapi.Doc().response(Book{}).AsOption())
func (b *DocBuilder) AsOption() RouteOption {
	return func(r *APIRoute) {
		for _, opt := range b.options {
			opt(r)
		}
	}
}

// ptr 是一个帮助函数，返回任意值的指针
func ptr[T any](v T) *T { return &v }

// DocSummary 为路由设置简短的摘要描述
func DocSummary(summary string) RouteOption {
	return func(r *APIRoute) {
		r.Summary = summary
	}
}

// DocHide 标记路由从 OpenAPI 文档中排除
func DocHide() RouteOption {
	return func(r *APIRoute) {
		r.Hide = true
	}
}

func DocOperationID(operationID string) RouteOption {
	return func(r *APIRoute) {
		r.OperationID = operationID
	}
}

// DocDescription 为路由设置描述
func DocDescription(description string) RouteOption {
	return func(route *APIRoute) {
		route.Description = description
	}
}

// DocPathParam 向路由文档添加路径参数
// name: 参数名称
// typ: 参数类型（例如："string", "int", "uuid"）
// desc: 参数描述
func DocPathParam(name, typ, desc string) RouteOption {
	return func(r *APIRoute) {
		schema := getSchemaForType(typ)
		r.PathParams = append(r.PathParams, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:        name,
				In:          "path",
				Required:    true,
				Schema:      schema,
				Description: desc,
			},
		})
	}
}

// DocAutoPathParams 自动从路由路径提取路径参数
// 并将其添加到文档中。
// 跳过已经定义的参数。
func DocAutoPathParams() RouteOption {
	return func(r *APIRoute) {
		pathParams := extractPathParams(r.Path)
		for _, param := range pathParams {
			// 检查参数是否已存在以避免重复
			exists := false
			for _, existing := range r.PathParams {
				if existing.Value.Name == param.Value.Name {
					exists = true
					break
				}
			}
			if !exists {
				r.PathParams = append(r.PathParams, param)
			}
		}
	}
}

// DocQueryParam 向路由文档添加查询参数
// name: 参数名称
// typ: 参数类型（例如："string", "int"）
// desc: 参数描述
// required: 参数是否为必需
func DocQueryParam(name, typ, desc string, required bool) RouteOption {
	return func(r *APIRoute) {
		schema := getSchemaForType(typ)
		r.QueryParams = append(r.QueryParams, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:        name,
				In:          "query",
				Required:    required,
				Schema:      schema,
				Description: desc,
			},
		})
	}
}

// DocHeader 向路由文档添加请求头参数
// name: 请求头名称
// typ: 请求头值类型（例如："string", "int"）
// desc: 请求头描述
// required: 请求头是否为必需
func DocHeader(name, typ, desc string, required bool) RouteOption {
	return func(r *APIRoute) {
		schema := getSchemaForType(typ)
		r.Headers = append(r.Headers, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:        name,
				In:          "header",
				Required:    required,
				Schema:      schema,
				Description: desc,
			},
		})
	}
}

// DocTag 添加单个标签对路由进行分类
func DocTag(tag string) RouteOption {
	return func(r *APIRoute) {
		r.Tags = append(r.Tags, tag)
	}
}

// DocTags 添加多个标签对路由进行分类
func DocTags(tags ...string) RouteOption {
	return func(doc *APIRoute) {
		doc.Tags = append(doc.Tags, tags...)
	}
}

// DocResponseHeader 向路由文档添加响应头
// name: 响应头名称
// typ: 响应头值类型（例如："string", "int"）
// desc: 响应头描述，可选
func DocResponseHeader(name, typ string, desc ...string) RouteOption {
	return func(r *APIRoute) {
		schema := getSchemaForType(typ)
		description := ""
		// 如果responseHeaders映射不存在则初始化
		if r.ResponseHeaders == nil {
			r.ResponseHeaders = make(map[string]*openapi3.HeaderRef)
		}
		if len(desc) != 0 {
			description = desc[0]
		}
		r.ResponseHeaders[name] = &openapi3.HeaderRef{
			Value: &openapi3.Header{
				Parameter: openapi3.Parameter{
					Description: description,
					Required:    true,
					Schema:      schema,
				},
			},
		}
	}
}

// DocResponse 为路由的OpenAPI文档注册响应架构。
// 可以以两种方式使用：
//  1. DocResponse(status int, value any) - 为指定HTTP状态码定义响应架构（例如：200、201、400）
//  2. DocResponse(value any) - DocResponse(200, value)的简写形式
//
// 示例：
//
//	DocResponse(201, CreatedResponse{})   // 201 Created响应
//	DocResponse(400, ErrorResponse{})     // 400 Bad Request响应
//	DocResponse(response{})               // 响应：默认状态200
func DocResponse(statusOrValue any, vOptional ...any) RouteOption {
	return func(doc *APIRoute) {
		switch val := statusOrValue.(type) {
		case int:
			// 用法：DocResponse(200, value)
			if len(vOptional) == 0 || vOptional[0] == nil {
				return
			}
			if doc.Responses == nil {
				doc.Responses = make(map[int]*openapi3.SchemaRef)
			}
			doc.Responses[val] = reflectToSchemaWithInfo(vOptional[0]).Schema

		default:
			// 用法：DocResponse(value)
			if val == nil {
				return
			}
			if doc.Responses == nil {
				doc.Responses = make(map[int]*openapi3.SchemaRef)
			}
			doc.Responses[200] = reflectToSchemaWithInfo(val).Schema
		}
	}
}

// DocErrorResponse 为路由的OpenAPI文档中的特定HTTP状态码
// 定义错误响应架构
// Deprecated: This function is deprecated in favor of DocResponse(status, v).
//
// Parameters:
//   - status: the HTTP status code (e.g., 400, 404, 500).
//   - v: a Go value (e.g., a struct instance) whose type will be used to generate
//     the OpenAPI schema for the error response.
//
// 返回：
//   - 一个RouteOption函数，将错误架构添加到路由的文档中
func DocErrorResponse(status int, v any) RouteOption {
	return func(doc *APIRoute) {
		if v == nil {
			return
		}
		// 从提供的Go值生成架构并将其分配给错误响应
		if doc.Responses == nil {
			doc.Responses = make(map[int]*openapi3.SchemaRef)
		}
		doc.Responses[status] = reflectToSchemaWithInfo(v).Schema
	}
}

// DocRequestBody 为路由定义请求体架构
// v: Go值，其类型将用于生成请求架构
func DocRequestBody(v any) RouteOption {
	return func(doc *APIRoute) {
		if v == nil {
			return
		}
		doc.Request = reflectToSchemaWithInfo(v).Schema
	}
}

// DocBearerAuth 标记路由需要Bearer令牌认证
func DocBearerAuth() RouteOption {
	return func(doc *APIRoute) {
		doc.BearerAuth = true
	}
}

// DocBasicAuth 标记路由需要Basic认证
func DocBasicAuth() RouteOption {
	return func(doc *APIRoute) {
		doc.BasicAuth = true
	}
}

// DocDeprecated 标记路由为已弃用
func DocDeprecated() RouteOption {
	return func(doc *APIRoute) {
		doc.Deprecated = true
	}
}

// reflectToSchemaWithInfo 将Go类型转换为带有类型信息的OpenAPI架构
func reflectToSchemaWithInfo(v any) *SchemaInfo {
	t := reflect.TypeOf(v)

	// 处理指针
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	schema := typeToSchemaWithInfo(t)

	return &SchemaInfo{
		Schema:   schema,
		TypeName: t.Name(),
		Package:  t.PkgPath(),
	}
}

// typeToSchemaWithInfo 将reflect.Type转换为带有适当命名的OpenAPI SchemaRef
func typeToSchemaWithInfo(t reflect.Type) *openapi3.SchemaRef {
	switch t.Kind() {
	case reflect.String:
		return openapi3.NewSchemaRef("", openapi3.NewStringSchema())

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		schema := openapi3.NewIntegerSchema()
		if t.Kind() == reflect.Int64 {
			schema.Format = Int64
		} else {
			schema.Format = "int32"
		}
		return openapi3.NewSchemaRef("", schema)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		schema := openapi3.NewIntegerSchema()
		schema.Min = ptr(float64(0))
		if t.Kind() == reflect.Uint64 {
			schema.Format = "int64"
		} else {
			schema.Format = "int32"
		}
		return openapi3.NewSchemaRef("", schema)

	case reflect.Float32, reflect.Float64:
		schema := openapi3.NewFloat64Schema()
		if t.Kind() == reflect.Float32 {
			schema.Format = Float
		} else {
			schema.Format = "double"
		}
		return openapi3.NewSchemaRef("", schema)

	case reflect.Bool:
		return openapi3.NewSchemaRef("", openapi3.NewBoolSchema())

	case reflect.Slice, reflect.Array:
		elemSchema := typeToSchemaWithInfo(t.Elem())
		schema := openapi3.NewArraySchema()
		schema.Items = elemSchema
		return openapi3.NewSchemaRef("", schema)

	case reflect.Map:
		if t.Key().Kind() == reflect.String {
			valueSchema := typeToSchemaWithInfo(t.Elem())
			schema := openapi3.NewObjectSchema()
			schema.AdditionalProperties = openapi3.AdditionalProperties{
				Schema: valueSchema,
			}
			return openapi3.NewSchemaRef("", schema)
		}
		return openapi3.NewSchemaRef("", openapi3.NewObjectSchema())

	case reflect.Struct:
		return structToSchemaWithInfo(t)

	case reflect.Interface:
		return openapi3.NewSchemaRef("", &openapi3.Schema{})

	default:
		return openapi3.NewSchemaRef("", openapi3.NewObjectSchema())
	}
}

// structToSchemaWithInfo 将结构体类型转换为带有适当命名的OpenAPI架构
func structToSchemaWithInfo(t reflect.Type) *openapi3.SchemaRef {
	// 处理特殊类型
	if t == reflect.TypeOf(time.Time{}) {
		schema := openapi3.NewStringSchema()
		schema.Format = "date-time"
		return openapi3.NewSchemaRef("", schema)
	}

	schema := openapi3.NewObjectSchema()
	required := make([]string, 0)

	// 将标题设置为结构体名称以获得更好的组件命名
	if t.Name() != "" {
		schema.Title = t.Name()
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// 跳过非导出字段
		if !field.IsExported() {
			continue
		}

		fieldName := getJSONFieldName(field)
		if fieldName == "-" {
			continue
		}

		fieldSchema := typeToSchemaWithInfo(field.Type)

		// 从注释或标签添加描述
		if desc := field.Tag.Get("description"); desc != "" {
			fieldSchema.Value.Description = desc
		}
		if desc := field.Tag.Get("doc"); desc != "" {
			fieldSchema.Value.Description = desc
		}

		schema.WithProperty(fieldName, fieldSchema.Value)

		// 检查字段是否为必需
		if isRequiredField(field) {
			required = append(required, fieldName)
		}
	}

	if len(required) > 0 {
		schema.Required = required
	}

	return openapi3.NewSchemaRef("", schema)
}

// getJSONFieldName 从结构体标签中提取JSON字段名
func getJSONFieldName(field reflect.StructField) string {
	jsonTag := field.Tag.Get("json")
	if jsonTag == "" {
		return field.Name
	}

	parts := strings.Split(jsonTag, ",")
	name := parts[0]

	if name == "" {
		return field.Name
	}

	return name
}

// isRequiredField 确定结构体字段是否为必需
func isRequiredField(field reflect.StructField) bool {
	jsonTag := field.Tag.Get("json")
	validateTag := field.Tag.Get("validate")

	// 检查json标签中是否存在omitempty
	if strings.Contains(jsonTag, "omitempty") {
		return false
	}

	// 检查validate标签中是否存在required
	if strings.Contains(validateTag, "required") {
		return true
	}

	// 检查字段是否为指针（通常为可选）
	if field.Type.Kind() == reflect.Ptr {
		return false
	}

	// 默认情况下，没有omitempty的非指针字段为必需
	return !strings.Contains(jsonTag, "omitempty")
}

// extractPathParams 从路由路径提取路径参数
// 支持以下模式：
// - /users/{id} -> id (string)
// - /users/{user_id} -> user_id (string)
// - /users/{id:int} -> id (int)
// - /users/{user_id:uuid} -> user_id (uuid)
func extractPathParams(path string) []*openapi3.ParameterRef {
	params := []*openapi3.ParameterRef{}

	// 查找花括号中的所有参数
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(path, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		paramDef := match[1]
		var name, typ, description string

		// 检查是否指定了类型（例如：{id:int} 或 {user_id:uuid}）
		if strings.Contains(paramDef, ":") {
			parts := strings.SplitN(paramDef, ":", 2)
			name = parts[0]
			typ = parts[1]
		} else {
			name = paramDef
			typ = inferTypeFromParamName(name)
		}

		description = generateParamDescription(name, typ)
		schema := getSchemaForType(typ)

		params = append(params, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:        name,
				In:          "path",
				Required:    true,
				Schema:      schema,
				Description: description,
			},
		})
	}

	return params
}

// inferTypeFromParamName 尝试从参数名推断参数类型
func inferTypeFromParamName(name string) string {
	name = strings.ToLower(name)

	// 常见ID模式
	if strings.HasSuffix(name, "_id") || name == "id" {
		return UUID // ID假设为UUID
	}

	// 数字模式
	if strings.Contains(name, "count") || strings.Contains(name, "limit") ||
		strings.Contains(name, "offset") || strings.Contains(name, "page") ||
		strings.Contains(name, "size") || strings.Contains(name, "number") {
		return Int
	}

	// 日期模式
	if strings.Contains(name, "date") || strings.Contains(name, "time") {
		return Date
	}

	// 布尔模式
	if strings.HasPrefix(name, "is_") || strings.HasPrefix(name, "has_") ||
		strings.HasPrefix(name, "can_") || strings.HasPrefix(name, "should_") {
		return Bool
	}

	// 默认为字符串
	return String
}

// generateParamDescription 为参数生成人类可读的描述
func generateParamDescription(name, typ string) string {
	// 将snake_case转换为人类可读格式
	words := strings.Split(strings.ReplaceAll(name, "_", " "), " ")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	readable := strings.Join(words, " ")

	switch typ {
	case "uuid":
		return fmt.Sprintf("%s identifier", readable)
	case "int":
		return fmt.Sprintf("%s (integer)", readable)
	case "bool":
		return fmt.Sprintf("%s (boolean)", readable)
	case "date":
		return fmt.Sprintf("%s (date)", readable)
	case "date-time":
		return fmt.Sprintf("%s (date-time)", readable)
	default:
		return readable
	}
}

func getSchemaForType(typ string) *openapi3.SchemaRef {
	switch strings.ToLower(typ) {
	case "string":
		return openapi3.NewSchemaRef("", openapi3.NewStringSchema())
	case "int", "integer":
		return openapi3.NewSchemaRef("", openapi3.NewInt32Schema())
	case "int64":
		return openapi3.NewSchemaRef("", openapi3.NewInt64Schema())
	case "float", "float32":
		schema := openapi3.NewFloat64Schema()
		schema.Format = "float"
		return openapi3.NewSchemaRef("", schema)
	case "float64", "double":
		return openapi3.NewSchemaRef("", openapi3.NewFloat64Schema())
	case "bool", "boolean":
		return openapi3.NewSchemaRef("", openapi3.NewBoolSchema())
	case "uuid":
		schema := openapi3.NewStringSchema()
		schema.Format = UUID
		return openapi3.NewSchemaRef("", schema)
	case "date":
		schema := openapi3.NewStringSchema()
		schema.Format = Date
		return openapi3.NewSchemaRef("", schema)
	case "datetime", DateTime:
		schema := openapi3.NewStringSchema()
		schema.Format = DateTime
		return openapi3.NewSchemaRef("", schema)
	default:
		return openapi3.NewSchemaRef("", openapi3.NewStringSchema())
	}
}
