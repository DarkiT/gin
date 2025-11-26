package sa

import (
	"errors"
	"reflect"
	"strings"

	core "github.com/darkit/gin/pkg/token"
	"github.com/darkit/gin/pkg/token/helper"
	"github.com/darkit/gin/pkg/token/manager"
	"github.com/gin-gonic/gin"
)

const saContextKey = "satoken"

// Annotation constants | 注解常量
const (
	TagSaCheckLogin      = "sa_check_login"
	TagSaCheckRole       = "sa_check_role"
	TagSaCheckPermission = "sa_check_permission"
	TagSaCheckDisable    = "sa_check_disable"
	TagSaIgnore          = "sa_ignore"
)

// Annotation annotation structure | 注解结构体
type Annotation struct {
	CheckLogin      bool     `json:"checkLogin"`
	CheckRole       []string `json:"checkRole"`
	CheckPermission []string `json:"checkPermission"`
	CheckDisable    bool     `json:"checkDisable"`
	Ignore          bool     `json:"ignore"`
}

// ParseTag parses struct tags | 解析结构体标签
func ParseTag(tag string) *Annotation {
	ann := &Annotation{}

	if tag == "" {
		return ann
	}

	parts := strings.Split(tag, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case part == TagSaCheckLogin || part == "login":
			ann.CheckLogin = true
		case strings.HasPrefix(part, TagSaCheckRole+"=") || strings.HasPrefix(part, "role="):
			roles := strings.TrimPrefix(part, TagSaCheckRole+"=")
			roles = strings.TrimPrefix(roles, "role=")
			if roles != "" {
				ann.CheckRole = strings.Split(roles, "|")
			}
		case strings.HasPrefix(part, TagSaCheckPermission+"=") || strings.HasPrefix(part, "permission="):
			perms := strings.TrimPrefix(part, TagSaCheckPermission+"=")
			perms = strings.TrimPrefix(perms, "permission=")
			if perms != "" {
				ann.CheckPermission = strings.Split(perms, "|")
			}
		case part == TagSaCheckDisable || part == "disable":
			ann.CheckDisable = true
		case part == TagSaIgnore || part == "ignore":
			ann.Ignore = true
		}
	}

	return ann
}

// Validate validates if annotation is valid | 验证注解是否有效
func (a *Annotation) Validate() bool {
	if a.Ignore {
		return true // When ignore is true, other checks are invalid | 忽略认证时，其他检查无效
	}

	count := 0
	if a.CheckLogin {
		count++
	}
	if len(a.CheckRole) > 0 {
		count++
	}
	if len(a.CheckPermission) > 0 {
		count++
	}
	if a.CheckDisable {
		count++
	}

	// At most one check type allowed | 最多只能有一个检查类型
	return count <= 1
}

// GetHandler gets handler with annotations | 获取带注解的处理器
func GetHandler(handler interface{}, annotations ...*Annotation) gin.HandlerFunc {
	merged := mergeAnnotations(annotations)
	return func(c *gin.Context) {
		saCtx, err := ensureAuthorization(c, merged)
		if err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}
		if saCtx != nil {
			c.Set(saContextKey, saCtx)
		}

		if callHandler(handler, c) {
			return
		}
		c.Next()
	}
}

func callHandler(handler interface{}, c *gin.Context) bool {
	if handler == nil {
		return false
	}

	switch h := handler.(type) {
	case func(*gin.Context):
		if h == nil {
			return false
		}
		h(c)
		return true
	case gin.HandlerFunc:
		if h == nil {
			return false
		}
		h(c)
		return true
	}

	hv := reflect.ValueOf(handler)
	if hv.Kind() != reflect.Func || hv.IsNil() || hv.Type().NumIn() != 1 {
		return false
	}

	argType := hv.Type().In(0)
	if !argType.AssignableTo(reflect.TypeOf(c)) {
		return false
	}

	hv.Call([]reflect.Value{reflect.ValueOf(c)})
	return true
}

// Decorator functions | 装饰器函数

// CheckLogin decorator for login checking | 检查登录装饰器
func CheckLogin() gin.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckLogin: true})
}

// CheckRole decorator for role checking | 检查角色装饰器
func CheckRole(roles ...string) gin.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckRole: roles})
}

// CheckPermission decorator for permission checking | 检查权限装饰器
func CheckPermission(perms ...string) gin.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckPermission: perms})
}

// CheckDisable decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisable() gin.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckDisable: true})
}

// Ignore decorator to ignore authentication | 忽略认证装饰器
func Ignore() gin.HandlerFunc {
	return GetHandler(nil, &Annotation{Ignore: true})
}

// WithAnnotation decorator with custom annotation | 使用自定义注解装饰器
func WithAnnotation(ann *Annotation) gin.HandlerFunc {
	return GetHandler(nil, ann)
}

// ProcessStructAnnotations processes annotations on struct tags | 处理结构体上的注解标签
func ProcessStructAnnotations(handler interface{}) gin.HandlerFunc {
	handlerValue := reflect.ValueOf(handler)
	handlerType := reflect.TypeOf(handler)

	// 默认使用通配符匹配，避免特定方法名引起歧义
	methodName := "*"
	if handlerType.Kind() == reflect.Ptr {
		handlerType = handlerType.Elem()
	}

	// Parse method annotations | 解析方法上的注解标签
	ann := parseMethodAnnotation(handlerType, methodName)

	return GetHandler(func(c *gin.Context) {
		handlerValue.MethodByName("ServeHTTP").Call([]reflect.Value{reflect.ValueOf(c)})
	}, ann)
}

// parseMethodAnnotation parses method annotations | 解析方法注解
func parseMethodAnnotation(t reflect.Type, methodName string) *Annotation {
	if t == nil {
		return &Annotation{}
	}

	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return &Annotation{}
	}

	if methodName == "" {
		methodName = "*"
	}

	var matched []*Annotation
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tagValue := field.Tag.Get("sa")
		if tagValue == "" {
			continue
		}

		segments := strings.Split(tagValue, ";")
		for _, segment := range segments {
			segment = strings.TrimSpace(segment)
			if segment == "" {
				continue
			}

			target := "*"
			tag := segment
			if idx := strings.Index(segment, ":"); idx != -1 {
				target = strings.TrimSpace(segment[:idx])
				tag = strings.TrimSpace(segment[idx+1:])
			}

			targetLower := strings.ToLower(target)
			methodLower := strings.ToLower(methodName)

			if targetLower == "*" || targetLower == methodLower {
				matched = append(matched, ParseTag(tag))
			}
		}
	}

	if len(matched) == 0 {
		return &Annotation{}
	}

	return mergeAnnotations(matched)
}

// HandlerWithAnnotations 带注解的处理器包装器
type HandlerWithAnnotations struct {
	Handler     interface{}
	Annotations []*Annotation
}

// NewHandlerWithAnnotations 创建带注解的处理器
func NewHandlerWithAnnotations(handler interface{}, annotations ...*Annotation) *HandlerWithAnnotations {
	return &HandlerWithAnnotations{
		Handler:     handler,
		Annotations: annotations,
	}
}

// ToGinHandler 转换为Gin处理器
func (h *HandlerWithAnnotations) ToGinHandler() gin.HandlerFunc {
	return GetHandler(h.Handler, h.Annotations...)
}

// Middleware 创建中间件版本
func Middleware(annotations ...*Annotation) gin.HandlerFunc {
	merged := mergeAnnotations(annotations)
	return func(c *gin.Context) {
		saCtx, err := ensureAuthorization(c, merged)
		if err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}
		if saCtx != nil {
			c.Set(saContextKey, saCtx)
		}
		c.Next()
	}
}

func mergeAnnotations(annotations []*Annotation) *Annotation {
	var merged *Annotation
	for _, ann := range annotations {
		if ann == nil {
			continue
		}
		if merged == nil {
			merged = &Annotation{}
		}
		merged.Ignore = merged.Ignore || ann.Ignore
		merged.CheckLogin = merged.CheckLogin || ann.CheckLogin
		merged.CheckDisable = merged.CheckDisable || ann.CheckDisable
		if len(ann.CheckRole) > 0 {
			merged.CheckRole = append(merged.CheckRole, ann.CheckRole...)
		}
		if len(ann.CheckPermission) > 0 {
			merged.CheckPermission = append(merged.CheckPermission, ann.CheckPermission...)
		}
	}
	return merged
}

func ensureAuthorization(c *gin.Context, annotation *Annotation) (*core.SaTokenContext, error) {
	if annotation != nil && annotation.Ignore {
		return nil, nil
	}

	saCtx := core.NewContext(NewGinContext(c), helper.GetManager())
	token := saCtx.GetTokenValue()
	if token == "" {
		return nil, core.NewNotLoginError()
	}

	if !helper.IsLogin(token) {
		return nil, core.NewNotLoginError()
	}

	loginID, err := helper.GetLoginID(token)
	if err != nil {
		if errors.Is(err, manager.ErrNotLogin) {
			return nil, core.NewNotLoginError()
		}
		return nil, core.NewError(core.CodeServerError, "failed to get login info", err)
	}

	if annotation != nil && annotation.CheckDisable && helper.IsDisable(loginID) {
		return nil, core.NewAccountDisabledError(loginID)
	}

	if annotation != nil {
		permissions := normalizeValues(annotation.CheckPermission)
		if len(permissions) > 0 && !hasAnyPermission(loginID, permissions) {
			return nil, core.NewPermissionDeniedError(strings.Join(permissions, ","))
		}

		roles := normalizeValues(annotation.CheckRole)
		if len(roles) > 0 && !hasAnyRole(loginID, roles) {
			return nil, core.NewRoleDeniedError(strings.Join(roles, ","))
		}
	}

	return saCtx, nil
}

func normalizeValues(values []string) []string {
	var cleaned []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	return cleaned
}

func hasAnyPermission(loginID string, permissions []string) bool {
	for _, perm := range permissions {
		if helper.HasPermission(loginID, perm) {
			return true
		}
	}
	return false
}

func hasAnyRole(loginID string, roles []string) bool {
	for _, role := range roles {
		if helper.HasRole(loginID, role) {
			return true
		}
	}
	return false
}
