package gin

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"time"
)

// SegmentType 路由段类型
type SegmentType int

const (
	SegmentTypeStatic   SegmentType = iota // 静态段
	SegmentTypeParam                       // 参数段 (:param)
	SegmentTypeWildcard                    // 通配符段 (*wildcard)
)

// String 返回段类型的字符串表示
func (st SegmentType) String() string {
	switch st {
	case SegmentTypeStatic:
		return "static"
	case SegmentTypeParam:
		return "param"
	case SegmentTypeWildcard:
		return "wildcard"
	default:
		return "unknown"
	}
}

// PatternSegment 路由段
type PatternSegment struct {
	Type     SegmentType `json:"type"`     // 段类型：静态、参数、通配符
	Value    string      `json:"value"`    // 段值
	IsParam  bool        `json:"is_param"` // 是否为参数
	Name     string      `json:"name"`     // 参数名（如果是参数段）
	Position int         `json:"position"` // 段在路径中的位置
}

// RoutePattern 路由模式结构
type RoutePattern struct {
	Method     string           `json:"method"`      // HTTP方法
	Pattern    string           `json:"pattern"`     // 原始路由模式
	ParamNames []string         `json:"param_names"` // 参数名列表
	IsWildcard bool             `json:"is_wildcard"` // 是否包含通配符
	Segments   []PatternSegment `json:"segments"`    // 路由段列表
	Priority   int              `json:"priority"`    // 路由优先级
	Hash       uint64           `json:"hash"`        // 路由模式哈希值
	CreateTime time.Time        `json:"create_time"` // 创建时间
}

// 预编译的正则表达式
var (
	paramRegex    = regexp.MustCompile(`^:([a-zA-Z_][a-zA-Z0-9_]*)$`)
	wildcardRegex = regexp.MustCompile(`^\*([a-zA-Z_][a-zA-Z0-9_]*)?$`)
	// 参数名验证正则表达式 - 必须以字母或下划线开头，后跟字母、数字或下划线
	paramNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// ParseRoutePattern 解析路由模式
func ParseRoutePattern(method, pattern string) (*RoutePattern, error) {
	// 预验证路由模式
	if err := ValidateRoutePattern(method, pattern); err != nil {
		return nil, fmt.Errorf("路由模式验证失败: %w", err)
	}

	if pattern == "" {
		pattern = "/"
	}

	// 确保路径以斜杠开头
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	// 创建路由模式对象
	rp := &RoutePattern{
		Method:     strings.ToUpper(method),
		Pattern:    pattern,
		ParamNames: make([]string, 0),
		IsWildcard: false,
		Segments:   make([]PatternSegment, 0),
		Priority:   calculatePriority(pattern),
		CreateTime: time.Now(),
	}

	// 解析路径段
	if err := rp.parseSegments(); err != nil {
		return nil, fmt.Errorf("解析路由段失败: %w", err)
	}

	// 计算哈希值
	rp.Hash = rp.calculateHash()

	return rp, nil
}

// parseSegments 解析路径段
func (rp *RoutePattern) parseSegments() error {
	// 移除首尾斜杠并分割路径
	path := strings.Trim(rp.Pattern, "/")
	if path == "" {
		// 根路径特殊处理
		rp.Segments = []PatternSegment{
			{
				Type:     SegmentTypeStatic,
				Value:    "/",
				IsParam:  false,
				Name:     "",
				Position: 0,
			},
		}
		return nil
	}

	segments := strings.Split(path, "/")
	rp.Segments = make([]PatternSegment, 0, len(segments))

	for i, segment := range segments {
		if segment == "" {
			continue // 跳过空段
		}

		patternSegment := PatternSegment{
			Position: i,
		}

		// 使用新的段类型识别功能
		segmentType, name, err := IdentifySegmentType(segment)
		if err != nil {
			return fmt.Errorf("段 %d ('%s') 识别失败: %w", i, segment, err)
		}

		patternSegment.Type = segmentType
		patternSegment.Value = segment
		patternSegment.Name = name

		switch segmentType {
		case SegmentTypeStatic:
			patternSegment.IsParam = false

		case SegmentTypeParam:
			patternSegment.IsParam = true
			rp.ParamNames = append(rp.ParamNames, name)

		case SegmentTypeWildcard:
			patternSegment.IsParam = true
			if name != "" {
				rp.ParamNames = append(rp.ParamNames, name)
			}
			rp.IsWildcard = true

			// 通配符必须是最后一个段
			if i < len(segments)-1 {
				return fmt.Errorf("通配符段 '%s' 必须是路径的最后一个段", segment)
			}
		}

		rp.Segments = append(rp.Segments, patternSegment)
	}

	return nil
}

// calculatePriority 计算路由优先级
// 优先级规则：静态段 > 参数段 > 通配符段
// 段数越多优先级越高，同等段数下静态段越多优先级越高
func calculatePriority(pattern string) int {
	if pattern == "/" {
		return 1000 // 根路径最高优先级
	}

	segments := strings.Split(strings.Trim(pattern, "/"), "/")
	priority := len(segments) * 100 // 基础优先级基于段数

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		if strings.HasPrefix(segment, "*") {
			// 通配符段优先级最低
			priority -= 50
		} else if strings.HasPrefix(segment, ":") {
			// 参数段优先级中等
			priority -= 20
		} else {
			// 静态段优先级最高
			priority += 10
		}
	}

	return priority
}

// calculateHash 计算路由模式哈希值
func (rp *RoutePattern) calculateHash() uint64 {
	h := fnv.New64a()

	// 包含方法和模式
	h.Write([]byte(rp.Method))
	h.Write([]byte(":"))
	h.Write([]byte(rp.Pattern))

	return h.Sum64()
}

// String 返回路由模式的字符串表示
func (rp *RoutePattern) String() string {
	return fmt.Sprintf("%s %s", rp.Method, rp.Pattern)
}

// Equals 检查两个路由模式是否相等
func (rp *RoutePattern) Equals(other *RoutePattern) bool {
	if other == nil {
		return false
	}

	return rp.Method == other.Method && rp.Pattern == other.Pattern
}

// IsConflictWith 检查是否与另一个路由模式冲突
func (rp *RoutePattern) IsConflictWith(other *RoutePattern) bool {
	if other == nil || rp.Method != other.Method {
		return false
	}

	// 完全相同的模式肯定冲突
	if rp.Pattern == other.Pattern {
		return true
	}

	// 更接近 gin 的路由行为：
	// 1) 静态 vs 参数/通配符 可以共存（静态优先），不视为冲突
	// 2) 同形状的动态路由（参数名不同但位置相同）冲突
	// 3) 多个通配符在同一路径前缀下冲突
	return rp.segmentsConflict(other)
}

// segmentsConflict 检查段级别的冲突
func (rp *RoutePattern) segmentsConflict(other *RoutePattern) bool {
	// 如果两者都含通配符且前缀相同，则视为冲突
	if rp.IsWildcard && other.IsWildcard {
		return rp.wildcardConflict(other)
	}

	// 只有一方含通配符时，静态路由优先，允许共存
	if rp.IsWildcard || other.IsWildcard {
		return false
	}

	// 段数不同，不冲突
	if len(rp.Segments) != len(other.Segments) {
		return false
	}

	// 逐段比较；静态不等直接不冲突；静态 vs 参数/参数 vs 参数 视为潜在冲突
	conflict := false
	for i, seg1 := range rp.Segments {
		seg2 := other.Segments[i]

		if seg1.Type == SegmentTypeStatic && seg2.Type == SegmentTypeStatic {
			if seg1.Value != seg2.Value {
				return false
			}
			continue
		}

		// 静态 vs 参数 或 参数 vs 参数 都可能匹配相同请求，视为冲突
		conflict = true
	}

	return conflict
}

// wildcardConflict 检查通配符相关的冲突
func (rp *RoutePattern) wildcardConflict(other *RoutePattern) bool {
	// 两个通配符路由：若通配符前缀完全一致则冲突
	if rp.IsWildcard && other.IsWildcard {
		minLen := len(rp.Segments) - 1
		if len(other.Segments)-1 < minLen {
			minLen = len(other.Segments) - 1
		}

		for i := 0; i < minLen; i++ {
			if !rp.segmentMatches(rp.Segments[i], other.Segments[i]) {
				return false
			}
		}
		return true
	}

	// 单通配符与普通路由允许共存（静态优先），不视为冲突
	return false
}

// segmentMatches 检查两个段是否匹配
func (rp *RoutePattern) segmentMatches(seg1, seg2 PatternSegment) bool {
	// 两个静态段必须完全相同
	if seg1.Type == SegmentTypeStatic && seg2.Type == SegmentTypeStatic {
		return seg1.Value == seg2.Value
	}

	// 参数段可以匹配任何段
	if seg1.Type == SegmentTypeParam || seg2.Type == SegmentTypeParam {
		return true
	}

	// 通配符可以匹配任何段
	if seg1.Type == SegmentTypeWildcard || seg2.Type == SegmentTypeWildcard {
		return true
	}

	return false
}

// GetParamNames 获取参数名列表
func (rp *RoutePattern) GetParamNames() []string {
	result := make([]string, len(rp.ParamNames))
	copy(result, rp.ParamNames)
	return result
}

// HasParam 检查是否包含指定参数
func (rp *RoutePattern) HasParam(name string) bool {
	for _, paramName := range rp.ParamNames {
		if paramName == name {
			return true
		}
	}
	return false
}

// GetSegmentCount 获取段数量
func (rp *RoutePattern) GetSegmentCount() int {
	return len(rp.Segments)
}

// GetStaticSegmentCount 获取静态段数量
func (rp *RoutePattern) GetStaticSegmentCount() int {
	count := 0
	for _, segment := range rp.Segments {
		if segment.Type == SegmentTypeStatic {
			count++
		}
	}
	return count
}

// GetParamSegmentCount 获取参数段数量
func (rp *RoutePattern) GetParamSegmentCount() int {
	count := 0
	for _, segment := range rp.Segments {
		if segment.Type == SegmentTypeParam {
			count++
		}
	}
	return count
}

// Clone 克隆路由模式
func (rp *RoutePattern) Clone() *RoutePattern {
	clone := &RoutePattern{
		Method:     rp.Method,
		Pattern:    rp.Pattern,
		ParamNames: make([]string, len(rp.ParamNames)),
		IsWildcard: rp.IsWildcard,
		Segments:   make([]PatternSegment, len(rp.Segments)),
		Priority:   rp.Priority,
		Hash:       rp.Hash,
		CreateTime: rp.CreateTime,
	}

	copy(clone.ParamNames, rp.ParamNames)
	copy(clone.Segments, rp.Segments)

	return clone
}

// Validate 验证路由模式的有效性
func (rp *RoutePattern) Validate() error {
	// 检查HTTP方法
	if rp.Method == "" {
		return fmt.Errorf("HTTP方法不能为空")
	}

	// 验证HTTP方法是否有效
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	}
	if !validMethods[rp.Method] {
		return fmt.Errorf("无效的HTTP方法: %s", rp.Method)
	}

	// 检查路径
	if rp.Pattern == "" {
		return fmt.Errorf("路由模式不能为空")
	}

	// 检查路径必须以斜杠开头
	if !strings.HasPrefix(rp.Pattern, "/") {
		return fmt.Errorf("路由模式必须以斜杠开头: %s", rp.Pattern)
	}

	// 检查参数名的唯一性和有效性
	paramNames := make(map[string]bool)
	for _, name := range rp.ParamNames {
		if name == "" {
			continue
		}

		// 验证参数名格式
		if !paramNameRegex.MatchString(name) {
			return fmt.Errorf("无效的参数名格式: %s (参数名必须以字母或下划线开头，只能包含字母、数字和下划线)", name)
		}

		// 检查参数名长度
		if len(name) > 50 {
			return fmt.Errorf("参数名过长: %s (最大长度50个字符)", name)
		}

		// 检查参数名唯一性
		if paramNames[name] {
			return fmt.Errorf("参数名 '%s' 重复", name)
		}
		paramNames[name] = true
	}

	// 检查段的有效性
	if err := rp.validateSegments(); err != nil {
		return fmt.Errorf("段验证失败: %w", err)
	}

	return nil
}

// validateSegments 验证路由段的有效性
func (rp *RoutePattern) validateSegments() error {
	if len(rp.Segments) == 0 {
		return fmt.Errorf("路由段不能为空")
	}

	wildcardFound := false

	for i, segment := range rp.Segments {
		// 验证段类型
		if segment.Type < SegmentTypeStatic || segment.Type > SegmentTypeWildcard {
			return fmt.Errorf("无效的段类型: %d", segment.Type)
		}

		// 验证段值不能为空
		if segment.Value == "" {
			return fmt.Errorf("段值不能为空 (位置: %d)", i)
		}

		// 验证位置信息
		if segment.Position != i {
			return fmt.Errorf("段位置信息不正确: 期望 %d, 实际 %d", i, segment.Position)
		}

		switch segment.Type {
		case SegmentTypeStatic:
			// 静态段验证
			if err := rp.validateStaticSegment(segment, i); err != nil {
				return err
			}

		case SegmentTypeParam:
			// 参数段验证
			if err := rp.validateParamSegment(segment, i); err != nil {
				return err
			}

		case SegmentTypeWildcard:
			// 通配符段验证
			if err := rp.validateWildcardSegment(segment, i); err != nil {
				return err
			}
			wildcardFound = true
		}

		// 通配符后不能有其他段
		if wildcardFound && i < len(rp.Segments)-1 {
			return fmt.Errorf("通配符段必须是路径的最后一个段")
		}
	}

	return nil
}

// validateStaticSegment 验证静态段
func (rp *RoutePattern) validateStaticSegment(segment PatternSegment, position int) error {
	// 静态段不应该是参数
	if segment.IsParam {
		return fmt.Errorf("静态段不应该标记为参数 (位置: %d)", position)
	}

	// 静态段不应该有参数名
	if segment.Name != "" {
		return fmt.Errorf("静态段不应该有参数名 (位置: %d)", position)
	}

	// 验证静态段值不包含特殊字符
	if strings.ContainsAny(segment.Value, ":*?") {
		return fmt.Errorf("静态段包含无效字符: %s (位置: %d)", segment.Value, position)
	}

	// 验证静态段长度
	if len(segment.Value) > 100 {
		return fmt.Errorf("静态段过长: %s (位置: %d, 最大长度100个字符)", segment.Value, position)
	}

	return nil
}

// validateParamSegment 验证参数段
func (rp *RoutePattern) validateParamSegment(segment PatternSegment, position int) error {
	// 参数段必须标记为参数
	if !segment.IsParam {
		return fmt.Errorf("参数段必须标记为参数 (位置: %d)", position)
	}

	// 参数段必须有参数名
	if segment.Name == "" {
		return fmt.Errorf("参数段必须有参数名 (位置: %d)", position)
	}

	// 验证参数段值格式
	if !strings.HasPrefix(segment.Value, ":") {
		return fmt.Errorf("参数段值必须以冒号开头: %s (位置: %d)", segment.Value, position)
	}

	// 验证参数名与段值一致性
	expectedValue := ":" + segment.Name
	if segment.Value != expectedValue {
		return fmt.Errorf("参数段值与参数名不一致: 期望 %s, 实际 %s (位置: %d)", expectedValue, segment.Value, position)
	}

	return nil
}

// validateWildcardSegment 验证通配符段
func (rp *RoutePattern) validateWildcardSegment(segment PatternSegment, position int) error {
	// 通配符段必须标记为参数
	if !segment.IsParam {
		return fmt.Errorf("通配符段必须标记为参数 (位置: %d)", position)
	}

	// 验证通配符段值格式
	if !strings.HasPrefix(segment.Value, "*") {
		return fmt.Errorf("通配符段值必须以星号开头: %s (位置: %d)", segment.Value, position)
	}

	// 验证通配符名与段值一致性（如果有名称）
	if segment.Name != "" {
		expectedValue := "*" + segment.Name
		if segment.Value != expectedValue {
			return fmt.Errorf("通配符段值与参数名不一致: 期望 %s, 实际 %s (位置: %d)", expectedValue, segment.Value, position)
		}
	} else {
		// 无名通配符只能是 "*"
		if segment.Value != "*" {
			return fmt.Errorf("无名通配符段值必须是 '*': %s (位置: %d)", segment.Value, position)
		}
	}

	// 通配符必须是最后一个段
	if position < len(rp.Segments)-1 {
		return fmt.Errorf("通配符段必须是路径的最后一个段 (位置: %d)", position)
	}

	return nil
}

// ValidateSegmentName 验证段名称（参数名或通配符名）
func ValidateSegmentName(name string) error {
	if name == "" {
		return nil // 空名称是允许的（如无名通配符）
	}

	// 验证名称格式
	if !paramNameRegex.MatchString(name) {
		return fmt.Errorf("无效的段名称格式: %s (必须以字母或下划线开头，只能包含字母、数字和下划线)", name)
	}

	// 验证名称长度
	if len(name) > 50 {
		return fmt.Errorf("段名称过长: %s (最大长度50个字符)", name)
	}

	// 检查保留关键字
	reservedNames := map[string]bool{
		"index": true, "new": true, "edit": true, "show": true, "create": true,
		"update": true, "destroy": true, "delete": true, "nil": true, "true": true,
		"false": true, "if": true, "else": true, "for": true, "while": true,
		"return": true, "break": true, "continue": true, "func": true, "var": true,
		"const": true, "type": true, "struct": true, "interface": true, "map": true,
		"chan": true, "select": true, "case": true, "default": true, "go": true,
		"defer": true, "package": true, "import": true,
	}

	if reservedNames[name] {
		return fmt.Errorf("段名称不能使用保留关键字: %s", name)
	}

	return nil
}

// IdentifySegmentType 识别段类型
func IdentifySegmentType(segment string) (SegmentType, string, error) {
	if segment == "" {
		return SegmentTypeStatic, "", fmt.Errorf("段不能为空")
	}

	// 检查参数段
	if strings.HasPrefix(segment, ":") {
		if matches := paramRegex.FindStringSubmatch(segment); matches != nil {
			paramName := matches[1]
			if err := ValidateSegmentName(paramName); err != nil {
				return SegmentTypeStatic, "", fmt.Errorf("参数段验证失败: %w", err)
			}
			return SegmentTypeParam, paramName, nil
		} else {
			// 以冒号开头但格式不正确的段
			return SegmentTypeStatic, "", fmt.Errorf("参数段格式无效: %s", segment)
		}
	}

	// 检查通配符段
	if strings.HasPrefix(segment, "*") {
		if matches := wildcardRegex.FindStringSubmatch(segment); matches != nil {
			wildcardName := matches[1]
			if err := ValidateSegmentName(wildcardName); err != nil {
				return SegmentTypeStatic, "", fmt.Errorf("通配符段验证失败: %w", err)
			}
			return SegmentTypeWildcard, wildcardName, nil
		} else {
			// 以星号开头但格式不正确的段
			return SegmentTypeStatic, "", fmt.Errorf("通配符段格式无效: %s", segment)
		}
	}

	// 静态段
	if strings.ContainsAny(segment, ":*") {
		return SegmentTypeStatic, "", fmt.Errorf("静态段包含无效字符: %s", segment)
	}

	return SegmentTypeStatic, "", nil
}

// ExtractParamNames 从路径中提取所有参数名
func ExtractParamNames(pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "/"
	}

	// 确保路径以斜杠开头
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	// 移除首尾斜杠并分割路径
	path := strings.Trim(pattern, "/")
	if path == "" {
		return make([]string, 0), nil // 根路径没有参数
	}

	segments := strings.Split(path, "/")
	paramNames := make([]string, 0)
	paramNameSet := make(map[string]bool)

	for i, segment := range segments {
		if segment == "" {
			continue // 跳过空段
		}

		segmentType, name, err := IdentifySegmentType(segment)
		if err != nil {
			return nil, fmt.Errorf("段 %d 识别失败: %w", i, err)
		}

		// 只处理参数段和通配符段
		if segmentType == SegmentTypeParam || segmentType == SegmentTypeWildcard {
			if name != "" {
				// 检查参数名唯一性
				if paramNameSet[name] {
					return nil, fmt.Errorf("参数名 '%s' 重复", name)
				}
				paramNameSet[name] = true
				paramNames = append(paramNames, name)
			}
		}

		// 通配符必须是最后一个段
		if segmentType == SegmentTypeWildcard && i < len(segments)-1 {
			return nil, fmt.Errorf("通配符段 '%s' 必须是路径的最后一个段", segment)
		}
	}

	return paramNames, nil
}

// ValidateRoutePattern 验证路由模式字符串的有效性
func ValidateRoutePattern(method, pattern string) error {
	// 验证HTTP方法
	if method == "" {
		return fmt.Errorf("HTTP方法不能为空")
	}

	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	}
	upperMethod := strings.ToUpper(method)
	if !validMethods[upperMethod] {
		return fmt.Errorf("无效的HTTP方法: %s", method)
	}

	// 验证路径
	if pattern == "" {
		pattern = "/"
	}

	// 确保路径以斜杠开头
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	// 验证路径长度
	if len(pattern) > 1000 {
		return fmt.Errorf("路径过长: %d 字符 (最大长度1000个字符)", len(pattern))
	}

	// 检查路径中的无效字符
	if strings.ContainsAny(pattern, " \t\n\r") {
		return fmt.Errorf("路径包含无效的空白字符")
	}

	// 验证参数名
	_, err := ExtractParamNames(pattern)
	if err != nil {
		return fmt.Errorf("路径验证失败: %w", err)
	}

	return nil
}

// ToMap 转换为映射表示
func (rp *RoutePattern) ToMap() map[string]interface{} {
	segments := make([]map[string]interface{}, len(rp.Segments))
	for i, seg := range rp.Segments {
		segments[i] = map[string]interface{}{
			"type":     seg.Type.String(),
			"value":    seg.Value,
			"is_param": seg.IsParam,
			"name":     seg.Name,
			"position": seg.Position,
		}
	}

	return map[string]interface{}{
		"method":      rp.Method,
		"pattern":     rp.Pattern,
		"param_names": rp.ParamNames,
		"is_wildcard": rp.IsWildcard,
		"segments":    segments,
		"priority":    rp.Priority,
		"hash":        rp.Hash,
		"create_time": rp.CreateTime,
	}
}
