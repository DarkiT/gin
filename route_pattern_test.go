package gin

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSegmentType_String 测试段类型字符串表示
func TestSegmentType_String(t *testing.T) {
	tests := []struct {
		name     string
		segType  SegmentType
		expected string
	}{
		{
			name:     "静态段",
			segType:  SegmentTypeStatic,
			expected: "static",
		},
		{
			name:     "参数段",
			segType:  SegmentTypeParam,
			expected: "param",
		},
		{
			name:     "通配符段",
			segType:  SegmentTypeWildcard,
			expected: "wildcard",
		},
		{
			name:     "未知类型",
			segType:  SegmentType(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.segType.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseRoutePattern 测试路由模式解析
func TestParseRoutePattern(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		pattern          string
		expectedError    bool
		expectedMethod   string
		expectedPattern  string
		expectedParams   []string
		expectedWildcard bool
		expectedSegments int
	}{
		{
			name:             "简单静态路由",
			method:           "GET",
			pattern:          "/users",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/users",
			expectedParams:   []string{},
			expectedWildcard: false,
			expectedSegments: 1,
		},
		{
			name:             "带参数的路由",
			method:           "GET",
			pattern:          "/users/:id",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/users/:id",
			expectedParams:   []string{"id"},
			expectedWildcard: false,
			expectedSegments: 2,
		},
		{
			name:             "多个参数的路由",
			method:           "GET",
			pattern:          "/users/:id/posts/:postId",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/users/:id/posts/:postId",
			expectedParams:   []string{"id", "postId"},
			expectedWildcard: false,
			expectedSegments: 4,
		},
		{
			name:             "带通配符的路由",
			method:           "GET",
			pattern:          "/static/*filepath",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/static/*filepath",
			expectedParams:   []string{"filepath"},
			expectedWildcard: true,
			expectedSegments: 2,
		},
		{
			name:             "根路径",
			method:           "GET",
			pattern:          "/",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/",
			expectedParams:   []string{},
			expectedWildcard: false,
			expectedSegments: 1,
		},
		{
			name:             "空路径自动转为根路径",
			method:           "GET",
			pattern:          "",
			expectedError:    false,
			expectedMethod:   "GET",
			expectedPattern:  "/",
			expectedParams:   []string{},
			expectedWildcard: false,
			expectedSegments: 1,
		},
		{
			name:             "没有前导斜杠的路径",
			method:           "POST",
			pattern:          "users",
			expectedError:    false,
			expectedMethod:   "POST",
			expectedPattern:  "/users",
			expectedParams:   []string{},
			expectedWildcard: false,
			expectedSegments: 1,
		},
		{
			name:          "空方法",
			method:        "",
			pattern:       "/users",
			expectedError: true,
		},
		{
			name:          "通配符不在末尾",
			method:        "GET",
			pattern:       "/static/*filepath/more",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRoutePattern(tt.method, tt.pattern)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.expectedMethod, result.Method)
			assert.Equal(t, tt.expectedPattern, result.Pattern)
			assert.Equal(t, tt.expectedParams, result.ParamNames)
			assert.Equal(t, tt.expectedWildcard, result.IsWildcard)
			assert.Len(t, result.Segments, tt.expectedSegments)
			assert.NotZero(t, result.Hash)
			assert.NotZero(t, result.Priority)
			assert.False(t, result.CreateTime.IsZero())
		})
	}
}

// TestRoutePattern_parseSegments 测试段解析
func TestRoutePattern_parseSegments(t *testing.T) {
	tests := []struct {
		name             string
		pattern          string
		expectedSegments []PatternSegment
	}{
		{
			name:    "静态段",
			pattern: "/users/profile",
			expectedSegments: []PatternSegment{
				{Type: SegmentTypeStatic, Value: "users", IsParam: false, Name: "", Position: 0},
				{Type: SegmentTypeStatic, Value: "profile", IsParam: false, Name: "", Position: 1},
			},
		},
		{
			name:    "参数段",
			pattern: "/users/:id",
			expectedSegments: []PatternSegment{
				{Type: SegmentTypeStatic, Value: "users", IsParam: false, Name: "", Position: 0},
				{Type: SegmentTypeParam, Value: ":id", IsParam: true, Name: "id", Position: 1},
			},
		},
		{
			name:    "通配符段",
			pattern: "/static/*filepath",
			expectedSegments: []PatternSegment{
				{Type: SegmentTypeStatic, Value: "static", IsParam: false, Name: "", Position: 0},
				{Type: SegmentTypeWildcard, Value: "*filepath", IsParam: true, Name: "filepath", Position: 1},
			},
		},
		{
			name:    "混合段",
			pattern: "/api/:version/users/:id/*action",
			expectedSegments: []PatternSegment{
				{Type: SegmentTypeStatic, Value: "api", IsParam: false, Name: "", Position: 0},
				{Type: SegmentTypeParam, Value: ":version", IsParam: true, Name: "version", Position: 1},
				{Type: SegmentTypeStatic, Value: "users", IsParam: false, Name: "", Position: 2},
				{Type: SegmentTypeParam, Value: ":id", IsParam: true, Name: "id", Position: 3},
				{Type: SegmentTypeWildcard, Value: "*action", IsParam: true, Name: "action", Position: 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := &RoutePattern{Pattern: tt.pattern}
			err := rp.parseSegments()

			assert.NoError(t, err)
			assert.Len(t, rp.Segments, len(tt.expectedSegments))

			for i, expected := range tt.expectedSegments {
				actual := rp.Segments[i]
				assert.Equal(t, expected.Type, actual.Type)
				assert.Equal(t, expected.Value, actual.Value)
				assert.Equal(t, expected.IsParam, actual.IsParam)
				assert.Equal(t, expected.Name, actual.Name)
				assert.Equal(t, expected.Position, actual.Position)
			}
		})
	}
}

// TestCalculatePriority 测试优先级计算
func TestCalculatePriority(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected int
	}{
		{
			name:     "根路径",
			pattern:  "/",
			expected: 1000,
		},
		{
			name:     "单个静态段",
			pattern:  "/users",
			expected: 110, // 1*100 + 10
		},
		{
			name:     "单个参数段",
			pattern:  "/:id",
			expected: 80, // 1*100 - 20
		},
		{
			name:     "单个通配符段",
			pattern:  "/*filepath",
			expected: 50, // 1*100 - 50
		},
		{
			name:     "混合段",
			pattern:  "/users/:id",
			expected: 190, // 2*100 + 10 - 20
		},
		{
			name:     "复杂路径",
			pattern:  "/api/v1/users/:id/*action",
			expected: 460, // 5*100 + 20 - 20 - 50 (api=+10, v1=+10, users=+10, :id=-20, *action=-50)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePriority(tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRoutePattern_Equals 测试路由模式相等性
func TestRoutePattern_Equals(t *testing.T) {
	rp1, _ := ParseRoutePattern("GET", "/users/:id")
	rp2, _ := ParseRoutePattern("GET", "/users/:id")
	rp3, _ := ParseRoutePattern("POST", "/users/:id")
	rp4, _ := ParseRoutePattern("GET", "/users/:name")

	tests := []struct {
		name     string
		rp1      *RoutePattern
		rp2      *RoutePattern
		expected bool
	}{
		{
			name:     "相同的路由模式",
			rp1:      rp1,
			rp2:      rp2,
			expected: true,
		},
		{
			name:     "不同的HTTP方法",
			rp1:      rp1,
			rp2:      rp3,
			expected: false,
		},
		{
			name:     "不同的路径",
			rp1:      rp1,
			rp2:      rp4,
			expected: false,
		},
		{
			name:     "与nil比较",
			rp1:      rp1,
			rp2:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rp1.Equals(tt.rp2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRoutePattern_IsConflictWith 测试路由冲突检测
func TestRoutePattern_IsConflictWith(t *testing.T) {
	tests := []struct {
		name     string
		pattern1 string
		method1  string
		pattern2 string
		method2  string
		expected bool
	}{
		{
			name:     "完全相同的路由",
			pattern1: "/users/:id",
			method1:  "GET",
			pattern2: "/users/:id",
			method2:  "GET",
			expected: true,
		},
		{
			name:     "不同HTTP方法",
			pattern1: "/users/:id",
			method1:  "GET",
			pattern2: "/users/:id",
			method2:  "POST",
			expected: false,
		},
		{
			name:     "参数名不同但冲突",
			pattern1: "/users/:id",
			method1:  "GET",
			pattern2: "/users/:name",
			method2:  "GET",
			expected: true,
		},
		{
			name:     "静态段和参数段冲突",
			pattern1: "/users/profile",
			method1:  "GET",
			pattern2: "/users/:id",
			method2:  "GET",
			expected: true,
		},
		{
			name:     "不同路径长度",
			pattern1: "/users",
			method1:  "GET",
			pattern2: "/users/:id",
			method2:  "GET",
			expected: false,
		},
		{
			name:     "通配符冲突",
			pattern1: "/static/*filepath",
			method1:  "GET",
			pattern2: "/static/*file",
			method2:  "GET",
			expected: true,
		},
		{
			name:     "通配符与普通路由冲突",
			pattern1: "/static/*filepath",
			method1:  "GET",
			pattern2: "/static/css/style.css",
			method2:  "GET",
			expected: false,
		},
		{
			name:     "不冲突的路径",
			pattern1: "/users/:id",
			method1:  "GET",
			pattern2: "/posts/:id",
			method2:  "GET",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp1, err := ParseRoutePattern(tt.method1, tt.pattern1)
			assert.NoError(t, err)

			rp2, err := ParseRoutePattern(tt.method2, tt.pattern2)
			assert.NoError(t, err)

			result := rp1.IsConflictWith(rp2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRoutePattern_GetMethods 测试获取方法
func TestRoutePattern_GetMethods(t *testing.T) {
	rp, err := ParseRoutePattern("GET", "/users/:id/posts/:postId")
	assert.NoError(t, err)

	// 测试GetParamNames
	paramNames := rp.GetParamNames()
	expected := []string{"id", "postId"}
	assert.Equal(t, expected, paramNames)

	// 测试HasParam
	assert.True(t, rp.HasParam("id"))
	assert.True(t, rp.HasParam("postId"))
	assert.False(t, rp.HasParam("nonexistent"))

	// 测试GetSegmentCount
	assert.Equal(t, 4, rp.GetSegmentCount())

	// 测试GetStaticSegmentCount
	assert.Equal(t, 2, rp.GetStaticSegmentCount())

	// 测试GetParamSegmentCount
	assert.Equal(t, 2, rp.GetParamSegmentCount())
}

// TestRoutePattern_Clone 测试克隆功能
func TestRoutePattern_Clone(t *testing.T) {
	original, err := ParseRoutePattern("GET", "/users/:id/posts/:postId")
	assert.NoError(t, err)

	clone := original.Clone()

	// 验证克隆的内容相同
	assert.Equal(t, original.Method, clone.Method)
	assert.Equal(t, original.Pattern, clone.Pattern)
	assert.Equal(t, original.ParamNames, clone.ParamNames)
	assert.Equal(t, original.IsWildcard, clone.IsWildcard)
	assert.Equal(t, original.Segments, clone.Segments)
	assert.Equal(t, original.Priority, clone.Priority)
	assert.Equal(t, original.Hash, clone.Hash)
	assert.Equal(t, original.CreateTime, clone.CreateTime)

	// 验证是不同的对象（通过地址比较）
	assert.True(t, original != clone)
	assert.True(t, &original.ParamNames != &clone.ParamNames)
	assert.True(t, &original.Segments != &clone.Segments)

	// 修改克隆不应影响原对象
	clone.Method = "POST"
	assert.Equal(t, "GET", original.Method)
}

// TestValidateSegmentName 测试段名称验证
func TestValidateSegmentName(t *testing.T) {
	tests := []struct {
		name          string
		segmentName   string
		expectedError bool
		errorContains string
	}{
		{
			name:          "有效的参数名",
			segmentName:   "id",
			expectedError: false,
		},
		{
			name:          "有效的下划线开头",
			segmentName:   "_private",
			expectedError: false,
		},
		{
			name:          "有效的包含数字",
			segmentName:   "user_id_123",
			expectedError: false,
		},
		{
			name:          "空名称（允许）",
			segmentName:   "",
			expectedError: false,
		},
		{
			name:          "数字开头（无效）",
			segmentName:   "123id",
			expectedError: true,
			errorContains: "无效的段名称格式",
		},
		{
			name:          "包含特殊字符",
			segmentName:   "user-id",
			expectedError: true,
			errorContains: "无效的段名称格式",
		},
		{
			name:          "过长的名称",
			segmentName:   strings.Repeat("a", 51),
			expectedError: true,
			errorContains: "段名称过长",
		},
		{
			name:          "保留关键字",
			segmentName:   "if",
			expectedError: true,
			errorContains: "不能使用保留关键字",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSegmentName(tt.segmentName)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestIdentifySegmentType 测试段类型识别
func TestIdentifySegmentType(t *testing.T) {
	tests := []struct {
		name          string
		segment       string
		expectedType  SegmentType
		expectedName  string
		expectedError bool
		errorContains string
	}{
		{
			name:         "静态段",
			segment:      "users",
			expectedType: SegmentTypeStatic,
			expectedName: "",
		},
		{
			name:         "参数段",
			segment:      ":id",
			expectedType: SegmentTypeParam,
			expectedName: "id",
		},
		{
			name:         "通配符段",
			segment:      "*filepath",
			expectedType: SegmentTypeWildcard,
			expectedName: "filepath",
		},
		{
			name:         "无名通配符",
			segment:      "*",
			expectedType: SegmentTypeWildcard,
			expectedName: "",
		},
		{
			name:          "空段",
			segment:       "",
			expectedError: true,
			errorContains: "段不能为空",
		},
		{
			name:          "无效参数名",
			segment:       ":123invalid",
			expectedError: true,
			errorContains: "参数段格式无效",
		},
		{
			name:          "静态段包含冒号",
			segment:       "user:id",
			expectedError: true,
			errorContains: "静态段包含无效字符",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segType, name, err := IdentifySegmentType(tt.segment)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedType, segType)
				assert.Equal(t, tt.expectedName, name)
			}
		})
	}
}

// TestExtractParamNames 测试参数名提取
func TestExtractParamNames(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		expected      []string
		expectedError bool
		errorContains string
	}{
		{
			name:     "无参数",
			pattern:  "/users",
			expected: []string{},
		},
		{
			name:     "单个参数",
			pattern:  "/users/:id",
			expected: []string{"id"},
		},
		{
			name:     "多个参数",
			pattern:  "/users/:id/posts/:postId",
			expected: []string{"id", "postId"},
		},
		{
			name:     "通配符参数",
			pattern:  "/static/*filepath",
			expected: []string{"filepath"},
		},
		{
			name:     "混合参数",
			pattern:  "/api/:version/users/:id/*action",
			expected: []string{"version", "id", "action"},
		},
		{
			name:     "根路径",
			pattern:  "/",
			expected: []string{},
		},
		{
			name:     "空路径",
			pattern:  "",
			expected: []string{},
		},
		{
			name:          "重复参数名",
			pattern:       "/users/:id/posts/:id",
			expectedError: true,
			errorContains: "参数名 'id' 重复",
		},
		{
			name:          "通配符不在末尾",
			pattern:       "/static/*filepath/more",
			expectedError: true,
			errorContains: "必须是路径的最后一个段",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractParamNames(tt.pattern)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestValidateRoutePattern 测试路由模式验证
func TestValidateRoutePattern(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		pattern       string
		expectedError bool
		errorContains string
	}{
		{
			name:    "有效的路由模式",
			method:  "GET",
			pattern: "/users/:id",
		},
		{
			name:          "空方法",
			method:        "",
			pattern:       "/users",
			expectedError: true,
			errorContains: "HTTP方法不能为空",
		},
		{
			name:          "无效方法",
			method:        "INVALID",
			pattern:       "/users",
			expectedError: true,
			errorContains: "无效的HTTP方法",
		},
		{
			name:    "空路径（自动转为根路径）",
			method:  "GET",
			pattern: "",
		},
		{
			name:          "过长路径",
			method:        "GET",
			pattern:       "/" + strings.Repeat("a", 1000),
			expectedError: true,
			errorContains: "路径过长",
		},
		{
			name:          "包含空白字符",
			method:        "GET",
			pattern:       "/users /profile",
			expectedError: true,
			errorContains: "包含无效的空白字符",
		},
		{
			name:          "重复参数名",
			method:        "GET",
			pattern:       "/users/:id/posts/:id",
			expectedError: true,
			errorContains: "参数名 'id' 重复",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRoutePattern(tt.method, tt.pattern)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRoutePattern_Validate 测试验证功能
func TestRoutePattern_Validate(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		pattern       string
		modifyPattern func(*RoutePattern)
		expectedError bool
		errorContains string
	}{
		{
			name:          "有效的路由模式",
			method:        "GET",
			pattern:       "/users/:id",
			expectedError: false,
		},
		{
			name:    "无效HTTP方法",
			method:  "GET",
			pattern: "/users",
			modifyPattern: func(rp *RoutePattern) {
				rp.Method = "INVALID"
			},
			expectedError: true,
			errorContains: "无效的HTTP方法",
		},
		{
			name:    "路径不以斜杠开头",
			method:  "GET",
			pattern: "/users",
			modifyPattern: func(rp *RoutePattern) {
				rp.Pattern = "users"
			},
			expectedError: true,
			errorContains: "必须以斜杠开头",
		},
		{
			name:    "重复参数名",
			method:  "GET",
			pattern: "/users/:id",
			modifyPattern: func(rp *RoutePattern) {
				rp.ParamNames = []string{"id", "id"}
			},
			expectedError: true,
			errorContains: "参数名 'id' 重复",
		},
		{
			name:    "无效参数名格式",
			method:  "GET",
			pattern: "/users/:id",
			modifyPattern: func(rp *RoutePattern) {
				rp.ParamNames = []string{"123invalid"}
			},
			expectedError: true,
			errorContains: "无效的参数名格式",
		},
		{
			name:    "参数名过长",
			method:  "GET",
			pattern: "/users/:id",
			modifyPattern: func(rp *RoutePattern) {
				rp.ParamNames = []string{strings.Repeat("a", 51)}
			},
			expectedError: true,
			errorContains: "参数名过长",
		},
		{
			name:    "段位置信息错误",
			method:  "GET",
			pattern: "/users/:id",
			modifyPattern: func(rp *RoutePattern) {
				rp.Segments[0].Position = 999
			},
			expectedError: true,
			errorContains: "段位置信息不正确",
		},
		{
			name:    "静态段标记为参数",
			method:  "GET",
			pattern: "/users",
			modifyPattern: func(rp *RoutePattern) {
				rp.Segments[0].IsParam = true
			},
			expectedError: true,
			errorContains: "静态段不应该标记为参数",
		},
		{
			name:    "参数段未标记为参数",
			method:  "GET",
			pattern: "/users/:id",
			modifyPattern: func(rp *RoutePattern) {
				rp.Segments[1].IsParam = false
			},
			expectedError: true,
			errorContains: "参数段必须标记为参数",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, err := ParseRoutePattern(tt.method, tt.pattern)
			// 如果解析阶段就失败了，直接检查错误
			if err != nil {
				if tt.expectedError {
					if tt.errorContains != "" {
						assert.Contains(t, err.Error(), tt.errorContains)
					}
				} else {
					t.Errorf("解析失败: %v", err)
				}
				return
			}

			if tt.modifyPattern != nil {
				tt.modifyPattern(rp)
			}

			err = rp.Validate()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRoutePattern_String 测试字符串表示
func TestRoutePattern_String(t *testing.T) {
	rp, err := ParseRoutePattern("GET", "/users/:id")
	assert.NoError(t, err)

	result := rp.String()
	expected := "GET /users/:id"
	assert.Equal(t, expected, result)
}

// TestRoutePattern_ToMap 测试转换为映射
func TestRoutePattern_ToMap(t *testing.T) {
	rp, err := ParseRoutePattern("GET", "/users/:id")
	assert.NoError(t, err)

	result := rp.ToMap()

	assert.Equal(t, "GET", result["method"])
	assert.Equal(t, "/users/:id", result["pattern"])
	assert.Equal(t, []string{"id"}, result["param_names"])
	assert.Equal(t, false, result["is_wildcard"])
	assert.NotZero(t, result["priority"])
	assert.NotZero(t, result["hash"])
	assert.IsType(t, time.Time{}, result["create_time"])

	segments := result["segments"].([]map[string]interface{})
	assert.Len(t, segments, 2)

	// 检查第一个段（静态段）
	assert.Equal(t, "static", segments[0]["type"])
	assert.Equal(t, "users", segments[0]["value"])
	assert.Equal(t, false, segments[0]["is_param"])
	assert.Equal(t, "", segments[0]["name"])
	assert.Equal(t, 0, segments[0]["position"])

	// 检查第二个段（参数段）
	assert.Equal(t, "param", segments[1]["type"])
	assert.Equal(t, ":id", segments[1]["value"])
	assert.Equal(t, true, segments[1]["is_param"])
	assert.Equal(t, "id", segments[1]["name"])
	assert.Equal(t, 1, segments[1]["position"])
}

// TestRoutePattern_Hash 测试哈希计算
func TestRoutePattern_Hash(t *testing.T) {
	rp1, err := ParseRoutePattern("GET", "/users/:id")
	assert.NoError(t, err)

	rp2, err := ParseRoutePattern("GET", "/users/:id")
	assert.NoError(t, err)

	rp3, err := ParseRoutePattern("POST", "/users/:id")
	assert.NoError(t, err)

	rp4, err := ParseRoutePattern("GET", "/users/:name")
	assert.NoError(t, err)

	// 相同的路由模式应该有相同的哈希值
	assert.Equal(t, rp1.Hash, rp2.Hash)

	// 不同的路由模式应该有不同的哈希值
	assert.NotEqual(t, rp1.Hash, rp3.Hash)
	assert.NotEqual(t, rp1.Hash, rp4.Hash)
}

// BenchmarkParseRoutePattern 基准测试路由模式解析
func BenchmarkParseRoutePattern(b *testing.B) {
	patterns := []struct {
		method  string
		pattern string
	}{
		{"GET", "/users"},
		{"GET", "/users/:id"},
		{"GET", "/users/:id/posts/:postId"},
		{"GET", "/static/*filepath"},
		{"GET", "/api/v1/users/:id/posts/:postId/comments/:commentId"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := patterns[i%len(patterns)]
		_, _ = ParseRoutePattern(pattern.method, pattern.pattern)
	}
}

// BenchmarkRoutePattern_IsConflictWith 基准测试冲突检测
func BenchmarkRoutePattern_IsConflictWith(b *testing.B) {
	rp1, _ := ParseRoutePattern("GET", "/users/:id/posts/:postId")
	rp2, _ := ParseRoutePattern("GET", "/users/:name/posts/:id")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rp1.IsConflictWith(rp2)
	}
}

// BenchmarkIdentifySegmentType 基准测试段类型识别
func BenchmarkIdentifySegmentType(b *testing.B) {
	segments := []string{
		"users",
		":id",
		"*filepath",
		"posts",
		":postId",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		segment := segments[i%len(segments)]
		_, _, _ = IdentifySegmentType(segment)
	}
}

// BenchmarkValidateSegmentName 基准测试段名称验证
func BenchmarkValidateSegmentName(b *testing.B) {
	names := []string{
		"id",
		"user_id",
		"postId",
		"_private",
		"version123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := names[i%len(names)]
		_ = ValidateSegmentName(name)
	}
}

// BenchmarkExtractParamNames 基准测试参数名提取
func BenchmarkExtractParamNames(b *testing.B) {
	patterns := []string{
		"/users",
		"/users/:id",
		"/users/:id/posts/:postId",
		"/api/:version/users/:id/*action",
		"/static/*filepath",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := patterns[i%len(patterns)]
		_, _ = ExtractParamNames(pattern)
	}
}

// BenchmarkValidateRoutePattern 基准测试路由模式验证
func BenchmarkValidateRoutePattern(b *testing.B) {
	patterns := []struct {
		method  string
		pattern string
	}{
		{"GET", "/users"},
		{"POST", "/users/:id"},
		{"PUT", "/users/:id/posts/:postId"},
		{"DELETE", "/api/:version/users/:id/*action"},
		{"GET", "/static/*filepath"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := patterns[i%len(patterns)]
		_ = ValidateRoutePattern(p.method, p.pattern)
	}
}

// BenchmarkRoutePattern_Validate 基准测试路由模式对象验证
func BenchmarkRoutePattern_Validate(b *testing.B) {
	patterns := []*RoutePattern{}

	// 预创建一些路由模式对象
	testPatterns := []struct {
		method  string
		pattern string
	}{
		{"GET", "/users"},
		{"POST", "/users/:id"},
		{"PUT", "/users/:id/posts/:postId"},
		{"DELETE", "/api/:version/users/:id/*action"},
		{"GET", "/static/*filepath"},
	}

	for _, p := range testPatterns {
		rp, _ := ParseRoutePattern(p.method, p.pattern)
		patterns = append(patterns, rp)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := patterns[i%len(patterns)]
		_ = pattern.Validate()
	}
}
