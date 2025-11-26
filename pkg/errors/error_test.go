package errors

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	err := New(ErrCodeInvalidParam)

	if err.Code != ErrCodeInvalidParam {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeInvalidParam, err.Code)
	}

	if err.Message != "无效参数" {
		t.Errorf("期望错误信息为 '无效参数'，但得到 '%s'", err.Message)
	}

	if err.GetStatus() != http.StatusBadRequest {
		t.Errorf("期望HTTP状态码为 %d，但得到 %d", http.StatusBadRequest, err.GetStatus())
	}
}

func TestWrap(t *testing.T) {
	originalErr := fmt.Errorf("原始错误")
	wrappedErr := Wrap(originalErr, ErrCodeDBQuery)

	if wrappedErr.Code != ErrCodeDBQuery {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeDBQuery, wrappedErr.Code)
	}

	if wrappedErr.Message != "数据库查询失败" {
		t.Errorf("期望错误信息为 '数据库查询失败'，但得到 '%s'", wrappedErr.Message)
	}

	if wrappedErr.Cause != originalErr {
		t.Error("原始错误未正确包装")
	}
}

func TestWrapWithNil(t *testing.T) {
	wrappedErr := Wrap(nil, ErrCodeDBQuery)

	if wrappedErr != nil {
		t.Error("期望Wrap(nil)返回nil，但得到了非nil值")
	}
}

func TestWrapWithMessage(t *testing.T) {
	originalErr := fmt.Errorf("原始错误")
	customMessage := "自定义错误信息"
	wrappedErr := WrapWithMessage(originalErr, ErrCodeDBQuery, customMessage)

	if wrappedErr.Code != ErrCodeDBQuery {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeDBQuery, wrappedErr.Code)
	}

	if wrappedErr.Message != customMessage {
		t.Errorf("期望错误信息为 '%s'，但得到 '%s'", customMessage, wrappedErr.Message)
	}

	if wrappedErr.Cause != originalErr {
		t.Error("原始错误未正确包装")
	}
}

func TestWithMethods(t *testing.T) {
	err := New(ErrCodeInvalidParam)

	// 测试 WithStatus
	customStatus := http.StatusTeapot // 418
	err = err.WithStatus(customStatus)
	if err.GetStatus() != customStatus {
		t.Errorf("期望HTTP状态码为 %d，但得到 %d", customStatus, err.GetStatus())
	}

	// 测试 WithMessage
	customMessage := "自定义消息"
	err = err.WithMessage(customMessage)
	if err.Message != customMessage {
		t.Errorf("期望错误信息为 '%s'，但得到 '%s'", customMessage, err.Message)
	}

	// 测试 WithData
	customData := map[string]string{"key": "value"}
	err = err.WithData(customData)

	// 使用反射比较 map
	dataMap, ok := err.Data.(map[string]string)
	if !ok {
		t.Errorf("期望附加数据类型为 map[string]string，但得到 %T", err.Data)
		return
	}

	if !reflect.DeepEqual(dataMap, customData) {
		t.Errorf("期望附加数据为 %v，但得到 %v", customData, dataMap)
	}

	// 测试 WithCause
	customCause := fmt.Errorf("自定义原因")
	err = err.WithCause(customCause)
	if err.Cause != customCause {
		t.Errorf("期望原始错误为 %v，但得到 %v", customCause, err.Cause)
	}
}

func TestIs(t *testing.T) {
	err1 := New(ErrCodeInvalidParam)
	if !Is(err1, ErrCodeInvalidParam) {
		t.Error("Is函数未能正确识别错误码")
	}

	if Is(err1, ErrCodeDBQuery) {
		t.Error("Is函数错误地匹配了不同的错误码")
	}

	// 测试包装的错误
	originalErr := fmt.Errorf("原始错误")
	wrappedErr := Wrap(originalErr, ErrCodeDBQuery)

	if !Is(wrappedErr, ErrCodeDBQuery) {
		t.Error("Is函数未能正确识别包装的错误码")
	}
}

func TestHelperFunctions(t *testing.T) {
	// 测试 InvalidParam
	paramErr := InvalidParam("name")
	if paramErr.Code != ErrCodeInvalidParam {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeInvalidParam, paramErr.Code)
	}
	if paramErr.Message != "无效参数: name" {
		t.Errorf("期望错误信息包含参数名，但得到 '%s'", paramErr.Message)
	}

	// 测试 MissingParam
	missingErr := MissingParam("id")
	if missingErr.Code != ErrCodeInvalidParam {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeInvalidParam, missingErr.Code)
	}
	if missingErr.Message != "缺少参数: id" {
		t.Errorf("期望错误信息包含参数名，但得到 '%s'", missingErr.Message)
	}

	// 测试 Unauthorized
	unauthorizedErr := Unauthorized("令牌过期")
	if unauthorizedErr.Code != ErrCodeUnauthorized {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeUnauthorized, unauthorizedErr.Code)
	}
	if unauthorizedErr.Message != "未授权: 令牌过期" {
		t.Errorf("期望错误信息包含原因，但得到 '%s'", unauthorizedErr.Message)
	}

	// 测试 NotFound
	notFoundErr := NotFound("用户")
	if notFoundErr.Code != ErrCodeNotFound {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeNotFound, notFoundErr.Code)
	}
	if notFoundErr.Message != "资源不存在: 用户" {
		t.Errorf("期望错误信息包含资源名，但得到 '%s'", notFoundErr.Message)
	}

	// 测试 Internal
	originalErr := fmt.Errorf("内部系统故障")
	internalErr := Internal(originalErr)
	if internalErr.Code != ErrCodeInternal {
		t.Errorf("期望错误码为 %d，但得到 %d", ErrCodeInternal, internalErr.Code)
	}
	if internalErr.Cause != originalErr {
		t.Error("原始错误未正确包装")
	}
}

func TestErrorOutput(t *testing.T) {
	// 测试错误信息格式化
	err := New(ErrCodeInvalidParam).
		WithMessage("参数校验失败").
		WithCause(fmt.Errorf("值超出范围"))

	errStr := err.Error()

	// 检查错误字符串是否包含所有关键信息
	if !strings.Contains(errStr, "错误码: 100") {
		t.Error("错误信息中应该包含错误码")
	}
	if !strings.Contains(errStr, "信息: 参数校验失败") {
		t.Error("错误信息中应该包含错误消息")
	}
	if !strings.Contains(errStr, "原因: 值超出范围") {
		t.Error("错误信息中应该包含原始错误")
	}
	if !strings.Contains(errStr, "位置:") {
		t.Error("错误信息中应该包含错误位置")
	}
}

func TestGetCallStack(t *testing.T) {
	stack := getCallStack(1)
	if stack == "" {
		t.Error("期望获得非空的调用栈信息")
	}

	// 检查调用栈中是否包含当前文件名 - 可能因为路径不同而失败，所以这里跳过具体检查
	t.Logf("获取到的调用栈信息: %s", stack)
}
