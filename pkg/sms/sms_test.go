package sms

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// mockProvider 模拟短信服务商
type mockProvider struct {
	sentMessages []mockMessage
}

type mockMessage struct {
	mobile     string
	templateID string
	params     map[string]string
}

func (p *mockProvider) Send(mobile, templateID string, params map[string]string) error {
	p.sentMessages = append(p.sentMessages, mockMessage{
		mobile:     mobile,
		templateID: templateID,
		params:     params,
	})
	return nil
}

// newMockProvider 创建模拟服务商
func newMockProvider(cfg SMSConfig) (SMSProvider, error) {
	return &mockProvider{}, nil
}

func TestSendCode(t *testing.T) {
	// 注册 mock provider
	RegisterProvider("mock", newMockProvider)

	// 初始化
	cfg := SMSConfig{
		Provider:  "mock",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		SignName:  "测试签名",
	}
	if err := InitDefaultProvider(cfg); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	// 测试发送验证码（不实际发送短信）
	code, err := SendCode("13800138000")
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}

	// 验证验证码长度
	if len(code) != 6 {
		t.Errorf("验证码长度应为6，实际为: %d", len(code))
	}

	// 验证验证码是否为纯数字
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Errorf("验证码应为纯数字，实际包含: %c", ch)
		}
	}

	// 验证码应该被存储
	storedCode, err := GetCode("13800138000")
	if err != nil {
		t.Fatalf("获取验证码失败: %v", err)
	}
	if storedCode != code {
		t.Errorf("存储的验证码不匹配，期望: %s, 实际: %s", code, storedCode)
	}
}

func TestVerifyCode(t *testing.T) {
	// 发送验证码
	code, err := SendCode("13800138001")
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}

	// 测试验证正确的验证码
	if !VerifyCode("13800138001", code) {
		t.Error("验证正确的验证码失败")
	}

	// 验证码应该被删除（一次性使用）
	if VerifyCode("13800138001", code) {
		t.Error("验证码应该在验证后被删除")
	}

	// 测试验证错误的验证码
	code2, _ := SendCode("13800138002")
	if VerifyCode("13800138002", "000000") {
		t.Error("不应该验证通过错误的验证码")
	}
	// 错误验证不应删除验证码
	if !VerifyCode("13800138002", code2) {
		t.Error("正确的验证码应该仍然有效")
	}
}

func TestCodeExpiry(t *testing.T) {
	// 发送验证码，设置1秒过期
	code, err := SendCode("13800138003", WithCodeExpiry(1*time.Second))
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}

	// 立即验证应该成功
	storedCode, err := GetCode("13800138003")
	if err != nil || storedCode != code {
		t.Error("验证码应该立即可用")
	}

	// 等待过期
	time.Sleep(1100 * time.Millisecond)

	// 验证码应该已过期
	_, err = GetCode("13800138003")
	if err != ErrCodeNotFound {
		t.Error("验证码应该已过期")
	}

	if VerifyCode("13800138003", code) {
		t.Error("过期的验证码不应该验证通过")
	}
}

func TestCodeOptions(t *testing.T) {
	// 测试自定义长度
	code, err := SendCode("13800138004", WithCodeLength(4))
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}
	if len(code) != 4 {
		t.Errorf("验证码长度应为4，实际为: %d", len(code))
	}

	// 测试字母数字混合
	code2, err := SendCode("13800138005", WithCodeType(CodeTypeAlphanumeric), WithCodeLength(8))
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}
	if len(code2) != 8 {
		t.Errorf("验证码长度应为8，实际为: %d", len(code2))
	}

	// 验证是否包含字母或数字
	hasDigit := false
	for _, ch := range code2 {
		if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		t.Error("字母数字验证码应该包含有效字符")
	}
}

func TestProviderRegistration(t *testing.T) {
	// 测试注册新的 provider
	called := false
	RegisterProvider("test-provider", func(cfg SMSConfig) (SMSProvider, error) {
		called = true
		return &mockProvider{}, nil
	})

	cfg := SMSConfig{
		Provider:  "test-provider",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		SignName:  "测试签名",
	}

	if err := InitDefaultProvider(cfg); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	if !called {
		t.Error("provider 工厂函数应该被调用")
	}

	// 测试无效的 provider
	invalidCfg := SMSConfig{
		Provider:  "invalid-provider",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		SignName:  "测试签名",
	}

	if err := InitDefaultProvider(invalidCfg); err != ErrSMSProviderInvalid {
		t.Errorf("应该返回 ErrSMSProviderInvalid，实际: %v", err)
	}
}

func TestProviderRegistryConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-provider-%d", i)
			RegisterProvider(name, newMockProvider)
			err := ValidateConfig(SMSConfig{
				Provider:  name,
				AccessKey: "test-key",
				SecretKey: "test-secret",
				SignName:  "测试签名",
			})
			if err != nil {
				t.Errorf("ValidateConfig(%s): %v", name, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestVerifyCodeBruteForceProtection(t *testing.T) {
	mobile := "13800138010"
	code, err := SendCode(mobile, WithMaxFailures(2), WithLockDuration(200*time.Millisecond))
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}

	if VerifyCode(mobile, "000000") {
		t.Fatal("错误验证码不应通过")
	}
	if VerifyCode(mobile, "111111") {
		t.Fatal("错误验证码不应通过")
	}
	if !IsLocked(mobile) {
		t.Fatal("连续失败后应锁定")
	}
	if GetFailures(mobile) != 2 {
		t.Fatalf("失败次数应为 2，实际: %d", GetFailures(mobile))
	}
	if VerifyCode(mobile, code) {
		t.Fatal("锁定期间不应验证通过")
	}

	time.Sleep(250 * time.Millisecond)
	if IsLocked(mobile) {
		t.Fatal("锁定到期后应解除")
	}
	if !VerifyCode(mobile, code) {
		t.Fatal("锁定到期后应允许验证")
	}
}

func TestVerifyCodeUnlock(t *testing.T) {
	mobile := "13800138011"
	code, err := SendCode(mobile, WithMaxFailures(1), WithLockDuration(time.Minute))
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}

	if VerifyCode(mobile, "000000") {
		t.Fatal("错误验证码不应通过")
	}
	if !IsLocked(mobile) {
		t.Fatal("达到上限后应锁定")
	}

	if err := Unlock(mobile); err != nil {
		t.Fatalf("手动解锁失败: %v", err)
	}
	if IsLocked(mobile) {
		t.Fatal("手动解锁后不应锁定")
	}
	if GetFailures(mobile) != 0 {
		t.Fatalf("解锁后失败次数应清零，实际: %d", GetFailures(mobile))
	}
	if !VerifyCode(mobile, code) {
		t.Fatal("解锁后应允许验证")
	}
}

func TestProviderNotImplemented(t *testing.T) {
	// 注册一个占位 provider
	RegisterProvider("placeholder", func(cfg SMSConfig) (SMSProvider, error) {
		return &placeholderProvider{}, nil
	})

	cfg := SMSConfig{
		Provider:  "placeholder",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		SignName:  "测试签名",
	}

	if err := InitDefaultProvider(cfg); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	err := SendSMS("13800138000", "SMS_001", map[string]string{"code": "123456"})
	if err != ErrSMSProviderNotImplemented {
		t.Fatalf("应该返回 ErrSMSProviderNotImplemented，实际: %v", err)
	}
}

// placeholderProvider 占位 provider，用于测试未实现的服务商
type placeholderProvider struct{}

func (p *placeholderProvider) Send(mobile, templateID string, params map[string]string) error {
	return ErrSMSProviderNotImplemented
}

func TestSendSMS(t *testing.T) {
	// 注册 mock provider
	mock := &mockProvider{}
	RegisterProvider("mock2", func(cfg SMSConfig) (SMSProvider, error) {
		return mock, nil
	})

	cfg := SMSConfig{
		Provider:  "mock2",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		SignName:  "测试签名",
	}

	if err := InitDefaultProvider(cfg); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	// 测试发送短信
	params := map[string]string{
		"code": "123456",
		"name": "张三",
	}

	err := SendSMS("13800138006", "SMS_001", params)
	if err != nil {
		t.Fatalf("发送短信失败: %v", err)
	}

	// 验证发送的消息
	if len(mock.sentMessages) != 1 {
		t.Fatalf("应该发送1条消息，实际: %d", len(mock.sentMessages))
	}

	msg := mock.sentMessages[0]
	if msg.mobile != "13800138006" {
		t.Errorf("手机号不匹配，期望: 13800138006, 实际: %s", msg.mobile)
	}
	if msg.templateID != "SMS_001" {
		t.Errorf("模板ID不匹配，期望: SMS_001, 实际: %s", msg.templateID)
	}
	if msg.params["code"] != "123456" {
		t.Errorf("参数code不匹配，期望: 123456, 实际: %s", msg.params["code"])
	}

	// 测试空手机号
	err = SendSMS("", "SMS_001", params)
	if err != ErrSMSMobileMissing {
		t.Errorf("应该返回 ErrSMSMobileMissing，实际: %v", err)
	}

	// 测试空模板ID
	err = SendSMS("13800138006", "", params)
	if err != ErrSMSTemplateIDMissing {
		t.Errorf("应该返回 ErrSMSTemplateIDMissing，实际: %v", err)
	}
}
