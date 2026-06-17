package sms

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// SMSConfig 表示短信配置。
type SMSConfig struct {
	Provider  string // 短信服务商：aliyun, tencent
	AccessKey string // 访问密钥 ID
	SecretKey string // 访问密钥 Secret
	SignName  string // 短信签名
	Region    string // 区域（部分服务商需要）
	AppID     string
}

// SMSProvider 表示短信服务商接口。
type SMSProvider interface {
	// Send 发送短信
	// mobile: 手机号
	// templateID: 短信模板 ID
	// params: 模板参数
	Send(mobile, templateID string, params map[string]string) error
}

var (
	// ErrSMSConfigMissing 表示短信配置缺失。
	ErrSMSConfigMissing = errors.New("短信配置缺失")

	// ErrSMSProviderInvalid 表示短信服务商无效。
	ErrSMSProviderInvalid = errors.New("短信服务商无效")

	// ErrSMSAccessKeyMissing 表示访问密钥缺失。
	ErrSMSAccessKeyMissing = errors.New("访问密钥不能为空")

	// ErrSMSSecretKeyMissing 表示密钥缺失。
	ErrSMSSecretKeyMissing = errors.New("密钥不能为空")

	// ErrSMSSignNameMissing 表示短信签名缺失。
	ErrSMSSignNameMissing = errors.New("短信签名不能为空")

	// ErrSMSMobileMissing 表示手机号缺失。
	ErrSMSMobileMissing = errors.New("手机号不能为空")

	// ErrSMSTemplateIDMissing 表示模板 ID 缺失。
	ErrSMSTemplateIDMissing = errors.New("模板ID不能为空")

	// ErrSMSNotInitialized 表示短信服务未初始化。
	ErrSMSNotInitialized = errors.New("短信服务未初始化")

	// ErrSMSProviderNotImplemented 表示短信服务商未实现。
	ErrSMSProviderNotImplemented = errors.New("短信服务商暂未实现")

	ErrSMSAppIDMissing = errors.New("短信应用ID不能为空")
)

var (
	smsProviderOnce sync.Once
	smsProviderInst SMSProvider
	smsProviderMu   sync.Mutex
	smsConfig       SMSConfig
)

// ProviderFactory 表示服务商工厂函数。
type ProviderFactory func(cfg SMSConfig) (SMSProvider, error)

var (
	providerFactories   = map[string]ProviderFactory{}
	providerFactoriesMu sync.RWMutex
)

// RegisterProvider 注册短信服务商。
func RegisterProvider(name string, factory ProviderFactory) {
	providerFactoriesMu.Lock()
	providerFactories[name] = factory
	providerFactoriesMu.Unlock()
}

// ValidateConfig 校验短信配置是否满足基础要求且服务商已注册。
func ValidateConfig(cfg SMSConfig) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if _, ok := getProviderFactory(cfg.Provider); !ok {
		return ErrSMSProviderInvalid
	}
	if cfg.Provider == "tencent" && strings.TrimSpace(cfg.AppID) == "" {
		return ErrSMSAppIDMissing
	}
	return nil
}

// InitDefaultProvider 初始化全局短信服务商。
func InitDefaultProvider(cfg SMSConfig) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}

	factory, _ := getProviderFactory(cfg.Provider)

	var initErr error
	smsProviderOnce.Do(func() {
		smsProviderInst, initErr = factory(cfg)
		if initErr == nil {
			smsConfig = cfg
		}
	})

	if initErr != nil {
		return initErr
	}

	// 如果已经初始化过，更新配置和实例
	smsProviderMu.Lock()
	defer smsProviderMu.Unlock()
	smsProviderInst, initErr = factory(cfg)
	if initErr == nil {
		smsConfig = cfg
	}
	return initErr
}

// DefaultProvider 获取全局短信服务商。
func DefaultProvider() (SMSProvider, error) {
	smsProviderMu.Lock()
	defer smsProviderMu.Unlock()
	if smsProviderInst == nil {
		return nil, ErrSMSNotInitialized
	}
	return smsProviderInst, nil
}

// GetConfig 获取当前短信配置。
func GetConfig() SMSConfig {
	smsProviderMu.Lock()
	defer smsProviderMu.Unlock()
	return smsConfig
}

// SendSMS 发送短信（使用全局服务商）。
func SendSMS(mobile, templateID string, params map[string]string) error {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return ErrSMSMobileMissing
	}
	if strings.TrimSpace(templateID) == "" {
		return ErrSMSTemplateIDMissing
	}

	provider, err := DefaultProvider()
	if err != nil {
		return err
	}

	return provider.Send(mobile, templateID, params)
}

func validateConfig(cfg SMSConfig) error {
	if strings.TrimSpace(cfg.Provider) == "" {
		return ErrSMSProviderInvalid
	}
	if strings.TrimSpace(cfg.AccessKey) == "" {
		return ErrSMSAccessKeyMissing
	}
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return ErrSMSSecretKeyMissing
	}
	if strings.TrimSpace(cfg.SignName) == "" {
		return ErrSMSSignNameMissing
	}
	return nil
}

// Service 表示 engine-scoped 的短信服务。
type Service struct {
	provider SMSProvider
	codes    *CodeManager
}

// NewService 创建一个短信服务实例。
func NewService(cfg SMSConfig) (*Service, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	factory, _ := getProviderFactory(cfg.Provider)

	provider, err := factory(cfg)
	if err != nil {
		return nil, err
	}

	return &Service{
		provider: provider,
		codes:    NewCodeManager(),
	}, nil
}

func getProviderFactory(provider string) (ProviderFactory, bool) {
	providerFactoriesMu.RLock()
	factory, ok := providerFactories[provider]
	providerFactoriesMu.RUnlock()
	return factory, ok
}

// Send 通过当前服务发送短信。
func (s *Service) Send(mobile, templateID string, params map[string]string) error {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return ErrSMSMobileMissing
	}
	if strings.TrimSpace(templateID) == "" {
		return ErrSMSTemplateIDMissing
	}
	if s == nil || s.provider == nil {
		return ErrSMSNotInitialized
	}
	return s.provider.Send(mobile, templateID, params)
}

// SendCode 发送验证码。
func (s *Service) SendCode(mobile string, opts ...SMSOption) (string, error) {
	return sendCode(context.Background(), s, mobile, opts...)
}

// VerifyCode 验证验证码。
func (s *Service) VerifyCode(mobile, code string) bool {
	return verifyCodeStore(s.codeStore(), mobile, code)
}

// IsLocked 检查手机号是否被锁定。
func (s *Service) IsLocked(mobile string) bool {
	return isLockedStore(s.codeStore(), mobile)
}

// Unlock 手动解锁手机号。
func (s *Service) Unlock(mobile string) error {
	return unlockStore(s.codeStore(), mobile)
}

// GetFailures 获取失败次数。
func (s *Service) GetFailures(mobile string) int {
	return getFailuresStore(s.codeStore(), mobile)
}

// GetCode 获取验证码（仅用于测试）。
func (s *Service) GetCode(mobile string) (string, error) {
	return getCodeStoreValue(s.codeStore(), mobile)
}

// DeleteCode 删除验证码。
func (s *Service) DeleteCode(mobile string) {
	deleteCodeStoreValue(s.codeStore(), mobile)
}

// Close 停止后台清理任务。
func (s *Service) Close() {
	if s == nil || s.codes == nil {
		return
	}
	s.codes.Close()
}

func (s *Service) codeStore() *CodeManager {
	if s == nil || s.codes == nil {
		return getCodeStore()
	}
	return s.codes
}
