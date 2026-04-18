package sms

import (
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

var providerFactories = map[string]ProviderFactory{}

// RegisterProvider 注册短信服务商。
func RegisterProvider(name string, factory ProviderFactory) {
	providerFactories[name] = factory
}

// InitDefaultProvider 初始化全局短信服务商。
func InitDefaultProvider(cfg SMSConfig) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}

	factory, ok := providerFactories[cfg.Provider]
	if !ok {
		return ErrSMSProviderInvalid
	}

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
