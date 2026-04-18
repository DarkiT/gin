package mail

import (
	"sync"
)

var (
	mailerOnce sync.Once
	mailerInst *Mailer
	mailerMu   sync.Mutex
)

// InitDefaultMailer 初始化全局邮件发送器
func InitDefaultMailer(cfg MailConfig) error {
	validatedMailer, err := NewMailer(cfg)
	if err != nil {
		return err
	}

	mailerOnce.Do(func() {
		mailerInst = validatedMailer
	})
	if mailerInst == nil {
		return ErrMailConfigMissing
	}
	mailerMu.Lock()
	defer mailerMu.Unlock()
	mailerInst.SetConfig(cfg)
	return nil
}

// DefaultMailer 获取全局邮件发送器
func DefaultMailer() (*Mailer, error) {
	mailerMu.Lock()
	defer mailerMu.Unlock()
	if mailerInst == nil {
		return nil, ErrMailConfigMissing
	}
	return mailerInst, nil
}
