// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"github.com/darkit/gin/pkg/mail"
)

// SendMail 发送纯文本邮件，to 为收件人地址。
func SendMail(to string, subject, body string, opts ...mail.MailOption) error {
	mailer, err := mail.DefaultMailer()
	if err != nil {
		return err
	}
	return mailer.SendMail(to, subject, body, opts...)
}

// SendMailHTML 发送 HTML 邮件，to 为收件人地址。
func SendMailHTML(to string, subject, htmlBody string, opts ...mail.MailOption) error {
	mailer, err := mail.DefaultMailer()
	if err != nil {
		return err
	}
	return mailer.SendMailHTML(to, subject, htmlBody, opts...)
}

// SendTemplate 发送模板邮件，templateName 为模板名称。
func SendTemplate(to string, subject, templateName string, data any, opts ...mail.MailOption) error {
	mailer, err := mail.DefaultMailer()
	if err != nil {
		return err
	}
	return mailer.SendTemplate(to, subject, templateName, data, opts...)
}

// SendBatch 批量发送纯文本邮件，recipients 为收件人列表。
func SendBatch(recipients []string, subject, body string, opts ...mail.MailOption) (*mail.BatchResult, error) {
	mailer, err := mail.DefaultMailer()
	if err != nil {
		return nil, err
	}
	return mailer.SendBatch(recipients, subject, body, opts...)
}
