package gin

import "github.com/darkit/gin/pkg/mail"

// SendMail 使用当前 Engine 作用域内的邮件发送器发送纯文本邮件。
func (e *Engine) SendMail(to string, subject, body string, opts ...mail.MailOption) error {
	mailer, err := e.Mailer()
	if err != nil {
		return err
	}
	return mailer.SendMail(to, subject, body, opts...)
}

// SendMailHTML 使用当前 Engine 作用域内的邮件发送器发送 HTML 邮件。
func (e *Engine) SendMailHTML(to string, subject, htmlBody string, opts ...mail.MailOption) error {
	mailer, err := e.Mailer()
	if err != nil {
		return err
	}
	return mailer.SendMailHTML(to, subject, htmlBody, opts...)
}

// SendTemplate 使用当前 Engine 作用域内的邮件发送器发送模板邮件。
func (e *Engine) SendTemplate(to string, subject, templateName string, data any, opts ...mail.MailOption) error {
	mailer, err := e.Mailer()
	if err != nil {
		return err
	}
	return mailer.SendTemplate(to, subject, templateName, data, opts...)
}

// SendBatch 使用当前 Engine 作用域内的邮件发送器批量发送纯文本邮件。
func (e *Engine) SendBatch(recipients []string, subject, body string, opts ...mail.MailOption) (*mail.BatchResult, error) {
	mailer, err := e.Mailer()
	if err != nil {
		return nil, err
	}
	return mailer.SendBatch(recipients, subject, body, opts...)
}
