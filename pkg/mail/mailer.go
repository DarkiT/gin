package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/gomail.v2"
)

// MailConfig 邮件发送配置
type MailConfig struct {
	Host     string // SMTP 主机
	Port     int    // SMTP 端口
	Username string // SMTP 用户名
	Password string // SMTP 密码
	From     string // 发件人地址
	FromName string // 发件人名称
	TLS      bool   // 是否启用 TLS
}

// MailOption 邮件选项
type MailOption func(*mailOptions)

type mailOptions struct {
	cc              []string
	bcc             []string
	attachments     []mailAttachment
	replyTo         string
	continueOnError bool
	maxConcurrent   int
	poolSize        int
	poolMaxIdle     time.Duration
	poolTimeout     time.Duration
}

type mailAttachment struct {
	path string
	name string
	data []byte
}

// SMTPPool SMTP 连接池
type SMTPPool struct {
	config    MailConfig
	pool      chan *smtpClient
	mu        sync.RWMutex
	closed    bool
	maxIdle   time.Duration
	timeout   time.Duration
	closeOnce sync.Once
}

type smtpClient struct {
	sender   gomail.SendCloser
	lastUsed time.Time
}

var (
	// ErrSMTPPoolClosed 连接池已关闭
	ErrSMTPPoolClosed = errors.New("SMTP 连接池已关闭")

	// ErrSMTPPoolTimeout 获取连接超时
	ErrSMTPPoolTimeout = errors.New("获取 SMTP 连接超时")
)

// NewSMTPPool 初始化 SMTP 连接池
func NewSMTPPool(config MailConfig, size int, opts ...MailOption) *SMTPPool {
	if size <= 0 {
		size = 5
	}
	options := applyMailOptions(opts...)
	return &SMTPPool{
		config:  config,
		pool:    make(chan *smtpClient, size),
		maxIdle: options.poolMaxIdle,
		timeout: options.poolTimeout,
	}
}

// Get 从池中获取连接
func (p *SMTPPool) Get() (*smtpClient, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrSMTPPoolClosed
	}
	maxIdle := p.maxIdle
	timeout := p.timeout
	p.mu.RUnlock()

	for {
		var client *smtpClient
		if timeout <= 0 {
			select {
			case client = <-p.pool:
			default:
			}
		} else {
			select {
			case client = <-p.pool:
			case <-time.After(timeout):
				return nil, ErrSMTPPoolTimeout
			}
		}

		if client == nil {
			return p.newClient()
		}
		if p.isExpired(client, maxIdle) {
			_ = client.sender.Close()
			continue
		}
		return client, nil
	}
}

// Put 归还连接到池中
func (p *SMTPPool) Put(client *smtpClient) error {
	if client == nil {
		return nil
	}
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return client.sender.Close()
	}
	maxIdle := p.maxIdle
	p.mu.RUnlock()

	if p.isExpired(client, maxIdle) {
		return client.sender.Close()
	}

	client.lastUsed = time.Now()
	select {
	case p.pool <- client:
		return nil
	default:
		return client.sender.Close()
	}
}

// Close 关闭所有连接
func (p *SMTPPool) Close() error {
	var closeErr error
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()

		close(p.pool)
		for client := range p.pool {
			if err := client.sender.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

func (p *SMTPPool) isExpired(client *smtpClient, maxIdle time.Duration) bool {
	if maxIdle <= 0 {
		return false
	}
	if client.lastUsed.IsZero() {
		return false
	}
	return time.Since(client.lastUsed) > maxIdle
}

func (p *SMTPPool) newClient() (*smtpClient, error) {
	d := gomail.NewDialer(p.config.Host, p.config.Port, p.config.Username, p.config.Password)
	if p.config.TLS {
		d.TLSConfig = &tls.Config{
			ServerName:         p.config.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
	}
	sender, err := d.Dial()
	if err != nil {
		return nil, err
	}
	return &smtpClient{
		sender:   sender,
		lastUsed: time.Now(),
	}, nil
}

// BatchResult 批量发送结果
type BatchResult struct {
	Total     int
	Succeeded int
	Failed    int
	Errors    map[string]error
}

// WithMailCC 设置抄送
func WithMailCC(cc ...string) MailOption {
	return func(o *mailOptions) {
		o.cc = append(o.cc, cc...)
	}
}

// WithMailBCC 设置密送
func WithMailBCC(bcc ...string) MailOption {
	return func(o *mailOptions) {
		o.bcc = append(o.bcc, bcc...)
	}
}

// WithMailAttachment 添加附件（文件路径）
func WithMailAttachment(path string) MailOption {
	return func(o *mailOptions) {
		if strings.TrimSpace(path) == "" {
			return
		}
		o.attachments = append(o.attachments, mailAttachment{path: path})
	}
}

// WithMailAttachmentData 添加附件（内存数据）
func WithMailAttachmentData(name string, data []byte) MailOption {
	return func(o *mailOptions) {
		if strings.TrimSpace(name) == "" || len(data) == 0 {
			return
		}
		o.attachments = append(o.attachments, mailAttachment{name: name, data: data})
	}
}

// WithMailReplyTo 设置回复地址
func WithMailReplyTo(replyTo string) MailOption {
	return func(o *mailOptions) {
		o.replyTo = strings.TrimSpace(replyTo)
	}
}

// WithContinueOnError 设置批量发送是否继续发送（默认 true）
func WithContinueOnError(continueOnError bool) MailOption {
	return func(o *mailOptions) {
		o.continueOnError = continueOnError
	}
}

// WithMaxConcurrent 设置批量发送最大并发数（默认 1）
func WithMaxConcurrent(maxConcurrent int) MailOption {
	return func(o *mailOptions) {
		o.maxConcurrent = maxConcurrent
	}
}

// WithPoolSize 设置连接池大小（默认 5）
func WithPoolSize(size int) MailOption {
	return func(o *mailOptions) {
		o.poolSize = size
	}
}

// WithPoolMaxIdle 设置连接最大空闲时间（默认 5 分钟）
func WithPoolMaxIdle(d time.Duration) MailOption {
	return func(o *mailOptions) {
		o.poolMaxIdle = d
	}
}

// WithPoolTimeout 设置获取连接超时（默认 10 秒）
func WithPoolTimeout(d time.Duration) MailOption {
	return func(o *mailOptions) {
		o.poolTimeout = d
	}
}

var (
	// ErrMailConfigMissing 邮件配置缺失
	ErrMailConfigMissing = errors.New("邮件配置缺失")

	// ErrMailHostMissing SMTP 主机缺失
	ErrMailHostMissing = errors.New("SMTP 主机不能为空")

	// ErrMailPortInvalid SMTP 端口无效
	ErrMailPortInvalid = errors.New("SMTP 端口无效")

	// ErrMailFromMissing 发件人缺失
	ErrMailFromMissing = errors.New("发件人地址不能为空")

	// ErrMailToMissing 收件人缺失
	ErrMailToMissing = errors.New("收件人不能为空")
)

// Mailer 邮件发送器
type Mailer struct {
	cfg      MailConfig
	sendHook func(to string, subject, body string, isHTML bool, opts ...MailOption) error
	pool     *SMTPPool
}

func (m *Mailer) setSendHook(hook func(to string, subject, body string, isHTML bool, opts ...MailOption) error) {
	m.sendHook = hook
}

// NewMailer 创建邮件发送器
func NewMailer(cfg MailConfig) (*Mailer, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, ErrMailHostMissing
	}
	if cfg.Port <= 0 {
		return nil, ErrMailPortInvalid
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, ErrMailFromMissing
	}
	return &Mailer{cfg: cfg}, nil
}

// SetConfig 更新邮件配置
func (m *Mailer) SetConfig(cfg MailConfig) {
	m.cfg = cfg
}

// ConfigurePool 配置 SMTP 连接池（可选）
func (m *Mailer) ConfigurePool(opts ...MailOption) {
	options := applyMailOptions(opts...)
	m.pool = NewSMTPPool(m.cfg, options.poolSize, WithPoolMaxIdle(options.poolMaxIdle), WithPoolTimeout(options.poolTimeout))
}

func (m *Mailer) dialer() *gomail.Dialer {
	d := gomail.NewDialer(m.cfg.Host, m.cfg.Port, m.cfg.Username, m.cfg.Password)
	if m.cfg.TLS {
		d.TLSConfig = &tls.Config{
			ServerName:         m.cfg.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
	}
	return d
}

// SendMail 发送纯文本邮件
func (m *Mailer) SendMail(to string, subject, body string, opts ...MailOption) error {
	return m.send(to, subject, body, false, opts...)
}

// SendMailHTML 发送 HTML 邮件
func (m *Mailer) SendMailHTML(to string, subject, htmlBody string, opts ...MailOption) error {
	return m.send(to, subject, htmlBody, true, opts...)
}

// SendTemplate 发送模板邮件
func (m *Mailer) SendTemplate(to string, subject, templateName string, data any, opts ...MailOption) error {
	htmlBody, err := RenderTemplate(templateName, data)
	if err != nil {
		return err
	}
	return m.send(to, subject, htmlBody, true, opts...)
}

// SendBatch 批量发送纯文本邮件
func (m *Mailer) SendBatch(recipients []string, subject, body string, opts ...MailOption) (*BatchResult, error) {
	if len(recipients) == 0 {
		return nil, ErrMailToMissing
	}

	options := applyMailOptions(opts...)
	if options.maxConcurrent <= 0 {
		options.maxConcurrent = 1
	}
	continueOnError := options.continueOnError

	result := &BatchResult{
		Total:  len(recipients),
		Errors: make(map[string]error),
	}

	if options.maxConcurrent == 1 {
		for _, to := range recipients {
			err := m.send(to, subject, body, false, opts...)
			if err != nil {
				result.Failed++
				result.Errors[to] = err
				if !continueOnError {
					break
				}
				continue
			}
			result.Succeeded++
		}
		if len(result.Errors) > 0 {
			return result, fmt.Errorf("批量发送失败: %d/%d", result.Failed, result.Total)
		}
		return result, nil
	}

	maxWorkers := options.maxConcurrent
	if maxWorkers > len(recipients) {
		maxWorkers = len(recipients)
	}

	type sendItem struct {
		to string
	}

	items := make(chan sendItem)
	var wg sync.WaitGroup
	var mu sync.Mutex
	stopCh := make(chan struct{})
	stopOnce := sync.Once{}

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			case item, ok := <-items:
				if !ok {
					return
				}
				err := m.send(item.to, subject, body, false, opts...)
				mu.Lock()
				if err != nil {
					result.Failed++
					result.Errors[item.to] = err
					if !continueOnError {
						stopOnce.Do(func() {
							close(stopCh)
						})
					}
				} else {
					result.Succeeded++
				}
				mu.Unlock()
			}
		}
	}

	wg.Add(maxWorkers)
	for i := 0; i < maxWorkers; i++ {
		go worker()
	}

feedLoop:
	for _, to := range recipients {
		select {
		case <-stopCh:
			break feedLoop
		case items <- sendItem{to: to}:
		}
	}
	close(items)

	wg.Wait()

	if len(result.Errors) > 0 {
		return result, fmt.Errorf("批量发送失败: %d/%d", result.Failed, result.Total)
	}
	return result, nil
}

func (m *Mailer) send(to string, subject, body string, isHTML bool, opts ...MailOption) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return ErrMailToMissing
	}

	options := applyMailOptions(opts...)

	if m.sendHook != nil {
		return m.sendHook(to, subject, body, isHTML, opts...)
	}

	msg := gomail.NewMessage()
	if m.cfg.FromName != "" {
		msg.SetAddressHeader("From", m.cfg.From, m.cfg.FromName)
	} else {
		msg.SetHeader("From", m.cfg.From)
	}
	msg.SetHeader("To", to)
	if len(options.cc) > 0 {
		msg.SetHeader("Cc", options.cc...)
	}
	if len(options.bcc) > 0 {
		msg.SetHeader("Bcc", options.bcc...)
	}
	if options.replyTo != "" {
		msg.SetHeader("Reply-To", options.replyTo)
	}
	msg.SetHeader("Subject", subject)

	contentType := "text/plain; charset=UTF-8"
	if isHTML {
		contentType = "text/html; charset=UTF-8"
	}
	msg.SetBody(contentType, body)

	if err := attachFiles(msg, options.attachments); err != nil {
		return err
	}

	if m.pool == nil {
		return m.dialer().DialAndSend(msg)
	}

	client, err := m.pool.Get()
	if err != nil {
		return err
	}

	if err := gomail.Send(client.sender, msg); err != nil {
		_ = client.sender.Close()
		return err
	}

	return m.pool.Put(client)
}

func applyMailOptions(opts ...MailOption) *mailOptions {
	options := &mailOptions{
		continueOnError: true,
		maxConcurrent:   1,
		poolSize:        5,
		poolMaxIdle:     5 * time.Minute,
		poolTimeout:     10 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	return options
}

func attachFiles(msg *gomail.Message, attachments []mailAttachment) error {
	for _, att := range attachments {
		if len(att.data) > 0 {
			name := strings.TrimSpace(att.name)
			if name == "" {
				name = "attachment"
			}
			msg.Attach(name, gomail.SetCopyFunc(func(w io.Writer) error {
				_, err := w.Write(att.data)
				return err
			}))
			continue
		}
		if strings.TrimSpace(att.path) == "" {
			continue
		}
		name := strings.TrimSpace(att.name)
		if name == "" {
			name = filepath.Base(att.path)
		}
		msg.Attach(att.path, gomail.Rename(name))
	}
	return nil
}
