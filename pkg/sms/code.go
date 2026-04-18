package sms

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	// CodeTypeNumeric 表示纯数字验证码类型。
	CodeTypeNumeric = "numeric"
	// CodeTypeAlphanumeric 表示字母数字混合验证码类型。
	CodeTypeAlphanumeric = "alphanumeric"
)

var (
	// ErrCodeExpired 表示验证码已过期。
	ErrCodeExpired = errors.New("验证码已过期")

	// ErrCodeInvalid 表示验证码无效。
	ErrCodeInvalid = errors.New("验证码无效")

	// ErrCodeNotFound 表示验证码不存在。
	ErrCodeNotFound = errors.New("验证码不存在")
)

// SMSOption 表示短信选项。
type SMSOption func(*smsOptions)

type smsOptions struct {
	codeLength   int               // 验证码长度
	codeExpiry   time.Duration     // 验证码过期时间
	codeType     string            // 验证码类型：numeric, alphanumeric
	templateID   string            // 短信模板 ID
	params       map[string]string // 额外模板参数
	maxFailures  int               // 失败次数上限
	lockDuration time.Duration     // 锁定时长
}

// WithCodeLength 设置验证码长度
func WithCodeLength(length int) SMSOption {
	return func(o *smsOptions) {
		if length > 0 {
			o.codeLength = length
		}
	}
}

// WithCodeExpiry 设置验证码过期时间
func WithCodeExpiry(expiry time.Duration) SMSOption {
	return func(o *smsOptions) {
		if expiry > 0 {
			o.codeExpiry = expiry
		}
	}
}

// WithCodeType 设置验证码类型
func WithCodeType(codeType string) SMSOption {
	return func(o *smsOptions) {
		if codeType == CodeTypeNumeric || codeType == CodeTypeAlphanumeric {
			o.codeType = codeType
		}
	}
}

// WithTemplateID 设置短信模板 ID
func WithTemplateID(templateID string) SMSOption {
	return func(o *smsOptions) {
		o.templateID = strings.TrimSpace(templateID)
	}
}

// WithTemplateParams 设置模板参数
func WithTemplateParams(params map[string]string) SMSOption {
	return func(o *smsOptions) {
		if o.params == nil {
			o.params = make(map[string]string)
		}
		for k, v := range params {
			o.params[k] = v
		}
	}
}

// WithMaxFailures 设置最大失败次数
func WithMaxFailures(maxFailures int) SMSOption {
	return func(o *smsOptions) {
		if maxFailures > 0 {
			o.maxFailures = maxFailures
		}
	}
}

// WithLockDuration 设置锁定时长
func WithLockDuration(duration time.Duration) SMSOption {
	return func(o *smsOptions) {
		if duration > 0 {
			o.lockDuration = duration
		}
	}
}

// codeEntry 验证码条目
type codeEntry struct {
	code   string
	expiry time.Time
}

type failureInfo struct {
	count       int
	lockedUntil time.Time
}

// CodeManager 表示验证码内存存储。
type CodeManager struct {
	mu           sync.RWMutex
	store        map[string]*codeEntry
	failures     map[string]failureInfo
	maxFailures  int
	lockDuration time.Duration
	done         chan struct{}
	wg           sync.WaitGroup
}

var (
	globalCodeStore     *CodeManager
	globalCodeStoreOnce sync.Once
)

// getCodeStore 获取全局验证码存储
func getCodeStore() *CodeManager {
	globalCodeStoreOnce.Do(func() {
		globalCodeStore = &CodeManager{
			store:        make(map[string]*codeEntry),
			failures:     make(map[string]failureInfo),
			maxFailures:  5,
			lockDuration: 15 * time.Minute,
			done:         make(chan struct{}),
		}
		// 启动清理 goroutine，每分钟清理一次过期条目
		globalCodeStore.wg.Add(1)
		go globalCodeStore.cleanupExpired()
	})
	return globalCodeStore
}

// set 设置验证码
func (s *CodeManager) set(mobile, code string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[mobile] = &codeEntry{
		code:   code,
		expiry: time.Now().Add(ttl),
	}
}

// get 获取验证码
func (s *CodeManager) get(mobile string) (string, bool) {
	s.mu.RLock()
	entry, exists := s.store[mobile]
	s.mu.RUnlock()

	if !exists {
		return "", false
	}

	if time.Now().After(entry.expiry) {
		return "", false
	}

	return entry.code, true
}

// delete 删除验证码
func (s *CodeManager) delete(mobile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, mobile)
}

// cleanupExpired 定期清理过期验证码
func (s *CodeManager) cleanupExpired() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer s.wg.Done()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for mobile, entry := range s.store {
				if now.After(entry.expiry) {
					delete(s.store, mobile)
				}
			}
			for mobile, info := range s.failures {
				if !info.lockedUntil.IsZero() && now.After(info.lockedUntil) {
					delete(s.failures, mobile)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

func (s *CodeManager) configure(maxFailures int, lockDuration time.Duration) {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockDuration <= 0 {
		lockDuration = 15 * time.Minute
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxFailures = maxFailures
	s.lockDuration = lockDuration
}

func (s *CodeManager) isLocked(mobile string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.failures[mobile]
	if !ok {
		return false
	}
	if info.lockedUntil.IsZero() {
		return false
	}
	if now.After(info.lockedUntil) {
		delete(s.failures, mobile)
		return false
	}
	return true
}

func (s *CodeManager) recordFailure(mobile string) {
	if s.maxFailures <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.failures[mobile]
	info.count++
	if info.count >= s.maxFailures {
		lockDuration := s.lockDuration
		if lockDuration <= 0 {
			lockDuration = 15 * time.Minute
		}
		info.lockedUntil = time.Now().Add(lockDuration)
	}
	s.failures[mobile] = info
}

func (s *CodeManager) resetFailure(mobile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, mobile)
}

func (s *CodeManager) unlock(mobile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, mobile)
}

func (s *CodeManager) getFailures(mobile string) int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.failures[mobile]
	if !ok {
		return 0
	}
	if !info.lockedUntil.IsZero() && now.After(info.lockedUntil) {
		delete(s.failures, mobile)
		return 0
	}
	return info.count
}

// Close 停止清理 goroutine
func (s *CodeManager) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	s.wg.Wait()
}

// generateCode 生成验证码
func generateCode(length int, codeType string) (string, error) {
	var charset string
	switch codeType {
	case CodeTypeNumeric:
		charset = "0123456789"
	case CodeTypeAlphanumeric:
		charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	default:
		charset = "0123456789"
	}

	code := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("生成随机数失败: %w", err)
		}
		code[i] = charset[n.Int64()]
	}

	return string(code), nil
}

// applyOptions 应用选项
func applyOptions(opts ...SMSOption) *smsOptions {
	options := &smsOptions{
		codeLength:   6,               // 默认6位
		codeExpiry:   5 * time.Minute, // 默认5分钟
		codeType:     CodeTypeNumeric, // 默认纯数字
		params:       make(map[string]string),
		maxFailures:  5,
		lockDuration: 15 * time.Minute,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	return options
}

// SendCode 发送验证码。
// 返回生成的验证码和错误信息。
func SendCode(mobile string, opts ...SMSOption) (string, error) {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return "", ErrSMSMobileMissing
	}

	options := applyOptions(opts...)

	// 生成验证码
	code, err := generateCode(options.codeLength, options.codeType)
	if err != nil {
		return "", err
	}

	// 存储验证码
	store := getCodeStore()
	store.configure(options.maxFailures, options.lockDuration)
	store.set(mobile, code, options.codeExpiry)

	// 如果提供了模板 ID，则发送短信
	if options.templateID != "" {
		// 将验证码添加到模板参数中
		if options.params == nil {
			options.params = make(map[string]string)
		}
		options.params["code"] = code

		if err := SendSMS(mobile, options.templateID, options.params); err != nil {
			// 发送失败，删除已存储的验证码
			store.delete(mobile)
			return "", err
		}
	}

	return code, nil
}

// VerifyCode 验证验证码。
func VerifyCode(mobile, code string) bool {
	mobile = strings.TrimSpace(mobile)
	code = strings.TrimSpace(code)

	if mobile == "" || code == "" {
		return false
	}

	store := getCodeStore()
	if store.isLocked(mobile) {
		return false
	}
	storedCode, exists := store.get(mobile)
	if !exists {
		store.recordFailure(mobile)
		return false
	}

	// 验证通过后删除验证码（一次性使用）
	if storedCode == code {
		store.delete(mobile)
		store.resetFailure(mobile)
		return true
	}

	store.recordFailure(mobile)
	return false
}

// IsLocked 检查手机号是否被锁定。
func IsLocked(mobile string) bool {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return false
	}
	store := getCodeStore()
	return store.isLocked(mobile)
}

// Unlock 手动解锁手机号。
func Unlock(mobile string) error {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return ErrSMSMobileMissing
	}
	store := getCodeStore()
	store.unlock(mobile)
	return nil
}

// GetFailures 获取失败次数。
func GetFailures(mobile string) int {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return 0
	}
	store := getCodeStore()
	return store.getFailures(mobile)
}

// GetCode 获取验证码（仅用于测试）。
func GetCode(mobile string) (string, error) {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return "", ErrSMSMobileMissing
	}

	store := getCodeStore()
	code, exists := store.get(mobile)
	if !exists {
		return "", ErrCodeNotFound
	}

	return code, nil
}

// DeleteCode 删除验证码。
func DeleteCode(mobile string) {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" {
		return
	}

	store := getCodeStore()
	store.delete(mobile)
}
