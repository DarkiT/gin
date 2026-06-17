package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/errs"
)

// SignTemplate provides API parameter signing and verification | API 参数签名模板
type SignTemplate struct {
	storage   adapter.Storage
	keyPrefix string
	nonceTTL  time.Duration
	// mu 用于 nonce 占用的进程内互斥降级（后端不支持 SetNX 时）。
	mu sync.Mutex
}

// NewSignTemplate creates a new signature template | 创建签名模板
func NewSignTemplate(storage adapter.Storage, prefix string, nonceTTL time.Duration) *SignTemplate {
	if nonceTTL <= 0 {
		nonceTTL = 5 * time.Minute
	}
	return &SignTemplate{
		storage:   storage,
		keyPrefix: prefix + "sign:nonce:",
		nonceTTL:  nonceTTL,
	}
}

// Sign generates HMAC-SHA256 signature from sorted params | 生成 HMAC-SHA256 签名
func (s *SignTemplate) Sign(params map[string]string, secret string) string {
	// Sort params by key
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(params[k])
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sb.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySign verifies signature with timestamp and nonce replay protection | 验证签名（含时间戳+Nonce防重放）
//
// 校验顺序（安全收紧）：
//  1. 时间戳双向新鲜度——既挡过期请求，也挡未来时间戳重放（补齐原先只挡过去的遗漏）；
//  2. 先验签（防伪造），签名错误直接拒，**不占用 nonce**（修正原先签名错误也消费 nonce 的 bug）；
//  3. 验签通过后再原子首次占用 nonce（防重放）；nonce 占用用 reserveOnce 收紧 TOCTOU 窗口。
func (s *SignTemplate) VerifySign(params map[string]string, secret, timestamp, nonce, signature string, maxAgeSeconds int64) error {
	// 1) 时间戳新鲜度：双向校验
	if maxAgeSeconds > 0 {
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: invalid timestamp", errs.ErrSignatureExpired)
		}
		now := time.Now().Unix()
		if now-ts > maxAgeSeconds {
			return errs.ErrSignatureExpired
		}
		// 未来时间戳同样按过期处理，堵住「未来时间戳在窗口内反复重放」。
		if ts-now > maxAgeSeconds {
			return errs.ErrSignatureExpired
		}
	}

	// 2) 先验签：构造待校验参数（含 timestamp / nonce），用恒定时间比对
	verifyParams := make(map[string]string, len(params)+2)
	maps.Copy(verifyParams, params)
	if timestamp != "" {
		verifyParams["timestamp"] = timestamp
	}
	if nonce != "" {
		verifyParams["nonce"] = nonce
	}
	expected := s.Sign(verifyParams, secret)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return errs.ErrSignatureInvalid
	}

	// 3) 验签通过后再防重放：原子首次占用 nonce，已占用则拒（TOCTOU 收紧）。
	if nonce != "" {
		if !reserveOnce(s.storage, &s.mu, s.keyPrefix+nonce, s.nonceTTL) {
			return errs.ErrNonceAlreadyUsed
		}
	}

	return nil
}
