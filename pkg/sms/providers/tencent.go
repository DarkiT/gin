package providers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkit/gin/pkg/sms"
)

// TencentProvider 腾讯云短信服务商
type TencentProvider struct {
	cfg    sms.SMSConfig
	client *http.Client
}

// NewTencentProvider 创建腾讯云短信服务商
func NewTencentProvider(cfg sms.SMSConfig) (sms.SMSProvider, error) {
	if strings.TrimSpace(cfg.AppID) == "" {
		return nil, sms.ErrSMSAppIDMissing
	}
	if strings.TrimSpace(cfg.Region) == "" {
		cfg.Region = "ap-guangzhou"
	}
	return &TencentProvider{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Send 发送短信
func (p *TencentProvider) Send(mobile, templateID string, params map[string]string) error {
	host := p.hostForMobile(mobile)
	body := map[string]any{
		"PhoneNumberSet": []string{normalizeTencentMobile(mobile)},
		"SmsSdkAppId":    p.cfg.AppID,
		"SignName":       p.cfg.SignName,
		"TemplateId":     templateID,
	}
	if templateParams := tencentTemplateParams(params); len(templateParams) > 0 {
		body["TemplateParamSet"] = templateParams
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("序列化腾讯云短信请求失败: %w", err)
	}

	timestamp := time.Now().Unix()
	authorization := p.authorization(host, payload, timestamp)
	req, err := http.NewRequest(http.MethodPost, "https://"+host, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("创建腾讯云短信请求失败: %w", err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", "SendSms")
	req.Header.Set("X-TC-Region", p.cfg.Region)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-TC-Version", "2021-01-11")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("调用腾讯云短信服务失败: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取腾讯云短信响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("腾讯云短信服务返回异常状态码 %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var result struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			SendStatusSet []struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"SendStatusSet"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return fmt.Errorf("解析腾讯云短信响应失败: %w", err)
	}
	if result.Response.Error != nil {
		return fmt.Errorf("腾讯云短信发送失败: %s", result.Response.Error.Message)
	}
	for _, item := range result.Response.SendStatusSet {
		if strings.TrimSpace(item.Code) != "Ok" {
			message := strings.TrimSpace(item.Message)
			if message == "" {
				message = item.Code
			}
			return fmt.Errorf("腾讯云短信发送失败: %s", message)
		}
	}
	return nil
}

func (p *TencentProvider) authorization(host string, payload []byte, timestamp int64) string {
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := date + "/sms/tc3_request"
	hashedPayload := tencentSHA256Hex(payload)
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		strconv.FormatInt(timestamp, 10),
		credentialScope,
		tencentSHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	secretDate := tencentHMAC([]byte("TC3"+p.cfg.SecretKey), date)
	secretService := tencentHMAC(secretDate, "sms")
	secretSigning := tencentHMAC(secretService, "tc3_request")
	signature := hex.EncodeToString(tencentHMAC(secretSigning, stringToSign))

	return fmt.Sprintf(
		"TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.cfg.AccessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
}

func (p *TencentProvider) hostForMobile(mobile string) string {
	trimmed := strings.TrimSpace(mobile)
	if strings.HasPrefix(trimmed, "+") && !strings.HasPrefix(trimmed, "+86") {
		return "sms.intl.tencentcloudapi.com"
	}
	return "sms.tencentcloudapi.com"
}

func normalizeTencentMobile(mobile string) string {
	trimmed := strings.TrimSpace(mobile)
	if trimmed == "" || strings.HasPrefix(trimmed, "+") {
		return trimmed
	}
	if isDigits(trimmed) && len(trimmed) == 11 {
		return "+86" + trimmed
	}
	return trimmed
}

func tencentTemplateParams(params map[string]string) []string {
	if len(params) == 0 {
		return nil
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	if areNumericKeys(keys) {
		sort.Slice(keys, func(i, j int) bool {
			left, _ := strconv.Atoi(keys[i])
			right, _ := strconv.Atoi(keys[j])
			return left < right
		})
	} else {
		sort.Strings(keys)
	}

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, params[key])
	}
	return values
}

func areNumericKeys(keys []string) bool {
	for _, key := range keys {
		if _, err := strconv.Atoi(key); err != nil {
			return false
		}
	}
	return len(keys) > 0
}

func isDigits(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func tencentSHA256Hex(payload []byte) string {
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

func tencentHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func init() {
	// 注册腾讯云短信服务商
	sms.RegisterProvider("tencent", NewTencentProvider)
}
