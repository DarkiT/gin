package providers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/darkit/gin/pkg/sms"
)

// AliyunProvider 阿里云短信服务商
type AliyunProvider struct {
	cfg      sms.SMSConfig
	client   *http.Client
	endpoint string
}

// NewAliyunProvider 创建阿里云短信服务商
func NewAliyunProvider(cfg sms.SMSConfig) (sms.SMSProvider, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		cfg.Region = "cn-hangzhou"
	}
	return &AliyunProvider{
		cfg:      cfg,
		client:   &http.Client{Timeout: 10 * time.Second},
		endpoint: "https://dysmsapi.aliyuncs.com/",
	}, nil
}

// Send 发送短信
func (p *AliyunProvider) Send(mobile, templateID string, params map[string]string) error {
	query := map[string]string{
		"AccessKeyId":      p.cfg.AccessKey,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     mobile,
		"RegionId":         p.cfg.Region,
		"SignName":         p.cfg.SignName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   aliyunNonce(),
		"SignatureVersion": "1.0",
		"TemplateCode":     templateID,
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
	}
	if len(params) > 0 {
		payload, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("序列化阿里云短信模板参数失败: %w", err)
		}
		query["TemplateParam"] = string(payload)
	}

	signature, err := p.sign(query)
	if err != nil {
		return err
	}
	query["Signature"] = signature

	req, err := http.NewRequest(http.MethodGet, p.endpoint+"?"+aliyunBuildQuery(query), nil)
	if err != nil {
		return fmt.Errorf("创建阿里云短信请求失败: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("调用阿里云短信服务失败: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取阿里云短信响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("阿里云短信服务返回异常状态码 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析阿里云短信响应失败: %w", err)
	}
	if result.Code != "OK" {
		if strings.TrimSpace(result.Message) == "" {
			result.Message = result.Code
		}
		return fmt.Errorf("阿里云短信发送失败: %s", result.Message)
	}
	return nil
}

func (p *AliyunProvider) sign(query map[string]string) (string, error) {
	stringToSign := "GET&%2F&" + aliyunPercentEncode(aliyunCanonicalQuery(query))
	mac := hmac.New(sha1.New, []byte(p.cfg.SecretKey+"&"))
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return "", fmt.Errorf("生成阿里云短信签名失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func aliyunCanonicalQuery(query map[string]string) string {
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliyunPercentEncode(key)+"="+aliyunPercentEncode(query[key]))
	}
	return strings.Join(parts, "&")
}

func aliyunBuildQuery(query map[string]string) string {
	return aliyunCanonicalQuery(query)
}

func aliyunPercentEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

func aliyunNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func init() {
	// 注册阿里云短信服务商
	sms.RegisterProvider("aliyun", NewAliyunProvider)
}
