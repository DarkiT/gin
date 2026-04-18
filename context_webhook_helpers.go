// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"bytes"
	"io"
	"strings"
)

const rawBodyCacheKey = "__darkit_raw_body"

var (
	defaultWebhookEventIDHeaders = []string{
		"X-Webhook-Id",
		"Webhook-Id",
		"X-Event-ID",
		"Event-Id",
		"X-GitHub-Delivery",
		"X-Shopify-Webhook-Id",
		"Svix-Id",
	}
	defaultWebhookSignatureHeaders = []string{
		"X-Signature",
		"X-Hub-Signature-256",
		"X-Hub-Signature",
		"Stripe-Signature",
		"X-Shopify-Hmac-Sha256",
		"Svix-Signature",
	}
	defaultWebhookTimestampHeaders = []string{
		"X-Timestamp",
		"X-Signature-Timestamp",
		"Webhook-Timestamp",
		"Svix-Timestamp",
	}
)

// RawBody 读取并缓存原始请求体，便于验签或重复绑定。
func (c *Context) RawBody() ([]byte, error) {
	if c == nil || c.Request == nil {
		return nil, nil
	}

	if cached, exists := c.Get(rawBodyCacheKey); exists {
		if body, ok := cached.([]byte); ok {
			return append([]byte(nil), body...), nil
		}
	}

	if c.Request.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Set(rawBodyCacheKey, append([]byte(nil), body...))
	return append([]byte(nil), body...), nil
}

// MustRawBody 读取原始请求体，失败时直接 panic。
func (c *Context) MustRawBody() []byte {
	body, err := c.RawBody()
	if err != nil {
		panic(err)
	}
	return body
}

// RawBodyString 以字符串形式返回原始请求体。
func (c *Context) RawBodyString() (string, error) {
	body, err := c.RawBody()
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// WebhookEventID 按常见头优先级提取 webhook 事件 ID。
func (c *Context) WebhookEventID(headers ...string) string {
	return c.headerByPriority(defaultWebhookEventIDHeaders, headers...)
}

// WebhookSignature 按常见头优先级提取 webhook 签名值。
func (c *Context) WebhookSignature(headers ...string) string {
	return c.headerByPriority(defaultWebhookSignatureHeaders, headers...)
}

// WebhookTimestamp 按常见头优先级提取 webhook 时间戳。
func (c *Context) WebhookTimestamp(headers ...string) string {
	return c.headerByPriority(defaultWebhookTimestampHeaders, headers...)
}

func (c *Context) headerByPriority(defaults []string, custom ...string) string {
	headerNames := append([]string(nil), custom...)
	headerNames = append(headerNames, defaults...)
	seen := make(map[string]struct{}, len(headerNames))
	for _, name := range headerNames {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if value := c.GetHeader(trimmed); value != "" {
			return value
		}
	}
	return ""
}
