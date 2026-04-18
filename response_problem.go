// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"encoding/json"
	"net/http"
)

const problemJSONContentType = "application/problem+json; charset=utf-8"

// ProblemDetail 定义 RFC 9457 风格的标准错误模型。
type ProblemDetail struct {
	Type       string            `json:"type,omitempty"`
	Title      string            `json:"title,omitempty"`
	Status     int               `json:"status,omitempty"`
	Detail     string            `json:"detail,omitempty"`
	Instance   string            `json:"instance,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
	Errors     []ValidationError `json:"errors,omitempty"`
	Extensions map[string]any    `json:"-"`
}

// MarshalJSON 将扩展字段按 RFC 9457 约定平铺到顶层。
func (p ProblemDetail) MarshalJSON() ([]byte, error) {
	payload := make(map[string]any, 7+len(p.Extensions))
	if p.Type != "" {
		payload["type"] = p.Type
	}
	if p.Title != "" {
		payload["title"] = p.Title
	}
	if p.Status > 0 {
		payload["status"] = p.Status
	}
	if p.Detail != "" {
		payload["detail"] = p.Detail
	}
	if p.Instance != "" {
		payload["instance"] = p.Instance
	}
	if p.RequestID != "" {
		payload["request_id"] = p.RequestID
	}
	if len(p.Errors) > 0 {
		payload["errors"] = p.Errors
	}
	for key, value := range p.Extensions {
		if _, exists := payload[key]; exists {
			continue
		}
		payload[key] = value
	}
	return json.Marshal(payload)
}

func newProblemDetail(status int, typeURI, title, detail, instance, requestID string) ProblemDetail {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if typeURI == "" {
		typeURI = "about:blank"
	}
	if title == "" {
		title = http.StatusText(status)
	}
	return ProblemDetail{
		Type:      typeURI,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Instance:  instance,
		RequestID: requestID,
	}
}
