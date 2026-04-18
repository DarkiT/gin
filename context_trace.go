// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import "go.opentelemetry.io/otel/trace"

// TraceID 返回当前请求关联的 OpenTelemetry Trace ID。
func (c *Context) TraceID() string {
	spanContext := trace.SpanContextFromContext(c.baseContext())
	if !spanContext.HasTraceID() {
		return ""
	}
	return spanContext.TraceID().String()
}

// SpanID 返回当前请求关联的 OpenTelemetry Span ID。
func (c *Context) SpanID() string {
	spanContext := trace.SpanContextFromContext(c.baseContext())
	if !spanContext.HasSpanID() {
		return ""
	}
	return spanContext.SpanID().String()
}
