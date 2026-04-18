package middleware

import (
	engine "github.com/darkit/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

// OTel 使用官方 otelgin 中间件为请求接入 OpenTelemetry 追踪与指标。
func OTel(service string, opts ...otelgin.Option) engine.HandlerFunc {
	if service == "" {
		service = "darkit/gin"
	}
	return engine.WrapMiddleware(otelgin.Middleware(service, opts...))
}
