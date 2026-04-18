package middleware

import (
	"net/http"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/circuitbreaker"
)

// CircuitBreakerConfig 熔断器中间件配置
type CircuitBreakerConfig struct {
	FailureThreshold int           // 失败阈值
	SuccessThreshold int           // 成功阈值（半开→关闭）
	Timeout          time.Duration // 开启状态超时时间
}

// DefaultCircuitBreakerConfig 默认熔断器配置
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
	}
}

// CircuitBreaker 返回熔断器中间件
func CircuitBreaker(config ...CircuitBreakerConfig) gin.HandlerFunc {
	cfg := DefaultCircuitBreakerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	cb := circuitbreaker.New(
		cfg.FailureThreshold,
		cfg.SuccessThreshold,
		cfg.Timeout,
	)

	return func(c *gin.Context) {
		if !cb.Allow() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "服务暂时不可用，请稍后重试",
			})
			c.Abort()
			return
		}

		c.Next()

		// 根据状态码判断成功或失败
		if c.Writer.Status() >= 500 {
			cb.Record(false)
		} else {
			cb.Record(true)
		}
	}
}
