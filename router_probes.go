// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"net/http"
	"time"
)

// ProbeCheck 定义健康探针检查函数。
type ProbeCheck func(*Context) error

// Probe 定义单个探针检查项。
type Probe struct {
	Name  string
	Check ProbeCheck
}

// ProbeResult 定义单个探针检查结果。
type ProbeResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ProbeResponse 定义探针接口返回结构。
type ProbeResponse struct {
	Status    string        `json:"status"`
	Checks    []ProbeResult `json:"checks,omitempty"`
	RequestID string        `json:"request_id,omitempty"`
	Timestamp int64         `json:"timestamp"`
}

// NamedProbe 创建一个命名探针检查项。
func NamedProbe(name string, check ProbeCheck) Probe {
	return Probe{
		Name:  name,
		Check: check,
	}
}

// Liveness 注册存活探针路由，默认路径为 /livez。
func (r *Router) Liveness(path ...string) {
	probePath := "/livez"
	if len(path) > 0 && path[0] != "" {
		probePath = path[0]
	}

	r.GET(probePath, func(c *Context) {
		c.JSON(http.StatusOK, ProbeResponse{
			Status:    "alive",
			RequestID: c.getRequestID(),
			Timestamp: time.Now().Unix(),
		})
	})
}

// Readiness 注册就绪探针路由，默认路径为 /readyz。
func (r *Router) Readiness(checks ...Probe) {
	r.ReadinessAt("/readyz", checks...)
}

// ReadinessAt 在指定路径注册就绪探针路由。
func (r *Router) ReadinessAt(path string, checks ...Probe) {
	r.registerProbe(path, "ready", "not_ready", checks...)
}

// Startup 注册启动探针路由，默认路径为 /startupz。
func (r *Router) Startup(checks ...Probe) {
	r.StartupAt("/startupz", checks...)
}

// StartupAt 在指定路径注册启动探针路由。
func (r *Router) StartupAt(path string, checks ...Probe) {
	r.registerProbe(path, "started", "starting", checks...)
}

func (r *Router) registerProbe(path, successStatus, failureStatus string, checks ...Probe) {
	if path == "" {
		return
	}

	r.GET(path, func(c *Context) {
		results := make([]ProbeResult, 0, len(checks))
		allHealthy := true

		for _, probe := range checks {
			if probe.Check == nil {
				continue
			}

			result := ProbeResult{
				Name:   probeName(probe),
				Status: "ok",
			}
			if err := probe.Check(c); err != nil {
				result.Status = "error"
				result.Message = err.Error()
				allHealthy = false
			}
			results = append(results, result)
		}

		status := successStatus
		code := http.StatusOK
		if !allHealthy {
			status = failureStatus
			code = http.StatusServiceUnavailable
		}

		c.JSON(code, ProbeResponse{
			Status:    status,
			Checks:    results,
			RequestID: c.getRequestID(),
			Timestamp: time.Now().Unix(),
		})
	})
}

func probeName(probe Probe) string {
	if probe.Name != "" {
		return probe.Name
	}
	return "probe"
}
