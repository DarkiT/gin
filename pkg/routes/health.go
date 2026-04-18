package routes

import engine "github.com/darkit/gin"

// HealthCheck 注册健康检查路由。
// 如果路由器为空则直接返回。
func HealthCheck(r *engine.Router, path ...string) {
	if r == nil {
		return
	}
	r.HealthCheck(path...)
}
