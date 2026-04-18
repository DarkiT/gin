package routes

import engine "github.com/darkit/gin"

// Probe 是根包探针检查定义的别名。
type Probe = engine.Probe

// ProbeCheck 是根包探针检查函数的别名。
type ProbeCheck = engine.ProbeCheck

// NamedProbe 创建一个命名探针检查项。
var NamedProbe = engine.NamedProbe

// Liveness 注册存活探针。
func Liveness(r *engine.Router, path ...string) {
	if r == nil {
		return
	}
	r.Liveness(path...)
}

// Readiness 注册就绪探针。
func Readiness(r *engine.Router, checks ...Probe) {
	if r == nil {
		return
	}
	r.Readiness(checks...)
}

// ReadinessAt 在指定路径注册就绪探针。
func ReadinessAt(r *engine.Router, path string, checks ...Probe) {
	if r == nil {
		return
	}
	r.ReadinessAt(path, checks...)
}

// Startup 注册启动探针。
func Startup(r *engine.Router, checks ...Probe) {
	if r == nil {
		return
	}
	r.Startup(checks...)
}

// StartupAt 在指定路径注册启动探针。
func StartupAt(r *engine.Router, path string, checks ...Probe) {
	if r == nil {
		return
	}
	r.StartupAt(path, checks...)
}
