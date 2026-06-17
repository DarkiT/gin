package manager

import "sync/atomic"

// StpInterface is the permission / disable data source | 权限数据源接口
type StpInterface interface {
	GetPermissionList(loginID, loginType string) []string
	GetRoleList(loginID, loginType string) []string
	IsDisabled(loginID, service string) (level int, ttl int64)
}

// DefaultStpInterface is a no-op implementation | 默认实现
type DefaultStpInterface struct{}

// GetPermissionList returns nil to defer to session cache | 默认不从外部加载权限
func (d *DefaultStpInterface) GetPermissionList(loginID, loginType string) []string {
	return nil
}

// GetRoleList returns nil | 默认不从外部加载角色
func (d *DefaultStpInterface) GetRoleList(loginID, loginType string) []string {
	return nil
}

// IsDisabled reports not disabled | 默认未封禁
func (d *DefaultStpInterface) IsDisabled(loginID, service string) (level int, ttl int64) {
	return NotDisableLevel, NotValueExpire
}

const (
	// NotDisableLevel sentinel: not disabled | 未封禁
	NotDisableLevel = -2
	// MinDisableLevel minimum tiered disable level | 最小封禁等级
	MinDisableLevel = 1
	// NotValueExpire sentinel for missing TTL | 无 TTL / 未设置
	NotValueExpire = -2
)

// globalStpInterface 以 atomic.Pointer 存储进程级 StpInterface，保证运行期热替换时的并发读安全。
// globalStpInterface holds the process-wide StpInterface via atomic.Pointer for race-free hot-swap.
var globalStpInterface atomic.Pointer[StpInterface]

func init() {
	// d 必须声明为 StpInterface 接口类型，&d 才是 atomic.Pointer 期望的 *StpInterface。
	d := StpInterface(&DefaultStpInterface{})
	globalStpInterface.Store(&d)
}

// SetGlobalStpInterface replaces the process-wide StpInterface | 注入全局 StpInterface
func SetGlobalStpInterface(impl StpInterface) {
	if impl == nil {
		impl = &DefaultStpInterface{}
	}
	globalStpInterface.Store(&impl)
}

// GetGlobalStpInterface returns the current StpInterface | 获取当前 StpInterface（并发安全）
func GetGlobalStpInterface() StpInterface {
	if p := globalStpInterface.Load(); p != nil {
		return *p
	}
	return &DefaultStpInterface{}
}
