package middleware

import (
	"net"
	"strings"

	"github.com/darkit/gin"
)

const realIPKey = "real_ip"

// RealIP 提取真实客户端 IP，并保存到上下文（key 见 GetRealIP）。
//
// ⚠️ 安全注意：底层 c.GetIP()/c.ClientIP() 遵循 Gin 的 TrustedProxies + RemoteIPHeaders 配置。
// Gin 默认 trustedProxies 为 ["0.0.0.0/0","::/0"]（全通配）并 ForwardedByClientIP=true，
// 这意味着默认会解析客户端可控的 X-Forwarded-For / X-Real-IP。攻击者只需每个请求换一个伪造 IP，
// 即可绕过所有以 IP 为维度的限流/审计。
//
// 生产环境部署在反代/负载均衡之后时，**必须**显式调用 engine.SetTrustedProxies(真实反代 CIDR)
// 收紧可信代理，否则请改用 RealIPStrict（强制 TCP 连接真实源，不信任任何代理头）。
func RealIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(realIPKey, c.GetIP())
		c.Next()
	}
}

// RealIPStrict 提取 TCP 连接的真实源地址（c.Request.RemoteAddr），不信任任何代理头。
//
// 适用于：① 直连部署（不经过反代）；② 反代已在外层处理 IP 且不希望本层再解析。
// 由于直接取连接源地址，可彻底避免伪造 X-Forwarded-For 绕过限流/审计。
func RealIPStrict() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(realIPKey, remoteAddrHost(c.Request.RemoteAddr))
		c.Next()
	}
}

// remoteAddrHost 从 addr（host:port 形式）中剥离端口，返回纯 host。
func remoteAddrHost(addr string) string {
	// 优先用 net.SplitHostPort 处理标准 host:port（含 IPv6 的 [::1]:port）。
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// 兜底：SplitHostPort 失败时，含多个冒号视为裸 IPv6（无端口），原样返回不截断。
	if strings.Count(addr, ":") > 1 {
		return addr
	}
	// 单冒号：去尾部端口片段。
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// GetRealIP 获取 RealIP / RealIPStrict 中间件保存的 IP。
func GetRealIP(c *gin.Context) string {
	if ip, exists := c.Get(realIPKey); exists {
		if str, ok := ip.(string); ok {
			return str
		}
	}
	return ""
}
