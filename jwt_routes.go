package gin

import (
	"fmt"
	"strings"
	"time"

	"github.com/darkit/gin/types"
)

// JWTTokens 登录/刷新返回的令牌信息
type JWTTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// JWTAuthRoutesConfig 配置自动化认证路由
type JWTAuthRoutesConfig struct {
	BasePath        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Authenticate    func(*Context) (*types.AuthInfo, error)
	ResponseBuilder func(*Context, *types.AuthInfo, JWTTokens) interface{}
	PostLogin       func(*Context, *types.AuthInfo, JWTTokens)
	PostLogout      func(*Context, *types.AuthInfo)
}

// JWTAuthRoutes 注册标准的登录/刷新/注销路由
func (r *Router) JWTAuthRoutes(cfg JWTAuthRoutesConfig) {
	if cfg.Authenticate == nil {
		panic("JWTAuthRoutes 需要提供 Authenticate 函数")
	}
	if r.jwtAdapter == nil {
		panic("JWTAuthRoutes 依赖 gin.WithJWT 或安全配置，请先启用 JWT")
	}

	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL < 0 {
		cfg.RefreshTokenTTL = 0
	}
	base := strings.TrimRight(cfg.BasePath, "/")
	if base == "" {
		base = "/auth"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}

	loginPath := base + "/login"
	refreshPath := base + "/refresh"
	logoutPath := base + "/logout"

	r.POST(loginPath, func(c *Context) {
		info, err := cfg.Authenticate(c)
		if err != nil {
			c.Unauthorized(err.Error())
			return
		}
		if info == nil {
			c.Unauthorized("认证失败")
			return
		}

		tokens, err := r.issueTokens(c, info, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
		if err != nil {
			c.ServerError(fmt.Sprintf("生成令牌失败: %v", err))
			return
		}

		var resp interface{}
		if cfg.ResponseBuilder != nil {
			resp = cfg.ResponseBuilder(c, info, tokens)
		} else {
			resp = H{
				"token_type":    "Bearer",
				"access_token":  tokens.AccessToken,
				"refresh_token": tokens.RefreshToken,
				"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
				"user":          info.Claims(),
			}
		}
		c.Success(resp)
		if cfg.PostLogin != nil {
			cfg.PostLogin(c, info, tokens)
		}
	})

	r.POST(refreshPath, func(c *Context) {
		adapter := c.getJWTAdapter()
		if adapter == nil {
			c.ServerError("JWT适配器未初始化")
			return
		}

		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if !c.BindJSON(&req) {
			return
		}

		payload, err := adapter.ValidateToken(req.RefreshToken)
		if err != nil {
			c.Unauthorized("刷新令牌无效")
			return
		}

		tokenType, _ := payload.GetClaim(ClaimType)
		if tokenTypeStr, _ := tokenType.(string); tokenTypeStr != TokenTypeRefresh {
			c.Unauthorized("令牌类型错误")
			return
		}

		info := authInfoFromPayload(payload)
		if info == nil {
			c.Unauthorized("刷新令牌无效")
			return
		}

		tokens, err := r.issueTokens(c, info, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
		if err != nil {
			c.ServerError(fmt.Sprintf("刷新令牌失败: %v", err))
			return
		}
		c.Success(H{
			"token_type":    "Bearer",
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
		})
	})

	r.POST(logoutPath, func(c *Context) {
		info, _ := c.AuthInfo()
		c.ClearJWT()
		if cfg.PostLogout != nil {
			cfg.PostLogout(c, info)
		}
		c.Success(H{"message": "注销成功"})
	})
}

func (r *Router) issueTokens(c *Context, info *types.AuthInfo, accessTTL, refreshTTL time.Duration) (JWTTokens, error) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return JWTTokens{}, fmt.Errorf("JWT适配器未初始化")
	}
	claims := info.Claims()
	accessPayload := make(JWTPayload)
	for k, v := range claims {
		accessPayload[k] = v
	}
	accessPayload[ClaimType] = TokenTypeAccess
	accessPayload[ClaimExp] = time.Now().Add(accessTTL).Unix()
	token, err := adapter.GenerateToken(accessPayload)
	if err != nil {
		return JWTTokens{}, err
	}
	c.SetJWT(token, int(accessTTL.Seconds()))
	result := JWTTokens{AccessToken: token}

	if refreshTTL > 0 {
		refreshClaims := make(JWTPayload)
		for k, v := range claims {
			refreshClaims[k] = v
		}
		refreshClaims[ClaimType] = TokenTypeRefresh
		refreshClaims[ClaimExp] = time.Now().Add(refreshTTL).Unix()
		refreshToken, err := adapter.GenerateToken(refreshClaims)
		if err != nil {
			return JWTTokens{}, err
		}
		result.RefreshToken = refreshToken
	}

	return result, nil
}

func authInfoFromPayload(payload JWTPayload) *types.AuthInfo {
	if payload == nil {
		return nil
	}
	info := &types.AuthInfo{Extra: types.H{}}
	if val, ok := payload["user_id"].(string); ok {
		info.UserID = val
	}
	if val, ok := payload["username"].(string); ok {
		info.Username = val
	}
	if val, ok := payload["email"].(string); ok {
		info.Email = val
	}
	if roles, ok := payload["roles"].([]string); ok {
		info.Roles = append(info.Roles, roles...)
	} else if rolesAny, ok := payload["roles"].([]interface{}); ok {
		for _, role := range rolesAny {
			if str, ok := role.(string); ok {
				info.Roles = append(info.Roles, str)
			}
		}
	}
	for k, v := range payload {
		info.Extra[k] = v
	}
	return info
}
