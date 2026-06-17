package oauth2

// ClientModel extended OAuth2 client metadata | OAuth2 客户端模型（扩展字段）
type ClientModel struct {
	ClientID          string
	ClientSecret      string
	AllowRedirectURIs []string
	ContractScopes    []string
	GrantTypes        []string
}
