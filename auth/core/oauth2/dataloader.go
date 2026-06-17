package oauth2

// DataLoader loads ClientModel by client_id | 客户端模型加载器
type DataLoader interface {
	LoadClient(clientID string) (*ClientModel, error)
}

// DataGenerator optional token/code generator hook | 生成器钩子（可扩展）
type DataGenerator any

// UserCredentialChecker validates username/password for password grant | 密码模式凭证校验
type UserCredentialChecker interface {
	CheckCredential(username, password string) (loginID string, ok bool)
}
