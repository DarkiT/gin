# pkg/mask

`pkg/mask` 提供基于结构体标签的通用脱敏能力，适用于响应输出前的数据清洗。

## 模块用途

- 根据字段 `mask` tag 自动脱敏字符串字段。
- 递归处理结构体、指针、切片、数组、map。
- 支持内置规则、自定义规则与自定义脱敏字符。

## 关键类型与函数

- `type MaskFunc func(value string) string`
- `type MaskOption func(*maskOptions)`
- `RegisterMaskFunc(tag string, fn MaskFunc)`
- `MaskValue(value any, opts ...MaskOption) any`

### 内置规则

- `MaskMobile`
- `MaskEmail`
- `MaskIDCard`
- `MaskBankCard`
- `MaskName`
- `MaskAddress`

对应标签：`mobile`、`email`、`idcard`、`bankcard`、`name`、`address`

## 配置项

- `WithMaskChar(char rune)`：修改默认脱敏字符，默认 `*`
- `WithMaskRules(rules map[string]MaskFunc)`：为本次调用叠加临时规则

## 使用示例

### 基于标签脱敏

```go
type User struct {
    Name   string `json:"name" mask:"name"`
    Mobile string `json:"mobile" mask:"mobile"`
    Email  string `json:"email" mask:"email"`
}

masked := mask.MaskValue(User{
    Name:   "张三",
    Mobile: "13800138000",
    Email:  "user@example.com",
})
```

### 自定义规则与字符

```go
mask.RegisterMaskFunc("secret", func(value string) string {
    return "[REDACTED]"
})

masked := mask.MaskValue(data, mask.WithMaskChar('#'))
```

## 与 Engine 的集成

- `Context` 提供了直接响应接口：
  - `c.OKMasked(data, opts...)`
  - `c.PaginatedMasked(data, page, perPage, total, opts...)`
- 也可以在业务中先调用 `mask.MaskValue`，再自行返回 JSON。

```go
r.GET("/profile", func(c *gin.Context) {
    c.OKMasked(user)
})
```
