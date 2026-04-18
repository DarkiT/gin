# pkg/validator

`pkg/validator` 为框架的参数绑定系统注册中国本地化校验规则，并支持扩展自定义验证器。

## 模块用途

- 向 `go-playground/validator` 注册常用业务校验标签
- 内置手机号、身份证、银行卡、统一社会信用代码校验
- 允许业务方注册额外验证规则
- 遵循中国业务场景的校验需求

## 内置校验规则

### 校验函数

| 函数 | 说明 |
|------|------|
| `ValidateMobile` | 手机号校验（中国大陆 11 位手机号） |
| `ValidateIDCard` | 身份证号码校验（18 位） |
| `ValidateBankCard` | 银行卡号校验（Luhn 算法） |
| `ValidateUSCC` | 统一社会信用代码校验（18 位） |

### 对应标签

| 标签 | 说明 | 示例 |
|------|------|------|
| `mobile` | 手机号 | `binding:"required,mobile"` |
| `idcard` | 身份证 | `binding:"required,idcard"` |
| `bankcard` | 银行卡 | `binding:"required,bankcard"` |
| `uscc` | 统一社会信用代码 | `binding:"required,uscc"` |

## 关键类型与函数

### ValidatorFunc

```go
type ValidatorFunc func(value string) bool
```

### RegisterValidator

```go
func RegisterValidator(tag string, fn ValidatorFunc)
```

注册自定义验证器。注册后，该标签可以在 `binding` 标签中使用。

### EnsureValidators

```go
func EnsureValidators()
```

确保所有验证器已注册。在框架初始化时自动调用，业务代码通常不需要显式调用。

## 使用示例

### 使用内置标签

```go
package main

import (
	"net/http"

	gin "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/validator"
)

type RegisterRequest struct {
	Mobile   string `json:"mobile" binding:"required,mobile"`
	IDCard   string `json:"id_card" binding:"required,idcard"`
	BankCard string `json:"bank_card" binding:"required,bankcard"`
	Company  string `json:"company" binding:"required,uscc"`
}

func main() {
	app := gin.Default()

	app.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.BadRequest(err.Error())
			return
		}
		c.Success(gin.H{"message": "注册成功"})
	})

	app.Run(":8080")
}
```

### 注册自定义标签

```go
package main

import (
	"fmt"
	"strings"

	gin "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/validator"
)

func init() {
	// 注册自定义验证器
	validator.RegisterValidator("tenant", func(value string) bool {
		return strings.HasPrefix(value, "tenant_")
	})

	validator.RegisterValidator("uppercase", func(value string) bool {
		for _, r := range value {
			if r >= 'a' && r <= 'z' {
				return false
			}
		}
		return true
	})
}

type Request struct {
	TenantID  string `json:"tenant_id" binding:"required,tenant"`
	Code      string `json:"code" binding:"required,uppercase"`
}

func main() {
	app := gin.Default()

	app.POST("/api", func(c *gin.Context) {
		var req Request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.BadRequest(err.Error())
			return
		}
		c.Success(gin.H{"message": "success"})
	})

	app.Run(":8080")
}
```

### 组合校验

```go
type UserRequest struct {
	// 必填且需要是有效手机号
	Mobile string `json:"mobile" binding:"required,mobile"`

	// 可选，但如果填写则需要是有效身份证
	IDCard string `json:"id_card" binding:"omitempty,idcard"`

	// 可选，但如果填写则需要是有效银行卡
	BankCard string `json:"bank_card" binding:"omitempty,bankcard"`
}
```

### 自定义错误消息

配合 `binding:"required,mobile"` 使用默认错误消息。如需自定义消息，可以使用 `json` 标签配合自定义绑定逻辑，或使用第三方验证库的高级特性。

## 校验规则详解

### 手机号 (mobile)

校验规则：
- 必须为 11 位数字
- 必须以 13、14、15、16、17、18、19 开头

```go
// 有效手机号示例
// 13800138000
// 15912345678
// 18612345678
```

### 身份证 (idcard)

校验规则：
- 18 位身份证号
- 前 17 位必须为数字
- 最后一位可以是数字或 X/x

```go
// 有效身份证示例
// 110101199001011234
// 11010119900101123X
```

### 银行卡 (bankcard)

校验规则：
- 使用 Luhn 算法校验
- 卡号长度 13-19 位

```go
// 有效银行卡号示例
// 6222021234567890123
```

### 统一社会信用代码 (uscc)

校验规则：
- 18 位
- 统一社会信用代码格式校验

```go
// 有效统一社会信用代码示例
// 91110000MA1234567X
```

## 与 Engine 的集成

该模块直接操作框架绑定器 `binding.Validator`：

```go
// 包初始化时自动注册内置规则
// 确保自定义规则就绪
validator.EnsureValidators()
```

因此它主要服务于 `ShouldBind` / `ShouldBindJSON` / `ShouldBindQuery` 等绑定校验链路，而非单独挂载到 `Engine` 选项中。

### 典型集成方式

```go
package main

import (
	gin "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/validator"
)

func main() {
	// 自定义验证器注册（通常在 init() 中）
	validator.RegisterValidator("custom_tag", func(value string) bool {
		// 自定义校验逻辑
		return true
	})

	// 创建应用
	app := gin.Default()

	// 业务代码使用验证器
	app.POST("/submit", func(c *gin.Context) {
		// binding 标签会自动使用注册的验证器
	})
}
```

## 注意事项

1. **注册时机**：自定义验证器应在应用启动早期（通常在 `init()` 或 main 函数开头）注册
2. **标签冲突**：避免与内置标签同名
3. **线程安全**：验证器注册后可在多 goroutine 中安全使用
4. **错误处理**：绑定失败时返回 `validator.ValidationErrors`，可使用 `Field()` 获取具体字段错误
