# pkg/sms

`pkg/sms` 提供短信服务商抽象、验证码生成与校验能力，并内置阿里云、腾讯云提供者。

## 模块用途

- 统一短信发送接口 `SMSProvider`。
- 支持独立创建短信服务实例，并可由 `Engine` 在运行阶段托管。
- 提供验证码生成、内存存储、失败计数、锁定与自动过期清理。

## 关键类型与函数

### 核心类型

- `type SMSConfig`
  - `Provider`：`aliyun` / `tencent`
  - `AccessKey` / `SecretKey`
  - `SignName`
  - `Region`
  - `AppID`：腾讯云必填
- `type Service`
  - `NewService(cfg)`：创建独立短信服务（推荐主路径）
  - `Send(...)`
  - `SendCode(...)`
  - `VerifyCode(...)`
  - `IsLocked(...)`
  - `Unlock(...)`
- `type SMSProvider interface`
  - `Send(mobile, templateID string, params map[string]string) error`

### 服务商管理

- `RegisterProvider(name, factory)`
- `GetConfig()`

兼容旧代码的包级全局函数：

- `InitDefaultProvider(cfg)`
- `DefaultProvider()`
- `SendSMS(mobile, templateID, params)`

### 短信发送与验证码

- `Service.Send(mobile, templateID, params)`：通过当前服务实例直接发送短信
- `SendCode(mobile, opts...)`：生成验证码，可选自动短信发送
- `VerifyCode(mobile, code)`：校验后即删除，一次性使用
- `IsLocked(mobile)`：检查手机号是否被锁定
- `Unlock(mobile)`：手动解锁
- `GetFailures(mobile)`：获取失败次数
- `GetCode(mobile)`：测试辅助
- `DeleteCode(mobile)`：删除验证码

### 验证码选项

- `WithCodeLength`
- `WithCodeExpiry`
- `WithCodeType`
- `WithTemplateID`
- `WithTemplateParams`
- `WithMaxFailures`
- `WithLockDuration`

## 配置项

### 统一配置

- `Provider`：服务商名称，必填
- `AccessKey` / `SecretKey`：服务商凭证，必填
- `SignName`：短信签名，必填
- `Region`：区域，可按服务商配置

### 阿里云（Aliyun）

- 默认区域：`cn-hangzhou`
- 使用 `TemplateCode` 与 JSON `TemplateParam`
- 通过签名串调用 `https://dysmsapi.aliyuncs.com/`

### 腾讯云（Tencent）

- `AppID` 必填
- 默认区域：`ap-guangzhou`
- 国内号码走 `sms.tencentcloudapi.com`
- 非 `+86` 国际号码走 `sms.intl.tencentcloudapi.com`

### 验证码默认值

- 长度：`6`
- 类型：`numeric`
- 过期时间：`5m`
- 最大失败次数：`5`
- 锁定时长：`15m`

## 使用示例

### 创建独立短信服务

```go
import (
    "github.com/darkit/gin/pkg/sms"
    _ "github.com/darkit/gin/pkg/sms/providers"
)

cfg := sms.SMSConfig{
    Provider:  "aliyun",
    AccessKey: "ak",
    SecretKey: "sk",
    SignName:  "Demo",
    Region:    "cn-hangzhou",
}

service, err := sms.NewService(cfg)
if err != nil {
    panic(err)
}
```

### 发送普通短信

```go
err := service.Send("13800138000", "SMS_123456", map[string]string{
    "name": "Alice",
})
```

### 发送验证码短信

```go
code, err := service.SendCode(
    "13800138000",
    sms.WithTemplateID("SMS_LOGIN_CODE"),
    sms.WithTemplateParams(map[string]string{"product": "Demo"}),
    sms.WithCodeLength(6),
    sms.WithCodeExpiry(5*time.Minute),
)
_ = code
_ = err
```

### 校验验证码与锁定控制

```go
ok := service.VerifyCode("13800138000", "123456")
if !ok && service.IsLocked("13800138000") {
    _ = service.Unlock("13800138000")
}
```

## 与 Engine 的集成

- `gin.WithSMS(cfg)`：在构造阶段保存并校验短信配置。
- 运行阶段 `Engine` 会自动初始化 engine-scoped `SMS` service。
- 请求内优先通过 `c.SMS()` 获取当前引擎绑定的短信服务。
- 应用级代码可通过 `app.SMS()` 获取当前引擎绑定的短信服务。
- 若使用阿里云或腾讯云，请记得 side-effect import：
  - `_ "github.com/darkit/gin/pkg/sms/providers"`
- `InitDefaultProvider` / `SendSMS` 等全局函数仍可用于脱离 `Engine` 的独立脚本或兼容旧代码，但不再是框架集成主路径。

```go
e := gin.New(
    gin.WithSMS(sms.SMSConfig{
        Provider:  "tencent",
        AccessKey: "ak",
        SecretKey: "sk",
        SignName:  "Demo",
        AppID:     "1400000000",
    }),
)
```

## 注意事项

- 验证码存储当前为内存实现，服务重启后会丢失。
- `VerifyCode` 成功后会立即删除验证码。
- 连续失败会触发锁定；生产环境建议再叠加发送频率限制。
