# pkg/mail

`pkg/mail` 提供基于 SMTP 的邮件发送能力，支持模板、附件、批量发送与连接池。

## 模块用途

- 封装 SMTP 邮件发送流程。
- 提供全局默认发送器，便于与 `Engine`、顶层辅助函数集成。
- 支持 HTML 模板邮件、附件、批量并发发送、SMTP 连接池复用。

## 关键类型与函数

### 核心类型

- `type MailConfig`
  - `Host` / `Port` / `Username` / `Password`
  - `From` / `FromName`
  - `TLS`
- `type Mailer`
  - `NewMailer(cfg)`
  - `SendMail`：纯文本邮件
  - `SendMailHTML`：HTML 邮件
  - `SendTemplate`：渲染模板后发送 HTML 邮件
  - `SendBatch`：批量发送纯文本邮件
  - `ConfigurePool`：启用 SMTP 连接池
- `type SMTPPool`
  - `NewSMTPPool`
  - `Get` / `Put` / `Close`
- `type BatchResult`
  - `Total` / `Succeeded` / `Failed` / `Errors`

### 全局函数

- `InitDefaultMailer(cfg)`：初始化全局默认发送器
- `DefaultMailer()`：获取全局发送器
- `RenderTemplate(templateName, data)`：渲染 `mail/templates` 下模板

### 常用选项

- `WithMailCC`
- `WithMailBCC`
- `WithMailReplyTo`
- `WithMailAttachment`
- `WithMailAttachmentData`
- `WithContinueOnError`
- `WithMaxConcurrent`
- `WithPoolSize`
- `WithPoolMaxIdle`
- `WithPoolTimeout`

## 配置项

### SMTP 基础配置

- `Host`：SMTP 主机，必填
- `Port`：SMTP 端口，必填
- `Username` / `Password`：认证凭证
- `From`：发件人邮箱，必填
- `FromName`：发件人显示名称
- `TLS`：是否启用 TLS，启用后最小版本为 TLS 1.2

### 连接池配置

- `WithPoolSize(n)`：池大小，默认 `5`
- `WithPoolMaxIdle(d)`：空闲连接最大存活时间，默认 `5m`
- `WithPoolTimeout(d)`：取连接超时，默认 `10s`

### 批量发送配置

- `WithMaxConcurrent(n)`：并发 worker 数，默认 `1`
- `WithContinueOnError(bool)`：单个失败后是否继续，默认 `true`

### 模板配置

- 模板目录固定为 `mail/templates`
- `RenderTemplate` 会校验模板名与路径，避免非法路径访问

## 使用示例

### 创建并发送邮件

```go
cfg := mail.MailConfig{
    Host:     "smtp.example.com",
    Port:     587,
    Username: "noreply@example.com",
    Password: "secret",
    From:     "noreply@example.com",
    FromName: "Demo App",
    TLS:      true,
}

mailer, err := mail.NewMailer(cfg)
if err != nil {
    panic(err)
}

err = mailer.SendMail(
    "user@example.com",
    "欢迎注册",
    "欢迎使用 Demo App",
    mail.WithMailCC("audit@example.com"),
)
```

### 发送模板邮件

```go
err := mailer.SendTemplate(
    "user@example.com",
    "重置密码",
    "reset_password.html",
    map[string]any{"Name": "Alice", "Code": "123456"},
)
```

### 启用连接池与批量发送

```go
mailer.ConfigurePool(
    mail.WithPoolSize(10),
    mail.WithPoolMaxIdle(10*time.Minute),
)

result, err := mailer.SendBatch(
    []string{"a@example.com", "b@example.com"},
    "系统通知",
    "今晚维护",
    mail.WithMaxConcurrent(3),
    mail.WithContinueOnError(true),
)
_ = result
_ = err
```

## 与 Engine 的集成

- `gin.WithMail(cfg)`：初始化 `Engine` 时注入邮件配置，并自动调用 `mail.InitDefaultMailer`。
- 顶层辅助函数会直接复用默认发送器：
  - `gin.SendMail`
  - `gin.SendMailHTML`
  - `gin.SendTemplate`
  - `gin.SendBatch`

```go
e := gin.New(
    gin.WithMail(mail.MailConfig{
        Host: "smtp.example.com",
        Port: 587,
        From: "noreply@example.com",
    }),
)

_ = gin.SendMail("user@example.com", "标题", "内容")
```
