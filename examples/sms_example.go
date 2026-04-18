package main

import (
	"fmt"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/sms"
	_ "github.com/darkit/gin/pkg/sms/providers" // 导入 providers 以注册服务商
)

func main() {
	// 示例1：配置短信服务（使用阿里云）
	app := gin.New(
		gin.WithSMS(sms.SMSConfig{
			Provider:  "aliyun",
			AccessKey: "your-access-key",
			SecretKey: "your-secret-key",
			SignName:  "您的短信签名",
			Region:    "cn-hangzhou",
		}),
	)

	// 示例2：发送验证码（不发送短信，仅生成和存储）
	app.POST("/api/send-code-simple", func(c *gin.Context) {
		mobile := c.GetString("mobile")

		// 发送验证码（仅生成和存储，不实际发送短信）
		code, err := sms.SendCode(mobile)
		if err != nil {
			c.ErrorResponse(400, err.Error())
			return
		}

		// 在生产环境中不要返回验证码，这里仅作演示
		c.Success(gin.H{
			"message": "验证码已生成",
			"code":    code, // 仅用于演示
		})
	})

	// 示例3：发送验证码（通过短信发送）
	app.POST("/api/send-code", func(c *gin.Context) {
		mobile := c.GetString("mobile")

		// 发送验证码并通过短信发送
		code, err := sms.SendCode(mobile,
			sms.WithTemplateID("SMS_123456789"), // 短信模板 ID
			sms.WithCodeLength(6),               // 验证码长度
			sms.WithCodeExpiry(5*time.Minute),   // 过期时间
			sms.WithTemplateParams(map[string]string{
				"product": "测试应用", // 额外的模板参数
			}),
		)
		if err != nil {
			c.ErrorResponse(400, err.Error())
			return
		}

		c.Success(gin.H{
			"message": "验证码已发送",
			"code":    code, // 仅用于演示，生产环境不要返回
		})
	})

	// 示例4：验证验证码
	app.POST("/api/verify-code", func(c *gin.Context) {
		mobile := c.GetString("mobile")
		code := c.GetString("code")

		// 验证验证码
		if !sms.VerifyCode(mobile, code) {
			c.ErrorResponse(400, "验证码错误或已过期")
			return
		}

		c.Success(gin.H{
			"message": "验证成功",
		})
	})

	// 示例5：自定义验证码类型
	app.POST("/api/send-alphanumeric-code", func(c *gin.Context) {
		mobile := c.GetString("mobile")

		// 发送字母数字混合验证码
		code, err := sms.SendCode(mobile,
			sms.WithCodeType(sms.CodeTypeAlphanumeric),
			sms.WithCodeLength(8),
			sms.WithCodeExpiry(10*time.Minute),
		)
		if err != nil {
			c.ErrorResponse(400, err.Error())
			return
		}

		c.Success(gin.H{
			"message": "验证码已生成",
			"code":    code, // 仅用于演示
		})
	})

	// 示例6：直接发送短信（不使用验证码功能）
	app.POST("/api/send-sms", func(c *gin.Context) {
		mobile := c.GetString("mobile")
		templateID := c.GetString("template_id")

		// 发送自定义短信
		err := sms.SendSMS(mobile, templateID, map[string]string{
			"name":    "张三",
			"product": "测试产品",
		})
		if err != nil {
			c.ErrorResponse(400, err.Error())
			return
		}

		c.Success(gin.H{
			"message": "短信已发送",
		})
	})

	// 示例7：运行时修改短信配置
	app.POST("/api/update-sms-config", func(c *gin.Context) {
		newConfig := sms.SMSConfig{
			Provider:  "tencent",
			AccessKey: "new-access-key",
			SecretKey: "new-secret-key",
			SignName:  "新的短信签名",
			Region:    "ap-guangzhou",
		}

		if err := sms.InitDefaultProvider(newConfig); err != nil {
			c.ErrorResponse(400, err.Error())
			return
		}

		c.Success(gin.H{
			"message": "短信配置已更新",
		})
	})

	fmt.Println("服务器运行在 http://localhost:8080")
	if err := app.Run(); err != nil {
		panic(err)
	}
}
