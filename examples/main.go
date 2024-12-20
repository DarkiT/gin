package main

import (
	"fmt"
	"github.com/darkit/gin"
)

func init() {
	// 注册路由
	gin.Register(gin.MethodAny, "/hello", helloHandler)
	gin.Register(gin.MethodPost, "/upload", uploadHandler)
}

func helloHandler(c *gin.Context) {
	c.AllowCORS() // 允许跨域请求

	// 获取请求参数
	name := c.Param("name")
	if name == "" {
		name = "world" // 默认值
	}

	// 构建响应数据
	data := gin.H{
		"message": fmt.Sprintf("Hello, %s!", name),
		"type":    c.Type(),
		"isSsl":   c.IsSsl(),
		"localIP": c.GetIP(),
		"domain":  c.Domain(),
		"query":   c.Query("queryParam"), // 获取查询参数
	}

	// 发送成功响应
	c.SuccessWithMsg("系统信息获取成功", data)
}

func uploadHandler(c *gin.Context) {
	c.AllowCORS() // 允许跨域请求

	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.Fail("文件上传失败") // 发送失败响应
		return
	}

	// 验证文件
	config := gin.UploadConfig{
		AllowedExts: []string{".jpg", ".png"}, // 允许的文件扩展名
		MaxSize:     5 * 1024 * 1024,          // 最大文件大小5MB
		SavePath:    "./uploads",              // 保存路径
	}

	if err := c.ValidateFile(file, config); err != nil {
		c.Fail("文件验证失败: " + err.Error()) // 发送失败响应
		return
	}

	// 保存文件
	newFileName, err := c.SaveUploadedFile(file, config)
	if err != nil {
		c.Fail("文件保存失败: " + err.Error()) // 发送失败响应
		return
	}

	// 发送成功响应
	c.SuccessWithMsg("文件上传成功", gin.H{"fileName": newFileName})
}

func main() {
	gin.SetMode(gin.DebugMode)
	engine := gin.Default()              // 创建服务器实例
	gin.InitRouting(engine).Run(":8282") // 启动服务器
}
