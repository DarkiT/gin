# Gin Framework - Context扩展

[![Go Reference](https://pkg.go.dev/badge/github.com/darkit/gin.svg)](https://pkg.go.dev/github.com/darkit/gin)
[![Go Report Card](https://goreportcard.com/badge/github.com/darkit/gin)](https://goreportcard.com/report/github.com/darkit/gin)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/darkit/gin/blob/master/LICENSE)

Gin是一个高性能的Web框架，基于Go语言构建，旨在提供简单易用的API和高效的路由处理。本项目对Gin框架的Context进行了功能扩充，以简化调用流程。

## 安装

使用Go模块管理工具安装Gin框架：

````bash
go get github.com/darkit/gin
````

## Context扩展功能

本项目对Gin的Context进行了扩展，增加了以下功能：

- **请求类型判断**：增加了HTTP请求类型判断。
- **统一响应结构**：提供了成功、失败、错误、禁止访问和资源不存在的统一响应格式，简化了响应的处理。
- **简化参数获取**：通过扩展的Context方法，简化了获取请求参数的流程。
- **文件上传验证**：增加了文件上传的验证功能，支持自定义文件类型和大小限制。
- **CORS支持**：简化了跨域请求的处理，提供了方便的方法来允许CORS。

### 使用示例

以下是一个简单的示例，展示如何使用扩展后的Context：

````go
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
````

### 简化调用流程

通过扩展的Context，用户可以更方便地进行以下操作：

- **获取请求参数**：使用`c.Param()`、`c.Query()`和`c.PostForm()`方法轻松获取请求参数。
- **发送响应**：使用`c.Success()`、`c.Fail()`等方法快速发送响应，减少了手动构建响应的复杂性。
- **文件上传**：使用`c.SaveUploadedFile()`和`c.ValidateFile()`方法，简化文件上传的处理和验证。

## 主要功能

- **路由管理**：支持多种HTTP方法（GET, POST, PUT, DELETE等）的路由注册。
- **中间件支持**：可以轻松添加中间件以处理请求和响应。
- **JSON响应**：提供统一的JSON响应格式，支持成功和失败的响应。
- **文件上传**：支持文件上传和验证功能。
- **类型判断**：增加了HTTP请求类型判断。
- **CORS支持**：允许跨域请求。

## 贡献

欢迎任何形式的贡献！请提交问题或拉取请求。

## 许可证

本项目采用MIT许可证，详细信息请参见 [LICENSE](LICENSE) 文件。
