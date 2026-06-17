package swagger

import (
	"encoding/json"
	"net/http"
	"strings"
)

// swaggerUIHTML Swagger UI HTML 页面模板
const swaggerUIHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - API 文档</title>
    <link rel="stylesheet" href="https://cdn.iocdn.cc/npm/swagger-ui-dist@5.10.0/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.iocdn.cc/npm/swagger-ui-dist@5.10.0/swagger-ui-bundle.js"></script>
    <script src="https://cdn.iocdn.cc/npm/swagger-ui-dist@5.10.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "{{.DocURL}}",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`

// UIHandler Swagger UI 处理器
type UIHandler struct {
	generator *Generator
	docURL    string
}

// NewUIHandler 创建 UI 处理器
func NewUIHandler(generator *Generator) *UIHandler {
	return &UIHandler{
		generator: generator,
		docURL:    "/swagger/doc.json",
	}
}

// ServeUI 提供 Swagger UI 页面
func (h *UIHandler) ServeUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 替换模板变量
	html := swaggerUIHTML
	html = replaceString(html, "{{.Title}}", h.generator.config.Title)
	html = replaceString(html, "{{.DocURL}}", h.docURL)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// ServeDoc 提供 OpenAPI JSON 文档
func (h *UIHandler) ServeDoc(w http.ResponseWriter, r *http.Request) {
	spec := h.generator.Generate()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(spec)
}

// replaceString 简单的字符串替换
func replaceString(s, old, new string) string {
	var result strings.Builder
	for {
		i := indexOf(s, old)
		if i < 0 {
			result.WriteString(s)
			break
		}
		result.WriteString(s[:i] + new)
		s = s[i+len(old):]
	}
	return result.String()
}

// indexOf 查找子字符串位置
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
