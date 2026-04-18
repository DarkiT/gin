package mail

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/darkit/gin/internal/pathutil"
)

const defaultTemplateDir = "mail/templates"

// RenderTemplate 渲染 HTML 模板
func RenderTemplate(templateName string, data any) (string, error) {
	name := strings.TrimSpace(templateName)
	if err := pathutil.SafeTemplateName(name); err != nil {
		return "", fmt.Errorf("模板名称非法: %w", err)
	}

	path, err := pathutil.SafePath(defaultTemplateDir, name)
	if err != nil {
		return "", fmt.Errorf("模板路径非法: %w", err)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("模板不存在: %w", err)
	}

	tpl, err := template.ParseFiles(path)
	if err != nil {
		return "", fmt.Errorf("解析模板失败: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染模板失败: %w", err)
	}
	return buf.String(), nil
}
