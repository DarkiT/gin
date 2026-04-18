// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import "net/http"

// WriteProblem 按 RFC 9457 规范输出标准错误响应。
func (c *Context) WriteProblem(problem ProblemDetail) {
	if c == nil || c.Context == nil {
		return
	}

	normalized := newProblemDetail(
		problem.Status,
		problem.Type,
		problem.Title,
		problem.Detail,
		problem.Instance,
		problem.RequestID,
	)
	normalized.Errors = append([]ValidationError(nil), problem.Errors...)
	normalized.Extensions = problem.Extensions

	if normalized.Instance == "" && c.Request != nil && c.Request.URL != nil {
		normalized.Instance = c.Request.URL.Path
	}
	if normalized.RequestID == "" {
		normalized.RequestID = c.getRequestID()
	}

	c.Header("Content-Type", problemJSONContentType)
	c.JSON(normalized.Status, normalized)
}

// Problem 输出标准 Problem Details 响应。
func (c *Context) Problem(status int, typeURI, title, detail string) {
	c.WriteProblem(newProblemDetail(status, typeURI, title, detail, "", c.getRequestID()))
}

// AbortWithProblem 输出 Problem Details 响应并中止后续处理链。
func (c *Context) AbortWithProblem(status int, typeURI, title, detail string) {
	c.Problem(status, typeURI, title, detail)
	c.Abort()
}

// ValidationProblem 输出带字段错误明细的 Problem Details 响应。
func (c *Context) ValidationProblem(errors []ValidationError, detail ...string) {
	message := "请求参数验证失败"
	if len(detail) > 0 && detail[0] != "" {
		message = detail[0]
	}

	problem := newProblemDetail(
		http.StatusUnprocessableEntity,
		"https://datatracker.ietf.org/doc/html/rfc9457",
		http.StatusText(http.StatusUnprocessableEntity),
		message,
		"",
		c.getRequestID(),
	)
	problem.Errors = append([]ValidationError(nil), errors...)
	c.WriteProblem(problem)
}
