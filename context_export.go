// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"fmt"
	"io"
	"net/http"

	"github.com/darkit/gin/pkg/export"
)

// ExportExcel 导出 Excel 文件，filename 为空时使用默认名称。
func (c *Context) ExportExcel(data any, filename string, opts ...export.ExcelOption) error {
	content, err := export.ExportExcel(data, opts...)
	if err != nil {
		return err
	}
	return c.writeDownload(content, filename, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
}

// StreamExcel 流式导出 Excel，dataChan 为数据通道。
func (c *Context) StreamExcel(dataChan <-chan any, filename string, opts ...export.ExcelOption) error {
	return c.streamDownload(filename, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", func(w io.Writer) error {
		return export.StreamExcel(dataChan, w, opts...)
	})
}

// ExportCSV 导出 CSV 文件，filename 为空时使用默认名称。
func (c *Context) ExportCSV(data any, filename string, opts ...export.CSVOption) error {
	content, err := export.ExportCSV(data, opts...)
	if err != nil {
		return err
	}
	return c.writeDownload(content, filename, "text/csv")
}

// StreamCSV 流式导出 CSV，dataChan 为数据通道。
func (c *Context) StreamCSV(dataChan <-chan any, filename string, opts ...export.CSVOption) error {
	return c.streamDownload(filename, "text/csv", func(w io.Writer) error {
		return export.StreamCSV(dataChan, w, opts...)
	})
}

func (c *Context) writeDownload(content []byte, filename, contentType string) error {
	if filename == "" {
		switch contentType {
		case "text/csv":
			filename = "export.csv"
		case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
			filename = "export.xlsx"
		default:
			filename = "export"
		}
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", contentType)
	c.Header("Content-Length", fmt.Sprintf("%d", len(content)))
	c.Status(http.StatusOK)
	_, err := c.Writer.Write(content)
	return err
}

func (c *Context) streamDownload(filename, contentType string, writeFunc func(io.Writer) error) error {
	if filename == "" {
		switch contentType {
		case "text/csv":
			filename = "export.csv"
		case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
			filename = "export.xlsx"
		default:
			filename = "export"
		}
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", contentType)
	c.Status(http.StatusOK)
	return writeFunc(c.Writer)
}
