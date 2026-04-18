package export

import (
	"time"

	"github.com/xuri/excelize/v2"
)

// ExcelOption 表示 Excel 导出选项。
type ExcelOption func(*excelOptions)

type excelOptions struct {
	sheetName      string
	headers        []string
	style          *excelize.Style
	rowStyle       *excelize.Style
	stream         bool
	fileDateFormat string
	dateLocation   *time.Location
	sheetNames     []string
	styles         []*excelize.Style
	rowStyles      []*excelize.Style
}

// CSVOption 表示 CSV 导出选项。
type CSVOption func(*csvOptions)

type csvOptions struct {
	delimiter    rune
	encoding     string
	headers      []string
	dateFormat   string
	dateLocation *time.Location
}

func defaultExcelOptions() *excelOptions {
	return &excelOptions{
		sheetName:      "Sheet1",
		fileDateFormat: "2006-01-02 15:04:05",
		dateLocation:   time.Local,
		stream:         false,
	}
}

func defaultCSVOptions() *csvOptions {
	return &csvOptions{
		delimiter:    ',',
		encoding:     "UTF-8",
		dateFormat:   "2006-01-02 15:04:05",
		dateLocation: time.Local,
	}
}

func applyExcelOptions(opts ...ExcelOption) *excelOptions {
	options := defaultExcelOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	return options
}

func applyCSVOptions(opts ...CSVOption) *csvOptions {
	options := defaultCSVOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	return options
}

// WithExcelSheet 设置 Sheet 名称。
func WithExcelSheet(name string) ExcelOption {
	return func(o *excelOptions) {
		if name != "" {
			o.sheetName = name
		}
	}
}

// WithExcelHeaders 设置表头。
func WithExcelHeaders(headers []string) ExcelOption {
	return func(o *excelOptions) {
		if len(headers) > 0 {
			o.headers = headers
		}
	}
}

// WithExcelStyle 设置全局样式（用于单 Sheet 数据行）。
func WithExcelStyle(style *excelize.Style) ExcelOption {
	return func(o *excelOptions) {
		o.style = style
	}
}

// WithExcelRowStyle 设置数据行样式（优先于全局样式）。
func WithExcelRowStyle(style *excelize.Style) ExcelOption {
	return func(o *excelOptions) {
		o.rowStyle = style
	}
}

// WithExcelStream 使用流式写入。
func WithExcelStream() ExcelOption {
	return func(o *excelOptions) {
		o.stream = true
	}
}

// WithExcelDateFormat 设置时间格式。
func WithExcelDateFormat(layout string) ExcelOption {
	return func(o *excelOptions) {
		if layout != "" {
			o.fileDateFormat = layout
		}
	}
}

// WithExcelLocation 设置时间时区。
func WithExcelLocation(loc *time.Location) ExcelOption {
	return func(o *excelOptions) {
		if loc != nil {
			o.dateLocation = loc
		}
	}
}

// WithExcelSheets 批量设置 Sheet 名称（多 Sheet）。
func WithExcelSheets(names []string) ExcelOption {
	return func(o *excelOptions) {
		if len(names) > 0 {
			o.sheetNames = names
		}
	}
}

// WithExcelStyles 设置多 Sheet 样式。
func WithExcelStyles(styles []*excelize.Style) ExcelOption {
	return func(o *excelOptions) {
		if len(styles) > 0 {
			o.styles = styles
		}
	}
}

// WithExcelRowStyles 设置多 Sheet 行样式。
func WithExcelRowStyles(styles []*excelize.Style) ExcelOption {
	return func(o *excelOptions) {
		if len(styles) > 0 {
			o.rowStyles = styles
		}
	}
}

// WithCSVDelimiter 设置 CSV 分隔符。
func WithCSVDelimiter(delimiter rune) CSVOption {
	return func(o *csvOptions) {
		if delimiter != 0 {
			o.delimiter = delimiter
		}
	}
}

// WithCSVEncoding 设置 CSV 编码（UTF-8 / GBK）。
func WithCSVEncoding(encoding string) CSVOption {
	return func(o *csvOptions) {
		if encoding != "" {
			o.encoding = encoding
		}
	}
}

// WithCSVHeaders 设置 CSV 表头。
func WithCSVHeaders(headers []string) CSVOption {
	return func(o *csvOptions) {
		if len(headers) > 0 {
			o.headers = headers
		}
	}
}

// WithCSVDateFormat 设置时间格式。
func WithCSVDateFormat(layout string) CSVOption {
	return func(o *csvOptions) {
		if layout != "" {
			o.dateFormat = layout
		}
	}
}

// WithCSVLocation 设置时间时区。
func WithCSVLocation(loc *time.Location) CSVOption {
	return func(o *csvOptions) {
		if loc != nil {
			o.dateLocation = loc
		}
	}
}
