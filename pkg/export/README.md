# pkg/export

`pkg/export` 提供 Excel / CSV 导出与流式写出能力，主要面向结构体切片数据。

## 模块用途

- 将结构体切片导出为 Excel 或 CSV 字节流。
- 支持流式导出，降低大批量数据的内存占用。
- 支持表头、时间格式、编码、样式、多 Sheet 等配置。

## 关键类型与函数

### Excel

- `ExportExcel(data any, opts ...ExcelOption) ([]byte, error)`
- `StreamExcel(dataChan <-chan any, writer io.Writer, opts ...ExcelOption) error`
- `ErrExcelInvalidData`：数据不是结构体/结构体切片时返回

### CSV

- `ExportCSV(data any, opts ...CSVOption) ([]byte, error)`
- `StreamCSV(dataChan <-chan any, writer io.Writer, opts ...CSVOption) error`
- `ErrCSVInvalidData`：数据不是结构体/结构体切片时返回

### 关键约束

- 输入必须是：
  - 结构体
  - 结构体指针
  - 结构体切片/数组
- 导出按字段顺序写出，要求字段可导出（`CanInterface()` 为真）

## 配置项

### ExcelOption

- `WithExcelSheet(name)`：单 Sheet 名称
- `WithExcelHeaders(headers)`：表头
- `WithExcelStyle(style)`：全局样式
- `WithExcelRowStyle(style)`：数据行样式
- `WithExcelDateFormat(layout)`：时间格式
- `WithExcelLocation(loc)`：时间时区
- `WithExcelSheets(names)`：多 Sheet 模式
- `WithExcelStyles(styles)`：多 Sheet 样式
- `WithExcelRowStyles(styles)`：多 Sheet 行样式

### CSVOption

- `WithCSVDelimiter(delimiter)`：分隔符，默认 `,`
- `WithCSVEncoding(encoding)`：`UTF-8` 或 `GBK`
- `WithCSVHeaders(headers)`：表头
- `WithCSVDateFormat(layout)`：时间格式
- `WithCSVLocation(loc)`：时间时区

## 使用示例

### 导出 Excel

```go
type User struct {
    ID    int
    Name  string
    Email string
}

content, err := export.ExportExcel([]User{
    {ID: 1, Name: "Alice", Email: "a@example.com"},
}, export.WithExcelHeaders([]string{"ID", "姓名", "邮箱"}))
_ = content
_ = err
```

### 导出多 Sheet Excel

```go
content, err := export.ExportExcel(data,
    export.WithExcelSheets([]string{"Users-A", "Users-B"}),
    export.WithExcelHeaders([]string{"ID", "Name", "Email"}),
)
_ = content
_ = err
```

### 导出 CSV（GBK）

```go
content, err := export.ExportCSV(data,
    export.WithCSVHeaders([]string{"ID", "Name", "Email"}),
    export.WithCSVEncoding("GBK"),
)
_ = content
_ = err
```

### 流式导出

```go
var writer io.Writer

ch := make(chan any)
go func() {
    defer close(ch)
    ch <- []User{{ID: 1, Name: "Alice", Email: "a@example.com"}}
    ch <- []User{{ID: 2, Name: "Bob", Email: "b@example.com"}}
}()

_ = export.StreamCSV(ch, writer, export.WithCSVHeaders([]string{"ID", "Name", "Email"}))
```

## 与 Engine 的集成

- `Context` 直接封装了导出能力：
  - `c.ExportExcel`
  - `c.StreamExcel`
  - `c.ExportCSV`
  - `c.StreamCSV`
- 当文件名为空时，框架默认使用：
  - Excel：`export.xlsx`
  - CSV：`export.csv`

```go
r.GET("/users/export", func(c *gin.Context) {
    _ = c.ExportExcel(users, "users.xlsx",
        export.WithExcelHeaders([]string{"ID", "姓名", "邮箱"}),
    )
})
```
