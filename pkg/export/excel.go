package export

import (
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/xuri/excelize/v2"
)

// ErrExcelInvalidData 表示 Excel 导出数据必须为结构体切片。
var ErrExcelInvalidData = errors.New("excel 数据必须为结构体切片")

// ExportExcel 导出 Excel 内容字节。
func ExportExcel(data any, opts ...ExcelOption) ([]byte, error) {
	options := applyExcelOptions(opts...)
	file := excelize.NewFile()
	if err := writeExcelData(file, data, options); err != nil {
		return nil, err
	}
	buf, err := file.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// StreamExcel 以流式写入 Excel 内容。
func StreamExcel(dataChan <-chan any, writer io.Writer, opts ...ExcelOption) error {
	if dataChan == nil {
		return ErrExcelInvalidData
	}
	options := applyExcelOptions(opts...)
	options.stream = true
	file := excelize.NewFile()

	if err := writeExcelStream(file, dataChan, options); err != nil {
		return err
	}
	_, err := file.WriteTo(writer)
	return err
}

func writeExcelData(file *excelize.File, data any, options *excelOptions) error {
	if file == nil {
		return errors.New("excel file is nil")
	}
	value := normalizeSliceValue(data)
	if !value.IsValid() || (value.Kind() != reflect.Slice && value.Kind() != reflect.Array) {
		return ErrExcelInvalidData
	}

	sheetName, err := ensureSheet(file, options.sheetName)
	if err != nil {
		return err
	}
	if len(options.sheetNames) > 0 {
		return writeExcelMultiSheets(file, value, options)
	}

	return writeExcelSheet(file, sheetName, value, options, false)
}

func writeExcelStream(file *excelize.File, dataChan <-chan any, options *excelOptions) error {
	if file == nil {
		return errors.New("excel file is nil")
	}
	sheetName, err := ensureSheet(file, options.sheetName)
	if err != nil {
		return err
	}
	writer, err := file.NewStreamWriter(sheetName)
	if err != nil {
		return err
	}

	rowIndex := 1
	if len(options.headers) > 0 {
		cell, _ := excelize.CoordinatesToCellName(1, rowIndex)
		headerRow := make([]any, 0, len(options.headers))
		for _, h := range options.headers {
			headerRow = append(headerRow, h)
		}
		if err := writer.SetRow(cell, headerRow); err != nil {
			return err
		}
		rowIndex++
	}

	for item := range dataChan {
		value := normalizeSliceValue(item)
		if !value.IsValid() || (value.Kind() != reflect.Slice && value.Kind() != reflect.Array) {
			return ErrExcelInvalidData
		}
		for i := 0; i < value.Len(); i++ {
			row, err := buildExcelRow(value.Index(i), options)
			if err != nil {
				return err
			}
			cell, _ := excelize.CoordinatesToCellName(1, rowIndex)
			rowValues := row
			if rowValues == nil {
				rowValues = []any{}
			}
			if err := writer.SetRow(cell, rowValues); err != nil {
				return err
			}
			rowIndex++
		}
	}
	return writer.Flush()
}

func writeExcelMultiSheets(file *excelize.File, value reflect.Value, options *excelOptions) error {
	for _, sheet := range options.sheetNames {
		if sheet != "" {
			if _, err := ensureSheet(file, sheet); err != nil {
				return err
			}
		}
	}
	start := 0
	if value.Len() == 0 {
		return nil
	}
	sheets := options.sheetNames
	if len(sheets) == 0 {
		sheets = []string{options.sheetName}
	}
	step := value.Len() / len(sheets)
	if step == 0 {
		step = 1
	}

	for i, sheet := range sheets {
		end := start + step
		if i == len(sheets)-1 || end > value.Len() {
			end = value.Len()
		}
		if start >= value.Len() {
			break
		}
		part := value.Slice(start, end)
		opt := *options
		opt.sheetName = sheet
		if len(options.styles) > i {
			opt.style = options.styles[i]
		}
		if len(options.rowStyles) > i {
			opt.rowStyle = options.rowStyles[i]
		}
		if err := writeExcelSheet(file, sheet, part, &opt, false); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func writeExcelSheet(file *excelize.File, sheetName string, value reflect.Value, options *excelOptions, stream bool) error {
	if stream {
		return errors.New("stream writer not supported in writeExcelSheet")
	}
	var err error
	sheetName, err = ensureSheet(file, sheetName)
	if err != nil {
		return err
	}
	rowIndex := 1
	if len(options.headers) > 0 {
		cell, _ := excelize.CoordinatesToCellName(1, rowIndex)
		if err := file.SetSheetRow(sheetName, cell, &options.headers); err != nil {
			return err
		}
		rowIndex++
	}

	for i := 0; i < value.Len(); i++ {
		row, err := buildExcelRow(value.Index(i), options)
		if err != nil {
			return err
		}
		cell, _ := excelize.CoordinatesToCellName(1, rowIndex)
		rowValues := row
		if rowValues == nil {
			rowValues = []any{}
		}
		if err := file.SetSheetRow(sheetName, cell, &rowValues); err != nil {
			return err
		}
		rowIndex++
	}

	if options.style != nil || options.rowStyle != nil {
		styleID := 0
		rowStyleID := 0
		var err error
		if options.style != nil {
			styleID, err = file.NewStyle(options.style)
			if err != nil {
				return err
			}
		}
		if options.rowStyle != nil {
			rowStyleID, err = file.NewStyle(options.rowStyle)
			if err != nil {
				return err
			}
		}
		rows := value.Len()
		cols := valueTypeFieldCount(value)
		if len(options.headers) > 0 {
			rows++
		}
		if rows > 0 && cols > 0 {
			endCell, _ := excelize.CoordinatesToCellName(cols, rows)
			startCell := "A1"
			if styleID > 0 {
				if err := file.SetCellStyle(sheetName, startCell, endCell, styleID); err != nil {
					return err
				}
			}
			if rowStyleID > 0 && rows > 1 {
				dataStart := 1
				if len(options.headers) > 0 {
					dataStart = 2
				}
				dataStartCell, _ := excelize.CoordinatesToCellName(1, dataStart)
				dataEndCell, _ := excelize.CoordinatesToCellName(cols, rows)
				if err := file.SetCellStyle(sheetName, dataStartCell, dataEndCell, rowStyleID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func buildExcelRow(item reflect.Value, options *excelOptions) ([]any, error) {
	if item.Kind() == reflect.Pointer {
		if item.IsNil() {
			return []any{}, nil
		}
		item = item.Elem()
	}
	if item.Kind() != reflect.Struct {
		return nil, ErrExcelInvalidData
	}

	row := make([]any, 0, item.NumField())
	for i := 0; i < item.NumField(); i++ {
		field := item.Field(i)
		if !field.CanInterface() {
			continue
		}
		row = append(row, formatExcelValue(field.Interface(), options))
	}
	return row, nil
}

func formatExcelValue(value any, options *excelOptions) any {
	switch v := value.(type) {
	case time.Time:
		if options.dateLocation != nil {
			v = v.In(options.dateLocation)
		}
		return v.Format(options.fileDateFormat)
	case *time.Time:
		if v == nil {
			return ""
		}
		if options.dateLocation != nil {
			return v.In(options.dateLocation).Format(options.fileDateFormat)
		}
		return v.Format(options.fileDateFormat)
	default:
		return v
	}
}

func normalizeSliceValue(data any) reflect.Value {
	if data == nil {
		return reflect.Value{}
	}
	value := reflect.ValueOf(data)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		list := reflect.MakeSlice(reflect.SliceOf(value.Type()), 1, 1)
		list.Index(0).Set(value)
		return list
	}
	return value
}

func ensureSheet(file *excelize.File, sheetName string) (string, error) {
	if sheetName == "" {
		sheetName = "Sheet1"
	}
	index, _ := file.GetSheetIndex(sheetName)
	if index <= 0 {
		if _, err := file.NewSheet(sheetName); err != nil {
			return "", err
		}
		file.SetActiveSheet(0)
	}
	defaultIndex, _ := file.GetSheetIndex("Sheet1")
	if sheetName != "Sheet1" && defaultIndex > 0 && len(file.GetSheetList()) > 1 {
		if err := file.DeleteSheet("Sheet1"); err != nil {
			return "", err
		}
	}
	return sheetName, nil
}

func valueTypeFieldCount(value reflect.Value) int {
	if !value.IsValid() || value.Len() == 0 {
		return 0
	}
	item := value.Index(0)
	if item.Kind() == reflect.Pointer {
		if item.IsNil() {
			return 0
		}
		item = item.Elem()
	}
	if item.Kind() != reflect.Struct {
		return 0
	}
	return item.NumField()
}
