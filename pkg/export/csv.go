package export

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ErrCSVInvalidData 表示 CSV 导出数据必须为结构体切片。
var ErrCSVInvalidData = errors.New("csv 数据必须为结构体切片")

// ExportCSV 导出 CSV 内容字节。
func ExportCSV(data any, opts ...CSVOption) ([]byte, error) {
	options := applyCSVOptions(opts...)
	rows, err := buildCSVRows(data, options)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	writer.Comma = options.delimiter
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return applyCSVEncoding(buf.Bytes(), options.encoding)
}

// StreamCSV 以流式写入 CSV 内容。
func StreamCSV(dataChan <-chan any, writer io.Writer, opts ...CSVOption) error {
	if dataChan == nil {
		return ErrCSVInvalidData
	}
	options := applyCSVOptions(opts...)
	out := writer
	if strings.EqualFold(options.encoding, "GBK") {
		encoder := simplifiedchinese.GBK.NewEncoder()
		out = transform.NewWriter(writer, encoder)
	}

	csvWriter := csv.NewWriter(out)
	csvWriter.Comma = options.delimiter
	defer csvWriter.Flush()

	first := true
	for item := range dataChan {
		rows, err := buildCSVRows(item, options)
		if err != nil {
			return err
		}
		for i, row := range rows {
			if !first && i == 0 && len(options.headers) > 0 {
				continue
			}
			if err := csvWriter.Write(row); err != nil {
				return err
			}
		}
		first = false
	}
	return csvWriter.Error()
}

func applyCSVEncoding(content []byte, encoding string) ([]byte, error) {
	if strings.EqualFold(encoding, "GBK") {
		encoder := simplifiedchinese.GBK.NewEncoder()
		return encoder.Bytes(content)
	}
	return content, nil
}

func buildCSVRows(data any, options *csvOptions) ([][]string, error) {
	if data == nil {
		return nil, ErrCSVInvalidData
	}
	value := reflect.ValueOf(data)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		value = reflect.MakeSlice(reflect.SliceOf(value.Type()), 1, 1)
		value.Index(0).Set(reflect.ValueOf(data))
	}
	if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
		return nil, ErrCSVInvalidData
	}

	var rows [][]string
	if len(options.headers) > 0 {
		rows = append(rows, options.headers)
	}

	for i := 0; i < value.Len(); i++ {
		item := value.Index(i)
		if item.Kind() == reflect.Pointer {
			if item.IsNil() {
				rows = append(rows, []string{})
				continue
			}
			item = item.Elem()
		}
		row, err := buildCSVRow(item, options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func buildCSVRow(item reflect.Value, options *csvOptions) ([]string, error) {
	if !item.IsValid() {
		return nil, nil
	}
	if item.Kind() != reflect.Struct {
		return nil, ErrCSVInvalidData
	}

	row := make([]string, 0, item.NumField())
	for i := 0; i < item.NumField(); i++ {
		field := item.Field(i)
		if !field.CanInterface() {
			continue
		}
		row = append(row, formatCSVValue(field.Interface(), options))
	}
	return row, nil
}

func formatCSVValue(value any, options *csvOptions) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case time.Time:
		if options.dateLocation != nil {
			v = v.In(options.dateLocation)
		}
		return v.Format(options.dateFormat)
	case *time.Time:
		if v == nil {
			return ""
		}
		if options.dateLocation != nil {
			return v.In(options.dateLocation).Format(options.dateFormat)
		}
		return v.Format(options.dateFormat)
	default:
		return fmt.Sprintf("%v", value)
	}
}
