package gin_test

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/export"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

type exportUser struct {
	ID    int
	Name  string
	Email string
}

func newExportTestContext(_ *testing.T, req *http.Request) (*engine.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(w)
	ginCtx.Request = req
	e := engine.New()
	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(e)
	return ctx, w
}

func TestExportExcel_Basic(t *testing.T) {
	data := []exportUser{{ID: 1, Name: "A", Email: "a@example.com"}}
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	ctx, w := newExportTestContext(t, req)
	if err := ctx.ExportExcel(data, "users.xlsx", export.WithExcelHeaders([]string{"ID", "Name", "Email"})); err != nil {
		t.Fatalf("export excel failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status not ok")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "spreadsheetml") {
		t.Fatalf("content type incorrect")
	}
	file, err := excelize.OpenReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	cell, err := file.GetCellValue("Sheet1", "A2")
	if err != nil {
		t.Fatalf("get cell: %v", err)
	}
	if cell != "1" {
		t.Fatalf("cell value mismatch")
	}
}

func TestExportCSV_Basic(t *testing.T) {
	data := []exportUser{{ID: 1, Name: "A", Email: "a@example.com"}}
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	ctx, w := newExportTestContext(t, req)
	if err := ctx.ExportCSV(data, "users.csv", export.WithCSVHeaders([]string{"ID", "Name", "Email"})); err != nil {
		t.Fatalf("export csv failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status not ok")
	}
	reader := csv.NewReader(bytes.NewReader(w.Body.Bytes()))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) < 2 || rows[1][0] != "1" {
		t.Fatalf("csv content mismatch")
	}
}

func TestStreamExcel_LargeData(t *testing.T) {
	dataChan := make(chan any, 2)
	dataChan <- []exportUser{{ID: 1, Name: "A", Email: "a@example.com"}}
	dataChan <- []exportUser{{ID: 2, Name: "B", Email: "b@example.com"}}
	close(dataChan)

	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	ctx, w := newExportTestContext(t, req)
	if err := ctx.StreamExcel(dataChan, "logs.xlsx", export.WithExcelHeaders([]string{"ID", "Name", "Email"})); err != nil {
		t.Fatalf("stream excel failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status not ok")
	}
	file, err := excelize.OpenReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	cell, err := file.GetCellValue("Sheet1", "A3")
	if err != nil {
		t.Fatalf("get cell: %v", err)
	}
	if cell != "2" {
		t.Fatalf("stream cell mismatch")
	}
}

func TestExportCSV_GBKEncoding(t *testing.T) {
	data := []exportUser{{ID: 1, Name: "张三", Email: "z@example.com"}}
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	ctx, w := newExportTestContext(t, req)
	if err := ctx.ExportCSV(data, "users.csv", export.WithCSVEncoding("GBK")); err != nil {
		t.Fatalf("export gbk failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status not ok")
	}
	content := w.Body.Bytes()
	if utf8.Valid(content) {
		t.Fatalf("gbk content should not be utf-8")
	}
}

func TestExportExcel_WithStyle(t *testing.T) {
	data := []exportUser{{ID: 1, Name: "A", Email: "a@example.com"}}
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	ctx, _ := newExportTestContext(t, req)
	style := &excelize.Style{Font: &excelize.Font{Bold: true}}
	if err := ctx.ExportExcel(data, "users.xlsx", export.WithExcelStyle(style)); err != nil {
		t.Fatalf("export excel with style failed: %v", err)
	}
}

func TestExportExcel_MultiSheet(t *testing.T) {
	data := []exportUser{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}, {ID: 3, Name: "C"}}
	content, err := export.ExportExcel(data, export.WithExcelSheets([]string{"One", "Two"}))
	if err != nil {
		t.Fatalf("export multi sheet failed: %v", err)
	}
	file, err := excelize.OpenReader(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	if index, _ := file.GetSheetIndex("Two"); index == 0 {
		t.Fatalf("sheet Two not found")
	}
}

func TestExportCSV_TimeFormat(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	data := []struct {
		At time.Time
	}{{At: now}}
	content, err := export.ExportCSV(data, export.WithCSVDateFormat("2006-01-02"))
	if err != nil {
		t.Fatalf("export csv time failed: %v", err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if rows[0][0] != "2024-01-02" {
		t.Fatalf("date format mismatch")
	}
}

func TestExportCSV_StructPointer(t *testing.T) {
	user := &exportUser{ID: 7, Name: "Pointer", Email: "p@example.com"}
	content, err := export.ExportCSV(user)
	if err != nil {
		t.Fatalf("export csv pointer struct failed: %v", err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "7" || rows[0][1] != "Pointer" {
		t.Fatalf("csv pointer struct content mismatch: %#v", rows)
	}
}

func TestExportCSV_Stream(t *testing.T) {
	dataChan := make(chan any, 1)
	dataChan <- []exportUser{{ID: 1, Name: "A"}}
	close(dataChan)

	var buf bytes.Buffer
	if err := export.StreamCSV(dataChan, &buf); err != nil {
		t.Fatalf("stream csv failed: %v", err)
	}
	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("stream csv content mismatch")
	}
}

func TestExportExcel_StreamWriter(t *testing.T) {
	dataChan := make(chan any, 1)
	dataChan <- []exportUser{{ID: 1, Name: "A"}}
	close(dataChan)
	var buf bytes.Buffer
	if err := export.StreamExcel(dataChan, &buf); err != nil {
		t.Fatalf("stream excel failed: %v", err)
	}
	if _, err := io.ReadAll(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("read buffer failed: %v", err)
	}
}
