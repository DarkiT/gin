package gin

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewPaginationBounds(t *testing.T) {
	p := NewPagination(0, 0, 0)
	if p.Page != 1 {
		t.Fatalf("page expected 1, got %d", p.Page)
	}
	if p.PerPage != 1 {
		t.Fatalf("perPage expected 1, got %d", p.PerPage)
	}
	if p.Total != 0 {
		t.Fatalf("total expected 0, got %d", p.Total)
	}
	if p.TotalPages != 0 {
		t.Fatalf("totalPages expected 0, got %d", p.TotalPages)
	}
}

func TestNewPaginationTotalPages(t *testing.T) {
	cases := []struct {
		page       int
		perPage    int
		total      int64
		totalPages int
	}{
		{1, 10, 1, 1},
		{1, 10, 10, 1},
		{1, 10, 11, 2},
		{2, 5, 20, 4},
		{3, 5, 21, 5},
	}

	for _, c := range cases {
		p := NewPagination(c.page, c.perPage, c.total)
		if p.TotalPages != c.totalPages {
			t.Fatalf("totalPages expected %d, got %d", c.totalPages, p.TotalPages)
		}
	}
}

func TestResponseJSON(t *testing.T) {
	now := time.Now().Unix()
	resp := Response{
		Code:      0,
		Message:   "ok",
		Data:      map[string]any{"k": "v"},
		RequestID: "req",
		Timestamp: now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if decoded.Code != resp.Code || decoded.Message != resp.Message || decoded.RequestID != resp.RequestID || decoded.Timestamp != now {
		t.Fatalf("decoded response mismatch")
	}
}

func TestPaginatedResponseJSON(t *testing.T) {
	pagination := NewPagination(1, 10, 11)
	now := time.Now().Unix()
	resp := PaginatedResponse{
		Code:       0,
		Message:    "ok",
		Data:       []string{"a"},
		Pagination: pagination,
		RequestID:  "req",
		Timestamp:  now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal paginated response: %v", err)
	}

	var decoded PaginatedResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal paginated response: %v", err)
	}

	if decoded.Pagination == nil {
		t.Fatalf("pagination missing after unmarshal")
	}
	if decoded.Pagination.TotalPages != pagination.TotalPages {
		t.Fatalf("totalPages expected %d, got %d", pagination.TotalPages, decoded.Pagination.TotalPages)
	}
}

func TestErrorResponseJSON(t *testing.T) {
	now := time.Now().Unix()
	resp := ErrorResponse{
		Code:      400,
		Message:   "bad",
		Errors:    []ValidationError{{Field: "name", Message: "required"}},
		RequestID: "req",
		Timestamp: now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error response: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}

	if len(decoded.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(decoded.Errors))
	}
	if decoded.Errors[0].Field != "name" {
		t.Fatalf("error field mismatch")
	}
}

func TestResponseHelpers(t *testing.T) {
	resp := newResponse(200, "ok", map[string]any{"k": "v"}, "rid")
	if resp.Code != 200 || resp.Message != "ok" || resp.RequestID != "rid" {
		t.Fatalf("newResponse fields mismatch")
	}
	if resp.Timestamp == 0 {
		t.Fatalf("newResponse timestamp should be set")
	}

	pagination := NewPagination(1, 10, 1)
	pResp := newPaginatedResponse(200, "ok", []string{"a"}, pagination, "rid")
	if pResp.Pagination == nil || pResp.Pagination.TotalPages != 1 {
		t.Fatalf("newPaginatedResponse pagination mismatch")
	}
	if pResp.Timestamp == 0 {
		t.Fatalf("newPaginatedResponse timestamp should be set")
	}

	errResp := newErrorResponse(400, "bad", []ValidationError{{Field: "f", Message: "m"}}, "rid")
	if len(errResp.Errors) != 1 || errResp.Errors[0].Field != "f" {
		t.Fatalf("newErrorResponse errors mismatch")
	}
	if errResp.Timestamp == 0 {
		t.Fatalf("newErrorResponse timestamp should be set")
	}
}
