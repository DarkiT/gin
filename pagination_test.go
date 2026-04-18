package gin_test

import (
	"net/http"
	"testing"

	engine "github.com/darkit/gin"
)

func TestParsePagination_Default(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	page, perPage := ctx.ParsePagination()
	if page != 1 || perPage != 20 {
		t.Fatalf("default pagination expected 1/20, got %d/%d", page, perPage)
	}
}

func TestParsePagination_WithQueryParams(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?page=2&per_page=15", "")
	page, perPage := ctx.ParsePagination()
	if page != 2 || perPage != 15 {
		t.Fatalf("query pagination expected 2/15, got %d/%d", page, perPage)
	}
}

func TestParsePagination_MultipleParamNames(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?page=1&page_size=30", "")
	page, perPage := ctx.ParsePagination()
	if page != 1 || perPage != 30 {
		t.Fatalf("page_size expected 1/30, got %d/%d", page, perPage)
	}

	ctx, _ = newTestContext(t, http.MethodGet, "/?page=1&limit=25", "")
	page, perPage = ctx.ParsePagination()
	if page != 1 || perPage != 25 {
		t.Fatalf("limit expected 1/25, got %d/%d", page, perPage)
	}

	ctx, _ = newTestContext(t, http.MethodGet, "/?page=1&per_page=10&page_size=99&limit=88", "")
	page, perPage = ctx.ParsePagination()
	if page != 1 || perPage != 10 {
		t.Fatalf("per_page priority expected 1/10, got %d/%d", page, perPage)
	}
}

func TestParsePagination_BoundaryValidation(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?page=0&per_page=-3", "")
	page, perPage := ctx.ParsePagination()
	if page != 1 || perPage != 20 {
		t.Fatalf("boundary default expected 1/20, got %d/%d", page, perPage)
	}
}

func TestParsePagination_CustomDefaults(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	page, perPage := ctx.ParsePagination(2, 50)
	if page != 2 || perPage != 50 {
		t.Fatalf("custom defaults expected 2/50, got %d/%d", page, perPage)
	}
}

func TestPaginationParams_WithOptions(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?page=5&per_page=200", "")
	params := ctx.PaginationParams(
		engine.WithDefaultPage(2),
		engine.WithDefaultPerPage(10),
		engine.WithMaxPerPage(100),
	)
	if params.Page != 5 {
		t.Fatalf("page expected 5, got %d", params.Page)
	}
	if params.PerPage != 100 {
		t.Fatalf("per_page max expected 100, got %d", params.PerPage)
	}
}

func TestPaginationParams_Offset(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?page=3&per_page=10", "")
	params := ctx.PaginationParams()
	if params.Offset != 20 {
		t.Fatalf("offset expected 20, got %d", params.Offset)
	}
}
