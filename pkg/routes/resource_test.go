package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
)

type testResourceController struct {
	indexCalls   int
	showCalls    int
	createCalls  int
	updateCalls  int
	patchCalls   int
	destroyCalls int
	lastID       string
}

func (t *testResourceController) Index(c *engine.Context) {
	t.indexCalls++
	c.Status(http.StatusOK)
}

func (t *testResourceController) Show(c *engine.Context) {
	t.showCalls++
	t.lastID = c.Input("id", c.Param("book_id"))
	c.Status(http.StatusOK)
}

func (t *testResourceController) Create(c *engine.Context) {
	t.createCalls++
	c.Status(http.StatusCreated)
}

func (t *testResourceController) Update(c *engine.Context) {
	t.updateCalls++
	t.lastID = c.Input("id", c.Param("book_id"))
	c.Status(http.StatusOK)
}

func (t *testResourceController) Patch(c *engine.Context) {
	t.patchCalls++
	t.lastID = c.Input("id", c.Param("book_id"))
	c.Status(http.StatusOK)
}

func (t *testResourceController) Destroy(c *engine.Context) {
	t.destroyCalls++
	t.lastID = c.Input("id", c.Param("book_id"))
	c.Status(http.StatusNoContent)
}

func TestResourceRegistersRoutes(t *testing.T) {
	e := engine.New()
	r := e.Router()
	ctrl := &testResourceController{}

	Resource(r, "users", ctrl)

	cases := []struct {
		method   string
		path     string
		status   int
		counter  *int
		paramVal string
	}{
		{method: http.MethodGet, path: "/users", status: http.StatusOK, counter: &ctrl.indexCalls},
		{method: http.MethodGet, path: "/users/10", status: http.StatusOK, counter: &ctrl.showCalls, paramVal: "10"},
		{method: http.MethodPost, path: "/users", status: http.StatusCreated, counter: &ctrl.createCalls},
		{method: http.MethodPut, path: "/users/10", status: http.StatusOK, counter: &ctrl.updateCalls, paramVal: "10"},
		{method: http.MethodPatch, path: "/users/10", status: http.StatusOK, counter: &ctrl.patchCalls, paramVal: "10"},
		{method: http.MethodDelete, path: "/users/10", status: http.StatusNoContent, counter: &ctrl.destroyCalls, paramVal: "10"},
	}

	for _, tc := range cases {
		ctrl.lastID = ""
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		e.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, w.Code)
		}
		if *tc.counter != 1 {
			t.Fatalf("%s %s counter=%d", tc.method, tc.path, *tc.counter)
		}
		if tc.paramVal != "" && ctrl.lastID != tc.paramVal {
			t.Fatalf("%s %s param=%s", tc.method, tc.path, ctrl.lastID)
		}
	}
}

func TestCRUDRegistersWithoutPatch(t *testing.T) {
	e := engine.New()
	r := e.Router()
	ctrl := &testResourceController{}

	CRUD(r, "items", ctrl)

	req := httptest.NewRequest(http.MethodPatch, "/items/1", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("patch should not be registered")
	}
}

func TestResourceWithCustomIDParam(t *testing.T) {
	e := engine.New()
	r := e.Router()
	ctrl := &testResourceController{}

	Resource(r, "books", ctrl, WithIDParam("book_id"))

	req := httptest.NewRequest(http.MethodGet, "/books/42", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if ctrl.lastID != "42" {
		t.Fatalf("expected custom id 42, got %s", ctrl.lastID)
	}
}

func TestResourceNilRouter(t *testing.T) {
	Resource(nil, "users", &testResourceController{})
	CRUD(nil, "users", &testResourceController{})
}
