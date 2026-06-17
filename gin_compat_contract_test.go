package gin_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	darkgin "github.com/darkit/gin"
	upstream "github.com/gin-gonic/gin"
)

func TestCoreInterfacesAreSatisfied(t *testing.T) {
	t.Parallel()

	var _ darkgin.IRoutes = darkgin.New()
	var _ darkgin.IRouter = darkgin.New()
	var _ darkgin.IRoutes = darkgin.New().Router()
	var _ darkgin.IRouter = darkgin.New().Router()
}

func TestPackageMiddlewaresReturnLocalHandlerFunc(t *testing.T) {
	t.Parallel()

	assertSameType(t, reflect.TypeOf(darkgin.Logger()), reflect.TypeFor[darkgin.HandlerFunc]())
	assertSameType(t, reflect.TypeOf(darkgin.Recovery()), reflect.TypeFor[darkgin.HandlerFunc]())
	assertSameType(t, reflect.TypeOf(darkgin.BasicAuth(darkgin.Accounts{"u": "p"})), reflect.TypeFor[darkgin.HandlerFunc]())
	assertSameType(t, reflect.TypeOf(darkgin.WrapF(func(w http.ResponseWriter, r *http.Request) {})), reflect.TypeFor[darkgin.HandlerFunc]())
	assertSameType(t, reflect.TypeOf(darkgin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))), reflect.TypeFor[darkgin.HandlerFunc]())
	assertSameType(t, reflect.TypeOf(darkgin.Bind(struct{}{})), reflect.TypeFor[darkgin.HandlerFunc]())
}

func TestCreateTestContextReturnsLocalTypes(t *testing.T) {
	t.Parallel()

	c, e := darkgin.CreateTestContext(httptest.NewRecorder())
	if c == nil || e == nil {
		t.Fatal("CreateTestContext returned nil")
	}
	if _, ok := any(c).(*darkgin.Context); !ok {
		t.Fatalf("context type = %T", c)
	}
	if _, ok := any(e).(*darkgin.Engine); !ok {
		t.Fatalf("engine type = %T", e)
	}

	c2 := darkgin.CreateTestContextOnly(httptest.NewRecorder(), e)
	if _, ok := any(c2).(*darkgin.Context); !ok {
		t.Fatalf("CreateTestContextOnly context type = %T", c2)
	}
}

func TestDefaultWriterAssignmentAffectsLogger(t *testing.T) {
	oldLocal := darkgin.DefaultWriter
	oldUpstream := upstream.DefaultWriter
	defer func() {
		darkgin.DefaultWriter = oldLocal
		upstream.DefaultWriter = oldUpstream
	}()

	var buf bytes.Buffer
	darkgin.DefaultWriter = &buf

	r := darkgin.New()
	r.Use(darkgin.Logger())
	r.GET("/ping", func(c *darkgin.Context) {
		c.String(http.StatusOK, "pong")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), "/ping") {
		t.Fatalf("logger should write to darkgin.DefaultWriter, got %q", buf.String())
	}
}

func TestSelectedAliasesStillMatchUpstream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		local    reflect.Type
		upstream reflect.Type
	}{
		{name: "Accounts", local: typeOf[darkgin.Accounts](), upstream: typeOf[upstream.Accounts]()},
		{name: "Error", local: typeOf[darkgin.Error](), upstream: typeOf[upstream.Error]()},
		{name: "ErrorType", local: typeOf[darkgin.ErrorType](), upstream: typeOf[upstream.ErrorType]()},
		{name: "H", local: typeOf[darkgin.H](), upstream: typeOf[upstream.H]()},
		{name: "Param", local: typeOf[darkgin.Param](), upstream: typeOf[upstream.Param]()},
		{name: "Params", local: typeOf[darkgin.Params](), upstream: typeOf[upstream.Params]()},
		{name: "ResponseWriter", local: typeOf[darkgin.ResponseWriter](), upstream: typeOf[upstream.ResponseWriter]()},
		{name: "Negotiate", local: typeOf[darkgin.Negotiate](), upstream: typeOf[upstream.Negotiate]()},
		{name: "OnlyFilesFS", local: typeOf[darkgin.OnlyFilesFS](), upstream: typeOf[upstream.OnlyFilesFS]()},
		{name: "RouteInfo", local: typeOf[darkgin.RouteInfo](), upstream: typeOf[upstream.RouteInfo]()},
		{name: "RoutesInfo", local: typeOf[darkgin.RoutesInfo](), upstream: typeOf[upstream.RoutesInfo]()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.local != tc.upstream {
				t.Fatalf("%s type identity mismatch: local=%s upstream=%s", tc.name, tc.local, tc.upstream)
			}
		})
	}
}

func TestMappedWrapperTypesKeepCompatibleShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		local    reflect.Type
		upstream reflect.Type
	}{
		{name: "Context", local: typeOf[darkgin.Context](), upstream: typeOf[upstream.Context]()},
		{name: "Engine", local: typeOf[darkgin.Engine](), upstream: typeOf[upstream.Engine]()},
		{name: "HandlerFunc", local: typeOf[darkgin.HandlerFunc](), upstream: typeOf[upstream.HandlerFunc]()},
		{name: "OptionFunc", local: typeOf[darkgin.OptionFunc](), upstream: typeOf[upstream.OptionFunc]()},
		{name: "RouterGroup", local: typeOf[darkgin.RouterGroup](), upstream: typeOf[upstream.RouterGroup]()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.local == tc.upstream {
				t.Fatalf("%s unexpectedly has upstream type identity; mapped wrapper contract changed", tc.name)
			}
			if tc.local.Kind() != tc.upstream.Kind() {
				t.Fatalf("%s kind mismatch: local=%s upstream=%s", tc.name, tc.local.Kind(), tc.upstream.Kind())
			}
		})
	}
}

func assertSameType(t *testing.T, got, want reflect.Type) {
	t.Helper()
	if got != want {
		t.Fatalf("type mismatch: got=%s want=%s", got, want)
	}
}

func typeOf[T any]() reflect.Type {
	return reflect.TypeFor[T]()
}
