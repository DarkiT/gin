package gin_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
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

	assertSameType(t, reflect.TypeOf(darkgin.Logger()), reflect.TypeOf(darkgin.HandlerFunc(nil)))
	assertSameType(t, reflect.TypeOf(darkgin.Recovery()), reflect.TypeOf(darkgin.HandlerFunc(nil)))
	assertSameType(t, reflect.TypeOf(darkgin.BasicAuth(darkgin.Accounts{"u": "p"})), reflect.TypeOf(darkgin.HandlerFunc(nil)))
	assertSameType(t, reflect.TypeOf(darkgin.WrapF(func(w http.ResponseWriter, r *http.Request) {})), reflect.TypeOf(darkgin.HandlerFunc(nil)))
	assertSameType(t, reflect.TypeOf(darkgin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))), reflect.TypeOf(darkgin.HandlerFunc(nil)))
	assertSameType(t, reflect.TypeOf(darkgin.Bind(struct{}{})), reflect.TypeOf(darkgin.HandlerFunc(nil)))
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.local != tc.upstream {
				t.Fatalf("%s type identity mismatch: local=%s upstream=%s", tc.name, tc.local, tc.upstream)
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
	return reflect.TypeOf((*T)(nil)).Elem()
}
