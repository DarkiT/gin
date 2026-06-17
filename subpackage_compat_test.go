package gin_test

import (
	"net/http"
	"reflect"
	"testing"

	darkbinding "github.com/darkit/gin/binding"
	darkrender "github.com/darkit/gin/render"
	upbinding "github.com/gin-gonic/gin/binding"
	uprender "github.com/gin-gonic/gin/render"
)

func TestBindingSubpackageMatchesUpstreamPublicShape(t *testing.T) {
	t.Parallel()

	if darkbinding.MIMEBSON != upbinding.MIMEBSON {
		t.Fatalf("MIMEBSON mismatch: local=%q upstream=%q", darkbinding.MIMEBSON, upbinding.MIMEBSON)
	}
	if reflect.TypeOf(darkbinding.BSON) != reflect.TypeOf(upbinding.BSON) {
		t.Fatalf("BSON binding type mismatch: local=%T upstream=%T", darkbinding.BSON, upbinding.BSON)
	}
	assertSameType(t, reflect.TypeFor[func(method string, contentType string) darkbinding.Binding](), reflect.TypeFor[func(method string, contentType string) upbinding.Binding]())
	assertSameType(t, reflect.TypeFor[func(ptr any, form map[string][]string, tag string) error](), reflect.TypeFor[func(ptr any, form map[string][]string, tag string) error]())

	if got, want := darkbinding.Default(http.MethodPost, darkbinding.MIMEBSON), darkbinding.BSON; got != want {
		t.Fatalf("Default(POST, MIMEBSON) = %T, want %T", got, want)
	}
}

func TestRenderSubpackageMatchesUpstreamPublicShape(t *testing.T) {
	t.Parallel()

	assertSameType(t, reflect.TypeFor[func(w http.ResponseWriter, obj any) error](), reflect.TypeFor[func(w http.ResponseWriter, obj any) error]())
	assertSameType(t, reflect.TypeFor[func(w http.ResponseWriter, obj any) error](), reflect.TypeFor[func(w http.ResponseWriter, obj any) error]())
	assertSameType(t, reflect.TypeFor[func(w http.ResponseWriter, format string, data []any) error](), reflect.TypeFor[func(w http.ResponseWriter, format string, data []any) (err error)]())
	assertSameType(t, reflect.TypeFor[darkrender.BSON](), reflect.TypeFor[uprender.BSON]())
}
