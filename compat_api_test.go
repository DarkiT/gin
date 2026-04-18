package gin_test

import (
	"reflect"
	"testing"

	darkgin "github.com/darkit/gin"
	upstream "github.com/gin-gonic/gin"
)

func TestContextCoreMethodSignatures(t *testing.T) {
	t.Parallel()

	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "Param", "(string) -> (string)")
	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "Error", "(error) -> (*gin.Error)")
	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "Negotiate", "(int, gin.Negotiate)")
	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "MustGet", "(interface {}) -> (interface {})")
	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "Copy", "() -> (*gin.Context)")
	assertMethodSignature(t, "Context", reflect.TypeOf((*darkgin.Context)(nil)), "Handler", "() -> (gin.HandlerFunc)")
}

func TestEngineCoreMethodSignatures(t *testing.T) {
	t.Parallel()

	engineType := reflect.TypeOf((*darkgin.Engine)(nil))
	assertMethodSignature(t, "Engine", engineType, "Use", "(...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "Handle", "(string, string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "GET", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "POST", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "PUT", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "PATCH", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "DELETE", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "HEAD", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "OPTIONS", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "Any", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "Match", "([]string, string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "Static", "(string, string) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "StaticFS", "(string, http.FileSystem) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "StaticFile", "(string, string) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "StaticFileFS", "(string, string, http.FileSystem) -> (gin.IRoutes)")
	assertMethodSignature(t, "Engine", engineType, "With", "(...gin.OptionFunc) -> (*gin.Engine)")
}

func TestRouterCoreMethodSignatures(t *testing.T) {
	t.Parallel()

	routerType := reflect.TypeOf((*darkgin.Router)(nil))
	assertMethodSignature(t, "Router", routerType, "Use", "(...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "Handle", "(string, string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "GET", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "POST", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "PUT", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "PATCH", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "DELETE", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "HEAD", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "OPTIONS", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "Any", "(string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "Match", "([]string, string, ...gin.HandlerFunc) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "Static", "(string, string) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "StaticFS", "(string, http.FileSystem) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "StaticFile", "(string, string) -> (gin.IRoutes)")
	assertMethodSignature(t, "Router", routerType, "StaticFileFS", "(string, string, http.FileSystem) -> (gin.IRoutes)")
}

func TestUpstreamStillMatchesExpectedBaselines(t *testing.T) {
	t.Parallel()

	contextType := reflect.TypeOf((*upstream.Context)(nil))
	assertMethodSignature(t, "UpstreamContext", contextType, "Param", "(string) -> (string)")
	assertMethodSignature(t, "UpstreamContext", contextType, "Error", "(error) -> (*gin.Error)")
	assertMethodSignature(t, "UpstreamContext", contextType, "Negotiate", "(int, gin.Negotiate)")
	assertMethodSignature(t, "UpstreamContext", contextType, "MustGet", "(interface {}) -> (interface {})")
}

func assertMethodSignature(t *testing.T, scope string, typ reflect.Type, methodName, want string) {
	t.Helper()

	method, ok := typ.MethodByName(methodName)
	if !ok {
		t.Fatalf("%s.%s is missing", scope, methodName)
	}
	if got := formatMethodSignature(method.Type); got != want {
		t.Fatalf("%s.%s signature = %s, want %s", scope, methodName, got, want)
	}
}

func formatMethodSignature(fnType reflect.Type) string {
	inCount := fnType.NumIn()
	inParts := make([]string, 0, inCount-1)
	for i := 1; i < inCount; i++ {
		part := fnType.In(i).String()
		if fnType.IsVariadic() && i == inCount-1 {
			part = "..." + fnType.In(i).Elem().String()
		}
		inParts = append(inParts, part)
	}

	outCount := fnType.NumOut()
	if outCount == 0 {
		return "(" + joinParts(inParts) + ")"
	}

	outParts := make([]string, 0, outCount)
	for i := 0; i < outCount; i++ {
		outParts = append(outParts, fnType.Out(i).String())
	}

	return "(" + joinParts(inParts) + ") -> (" + joinParts(outParts) + ")"
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}
