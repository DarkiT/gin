package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	darkgin "github.com/darkit/gin"
	upgin "github.com/gin-gonic/gin"
)

func compareAllMethods() []methodReport {
	return []methodReport{
		compareMethods(
			"Context",
			reflect.TypeFor[*darkgin.Context](),
			reflect.TypeFor[*upgin.Context](),
			"同名 wrapper，嵌入原生 gin.Context 并补充增强能力。",
		),
		compareMethods(
			"Engine",
			reflect.TypeFor[*darkgin.Engine](),
			reflect.TypeFor[*upgin.Engine](),
			"同名 wrapper，嵌入原生 gin.Engine 并增加生命周期、缓存、日志等扩展。",
		),
		compareMethods(
			"Router",
			reflect.TypeFor[*darkgin.Router](),
			reflect.TypeFor[*upgin.RouterGroup](),
			"扩展框架的主路由入口是 Router；上游对应公共入口是 RouterGroup。",
		),
	}
}

func collectPackageExports(dir string) (map[string]exportSymbol, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("目录 %s 中未找到 package", dir)
	}

	var pkg *ast.Package
	for _, candidate := range pkgs {
		pkg = candidate
		break
	}

	exports := make(map[string]exportSymbol)
	for fileName, file := range pkg.Files {
		relFile := filepath.Base(fileName)
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				switch d.Tok.String() {
				case "const", "var":
					collectValueExports(exports, d, relFile)
				case "type":
					collectTypeExports(exports, d, relFile)
				}
			case *ast.FuncDecl:
				if d.Recv == nil && ast.IsExported(d.Name.Name) {
					exports[d.Name.Name] = exportSymbol{Name: d.Name.Name, Kind: "func", File: relFile}
				}
			}
		}
	}

	return exports, nil
}

func collectValueExports(exports map[string]exportSymbol, decl *ast.GenDecl, file string) {
	kind := decl.Tok.String()
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range valueSpec.Names {
			if ast.IsExported(name.Name) {
				exports[name.Name] = exportSymbol{Name: name.Name, Kind: kind, File: file}
			}
		}
	}
}

func collectTypeExports(exports map[string]exportSymbol, decl *ast.GenDecl, file string) {
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		if ast.IsExported(typeSpec.Name.Name) {
			exports[typeSpec.Name.Name] = exportSymbol{Name: typeSpec.Name.Name, Kind: "type", File: file}
		}
	}
}

func comparePackageExports(local, upstream map[string]exportSymbol) packageReport {
	typePairs := namedTypePairs()
	rep := packageReport{
		UpstreamExports: len(upstream),
		LocalExports:    len(local),
	}

	for _, name := range sortedKeys(upstream) {
		upSym := upstream[name]
		localSym, ok := local[name]
		if !ok {
			rep.Missing = append(rep.Missing, symbolFinding{
				Name:         name,
				UpstreamKind: upSym.Kind,
				Status:       "missing",
				Note:         "上游公开名未在本地根包公开。",
			})
			continue
		}

		finding := symbolFinding{
			Name:         name,
			UpstreamKind: upSym.Kind,
			LocalKind:    localSym.Kind,
		}

		switch {
		case upSym.Kind != localSym.Kind:
			finding.Status = "mapped"
			finding.Note = "名字已保留，但声明种类不同，通常是通过 var 函数别名做兼容桥接。"
			rep.Mapped = append(rep.Mapped, finding)
		case upSym.Kind == "type" && isDivergentNamedType(typePairs, name):
			finding.Status = "mapped"
			finding.Note = typePairs[name].Note
			rep.Mapped = append(rep.Mapped, finding)
		default:
			finding.Status = "synced"
			finding.Note = "根包已公开同名符号。"
			rep.Synced = append(rep.Synced, finding)
		}
	}

	for _, name := range sortedKeys(local) {
		if _, ok := upstream[name]; ok {
			continue
		}
		localSym := local[name]
		rep.LocalOnly = append(rep.LocalOnly, symbolFinding{
			Name:      name,
			LocalKind: localSym.Kind,
			Status:    "local_only",
			Note:      "扩展框架新增公开能力。",
		})
	}

	return rep
}

func isDivergentNamedType(pairs map[string]namedTypePair, name string) bool {
	pair, ok := pairs[name]
	return ok && pair.Local != nil && pair.Upstream != nil && pair.Local != pair.Upstream
}

func compareNamedTypes() namedTypeReport {
	pairs := namedTypePairs()
	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)

	rep := namedTypeReport{}
	for _, name := range names {
		pair := pairs[name]
		finding := typeFinding{
			Name:         name,
			LocalType:    typeIdentity(pair.Local),
			UpstreamType: typeIdentity(pair.Upstream),
			Note:         pair.Note,
		}
		if pair.Local == pair.Upstream {
			finding.Status = "synced"
			rep.Synced = append(rep.Synced, finding)
			continue
		}
		finding.Status = "divergent"
		rep.Divergent = append(rep.Divergent, finding)
	}
	return rep
}

func compareMethods(typeName string, local, upstream reflect.Type, note string) methodReport {
	localMethods := collectMethods(local)
	upstreamMethods := collectMethods(upstream)
	mappedMethods := compatibleMappedMethods(typeName)

	report := methodReport{
		TypeName:       typeName,
		LocalMethodSet: typeIdentity(local),
		UpstreamType:   typeIdentity(upstream),
		Note:           note,
	}

	for _, name := range sortedMethodKeys(upstreamMethods) {
		upMethod := upstreamMethods[name]
		localMethod, ok := localMethods[name]
		if !ok {
			report.UpstreamOnly = append(report.UpstreamOnly, methodFinding{
				Name:              name,
				UpstreamSignature: upMethod,
				Status:            "upstream_only",
				Note:              "上游方法未出现在本地 wrapper 方法集中。",
			})
			continue
		}

		if localMethod == upMethod {
			report.SyncedCount++
			continue
		}

		if mapped, ok := mappedMethods[name]; ok {
			report.Mapped = append(report.Mapped, methodFinding{
				Name:              name,
				LocalSignature:    localMethod,
				UpstreamSignature: upMethod,
				Status:            "mapped",
				Note:              mapped,
			})
			continue
		}

		report.Incompatible = append(report.Incompatible, methodFinding{
			Name:              name,
			LocalSignature:    localMethod,
			UpstreamSignature: upMethod,
			Status:            "incompatible",
			Note:              "同名方法存在，但签名或关联类型已改变。",
		})
	}

	for _, name := range sortedMethodKeys(localMethods) {
		if _, ok := upstreamMethods[name]; ok {
			continue
		}
		report.LocalOnly = append(report.LocalOnly, methodFinding{
			Name:           name,
			LocalSignature: localMethods[name],
			Status:         "local_only",
			Note:           "扩展框架新增方法。",
		})
	}

	return report
}

func compatibleMappedMethods(typeName string) map[string]string {
	switch typeName {
	case "Context":
		return map[string]string{
			"Copy":    "返回增强 Context wrapper，内部仍携带上游 *gin.Context 副本，用于保持扩展能力。",
			"Handler": "返回增强 HandlerFunc，底层继续包装当前 gin.HandlerFunc。",
		}
	case "Engine":
		return map[string]string{
			"Any":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"DELETE":       "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"GET":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Group":        "返回增强 RouterGroup wrapper，内部承载上游 RouterGroup 并保留扩展能力。",
			"HEAD":         "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Handle":       "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Match":        "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"OPTIONS":      "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"PATCH":        "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"POST":         "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"PUT":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Static":       "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFS":     "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFile":   "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFileFS": "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"Use":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"With":         "本地 OptionFunc 绑定增强 Engine；调用形态与上游一致，配置目标不同。",
		}
	case "Router":
		return map[string]string{
			"Any":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"DELETE":       "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"GET":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Group":        "返回增强 RouterGroup wrapper，内部承载上游 RouterGroup 并保留扩展能力。",
			"HEAD":         "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Handle":       "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Match":        "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"OPTIONS":      "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"PATCH":        "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"POST":         "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"PUT":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
			"Static":       "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFS":     "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFile":   "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"StaticFileFS": "返回增强 IRoutes；静态资源注册语义委托给上游 Gin。",
			"Use":          "参数与返回值映射到本项目增强 HandlerFunc/IRoutes；调用方式与上游一致。",
		}
	default:
		return nil
	}
}

func collectMethods(t reflect.Type) map[string]string {
	methods := make(map[string]string, t.NumMethod())
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		methods[method.Name] = methodSignature(method.Type)
	}
	return methods
}

func methodSignature(t reflect.Type) string {
	inputs := make([]string, 0, t.NumIn())
	for i := 1; i < t.NumIn(); i++ {
		isVariadic := t.IsVariadic() && i == t.NumIn()-1
		inputs = append(inputs, typeIdentityWithVariadic(t.In(i), isVariadic))
	}
	outputs := make([]string, 0, t.NumOut())
	for i := 0; i < t.NumOut(); i++ {
		outputs = append(outputs, typeIdentity(t.Out(i)))
	}
	if len(outputs) == 0 {
		return fmt.Sprintf("(%s)", strings.Join(inputs, ", "))
	}
	return fmt.Sprintf("(%s) -> (%s)", strings.Join(inputs, ", "), strings.Join(outputs, ", "))
}

func typeIdentityWithVariadic(t reflect.Type, variadic bool) string {
	if variadic && t.Kind() == reflect.Slice {
		return "..." + typeIdentity(t.Elem())
	}
	return typeIdentity(t)
}

func typeIdentity(t reflect.Type) string {
	if t.Name() != "" {
		if pkg := t.PkgPath(); pkg != "" {
			return pkg + "." + t.Name()
		}
		return t.Name()
	}

	switch t.Kind() {
	case reflect.Pointer:
		return "*" + typeIdentity(t.Elem())
	case reflect.Slice:
		return "[]" + typeIdentity(t.Elem())
	case reflect.Array:
		return fmt.Sprintf("[%d]%s", t.Len(), typeIdentity(t.Elem()))
	case reflect.Map:
		return fmt.Sprintf("map[%s]%s", typeIdentity(t.Key()), typeIdentity(t.Elem()))
	case reflect.Chan:
		return channelTypeIdentity(t)
	case reflect.Func:
		return t.String()
	default:
		return t.String()
	}
}

func channelTypeIdentity(t reflect.Type) string {
	prefix := "chan "
	switch t.ChanDir() {
	case reflect.RecvDir:
		prefix = "<-chan "
	case reflect.SendDir:
		prefix = "chan<- "
	}
	return prefix + typeIdentity(t.Elem())
}

func sortedKeys(m map[string]exportSymbol) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedMethodKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
