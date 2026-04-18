package main

import (
	"reflect"

	darkgin "github.com/darkit/gin"
	upgin "github.com/gin-gonic/gin"
)

type namedTypePair struct {
	Local    reflect.Type
	Upstream reflect.Type
	Note     string
}

func namedTypePairs() map[string]namedTypePair {
	return map[string]namedTypePair{
		"Accounts": {
			Local:    reflect.TypeOf(darkgin.Accounts{}),
			Upstream: reflect.TypeOf(upgin.Accounts{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Context": {
			Local:    reflect.TypeOf((*darkgin.Context)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.Context)(nil)).Elem(),
			Note:     "同名 wrapper；本地 Context 嵌入原生 gin.Context 并增加增强方法。",
		},
		"ContextKeyType": {
			Local:    reflect.TypeOf(darkgin.ContextKeyType(0)),
			Upstream: reflect.TypeOf(upgin.ContextKeyType(0)),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Engine": {
			Local:    reflect.TypeOf((*darkgin.Engine)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.Engine)(nil)).Elem(),
			Note:     "同名 wrapper；本地 Engine 嵌入原生 gin.Engine 并挂接扩展组件。",
		},
		"Error": {
			Local:    reflect.TypeOf((*darkgin.Error)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.Error)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"ErrorType": {
			Local:    reflect.TypeOf(darkgin.ErrorType(0)),
			Upstream: reflect.TypeOf(upgin.ErrorType(0)),
			Note:     "通过类型别名直接对齐上游。",
		},
		"H": {
			Local:    reflect.TypeOf(darkgin.H{}),
			Upstream: reflect.TypeOf(upgin.H{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"HandlerFunc": {
			Local:    reflect.TypeOf((darkgin.HandlerFunc)(nil)),
			Upstream: reflect.TypeOf((upgin.HandlerFunc)(nil)),
			Note:     "同名新类型；本地签名绑定增强 Context。",
		},
		"HandlersChain": {
			Local:    reflect.TypeOf(darkgin.HandlersChain{}),
			Upstream: reflect.TypeOf(upgin.HandlersChain{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"IRouter": {
			Local:    reflect.TypeOf((*darkgin.IRouter)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.IRouter)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"IRoutes": {
			Local:    reflect.TypeOf((*darkgin.IRoutes)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.IRoutes)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LogFormatter": {
			Local:    reflect.TypeOf((darkgin.LogFormatter)(nil)),
			Upstream: reflect.TypeOf((upgin.LogFormatter)(nil)),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LogFormatterParams": {
			Local:    reflect.TypeOf((*darkgin.LogFormatterParams)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.LogFormatterParams)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LoggerConfig": {
			Local:    reflect.TypeOf(darkgin.LoggerConfig{}),
			Upstream: reflect.TypeOf(upgin.LoggerConfig{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Negotiate": {
			Local:    reflect.TypeOf(darkgin.Negotiate{}),
			Upstream: reflect.TypeOf(upgin.Negotiate{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"OnlyFilesFS": {
			Local:    reflect.TypeOf(darkgin.OnlyFilesFS{}),
			Upstream: reflect.TypeOf(upgin.OnlyFilesFS{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"OptionFunc": {
			Local:    reflect.TypeOf((darkgin.OptionFunc)(nil)),
			Upstream: reflect.TypeOf((upgin.OptionFunc)(nil)),
			Note:     "同名新类型；本地 OptionFunc 绑定增强 Engine，而不是上游 raw Engine。",
		},
		"Param": {
			Local:    reflect.TypeOf(darkgin.Param{}),
			Upstream: reflect.TypeOf(upgin.Param{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Params": {
			Local:    reflect.TypeOf(darkgin.Params{}),
			Upstream: reflect.TypeOf(upgin.Params{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RecoveryFunc": {
			Local:    reflect.TypeOf((darkgin.RecoveryFunc)(nil)),
			Upstream: reflect.TypeOf((upgin.RecoveryFunc)(nil)),
			Note:     "通过类型别名直接对齐上游。",
		},
		"ResponseWriter": {
			Local:    reflect.TypeOf((*darkgin.ResponseWriter)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.ResponseWriter)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RouteInfo": {
			Local:    reflect.TypeOf(darkgin.RouteInfo{}),
			Upstream: reflect.TypeOf(upgin.RouteInfo{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RouterGroup": {
			Local:    reflect.TypeOf((*darkgin.RouterGroup)(nil)).Elem(),
			Upstream: reflect.TypeOf((*upgin.RouterGroup)(nil)).Elem(),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RoutesInfo": {
			Local:    reflect.TypeOf(darkgin.RoutesInfo{}),
			Upstream: reflect.TypeOf(upgin.RoutesInfo{}),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Skipper": {
			Local:    reflect.TypeOf((darkgin.Skipper)(nil)),
			Upstream: reflect.TypeOf((upgin.Skipper)(nil)),
			Note:     "通过类型别名直接对齐上游。",
		},
	}
}
