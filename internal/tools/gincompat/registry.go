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
			Local:    reflect.TypeFor[darkgin.Accounts](),
			Upstream: reflect.TypeFor[upgin.Accounts](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Context": {
			Local:    reflect.TypeFor[darkgin.Context](),
			Upstream: reflect.TypeFor[upgin.Context](),
			Note:     "同名 wrapper；本地 Context 嵌入原生 gin.Context 并增加增强方法。",
		},
		"ContextKeyType": {
			Local:    reflect.TypeFor[darkgin.ContextKeyType](),
			Upstream: reflect.TypeFor[upgin.ContextKeyType](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Engine": {
			Local:    reflect.TypeFor[darkgin.Engine](),
			Upstream: reflect.TypeFor[upgin.Engine](),
			Note:     "同名 wrapper；本地 Engine 嵌入原生 gin.Engine 并挂接扩展组件。",
		},
		"Error": {
			Local:    reflect.TypeFor[darkgin.Error](),
			Upstream: reflect.TypeFor[upgin.Error](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"ErrorType": {
			Local:    reflect.TypeFor[darkgin.ErrorType](),
			Upstream: reflect.TypeFor[upgin.ErrorType](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"H": {
			Local:    reflect.TypeFor[darkgin.H](),
			Upstream: reflect.TypeFor[upgin.H](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"HandlerFunc": {
			Local:    reflect.TypeFor[darkgin.HandlerFunc](),
			Upstream: reflect.TypeFor[upgin.HandlerFunc](),
			Note:     "同名新类型；本地签名绑定增强 Context。",
		},
		"HandlersChain": {
			Local:    reflect.TypeFor[darkgin.HandlersChain](),
			Upstream: reflect.TypeFor[upgin.HandlersChain](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"IRouter": {
			Local:    reflect.TypeFor[darkgin.IRouter](),
			Upstream: reflect.TypeFor[upgin.IRouter](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"IRoutes": {
			Local:    reflect.TypeFor[darkgin.IRoutes](),
			Upstream: reflect.TypeFor[upgin.IRoutes](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LogFormatter": {
			Local:    reflect.TypeFor[darkgin.LogFormatter](),
			Upstream: reflect.TypeFor[upgin.LogFormatter](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LogFormatterParams": {
			Local:    reflect.TypeFor[darkgin.LogFormatterParams](),
			Upstream: reflect.TypeFor[upgin.LogFormatterParams](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"LoggerConfig": {
			Local:    reflect.TypeFor[darkgin.LoggerConfig](),
			Upstream: reflect.TypeFor[upgin.LoggerConfig](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Negotiate": {
			Local:    reflect.TypeFor[darkgin.Negotiate](),
			Upstream: reflect.TypeFor[upgin.Negotiate](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"OnlyFilesFS": {
			Local:    reflect.TypeFor[darkgin.OnlyFilesFS](),
			Upstream: reflect.TypeFor[upgin.OnlyFilesFS](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"OptionFunc": {
			Local:    reflect.TypeFor[darkgin.OptionFunc](),
			Upstream: reflect.TypeFor[upgin.OptionFunc](),
			Note:     "同名新类型；本地 OptionFunc 绑定增强 Engine，而不是上游 raw Engine。",
		},
		"Param": {
			Local:    reflect.TypeFor[darkgin.Param](),
			Upstream: reflect.TypeFor[upgin.Param](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Params": {
			Local:    reflect.TypeFor[darkgin.Params](),
			Upstream: reflect.TypeFor[upgin.Params](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RecoveryFunc": {
			Local:    reflect.TypeFor[darkgin.RecoveryFunc](),
			Upstream: reflect.TypeFor[upgin.RecoveryFunc](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"ResponseWriter": {
			Local:    reflect.TypeFor[darkgin.ResponseWriter](),
			Upstream: reflect.TypeFor[upgin.ResponseWriter](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RouteInfo": {
			Local:    reflect.TypeFor[darkgin.RouteInfo](),
			Upstream: reflect.TypeFor[upgin.RouteInfo](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RouterGroup": {
			Local:    reflect.TypeFor[darkgin.RouterGroup](),
			Upstream: reflect.TypeFor[upgin.RouterGroup](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"RoutesInfo": {
			Local:    reflect.TypeFor[darkgin.RoutesInfo](),
			Upstream: reflect.TypeFor[upgin.RoutesInfo](),
			Note:     "通过类型别名直接对齐上游。",
		},
		"Skipper": {
			Local:    reflect.TypeFor[darkgin.Skipper](),
			Upstream: reflect.TypeFor[upgin.Skipper](),
			Note:     "通过类型别名直接对齐上游。",
		},
	}
}
