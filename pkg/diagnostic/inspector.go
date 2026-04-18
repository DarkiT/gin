package diagnostic

import (
	"fmt"
	"runtime"
	"sort"
	"time"

	engine "github.com/darkit/gin"
	"github.com/gin-gonic/gin"
)

type Inspector struct {
	engine    *engine.Engine
	startTime time.Time
}

type MemoryStats struct {
	Alloc      uint64 `json:"alloc"`
	TotalAlloc uint64 `json:"total_alloc"`
	Sys        uint64 `json:"sys"`
	NumGC      uint32 `json:"num_gc"`
}

type RoutesInfo struct {
	Count int      `json:"count"`
	Items []string `json:"items"`
}

type Status struct {
	Uptime       string       `json:"uptime"`
	Version      string       `json:"version"`
	GoVersion    string       `json:"go_version"`
	NumGoroutine int          `json:"num_goroutine"`
	Memory       *MemoryStats `json:"memory"`
	Routes       *RoutesInfo  `json:"routes"`
}

func NewInspector(e *engine.Engine) *Inspector {
	return &Inspector{engine: e, startTime: time.Now()}
}

func (i *Inspector) GetStatus() *Status {
	mem := runtime.MemStats{}
	runtime.ReadMemStats(&mem)

	routes := i.routesInfo()
	return &Status{
		Uptime:       time.Since(i.startTime).String(),
		Version:      i.version(),
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		Memory: &MemoryStats{
			Alloc:      mem.Alloc,
			TotalAlloc: mem.TotalAlloc,
			Sys:        mem.Sys,
			NumGC:      mem.NumGC,
		},
		Routes: routes,
	}
}

func (i *Inspector) PrintRoutes() {
	if i.engine == nil {
		return
	}
	for _, info := range i.engine.Routes() {
		fmt.Printf("%s %s -> %s\n", info.Method, info.Path, info.Handler)
	}
}

func (i *Inspector) routesInfo() *RoutesInfo {
	if i.engine == nil {
		return &RoutesInfo{}
	}
	items := make([]string, 0)
	for _, info := range i.engine.Routes() {
		items = append(items, fmt.Sprintf("%s %s", info.Method, info.Path))
	}
	sort.Strings(items)
	return &RoutesInfo{
		Count: len(items),
		Items: items,
	}
}

func (i *Inspector) version() string {
	if i.engine == nil {
		return ""
	}
	return gin.Version
}

func (i *Inspector) Handler() engine.HandlerFunc {
	return func(c *engine.Context) {
		c.JSON(200, i.GetStatus())
	}
}
