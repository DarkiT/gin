package main

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/routes"
)

// DemoState 保存示例中的探针状态。
type DemoState struct {
	databaseReady atomic.Bool
	cacheReady    atomic.Bool
	started       atomic.Bool
}

func main() {
	state := &DemoState{}
	state.databaseReady.Store(true)
	state.cacheReady.Store(true)
	state.started.Store(false)

	go func() {
		time.Sleep(5 * time.Second)
		state.started.Store(true)
	}()

	e := gin.Default(
		gin.WithAddr(":8080"),
	)
	r := e.Router()

	routes.HealthCheck(r)
	routes.Liveness(r)
	routes.Readiness(
		r,
		routes.NamedProbe("database", func(c *gin.Context) error {
			if !state.databaseReady.Load() {
				return errors.New("database is not ready")
			}
			return nil
		}),
		routes.NamedProbe("cache", func(c *gin.Context) error {
			if !state.cacheReady.Load() {
				return errors.New("cache is not ready")
			}
			return nil
		}),
	)
	routes.Startup(
		r,
		routes.NamedProbe("bootstrap", func(c *gin.Context) error {
			if !state.started.Load() {
				return errors.New("application is still starting")
			}
			return nil
		}),
	)

	r.GET("/status", func(c *gin.Context) {
		c.Success(gin.H{
			"database_ready": state.databaseReady.Load(),
			"cache_ready":    state.cacheReady.Load(),
			"started":        state.started.Load(),
		})
	})

	r.POST("/admin/:component/:action", func(c *gin.Context) {
		component := c.Param("component")
		action := c.Param("action")
		value, ok := actionToState(action)
		if !ok {
			c.BadRequest("action 仅支持 up/down")
			return
		}

		switch component {
		case "database":
			state.databaseReady.Store(value)
		case "cache":
			state.cacheReady.Store(value)
		case "startup":
			state.started.Store(value)
		default:
			c.BadRequest("component 仅支持 database/cache/startup")
			return
		}

		c.Success(gin.H{
			"component": component,
			"value":     value,
		})
	})

	fmt.Println("Probe example is running on http://localhost:8080")
	fmt.Println("  - GET  /health")
	fmt.Println("  - GET  /livez")
	fmt.Println("  - GET  /readyz")
	fmt.Println("  - GET  /startupz")
	fmt.Println("  - GET  /status")
	fmt.Println("  - POST /admin/:component/:action")

	if err := e.Run(); err != nil {
		panic(err)
	}
}

func actionToState(action string) (bool, bool) {
	switch action {
	case "up":
		return true, true
	case "down":
		return false, true
	default:
		return false, false
	}
}
