package gin

import (
	"context"
	"errors"
	"time"

	"github.com/darkit/gin/pkg/cache"
)

// ErrNilCache 表示传入 Engine 的缓存实现为空。
var ErrNilCache = errors.New("gin: cache is nil")

// noopCache 是 Engine 停止后使用的空缓存占位。
// 它让 c.Cache() 在生命周期停止后仍返回非 nil 对象，同时所有读写都显式失败。
type noopCache struct{}

func (noopCache) Get(context.Context, string) ([]byte, error) { return nil, cache.ErrClosed }

func (noopCache) Set(context.Context, string, []byte, time.Duration) error { return cache.ErrClosed }

func (noopCache) Delete(context.Context, string) error { return cache.ErrClosed }

func (noopCache) Clear(context.Context) error { return cache.ErrClosed }
func (noopCache) Close() error                { return nil }

func registerCacheResource(e *Engine) {
	if e == nil || e.resources == nil {
		return
	}
	e.resources.register(managedResource{
		name: "cache",
		start: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.cache != nil {
				return nil
			}
			return ErrNilCache
		},
		stop: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.cache == nil {
				return nil
			}
			current := engine.cache
			if _, ok := current.(noopCache); ok {
				return nil
			}
			if err := current.Close(); err != nil {
				return err
			}
			engine.cache = noopCache{}
			return nil
		},
	})
}

func setEngineCache(e *Engine, c cache.Cache) {
	if c == nil {
		panic(ErrNilCache)
	}
	if e == nil {
		return
	}
	e.cache = c
}
