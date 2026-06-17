package gin

import (
	"context"

	"github.com/darkit/gin/auth"
)

func registerAuthResource(e *Engine) {
	if e == nil || e.resources == nil {
		return
	}
	e.resources.register(managedResource{
		name: "auth-manager",
		start: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.authConfig == nil || engine.authManager != nil {
				return nil
			}

			cfg := *engine.authConfig
			storage := cfg.Storage
			if storage == nil {
				storage = auth.NewMemoryStorage()
			}
			engine.authManager = auth.NewManager(storage, &cfg)
			return nil
		},
		stop: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.authManager == nil {
				return nil
			}
			engine.authManager.CloseManager()
			engine.authManager = nil
			return nil
		},
	})
}
