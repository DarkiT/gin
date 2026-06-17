package gin

import (
	"context"

	"github.com/darkit/gin/pkg/sms"
)

func registerSMSResource(e *Engine) {
	if e == nil || e.resources == nil {
		return
	}
	e.resources.register(managedResource{
		name: "sms-service",
		start: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.smsService != nil || isZeroSMSConfig(engine.smsConfig) {
				return nil
			}

			service, err := sms.NewService(engine.smsConfig)
			if err != nil {
				return err
			}
			engine.smsService = service
			return nil
		},
		stop: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.smsService == nil {
				return nil
			}
			engine.smsService.Close()
			engine.smsService = nil
			return nil
		},
	})
}

func isZeroSMSConfig(cfg sms.SMSConfig) bool {
	return cfg == (sms.SMSConfig{})
}
