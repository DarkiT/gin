package gin

import (
	"context"

	"github.com/darkit/gin/pkg/mail"
)

func registerMailResource(e *Engine) {
	if e == nil || e.resources == nil {
		return
	}
	e.resources.register(managedResource{
		name: "mail-mailer",
		start: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.mailer != nil || isZeroMailConfig(engine.mailConfig) {
				return nil
			}

			mailer, err := mail.NewMailer(engine.mailConfig)
			if err != nil {
				return err
			}
			engine.mailer = mailer
			return nil
		},
		stop: func(_ context.Context, engine *Engine) error {
			if engine == nil || engine.mailer == nil {
				return nil
			}
			if pool := engine.mailer.SMTPPool(); pool != nil {
				if err := pool.Close(); err != nil {
					return err
				}
			}
			engine.mailer = nil
			return nil
		},
	})
}

func isZeroMailConfig(cfg mail.MailConfig) bool {
	return cfg == (mail.MailConfig{})
}
