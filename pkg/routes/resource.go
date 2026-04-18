package routes

import engine "github.com/darkit/gin"

type (
	ResourceController = engine.ResourceController
	ResourceOption     = engine.ResourceOption
)

var WithIDParam = engine.WithIDParam

func Resource(r *engine.Router, name string, ctrl ResourceController, opts ...ResourceOption) {
	if r == nil {
		return
	}
	r.Resource(name, ctrl, opts...)
}

func CRUD(r *engine.Router, name string, ctrl ResourceController) {
	if r == nil {
		return
	}
	r.CRUD(name, ctrl)
}
