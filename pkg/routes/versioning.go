package routes

import engine "github.com/darkit/gin"

func Version(r *engine.Router, v string) *engine.Router {
	if r == nil {
		return nil
	}
	return r.Version(v)
}

func VersionedAPI(r *engine.Router, v string, setup func(*engine.Router)) {
	if r == nil {
		return
	}
	r.VersionedAPI(v, setup)
}
