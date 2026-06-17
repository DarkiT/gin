package middleware

import (
	"fmt"
	"sync"
	"testing"

	"github.com/darkit/gin"
)

func TestRegistryRegisterGet(t *testing.T) {
	r := NewRegistry()

	mw := &Middleware{
		Name:    "test",
		Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} },
		Order:   5,
		Enabled: true,
	}
	r.Register(mw)

	if _, ok := r.Get("test"); !ok {
		t.Fatalf("expected middleware enabled")
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatalf("unexpected middleware")
	}
}

func TestRegistryEnableDisable(t *testing.T) {
	r := NewRegistry()

	r.Register(&Middleware{Name: "m1", Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} }, Order: 1, Enabled: false})
	if _, ok := r.Get("m1"); ok {
		t.Fatalf("expected disabled middleware")
	}

	r.Enable("m1")
	if _, ok := r.Get("m1"); !ok {
		t.Fatalf("expected enabled middleware")
	}

	r.Disable("m1")
	if _, ok := r.Get("m1"); ok {
		t.Fatalf("expected disabled middleware")
	}
}

func TestRegistryGetChainOrder(t *testing.T) {
	r := NewRegistry()
	r.Register(&Middleware{Name: "a", Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} }, Order: 20, Enabled: true})
	r.Register(&Middleware{Name: "b", Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} }, Order: 10, Enabled: true})
	r.Register(&Middleware{Name: "c", Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} }, Order: 30, Enabled: false})

	chain := r.GetChain()
	if len(chain) < 2 {
		t.Fatalf("expected at least 2 middlewares, got %d", len(chain))
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("mw-%d", i)
			r.Register(&Middleware{Name: name, Factory: func() gin.HandlerFunc { return func(c *gin.Context) {} }, Order: i, Enabled: true})
		}(i)
	}
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("mw-%d", i)
			r.Enable(name)
			r.Disable(name)
			_, _ = r.Get(name)
		}(i)
	}
	wg.Wait()
}
