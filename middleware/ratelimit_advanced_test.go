package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

type fakeRateLimitStore struct {
	allow bool
	calls int
}

func (s *fakeRateLimitStore) Allow(_ string, _ float64, _ int) bool {
	s.calls++
	return s.allow
}

func (s *fakeRateLimitStore) Close() error {
	return nil
}

func TestRateLimitByUser_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u1")
		c.Next()
	})
	r.Use(RateLimitByUser("1-S", WithRateLimitBurst(1)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request ok, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
}

func TestRateLimitByKey_CustomExtractor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RateLimitByKey(func(c *gin.Context) string {
		return c.GetHeader("X-API-Key")
	}, "1-S", WithRateLimitBurst(1)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-API-Key", "k1")
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request ok, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-API-Key", "k1")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
}

func TestRateLimitTier_DifferentRates(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", c.GetHeader("X-User"))
		c.Set("user_tier", c.GetHeader("X-Tier"))
		c.Next()
	})
	r.Use(RateLimitTier(map[string]float64{
		"free": 1,
		"pro":  5,
	}, func(c *gin.Context) string {
		return c.GetString("user_tier")
	}, WithRateLimitBurst(1)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	freeReq1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-User", "u-free")
	req1.Header.Set("X-Tier", "free")
	r.ServeHTTP(freeReq1, req1)
	if freeReq1.Code != http.StatusOK {
		t.Fatalf("expected free first ok, got %d", freeReq1.Code)
	}

	freeReq2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-User", "u-free")
	req2.Header.Set("X-Tier", "free")
	r.ServeHTTP(freeReq2, req2)
	if freeReq2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected free second 429, got %d", freeReq2.Code)
	}

	proReq1 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("X-User", "u-pro")
	req3.Header.Set("X-Tier", "pro")
	r.ServeHTTP(proReq1, req3)
	if proReq1.Code != http.StatusOK {
		t.Fatalf("expected pro first ok, got %d", proReq1.Code)
	}
}

func TestRateLimitTier_DefaultTier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-default")
		c.Next()
	})
	r.Use(RateLimitTier(map[string]float64{}, nil, WithRateLimitBurst(1)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request ok, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
}

func TestRateLimitAdvanced_Burst(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-burst")
		c.Next()
	})
	r.Use(RateLimitByUser("1000-S", WithRateLimitBurst(2)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected ok, got %d", w.Code)
		}
	}

	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w3.Code)
	}
}

func TestRateLimitAdvanced_DistributedStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := &fakeRateLimitStore{allow: false}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-store")
		c.Next()
	})
	r.Use(RateLimitByUser("1-S", WithRateLimitStore(store), WithRateLimitBurst(1)))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}

	if store.calls != 1 {
		t.Fatalf("expected store called once, got %d", store.calls)
	}
}

func TestRateLimitAdvanced_OnLimitCallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	triggered := 0
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-callback")
		c.Next()
	})
	r.Use(RateLimitByUser("1-S", WithRateLimitBurst(1), WithRateLimitOnLimit(func(c *gin.Context) {
		triggered++
		c.AbortWithStatus(http.StatusTooManyRequests)
	})))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first ok, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}

	if triggered != 1 {
		t.Fatalf("expected callback once, got %d", triggered)
	}
}
