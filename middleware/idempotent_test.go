package middleware

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/darkit/gin"
	"github.com/stretchr/testify/assert"
)

type testIdempotentStore struct {
	mu    sync.Mutex
	store map[string]testIdempotentEntry
}

type testIdempotentEntry struct {
	statusCode int
	body       []byte
	expiry     time.Time
	pending    bool
}

func newTestIdempotentStore() *testIdempotentStore {
	return &testIdempotentStore{store: make(map[string]testIdempotentEntry)}
}

func (s *testIdempotentStore) Get(key string) (int, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.store[key]
	if !exists {
		return 0, nil, false
	}
	if time.Now().After(entry.expiry) {
		return 0, nil, false
	}
	// pending 占位视为未命中，与 MemoryIdempotentStore 语义一致。
	if entry.pending {
		return 0, nil, false
	}
	return entry.statusCode, append([]byte(nil), entry.body...), true
}

// Reserve 与 MemoryIdempotentStore.Reserve 语义对齐，供并发测试使用。
func (s *testIdempotentStore) Reserve(key string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, exists := s.store[key]; exists && !time.Now().After(entry.expiry) {
		return false
	}
	s.store[key] = testIdempotentEntry{
		expiry:  time.Now().Add(ttl),
		pending: true,
	}
	return true
}

func (s *testIdempotentStore) Set(key string, statusCode int, body []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = testIdempotentEntry{
		statusCode: statusCode,
		body:       append([]byte(nil), body...),
		expiry:     time.Now().Add(ttl),
	}
	return nil
}

func (s *testIdempotentStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	return nil
}

func (s *testIdempotentStore) Close() error {
	return nil
}

func buildIdempotentKeyFromParts(method, path, requestKey, namespace string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(requestKey))
	h.Write([]byte{0})
	h.Write([]byte(namespace))
	return fmt.Sprintf("idempotent:%x", h.Sum(nil))
}

func TestIdempotent_FirstRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls int
	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusCreated, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("Idempotency-Key", "abc")
	e.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "ok", w.Body.String())
	assert.Equal(t, 1, calls)
}

func TestIdempotent_DuplicateRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls int
	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, fmt.Sprintf("call-%d", calls))
	})

	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req1.Header.Set("Idempotency-Key", "dup")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req2.Header.Set("Idempotency-Key", "dup")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "call-1", w1.Body.String())
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "call-1", w2.Body.String())
	assert.Equal(t, 1, calls)
}

func TestIdempotent_NoKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls int
	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, fmt.Sprintf("call-%d", calls))
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	e.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	e.ServeHTTP(w2, req2)

	assert.Equal(t, "call-1", w1.Body.String())
	assert.Equal(t, "call-2", w2.Body.String())
	assert.Equal(t, 2, calls)
}

func TestIdempotent_TTLExpiry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls int
	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store), WithIdempotentTTL(50*time.Millisecond)))
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, fmt.Sprintf("call-%d", calls))
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req1.Header.Set("Idempotency-Key", "ttl")
	e.ServeHTTP(w1, req1)

	time.Sleep(80 * time.Millisecond)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req2.Header.Set("Idempotency-Key", "ttl")
	e.ServeHTTP(w2, req2)

	assert.Equal(t, "call-1", w1.Body.String())
	assert.Equal(t, "call-2", w2.Body.String())
	assert.Equal(t, 2, calls)
}

func TestIdempotent_DifferentKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls int
	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, fmt.Sprintf("call-%d", calls))
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req1.Header.Set("Idempotency-Key", "key-a")
	e.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req2.Header.Set("Idempotency-Key", "key-b")
	e.ServeHTTP(w2, req2)

	assert.Equal(t, "call-1", w1.Body.String())
	assert.Equal(t, "call-2", w2.Body.String())
	assert.Equal(t, 2, calls)
}

func TestIdempotent_CustomStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestIdempotentStore()

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusAccepted, "stored")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("Idempotency-Key", "custom")
	e.ServeHTTP(w, req)

	status, body, exists := store.Get(buildIdempotentKeyFromParts(http.MethodPost, "/submit", "custom", ""))
	assert.True(t, exists)
	assert.Equal(t, http.StatusAccepted, status)
	assert.Equal(t, []byte("stored"), body)
}

func TestIdempotent_DefaultKeyIsNamespacedByMethodAndRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestIdempotentStore()
	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))

	var submitCalls int
	e.POST("/submit", func(c *gin.Context) {
		submitCalls++
		c.String(http.StatusOK, "submit-%d", submitCalls)
	})

	var cancelCalls int
	e.POST("/cancel", func(c *gin.Context) {
		cancelCalls++
		c.String(http.StatusOK, "cancel-%d", cancelCalls)
	})

	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req1.Header.Set("Idempotency-Key", "same")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/cancel", nil)
	req2.Header.Set("Idempotency-Key", "same")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	req3 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req3.Header.Set("Idempotency-Key", "same")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, req3)

	assert.Equal(t, "submit-1", w1.Body.String())
	assert.Equal(t, "cancel-1", w2.Body.String())
	assert.Equal(t, "submit-1", w3.Body.String())
	assert.Equal(t, 1, submitCalls)
	assert.Equal(t, 1, cancelCalls)
}

func TestIdempotent_NamespaceFuncPartitionsReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestIdempotentStore()
	e := gin.New()
	e.Use(Idempotent(
		WithIdempotentStore(store),
		WithIdempotentNamespaceFunc(func(c *gin.Context) string {
			return c.GetHeader("Authorization")
		}),
	))

	var calls int
	e.POST("/submit", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, c.GetHeader("Authorization")+":call-%d", calls)
	})

	req1 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req1.Header.Set("Idempotency-Key", "same")
	req1.Header.Set("Authorization", "Bearer user-a")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req2.Header.Set("Idempotency-Key", "same")
	req2.Header.Set("Authorization", "Bearer user-b")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	req3 := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req3.Header.Set("Idempotency-Key", "same")
	req3.Header.Set("Authorization", "Bearer user-a")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, req3)

	assert.Equal(t, "Bearer user-a:call-1", w1.Body.String())
	assert.Equal(t, "Bearer user-b:call-2", w2.Body.String())
	assert.Equal(t, "Bearer user-a:call-1", w3.Body.String())
	assert.Equal(t, 2, calls)
}

func TestIdempotent_DefaultKeyUsesRequestPathWithinRoutePattern(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestIdempotentStore()
	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))

	var calls int
	e.POST("/orders/:id", func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, "order-%s-call-%d", c.Param("id"), calls)
	})

	req1 := httptest.NewRequest(http.MethodPost, "/orders/1001", nil)
	req1.Header.Set("Idempotency-Key", "route-pattern")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/orders/2002", nil)
	req2.Header.Set("Idempotency-Key", "route-pattern")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	assert.Equal(t, "order-1001-call-1", w1.Body.String())
	assert.Equal(t, "order-2002-call-2", w2.Body.String())
	assert.Equal(t, 2, calls)
}

func TestIdempotent_DefaultKeyIsNamespacedByMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestIdempotentStore()
	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))

	var postCalls int
	e.POST("/resource", func(c *gin.Context) {
		postCalls++
		c.String(http.StatusOK, "post-%d", postCalls)
	})

	var putCalls int
	e.PUT("/resource", func(c *gin.Context) {
		putCalls++
		c.String(http.StatusOK, "put-%d", putCalls)
	})

	req1 := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req1.Header.Set("Idempotency-Key", "same")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodPut, "/resource", nil)
	req2.Header.Set("Idempotency-Key", "same")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	req3 := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req3.Header.Set("Idempotency-Key", "same")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, req3)

	assert.Equal(t, "post-1", w1.Body.String())
	assert.Equal(t, "put-1", w2.Body.String())
	assert.Equal(t, "post-1", w3.Body.String())
	assert.Equal(t, 1, postCalls)
	assert.Equal(t, 1, putCalls)
}

// TestIdempotent_AbortReleasesReservation 验证 handler abort 后 pending 占位被释放，
// 后续相同 key 请求可重试（而非被 5min TTL 内全部 409 锁死）。
func TestIdempotent_AbortReleasesReservation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newTestIdempotentStore()
	calls := 0

	e := gin.New()
	e.Use(Idempotent(WithIdempotentStore(store)))
	e.POST("/pay", func(c *gin.Context) {
		calls++
		if calls == 1 {
			// 首次模拟业务失败并 abort（不缓存、应允许重试）
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "boom"})
			return
		}
		c.String(http.StatusOK, "ok")
	})

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/pay", nil)
		req.Header.Set("Idempotency-Key", "retry-key")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		return w
	}

	w1 := do()
	assert.Equal(t, http.StatusInternalServerError, w1.Code)

	// 第二次不应被 409 锁死，占位已在首次 abort 后释放，可正常重试成功
	w2 := do()
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "ok", w2.Body.String())
	assert.Equal(t, 2, calls)
}
