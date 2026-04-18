package middleware

import (
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
	return entry.statusCode, append([]byte(nil), entry.body...), true
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

	status, body, exists := store.Get("custom")
	assert.True(t, exists)
	assert.Equal(t, http.StatusAccepted, status)
	assert.Equal(t, []byte("stored"), body)
}
