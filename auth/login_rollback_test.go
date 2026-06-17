package auth

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type failingLoginStorage struct {
	mu       sync.Mutex
	data     map[string]any
	setCalls int
	failSet  int
	failErr  error
}

func newFailingLoginStorage(failSet int) *failingLoginStorage {
	return &failingLoginStorage{
		data:    make(map[string]any),
		failSet: failSet,
		failErr: errors.New("injected set failure"),
	}
}

func (s *failingLoginStorage) Set(key string, value any, expiration time.Duration) error {
	_ = expiration
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setCalls++
	if s.failSet > 0 && s.setCalls == s.failSet {
		return s.failErr
	}
	s.data[key] = value
	return nil
}

func (s *failingLoginStorage) SetKeepTTL(key string, value any) error {
	return s.Set(key, value, 0)
}

func (s *failingLoginStorage) Get(key string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return value, nil
}

func (s *failingLoginStorage) Delete(keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		delete(s.data, key)
	}
	return nil
}

func (s *failingLoginStorage) Exists(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	return ok
}

func (s *failingLoginStorage) Keys(pattern string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		if wildcardMatch(pattern, key) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (s *failingLoginStorage) Expire(key string, expiration time.Duration) error {
	_ = expiration
	if !s.Exists(key) {
		return errors.New("key not found")
	}
	return nil
}

func (s *failingLoginStorage) TTL(key string) (time.Duration, error) {
	if !s.Exists(key) {
		return -2 * time.Second, errors.New("key not found")
	}
	return -1 * time.Second, nil
}

func (s *failingLoginStorage) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]any)
	return nil
}

func (s *failingLoginStorage) Ping() error { return nil }

func (s *failingLoginStorage) keysSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		keys = append(keys, key)
	}
	return keys
}

func wildcardMatch(pattern, key string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(key, before)
	}
	return pattern == key
}

func TestLoginRollsBackTokenWhenAccountMappingFails(t *testing.T) {
	store := newFailingLoginStorage(2)
	cfg := DefaultAuthConfig()
	cfg.ShareToken = false
	cfg.KeyPrefix = "rollback:"
	mgr := NewManager(store, &cfg)

	_, err := mgr.Login("user-rollback", "web")
	if err == nil || !strings.Contains(err.Error(), "failed to save account mapping") {
		t.Fatalf("Login() error = %v, want account mapping failure", err)
	}
	if keys := store.keysSnapshot(); len(keys) != 0 {
		t.Fatalf("storage keys after rollback = %v, want empty", keys)
	}
}

func TestLoginRollsBackTokenAndAccountWhenSessionFails(t *testing.T) {
	store := newFailingLoginStorage(3)
	cfg := DefaultAuthConfig()
	cfg.ShareToken = false
	cfg.KeyPrefix = "rollback:"
	mgr := NewManager(store, &cfg)

	_, err := mgr.Login("user-rollback", "web")
	if err == nil || !strings.Contains(err.Error(), "failed to save session") {
		t.Fatalf("Login() error = %v, want session failure", err)
	}
	if keys := store.keysSnapshot(); len(keys) != 0 {
		t.Fatalf("storage keys after rollback = %v, want empty", keys)
	}
}
