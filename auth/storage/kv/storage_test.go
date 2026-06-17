package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/darkit/gin/auth/core/manager"
	"github.com/darkit/gin/pkg/storage"
)

type fullStore struct {
	mu         sync.RWMutex
	data       map[string][]byte
	expires    map[string]time.Time
	existsHits int
	pingHits   int
}

type atomicFullStore struct {
	*fullStore
}

func newFullStore() *fullStore {
	return &fullStore{
		data:    make(map[string][]byte),
		expires: make(map[string]time.Time),
	}
}

func newAtomicFullStore() *atomicFullStore {
	return &atomicFullStore{fullStore: newFullStore()}
}

func (s *fullStore) Get(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiredLocked(key) {
		delete(s.data, key)
		delete(s.expires, key)
		return nil, nil
	}
	val, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (s *fullStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte(nil), val...)
	if ttl > 0 {
		s.expires[key] = time.Now().Add(ttl)
	} else {
		delete(s.expires, key)
	}
	return nil
}

func (s *fullStore) Delete(ctx context.Context, key string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	delete(s.expires, key)
	return nil
}

func (s *fullStore) Clear(ctx context.Context) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string][]byte)
	s.expires = make(map[string]time.Time)
	return nil
}

func (s *fullStore) Close() error { return nil }

func (s *fullStore) Exists(ctx context.Context, key string) (bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.existsHits++
	if s.expiredLocked(key) {
		delete(s.data, key)
		delete(s.expires, key)
		return false, nil
	}
	_, ok := s.data[key]
	return ok, nil
}

func (s *fullStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		if s.expiredLocked(key) {
			delete(s.data, key)
			delete(s.expires, key)
			continue
		}
		if matchPattern(key, pattern) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *fullStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	if ttl > 0 {
		s.expires[key] = time.Now().Add(ttl)
	} else {
		delete(s.expires, key)
	}
	return nil
}

func (s *fullStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiredLocked(key) {
		delete(s.data, key)
		delete(s.expires, key)
		return -2 * time.Second, nil
	}
	if _, ok := s.data[key]; !ok {
		return -2 * time.Second, fmt.Errorf("key not found: %s", key)
	}
	exp, ok := s.expires[key]
	if !ok {
		return -1 * time.Second, nil
	}
	return time.Until(exp), nil
}

func (s *fullStore) SetKeepTTL(ctx context.Context, key string, val []byte) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	s.data[key] = append([]byte(nil), val...)
	return nil
}

func (s *fullStore) Ping(ctx context.Context) error {
	_ = ctx
	s.pingHits++
	return nil
}

func (s *atomicFullStore) SetNX(ctx context.Context, key string, val []byte, ttl time.Duration) (bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiredLocked(key) {
		delete(s.data, key)
		delete(s.expires, key)
	}
	if _, ok := s.data[key]; ok {
		return false, nil
	}
	s.data[key] = append([]byte(nil), val...)
	if ttl > 0 {
		s.expires[key] = time.Now().Add(ttl)
	} else {
		delete(s.expires, key)
	}
	return true, nil
}

func (s *fullStore) expiredLocked(key string) bool {
	exp, ok := s.expires[key]
	return ok && time.Now().After(exp)
}

type minimalStore struct {
	data map[string][]byte
}

func newMinimalStore() *minimalStore { return &minimalStore{data: make(map[string][]byte)} }

func (s *minimalStore) Get(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	val, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (s *minimalStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	_, _ = ctx, ttl
	s.data[key] = append([]byte(nil), val...)
	return nil
}

func (s *minimalStore) Delete(ctx context.Context, key string) error {
	_ = ctx
	delete(s.data, key)
	return nil
}

func (s *minimalStore) Clear(ctx context.Context) error {
	_ = ctx
	s.data = make(map[string][]byte)
	return nil
}
func (s *minimalStore) Close() error { return nil }

type binaryValue struct{ Name string }

func (v binaryValue) MarshalBinary() ([]byte, error) { return []byte("bin:" + v.Name), nil }

func TestStrictRequiresAuthCapabilities(t *testing.T) {
	if err := SupportsAuth(newFullStore()); err != nil {
		t.Fatalf("SupportsAuth(full) error = %v", err)
	}
	if _, err := NewStrict(newFullStore()); err != nil {
		t.Fatalf("NewStrict(full) error = %v", err)
	}

	_, err := NewStrict(newMinimalStore())
	var missing *MissingCapabilityError
	if !errors.As(err, &missing) || !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("NewStrict(minimal) error = %v, want MissingCapabilityError", err)
	}
	if missing.Capability != "storage.TTLStore" {
		t.Fatalf("missing capability = %q, want storage.TTLStore", missing.Capability)
	}
}

func TestRelaxedBasicOperationsAndEncoding(t *testing.T) {
	store := newFullStore()
	s := NewRelaxed(store)
	var _ storage.Store = store

	if err := s.Set("string", "value", time.Minute); err != nil {
		t.Fatalf("Set(string) error = %v", err)
	}
	got, err := s.Get("string")
	if err != nil || got != "value" {
		t.Fatalf("Get(string) = %#v, %v; want value, nil", got, err)
	}

	if err := s.Set("bytes", []byte("raw"), 0); err != nil {
		t.Fatalf("Set(bytes) error = %v", err)
	}
	got, err = s.Get("bytes")
	if err != nil || got != "raw" {
		t.Fatalf("Get(bytes) = %#v, %v; want raw, nil", got, err)
	}

	if err := s.Set("binary", binaryValue{Name: "alice"}, 0); err != nil {
		t.Fatalf("Set(binary) error = %v", err)
	}
	got, err = s.Get("binary")
	if err != nil || got != "bin:alice" {
		t.Fatalf("Get(binary) = %#v, %v; want bin:alice, nil", got, err)
	}

	payload := map[string]any{"name": "darkit", "n": float64(1)}
	if err := s.Set("json", payload, 0); err != nil {
		t.Fatalf("Set(json) error = %v", err)
	}
	got, err = s.Get("json")
	if err != nil {
		t.Fatalf("Get(json) error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got.(string)), &decoded); err != nil {
		t.Fatalf("json payload should unmarshal: %v", err)
	}
	if decoded["name"] != payload["name"] || decoded["n"] != payload["n"] {
		t.Fatalf("decoded = %#v, want %#v", decoded, payload)
	}
}

func TestMissingAndEmptyKeySemantics(t *testing.T) {
	s := NewRelaxed(newFullStore())

	if _, err := s.Get("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrKeyNotFound", err)
	}
	if err := s.Set("", "value", 0); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("Set(empty) error = %v, want ErrEmptyKey", err)
	}
	if err := s.Delete(""); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("Delete(empty) error = %v, want ErrEmptyKey", err)
	}
	if ok := s.Exists(""); ok {
		t.Fatalf("Exists(empty) = true, want false")
	}
}

func TestTTLKeysSetKeepTTLAndStateTransitions(t *testing.T) {
	store := newFullStore()
	s, err := NewStrict(store)
	if err != nil {
		t.Fatalf("NewStrict() error = %v", err)
	}

	if err := s.Set("auth:token:1", "one", time.Minute); err != nil {
		t.Fatalf("Set(token) error = %v", err)
	}
	if err := s.Set("auth:token:2", "two", time.Minute); err != nil {
		t.Fatalf("Set(token2) error = %v", err)
	}
	if err := s.Set("auth:account:1", "one", 0); err != nil {
		t.Fatalf("Set(account) error = %v", err)
	}

	keys, err := s.Keys("auth:token:*")
	if err != nil {
		t.Fatalf("Keys() error = %v", err)
	}
	if want := []string{"auth:token:1", "auth:token:2"}; fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("Keys() = %v, want %v", keys, want)
	}

	oldTTL, err := s.TTL("auth:token:1")
	if err != nil || oldTTL <= 0 {
		t.Fatalf("TTL() = %v, %v; want positive, nil", oldTTL, err)
	}
	if err := s.SetKeepTTL("auth:token:1", "updated"); err != nil {
		t.Fatalf("SetKeepTTL() error = %v", err)
	}
	newTTL, err := s.TTL("auth:token:1")
	if err != nil || newTTL <= 0 {
		t.Fatalf("TTL(after SetKeepTTL) = %v, %v; want positive, nil", newTTL, err)
	}
	if newTTL > oldTTL+time.Second {
		t.Fatalf("SetKeepTTL should preserve TTL, before=%v after=%v", oldTTL, newTTL)
	}
	got, err := s.Get("auth:token:1")
	if err != nil || got != "updated" {
		t.Fatalf("Get(updated) = %#v, %v; want updated, nil", got, err)
	}

	if err := s.Expire("auth:token:1", 50*time.Millisecond); err != nil {
		t.Fatalf("Expire() error = %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if ok := s.Exists("auth:token:1"); ok {
		t.Fatalf("Exists(expired) = true, want false")
	}
	if _, err := s.Get("auth:token:1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(expired) error = %v, want ErrKeyNotFound", err)
	}
}

func TestUnsupportedOperationsInRelaxedMode(t *testing.T) {
	s := NewRelaxed(newMinimalStore())
	if err := s.Set("k", "v", 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := s.SetKeepTTL("k", "v2"); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("SetKeepTTL() error = %v, want ErrUnsupportedOperation", err)
	}
	if _, err := s.Keys("*"); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("Keys() error = %v, want ErrUnsupportedOperation", err)
	}
	if err := s.Expire("k", time.Minute); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("Expire() error = %v, want ErrUnsupportedOperation", err)
	}
	if _, err := s.TTL("k"); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("TTL() error = %v, want ErrUnsupportedOperation", err)
	}
}

func TestManagerLoginWithStrictKVStorage(t *testing.T) {
	store := newFullStore()
	s, err := NewStrict(store)
	if err != nil {
		t.Fatalf("NewStrict() error = %v", err)
	}
	mgr := manager.NewManager(s, nil)

	token, err := mgr.Login("user-1001", "web")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if !mgr.IsLogin(token) {
		t.Fatalf("IsLogin() = false, want true")
	}
	loginID, err := mgr.GetLoginID(token)
	if err != nil || loginID != "user-1001" {
		t.Fatalf("GetLoginID() = %q, %v; want user-1001, nil", loginID, err)
	}
	tokens, err := mgr.GetTokenValueListByLoginID("user-1001")
	if err != nil {
		t.Fatalf("GetTokenValueListByLoginID() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0] != token {
		t.Fatalf("tokens = %v, want [%s]", tokens, token)
	}
	if err := mgr.KickoutByToken(token); err != nil {
		t.Fatalf("KickoutByToken() error = %v", err)
	}
	if ok, err := mgr.CheckLoginWithState(token); ok || !errors.Is(err, manager.ErrTokenKickout) {
		t.Fatalf("CheckLoginWithState(kicked) = %v, %v; want false, ErrTokenKickout", ok, err)
	}
}

func TestPingAndStoreAccessor(t *testing.T) {
	store := newFullStore()
	s := NewRelaxed(store)

	if err := s.Ping(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if store.pingHits != 1 {
		t.Fatalf("Ping() hits = %d, want 1", store.pingHits)
	}
	if s.Store() != store {
		t.Fatalf("Store() should expose underlying store")
	}
	if (*Storage)(nil).Store() != nil {
		t.Fatalf("nil Storage Store() should return nil")
	}
}

func TestNilStorageReturnsErrNilStore(t *testing.T) {
	var s *Storage
	if err := s.Set("k", "v", 0); !errors.Is(err, ErrNilStore) {
		t.Fatalf("Set(nil) error = %v, want ErrNilStore", err)
	}
	if _, err := s.Get("k"); !errors.Is(err, ErrNilStore) {
		t.Fatalf("Get(nil) error = %v, want ErrNilStore", err)
	}
	if err := s.Clear(); !errors.Is(err, ErrNilStore) {
		t.Fatalf("Clear(nil) error = %v, want ErrNilStore", err)
	}
}

func TestAtomicStorageExposesSetNXOnlyForAtomicStore(t *testing.T) {
	store := newAtomicFullStore()
	s := NewAtomic(store)

	ok, err := s.SetNX("lock", "first", time.Minute)
	if err != nil || !ok {
		t.Fatalf("SetNX(first) = %v, %v; want true, nil", ok, err)
	}
	ok, err = s.SetNX("lock", "second", time.Minute)
	if err != nil || ok {
		t.Fatalf("SetNX(second) = %v, %v; want false, nil", ok, err)
	}
	got, err := s.Get("lock")
	if err != nil || got != "first" {
		t.Fatalf("Get(lock) = %#v, %v; want first, nil", got, err)
	}
}
