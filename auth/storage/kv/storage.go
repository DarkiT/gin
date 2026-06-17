// Package kv 将 pkg/storage.Store 适配为 auth.Storage。
package kv

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/pkg/storage"
)

var (
	// ErrNilStore 表示传入的通用 KV 存储为空。
	ErrNilStore = errors.New("auth/storage/kv: storage store is nil")
	// ErrEmptyKey 表示认证存储不接受空 key。
	ErrEmptyKey = errors.New("auth/storage/kv: key is empty")
	// ErrKeyNotFound 表示指定 key 不存在。
	ErrKeyNotFound = errors.New("auth/storage/kv: key not found")
	// ErrUnsupportedOperation 表示底层 storage.Store 不支持认证所需的增强能力。
	ErrUnsupportedOperation = errors.New("auth/storage/kv: unsupported operation")
)

// MissingCapabilityError 描述 strict 模式下缺失的底层存储能力。
type MissingCapabilityError struct {
	Capability string
}

// Error 返回缺失能力错误文本。
func (e *MissingCapabilityError) Error() string {
	if e == nil || e.Capability == "" {
		return ErrUnsupportedOperation.Error()
	}
	return fmt.Sprintf("%s: missing %s", ErrUnsupportedOperation, e.Capability)
}

// Unwrap 支持 errors.Is 匹配 ErrUnsupportedOperation。
func (e *MissingCapabilityError) Unwrap() error {
	return ErrUnsupportedOperation
}

// Storage 将通用字节型 KV 存储适配为 auth.Storage。
//
// 约束：
//   - Get 返回 string，保持 auth 管理器对 token/account/session 数据的既有解析语义。
//   - Strict 模式要求底层同时支持 storage.TTLStore 与 storage.KeyScanner。
//   - Close 不属于 auth.Storage 接口，若需要释放底层资源，请通过 Engine 生命周期或直接关闭原始 store。
type Storage struct {
	store storage.Store
}

// NewRelaxed 创建宽松模式认证存储适配器。
//
// 宽松模式允许底层只实现 storage.Store；当调用 Keys、Expire、TTL 或 SetKeepTTL 等增强能力时，
// 若底层不支持对应接口，会返回 ErrUnsupportedOperation。该模式适合测试或明确不使用完整 auth 能力的场景。
func NewRelaxed(store storage.Store) *Storage {
	if store == nil {
		panic(ErrNilStore.Error())
	}
	return &Storage{store: store}
}

// NewStrict 创建严格模式认证存储适配器。
//
// 严格模式用于生产认证主链，会在构造期检查底层是否支持 token/session 所需的 TTL 与 key 扫描能力。
func NewStrict(store storage.Store) (*Storage, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	if err := SupportsAuth(store); err != nil {
		return nil, err
	}
	return &Storage{store: store}, nil
}

// SupportsAuth 检查通用存储是否满足 auth/session 主链所需能力。
func SupportsAuth(store storage.Store) error {
	if store == nil {
		return ErrNilStore
	}
	if _, ok := store.(storage.TTLStore); !ok {
		return &MissingCapabilityError{Capability: "storage.TTLStore"}
	}
	if _, ok := store.(storage.KeyScanner); !ok {
		return &MissingCapabilityError{Capability: "storage.KeyScanner"}
	}
	return nil
}

// Store 返回底层通用 KV 存储。
func (s *Storage) Store() storage.Store {
	if s == nil {
		return nil
	}
	return s.store
}

// Set 写入 key-value 数据，expiration <= 0 表示不过期。
func (s *Storage) Set(key string, value any, expiration time.Duration) error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	if err := validateKey(key); err != nil {
		return err
	}
	payload, err := marshal(value)
	if err != nil {
		return err
	}
	return s.store.Set(context.Background(), key, payload, expiration)
}

// SetKeepTTL 更新 key 的值并保留原 TTL。
func (s *Storage) SetKeepTTL(key string, value any) error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	if err := validateKey(key); err != nil {
		return err
	}
	payload, err := marshal(value)
	if err != nil {
		return err
	}
	if ttlStore, ok := s.store.(storage.TTLStore); ok {
		return normalizeMiss(ttlStore.SetKeepTTL(context.Background(), key, payload))
	}
	return ErrUnsupportedOperation
}

// Get 读取 key 的值。不存在时返回 ErrKeyNotFound。
func (s *Storage) Get(key string) (any, error) {
	if s == nil || s.store == nil {
		return nil, ErrNilStore
	}
	if err := validateKey(key); err != nil {
		return nil, err
	}
	payload, err := s.store.Get(context.Background(), key)
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, ErrKeyNotFound
	}
	return string(payload), nil
}

// Delete 删除一个或多个 key；key 不存在时也返回 nil。
func (s *Storage) Delete(keys ...string) error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	for _, key := range keys {
		if err := validateKey(key); err != nil {
			return err
		}
	}
	for _, key := range keys {
		if err := s.store.Delete(context.Background(), key); err != nil {
			return err
		}
	}
	return nil
}

// Exists 检查 key 是否存在。
func (s *Storage) Exists(key string) bool {
	if s == nil || s.store == nil {
		return false
	}
	if err := validateKey(key); err != nil {
		return false
	}
	if existsStore, ok := s.store.(storage.ExistenceStore); ok {
		ok, err := existsStore.Exists(context.Background(), key)
		return err == nil && ok
	}
	payload, err := s.store.Get(context.Background(), key)
	return err == nil && payload != nil
}

// Keys 返回匹配 pattern 的 key 列表。
func (s *Storage) Keys(pattern string) ([]string, error) {
	if s == nil || s.store == nil {
		return nil, ErrNilStore
	}
	if scanner, ok := s.store.(storage.KeyScanner); ok {
		return scanner.Keys(context.Background(), pattern)
	}
	return nil, ErrUnsupportedOperation
}

// Expire 更新 key 的过期时间。
func (s *Storage) Expire(key string, expiration time.Duration) error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	if err := validateKey(key); err != nil {
		return err
	}
	if ttlStore, ok := s.store.(storage.TTLStore); ok {
		return normalizeMiss(ttlStore.Expire(context.Background(), key, expiration))
	}
	return ErrUnsupportedOperation
}

// TTL 返回 key 的剩余过期时间。
func (s *Storage) TTL(key string) (time.Duration, error) {
	if s == nil || s.store == nil {
		return 0, ErrNilStore
	}
	if err := validateKey(key); err != nil {
		return 0, err
	}
	if ttlStore, ok := s.store.(storage.TTLStore); ok {
		return ttlStore.TTL(context.Background(), key)
	}
	return 0, ErrUnsupportedOperation
}

// Clear 清空底层存储命名空间。
func (s *Storage) Clear() error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	return s.store.Clear(context.Background())
}

// Ping 检查底层存储是否可访问。
func (s *Storage) Ping() error {
	if s == nil || s.store == nil {
		return ErrNilStore
	}
	if pinger, ok := s.store.(interface{ Ping(context.Context) error }); ok {
		return pinger.Ping(context.Background())
	}
	return nil
}

// NewAtomic 创建带原子 SetNX 能力的认证存储适配器。
//
// 只有底层明确实现 AtomicStore 时才应暴露 SetNX，避免 OAuth2 操作锁误用非原子 fallback。
func NewAtomic(store AtomicStore) *AtomicStorage {
	if store == nil {
		panic(ErrNilStore.Error())
	}
	return &AtomicStorage{Storage: Storage{store: store}, atomic: store}
}

// AtomicStore 表示通用存储额外支持原子 SetNX。
type AtomicStore interface {
	storage.Store
	SetNX(ctx context.Context, key string, val []byte, ttl time.Duration) (bool, error)
}

// AtomicStorage 在 Storage 基础上暴露 OAuth2 锁需要的原子 SetNX。
type AtomicStorage struct {
	Storage
	atomic AtomicStore
}

// SetNX 在 key 不存在时原子写入数据。
func (s *AtomicStorage) SetNX(key string, value any, expiration time.Duration) (bool, error) {
	if err := validateKey(key); err != nil {
		return false, err
	}
	payload, err := marshal(value)
	if err != nil {
		return false, err
	}
	return s.atomic.SetNX(context.Background(), key, payload, expiration)
}

func validateKey(key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	return nil
}

func marshal(value any) ([]byte, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case []byte:
		return append([]byte(nil), v...), nil
	case string:
		return []byte(v), nil
	case encoding.BinaryMarshaler:
		payload, err := v.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), payload...), nil
	case fmt.Stringer:
		return []byte(v.String()), nil
	default:
		payload, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}
}

func normalizeMiss(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	miss := strings.Contains(message, "not found") ||
		strings.Contains(message, "not exist") ||
		strings.Contains(message, "no such key")
	if miss {
		return ErrKeyNotFound
	}
	return err
}

func matchPattern(key, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := filepath.Match(pattern, key)
	if err == nil {
		return matched
	}
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(key, before)
	}
	return key == pattern
}

var _ adapter.Storage = (*Storage)(nil)
