package cache

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// 添加分片常量和条件变量相关定义
const (
	// DefaultHistorySize 默认历史记录大小
	DefaultHistorySize = 50
	// DefaultBufferSize 默认缓存缓冲区大小
	DefaultBufferSize = 512
	// DefaultShardCount 默认分片数量，设为CPU数量的2倍提高并发性
	DefaultShardCount = 16
	// DefaultCleanupInterval 默认清理过期数据的间隔
	DefaultCleanupInterval = 5 * time.Minute
	// DefaultItemsPerCleanup 每次清理处理的最大项目数，避免长时间锁定
	DefaultItemsPerCleanup = 1000
)

// CacheItem 表示缓存中的一个项目
type CacheItem[T any] struct {
	Value      T
	Expiration int64 // Unix时间戳，表示过期时间
}

// ListItem 表示列表中的一个项目
type ListItem[T any] struct {
	Value T
}

// PersistenceData 持久化数据结构
type PersistenceData[K comparable, V any] struct {
	Items             map[K]CacheItem[V]
	ListItems         map[K][]ListItem[V]
	Expiration        map[K]int64
	DefaultExpiration time.Duration
}

// Stats 缓存统计信息
type Stats struct {
	ItemsCount    int           `json:"itemsCount"`    // 普通缓存项数量
	ListsCount    int           `json:"listsCount"`    // 列表数量
	HitCount      uint64        `json:"hitCount"`      // 命中次数
	MissCount     uint64        `json:"missCount"`     // 未命中次数
	LastSaveTime  time.Time     `json:"lastSaveTime"`  // 最后一次保存时间
	LastLoadTime  time.Time     `json:"lastLoadTime"`  // 最后一次加载时间
	CreationTime  time.Time     `json:"creationTime"`  // 创建时间
	MemoryUsage   uint64        `json:"memoryUsage"`   // 预估内存使用（字节）
	ExpiredCount  uint64        `json:"expiredCount"`  // 过期项目计数
	DeletedCount  uint64        `json:"deletedCount"`  // 删除项目计数
	PersistPath   string        `json:"persistPath"`   // 持久化路径
	IsAutoPersist bool          `json:"isAutoPersist"` // 是否开启自动持久化
	SaveInterval  time.Duration `json:"saveInterval"`  // 保存间隔
}

// Shard 表示缓存的一个分片
type Shard[K comparable, V any] struct {
	// 基本内存缓存项
	items map[K]CacheItem[V]
	// 列表缓存项
	listItems map[K][]ListItem[V]
	// 通用过期时间映射（主要用于列表缓存）
	expiration map[K]int64
	// 互斥锁，每个分片有自己的锁
	mu sync.RWMutex
	// 用于阻塞操作的条件变量
	cond *sync.Cond
	// 用于信号通知的通道
	notify map[K][]chan struct{}
}

// isExpired 检查键是否过期（在分片内）
func (s *Shard[K, V]) isExpired(key K) bool {
	exp, exists := s.expiration[key]
	if !exists {
		return false
	}

	if exp < 0 {
		return false // 永不过期
	}

	return exp > 0 && time.Now().UnixNano() > exp
}

// Cache 是一个综合的缓存实现，支持内存缓存和列表缓存
type Cache[K comparable, V any] struct {
	// 分片数组，将缓存分成多个独立分片
	shards []*Shard[K, V]
	// 分片数量
	shardCount int
	// 清理过期项的间隔
	cleanupInterval time.Duration
	// 默认过期时间
	defaultExpiration time.Duration
	// 停止清理的通道
	stopCleanup chan bool

	// 持久化相关
	persistPath         string        // 持久化文件路径
	autoPersistEnabled  bool          // 是否启用自动持久化
	autoPersistInterval time.Duration // 自动持久化间隔
	stopAutoPersist     chan bool     // 停止自动持久化的通道
	lastSaveTime        time.Time     // 最后一次保存时间
	lastLoadTime        time.Time     // 最后一次加载时间
	dirty               atomic.Bool   // 数据是否已修改（需要保存）

	// 全局互斥锁，只用于持久化等全局操作
	globalMu sync.RWMutex

	// 统计信息
	stats struct {
		hitCount     atomic.Uint64 // 命中次数，使用原子操作
		missCount    atomic.Uint64 // 未命中次数
		creationTime time.Time     // 创建时间
		expiredCount atomic.Uint64 // 过期项目计数
		deletedCount atomic.Uint64 // 删除项目计数
	}
}

// 获取分片索引的哈希函数
func getShard[K comparable](key K, shardCount int) int {
	// 使用简单但高效的哈希策略
	h := getHash(key)
	return int(h % uint32(shardCount))
}

// 获取指定键的分片
func (c *Cache[K, V]) getShard(key K) *Shard[K, V] {
	return c.shards[getShard(key, c.shardCount)]
}

// 获取键的哈希值
func getHash[K comparable](key K) uint32 {
	// 根据类型选择合适的哈希策略
	switch k := any(key).(type) {
	case string:
		return fnv32(k)
	case int:
		return uint32(k)
	case int8:
		return uint32(uint8(k))
	case int16:
		return uint32(uint16(k))
	case int32:
		return uint32(uint32(k))
	case int64:
		return uint32(uint64(k) ^ uint64(k>>32))
	case uint:
		return uint32(k)
	case uint8:
		return uint32(k)
	case uint16:
		return uint32(k)
	case uint32:
		return k
	case uint64:
		return uint32(k ^ (k >> 32))
	case fmt.Stringer:
		return fnv32(k.String())
	default:
		return fnv32(fmt.Sprintf("%T:%v", key, key))
	}
}

// FNV-1a哈希算法，用于字符串类型
func fnv32(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	return hash
}

// NewCache 创建一个新的综合缓存
// defaultExpiration: 默认的过期时间
// cleanupInterval: 清理过期项的间隔时间
// 可选的shardCount: 分片数量，默认为CPU核心数*2
func NewCache[K comparable, V any](defaultExpiration, cleanupInterval time.Duration, options ...int) *Cache[K, V] {
	shardCount := DefaultShardCount
	if len(options) > 0 && options[0] > 0 {
		shardCount = options[0]
	} else {
		// 根据CPU核心数调整分片数量
		numCPU := runtime.NumCPU()
		if numCPU > 1 {
			shardCount = numCPU * 2 // 默认为CPU核心数的2倍
		}
	}

	cache := &Cache[K, V]{
		shards:            make([]*Shard[K, V], shardCount),
		shardCount:        shardCount,
		cleanupInterval:   cleanupInterval,
		defaultExpiration: defaultExpiration,
		stopCleanup:       make(chan bool),
		stopAutoPersist:   make(chan bool),
	}

	// 初始化所有分片
	for i := 0; i < shardCount; i++ {
		shard := &Shard[K, V]{
			items:      make(map[K]CacheItem[V]),
			listItems:  make(map[K][]ListItem[V]),
			expiration: make(map[K]int64),
			notify:     make(map[K][]chan struct{}),
		}
		shard.cond = sync.NewCond(&shard.mu)
		cache.shards[i] = shard
	}

	cache.stats.creationTime = time.Now()

	// 如果清理间隔大于0，启动定期清理
	if cleanupInterval > 0 {
		go cache.startCleanupTimer()
	}

	return cache
}

// NewCacheWithPersistence 初始化带持久化的全局缓存
func NewCacheWithPersistence[K comparable, V any](defaultExpiration, cleanupInterval time.Duration, persistPath string, autoPersistInterval time.Duration) *Cache[K, V] {
	cache := NewCache[K, V](defaultExpiration, cleanupInterval).WithPersistence(persistPath, autoPersistInterval)
	cache.EnableAutoPersist()
	return cache
}

// WithPersistence 配置持久化选项
func (c *Cache[K, V]) WithPersistence(persistPath string, autoPersistInterval time.Duration) *Cache[K, V] {
	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	c.persistPath = persistPath
	c.autoPersistInterval = autoPersistInterval

	// 创建目录（如果不存在）
	err := os.MkdirAll(filepath.Dir(persistPath), 0o755)
	if err != nil {
		fmt.Printf("Warning: Failed to create directory for persistence: %v\n", err)
	}

	return c
}

// EnableAutoPersist 启用自动持久化
func (c *Cache[K, V]) EnableAutoPersist() {
	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	if c.persistPath == "" {
		fmt.Println("Warning: Persistence path not set, auto-persist not enabled")
		return
	}

	if !c.autoPersistEnabled && c.autoPersistInterval > 0 {
		c.autoPersistEnabled = true
		go c.startAutoPersistTimer()
	}
}

// DisableAutoPersist 禁用自动持久化
func (c *Cache[K, V]) DisableAutoPersist() {
	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	if c.autoPersistEnabled {
		c.autoPersistEnabled = false
		c.stopAutoPersist <- true
	}
}

// startAutoPersistTimer 启动自动持久化定时器
func (c *Cache[K, V]) startAutoPersistTimer() {
	ticker := time.NewTicker(c.autoPersistInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if c.dirty.Load() {
				err := c.Save()
				if err != nil {
					fmt.Printf("Auto-persist error: %v\n", err)
				}
			}
		case <-c.stopAutoPersist:
			return
		}
	}
}

// Save 保存缓存到文件，优化锁策略
func (c *Cache[K, V]) Save() error {
	if c.persistPath == "" {
		return errors.New("persistence path not set")
	}

	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	data := PersistenceData[K, V]{
		Items:             make(map[K]CacheItem[V]),
		ListItems:         make(map[K][]ListItem[V]),
		Expiration:        make(map[K]int64),
		DefaultExpiration: c.defaultExpiration,
	}

	// 分片收集数据，减少全局锁持有时间
	now := time.Now().UnixNano()

	for _, shard := range c.shards {
		shard.mu.RLock()

		// 只保存未过期的项目
		for k, v := range shard.items {
			if v.Expiration <= 0 || v.Expiration > now {
				data.Items[k] = v
			}
		}

		for k, v := range shard.listItems {
			exp, hasExp := shard.expiration[k]
			if !hasExp || exp <= 0 || exp > now {
				data.ListItems[k] = v
				if hasExp {
					data.Expiration[k] = exp
				}
			}
		}

		shard.mu.RUnlock()
	}

	// 创建临时文件
	tempFile := c.persistPath + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("error creating temporary file: %w", err)
	}

	// 使用gob编码数据
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("error encoding cache data: %v; close error: %w", err, closeErr)
		}
		return fmt.Errorf("error encoding cache data: %w", err)
	}

	if err := file.Sync(); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("error syncing file: %v; close error: %w", err, closeErr)
		}
		return fmt.Errorf("error syncing file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("error closing file: %w", err)
	}

	// 重命名临时文件（原子操作）
	if err := os.Rename(tempFile, c.persistPath); err != nil {
		return fmt.Errorf("error renaming temporary file: %w", err)
	}

	c.lastSaveTime = time.Now()
	c.dirty.Store(false)

	return nil
}

// Load 从文件加载缓存
func (c *Cache[K, V]) Load() error {
	if c.persistPath == "" {
		return errors.New("persistence path not set")
	}

	file, err := os.Open(c.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在不是错误，只是还没有持久化数据
		}
		return fmt.Errorf("error opening persistence file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Printf("cache: failed to close persistence file: %v\n", closeErr)
		}
	}()

	var data PersistenceData[K, V]
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if err == io.EOF {
			return nil // 空文件不是错误
		}
		return fmt.Errorf("error decoding persistence data: %w", err)
	}

	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	// 清空当前数据
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.items = make(map[K]CacheItem[V])
		shard.listItems = make(map[K][]ListItem[V])
		shard.expiration = make(map[K]int64)
		shard.mu.Unlock()
	}

	// 只加载未过期的项
	now := time.Now().UnixNano()
	for k, v := range data.Items {
		if v.Expiration <= 0 || v.Expiration > now {
			c.Set(k, v.Value) // 使用Set来处理过期时间
		}
	}

	for k, v := range data.ListItems {
		exp, hasExp := data.Expiration[k]
		if !hasExp || exp <= 0 || exp > now {
			for _, shard := range c.shards {
				shard.mu.Lock()
				shard.listItems[k] = v
				shard.expiration[k] = exp
				shard.mu.Unlock()
			}
		}
	}

	c.defaultExpiration = data.DefaultExpiration
	c.lastLoadTime = time.Now()
	c.dirty.Store(false)

	return nil
}

// LoadOrInit 从文件加载缓存，如果文件不存在则初始化一个新的缓存
func (c *Cache[K, V]) LoadOrInit() error {
	err := c.Load()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

//------------------------------------------------------------------------------
// 原有缓存功能增强
//------------------------------------------------------------------------------

// markDirty 标记缓存为已修改状态
func (c *Cache[K, V]) markDirty() {
	c.dirty.Store(true)
}

// startCleanupTimer 启动定期清理过期项的计时器
func (c *Cache[K, V]) startCleanupTimer() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

// DeleteExpired 删除所有过期的项
// 采用分片清理策略减少锁争用，每次只清理部分数据
func (c *Cache[K, V]) DeleteExpired() {
	now := time.Now().UnixNano()

	// 随机选择起始分片，避免总是从同一个分片开始清理
	startShard := rand.Intn(c.shardCount)

	for i := 0; i < c.shardCount; i++ {
		shardIndex := (startShard + i) % c.shardCount
		shard := c.shards[shardIndex]

		removed := 0
		processed := 0

		shard.mu.Lock()

		// 清理普通缓存项，限制每次处理的数量
		for k, v := range shard.items {
			processed++
			if processed > DefaultItemsPerCleanup {
				break // 避免长时间锁定
			}

			if v.Expiration > 0 && now > v.Expiration {
				delete(shard.items, k)
				removed++

				// 通知等待的goroutine（如果有）
				c.notifyWaiters(shard, k)
			}
		}

		// 清理列表项
		for k, exp := range shard.expiration {
			processed++
			if processed > DefaultItemsPerCleanup*2 {
				break // 避免长时间锁定
			}

			if exp > 0 && now > exp {
				delete(shard.listItems, k)
				delete(shard.expiration, k)
				removed++

				// 通知等待的goroutine（如果有）
				c.notifyWaiters(shard, k)
			}
		}

		shard.mu.Unlock()

		if removed > 0 {
			c.stats.expiredCount.Add(uint64(removed))
			c.markDirty()
		}
	}
}

// 通知所有等待指定键的goroutine
func (c *Cache[K, V]) notifyWaiters(shard *Shard[K, V], key K) {
	if chans, ok := shard.notify[key]; ok {
		for _, ch := range chans {
			close(ch)
		}
		delete(shard.notify, key)
	}
}

// 向分片添加通知通道
func (c *Cache[K, V]) addNotify(shard *Shard[K, V], key K) <-chan struct{} {
	ch := make(chan struct{})
	shard.notify[key] = append(shard.notify[key], ch)
	return ch
}

// Close 停止清理过期项和自动持久化的goroutine
func (c *Cache[K, V]) Close() {
	if c.cleanupInterval > 0 {
		c.stopCleanup <- true
	}

	if c.autoPersistEnabled {
		c.stopAutoPersist <- true
	}

	// 最后保存一次数据
	if c.persistPath != "" && c.dirty.Load() {
		err := c.Save()
		if err != nil {
			fmt.Printf("Error saving cache during close: %v\n", err)
		}
	}
}

// GetStats 获取缓存统计信息
func (c *Cache[K, V]) GetStats() Stats {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	var memUsage uint64

	// 简单估计内存使用量，不精确
	memUsage = uint64(len(c.shards) * 64) // 假设每个分片平均64字节

	for _, shard := range c.shards {
		shard.mu.RLock()
		memUsage += uint64(len(shard.items) * 64)     // 假设每个分片中的键值对平均64字节
		memUsage += uint64(len(shard.listItems) * 32) // 假设每个分片中的列表平均32字节
		shard.mu.RUnlock()
	}

	return Stats{
		ItemsCount:    len(c.shards), // 分片数量
		ListsCount:    len(c.shards), // 分片数量
		HitCount:      c.stats.hitCount.Load(),
		MissCount:     c.stats.missCount.Load(),
		LastSaveTime:  c.lastSaveTime,
		LastLoadTime:  c.lastLoadTime,
		CreationTime:  c.stats.creationTime,
		MemoryUsage:   memUsage,
		ExpiredCount:  c.stats.expiredCount.Load(),
		DeletedCount:  c.stats.deletedCount.Load(),
		PersistPath:   c.persistPath,
		IsAutoPersist: c.autoPersistEnabled,
		SaveInterval:  c.autoPersistInterval,
	}
}

// Flush 清除所有数据并删除持久化文件
func (c *Cache[K, V]) Flush() error {
	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.items = make(map[K]CacheItem[V])
		shard.listItems = make(map[K][]ListItem[V])
		shard.expiration = make(map[K]int64)
		shard.mu.Unlock()
	}

	c.markDirty()

	// 删除持久化文件
	if c.persistPath != "" {
		err := os.Remove(c.persistPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error removing persistence file: %w", err)
		}
	}

	return nil
}

// GetTTL 获取键的剩余生存时间
func (c *Cache[K, V]) GetTTL(key K) (time.Duration, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		return 0, false
	}

	if item.Expiration < 0 {
		return -1, true // 永不过期
	}

	if item.Expiration == 0 {
		return 0, true // 已过期
	}

	remaining := time.Duration(item.Expiration - time.Now().UnixNano())
	if remaining < 0 {
		return 0, true // 已过期
	}

	return remaining, true
}

// GetListTTL 获取列表键的剩余生存时间
func (c *Cache[K, V]) GetListTTL(key K) (time.Duration, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	_, exists := shard.listItems[key]
	if !exists {
		return 0, false
	}

	exp, hasExp := shard.expiration[key]
	if !hasExp || exp < 0 {
		return -1, true // 永不过期
	}

	if exp == 0 {
		return 0, true // 已过期
	}

	remaining := time.Duration(exp - time.Now().UnixNano())
	if remaining < 0 {
		return 0, true // 已过期
	}

	return remaining, true
}

//------------------------------------------------------------------------------
// MemoryCache 类型的方法实现
//------------------------------------------------------------------------------

// Set 设置缓存项，可选过期时间。不传递过期时间时使用默认过期时间
func (c *Cache[K, V]) Set(key K, value V, duration ...time.Duration) {
	var expiration int64

	// 确定使用的过期时间
	var d time.Duration
	if len(duration) > 0 {
		d = duration[0]
	} else {
		d = c.defaultExpiration
	}

	if d > 0 {
		expiration = time.Now().Add(d).UnixNano()
	} else {
		// 负值表示永不过期
		expiration = -1
	}

	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	shard.items[key] = CacheItem[V]{
		Value:      value,
		Expiration: expiration,
	}

	// 通知等待的goroutine
	c.notifyWaiters(shard, key)

	shard.mu.Unlock()

	c.markDirty()
}

// Get 获取缓存项
func (c *Cache[K, V]) Get(key K) (V, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		var zero V
		c.stats.missCount.Add(1)
		return zero, false
	}

	// 检查是否过期
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		var zero V
		c.stats.missCount.Add(1)
		return zero, false
	}

	c.stats.hitCount.Add(1)
	return item.Value, true
}

// GetWithTTL 获取缓存项及其剩余生存时间
func (c *Cache[K, V]) GetWithTTL(key K) (V, time.Duration, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		var zero V
		c.stats.missCount.Add(1)
		return zero, 0, false
	}

	// 检查是否过期
	now := time.Now().UnixNano()
	if item.Expiration > 0 && now > item.Expiration {
		var zero V
		c.stats.missCount.Add(1)
		return zero, 0, false
	}

	var ttl time.Duration
	if item.Expiration < 0 {
		ttl = -1 // 永不过期
	} else {
		ttl = time.Duration(item.Expiration - now)
		if ttl < 0 {
			ttl = 0
		}
	}

	c.stats.hitCount.Add(1)
	return item.Value, ttl, true
}

// Delete 删除缓存项
func (c *Cache[K, V]) Delete(key K) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if _, exists := shard.items[key]; exists {
		delete(shard.items, key)
		c.notifyWaiters(shard, key) // 通知等待的goroutine
		c.stats.deletedCount.Add(1)
		c.markDirty()
	}
}

// ForEach 遍历所有未过期的缓存项并对每一项执行指定的函数
// 优化为分片遍历，减少锁争用
func (c *Cache[K, V]) ForEach(fn func(key K, value V) bool) {
	now := time.Now().UnixNano()

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()

		// 创建临时列表以减少锁持有时间
		items := make([]struct {
			key   K
			value V
		}, 0, len(shard.items))

		for k, item := range shard.items {
			// 跳过已过期的项
			if item.Expiration > 0 && now > item.Expiration {
				continue
			}

			items = append(items, struct {
				key   K
				value V
			}{k, item.Value})
		}

		shard.mu.RUnlock()

		// 在锁外执行回调函数
		for _, item := range items {
			if !fn(item.key, item.value) {
				return
			}
		}
	}
}

// Clear 清空缓存
func (c *Cache[K, V]) Clear() {
	c.globalMu.Lock()
	defer c.globalMu.Unlock()

	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.items = make(map[K]CacheItem[V])
		shard.listItems = make(map[K][]ListItem[V])
		shard.expiration = make(map[K]int64)
		shard.mu.Unlock()
	}

	c.markDirty()
}

// Count 返回缓存中的普通项目数量
func (c *Cache[K, V]) Count() int {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	count := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		count += len(shard.items)
		shard.mu.RUnlock()
	}
	return count
}

// Keys 返回所有的普通缓存键
func (c *Cache[K, V]) Keys() []K {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	keys := make(map[K]struct{})
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k := range shard.items {
			keys[k] = struct{}{}
		}
		shard.mu.RUnlock()
	}

	result := make([]K, 0, len(keys))
	for k := range keys {
		result = append(result, k)
	}
	return result
}

// Has 检查键是否存在且未过期
func (c *Cache[K, V]) Has(key K) bool {
	_, exists := c.Get(key)
	return exists
}

// Increment 对数值类型进行增加操作
func (c *Cache[K, V]) Increment(key K, increment any) (any, error) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	item, found := shard.items[key]

	// 处理值存在的情况
	if found && item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		item = CacheItem[V]{}
	}

	var newValue any

	switch increment := increment.(type) {
	case int:
		switch current := any(item.Value).(type) {
		case int:
			newValue = current + increment
		case int8:
			newValue = int(current) + increment
		case int16:
			newValue = int(current) + increment
		case int32:
			newValue = int(current) + increment
		case int64:
			newValue = int(current) + increment
		case uint:
			newValue = int(current) + increment
		case uint8:
			newValue = int(current) + increment
		case uint16:
			newValue = int(current) + increment
		case uint32:
			newValue = int(current) + increment
		case uint64:
			newValue = int(current) + increment
		case float32:
			newValue = float64(current) + float64(increment)
		case float64:
			newValue = current + float64(increment)
		default:
			return nil, errors.New("the value for this key is not a number")
		}
	case int64:
		switch current := any(item.Value).(type) {
		case int:
			newValue = int64(current) + increment
		case int8:
			newValue = int64(current) + increment
		case int16:
			newValue = int64(current) + increment
		case int32:
			newValue = int64(current) + increment
		case int64:
			newValue = current + increment
		case uint:
			newValue = int64(current) + increment
		case uint8:
			newValue = int64(current) + increment
		case uint16:
			newValue = int64(current) + increment
		case uint32:
			newValue = int64(current) + increment
		case uint64:
			newValue = int64(current) + increment
		case float32:
			newValue = float64(current) + float64(increment)
		case float64:
			newValue = current + float64(increment)
		default:
			return nil, errors.New("the value for this key is not a number")
		}
	case float64:
		switch current := any(item.Value).(type) {
		case int:
			newValue = float64(current) + increment
		case int8:
			newValue = float64(current) + increment
		case int16:
			newValue = float64(current) + increment
		case int32:
			newValue = float64(current) + increment
		case int64:
			newValue = float64(current) + increment
		case uint:
			newValue = float64(current) + increment
		case uint8:
			newValue = float64(current) + increment
		case uint16:
			newValue = float64(current) + increment
		case uint32:
			newValue = float64(current) + increment
		case uint64:
			newValue = float64(current) + increment
		case float32:
			newValue = float64(current) + increment
		case float64:
			newValue = current + increment
		default:
			return nil, errors.New("the value for this key is not a number")
		}
	default:
		return nil, errors.New("increment value must be int, int64 or float64")
	}

	// 尝试将结果转换回原始类型
	switch any(item.Value).(type) {
	case int:
		switch n := newValue.(type) {
		case int:
			item.Value = any(n).(V)
		case int64:
			item.Value = any(int(n)).(V)
		case float64:
			item.Value = any(int(n)).(V)
		}
	case int8:
		switch n := newValue.(type) {
		case int:
			item.Value = any(int8(n)).(V)
		case int64:
			item.Value = any(int8(n)).(V)
		case float64:
			item.Value = any(int8(n)).(V)
		}
	case int16:
		switch n := newValue.(type) {
		case int:
			item.Value = any(int16(n)).(V)
		case int64:
			item.Value = any(int16(n)).(V)
		case float64:
			item.Value = any(int16(n)).(V)
		}
	case int32:
		switch n := newValue.(type) {
		case int:
			item.Value = any(int32(n)).(V)
		case int64:
			item.Value = any(int32(n)).(V)
		case float64:
			item.Value = any(int32(n)).(V)
		}
	case int64:
		switch n := newValue.(type) {
		case int:
			item.Value = any(int64(n)).(V)
		case int64:
			item.Value = any(n).(V)
		case float64:
			item.Value = any(int64(n)).(V)
		}
	case uint:
		switch n := newValue.(type) {
		case int:
			item.Value = any(uint(n)).(V)
		case int64:
			item.Value = any(uint(n)).(V)
		case float64:
			item.Value = any(uint(n)).(V)
		}
	case uint8:
		switch n := newValue.(type) {
		case int:
			item.Value = any(uint8(n)).(V)
		case int64:
			item.Value = any(uint8(n)).(V)
		case float64:
			item.Value = any(uint8(n)).(V)
		}
	case uint16:
		switch n := newValue.(type) {
		case int:
			item.Value = any(uint16(n)).(V)
		case int64:
			item.Value = any(uint16(n)).(V)
		case float64:
			item.Value = any(uint16(n)).(V)
		}
	case uint32:
		switch n := newValue.(type) {
		case int:
			item.Value = any(uint32(n)).(V)
		case int64:
			item.Value = any(uint32(n)).(V)
		case float64:
			item.Value = any(uint32(n)).(V)
		}
	case uint64:
		switch n := newValue.(type) {
		case int:
			item.Value = any(uint64(n)).(V)
		case int64:
			item.Value = any(uint64(n)).(V)
		case float64:
			item.Value = any(uint64(n)).(V)
		}
	case float32:
		switch n := newValue.(type) {
		case int:
			item.Value = any(float32(n)).(V)
		case int64:
			item.Value = any(float32(n)).(V)
		case float64:
			item.Value = any(float32(n)).(V)
		}
	case float64:
		switch n := newValue.(type) {
		case int:
			item.Value = any(float64(n)).(V)
		case int64:
			item.Value = any(float64(n)).(V)
		case float64:
			item.Value = any(n).(V)
		}
	default:
		// 如果不是已知类型，尝试直接赋值
		var ok bool
		item.Value, ok = newValue.(V)
		if !ok {
			return nil, errors.New("cannot convert incremented value back to original type")
		}
	}

	shard.items[key] = item
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	return newValue, nil
}

//------------------------------------------------------------------------------
// ListCache 类型的方法实现
//------------------------------------------------------------------------------

// SetList 设置列表的过期时间，不传递过期时间时使用默认过期时间
func (c *Cache[K, V]) SetList(key K, duration ...time.Duration) {
	var expiration int64

	// 确定使用的过期时间
	var d time.Duration
	if len(duration) > 0 {
		d = duration[0]
	} else {
		d = c.defaultExpiration
	}

	if d > 0 {
		expiration = time.Now().Add(d).UnixNano()
	} else if d == 0 {
		// 0表示立即过期
		expiration = 0
	} else {
		// 负值表示永不过期
		expiration = -1
	}

	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	shard.expiration[key] = expiration
	shard.mu.Unlock()

	c.markDirty()
}

// LPush 将一个或多个值插入到列表头部
func (c *Cache[K, V]) LPush(key K, values ...V) int {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
	}

	list, exists := shard.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
	}

	newList := make([]ListItem[V], len(values))
	for i, v := range values {
		newList[i] = ListItem[V]{Value: v}
	}

	shard.listItems[key] = append(newList, list...)
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	return len(shard.listItems[key])
}

// RPush 将一个或多个值插入到列表尾部
func (c *Cache[K, V]) RPush(key K, values ...V) int {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
	}

	list, exists := shard.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
	}

	for _, v := range values {
		list = append(list, ListItem[V]{Value: v})
	}

	shard.listItems[key] = list
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	return len(shard.listItems[key])
}

// LPop 移除并返回列表头部的元素
func (c *Cache[K, V]) LPop(key K) (V, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	var zero V

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		c.stats.missCount.Add(1)
		return zero, false
	}

	list, exists := shard.listItems[key]
	if !exists || len(list) == 0 {
		c.stats.missCount.Add(1)
		return zero, false
	}

	value := list[0].Value
	shard.listItems[key] = list[1:]
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	// 如果列表为空，删除该键
	if len(shard.listItems[key]) == 0 {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
	}

	c.stats.hitCount.Add(1)
	return value, true
}

// RPop 移除并返回列表尾部的元素
func (c *Cache[K, V]) RPop(key K) (V, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	var zero V

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		c.stats.missCount.Add(1)
		return zero, false
	}

	list, exists := shard.listItems[key]
	if !exists || len(list) == 0 {
		c.stats.missCount.Add(1)
		return zero, false
	}

	lastIndex := len(list) - 1
	value := list[lastIndex].Value
	shard.listItems[key] = list[:lastIndex]
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	// 如果列表为空，删除该键
	if len(shard.listItems[key]) == 0 {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
	}

	c.stats.hitCount.Add(1)
	return value, true
}

// LIndex 通过索引获取列表中的元素
func (c *Cache[K, V]) LIndex(key K, index int) (V, bool) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	var zero V

	if shard.isExpired(key) {
		c.stats.missCount.Add(1)
		return zero, false
	}

	list, exists := shard.listItems[key]
	if !exists {
		c.stats.missCount.Add(1)
		return zero, false
	}

	length := len(list)
	if index < 0 {
		// 处理负索引，如-1表示最后一个元素
		index = length + index
	}

	if index < 0 || index >= length {
		c.stats.missCount.Add(1)
		return zero, false
	}

	c.stats.hitCount.Add(1)
	return list[index].Value, true
}

// LRange 获取列表指定范围内的元素
func (c *Cache[K, V]) LRange(key K, start, stop int) []V {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if shard.isExpired(key) {
		c.stats.missCount.Add(1)
		return []V{}
	}

	list, exists := shard.listItems[key]
	if !exists {
		c.stats.missCount.Add(1)
		return []V{}
	}

	length := len(list)

	// 处理负索引
	if start < 0 {
		start = length + start
		if start < 0 {
			start = 0
		}
	}

	if stop < 0 {
		stop = length + stop
	}

	// 确保索引在有效范围内
	if start >= length || start > stop {
		return []V{}
	}

	if stop >= length {
		stop = length - 1
	}

	result := make([]V, 0, stop-start+1)
	for i := start; i <= stop; i++ {
		result = append(result, list[i].Value)
	}

	c.stats.hitCount.Add(1)
	return result
}

// LLen 获取列表长度
func (c *Cache[K, V]) LLen(key K) int {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if shard.isExpired(key) {
		return 0
	}

	list, exists := shard.listItems[key]
	if !exists {
		return 0
	}

	return len(list)
}

// LRem 移除列表中与参数value相等的元素
// count > 0: 从头往尾移除count个值为value的元素
// count < 0: 从尾往头移除count个值为value的元素
// count = 0: 移除所有值为value的元素
func (c *Cache[K, V]) LRem(key K, count int, value V, equals func(a, b V) bool) int {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		return 0
	}

	list, exists := shard.listItems[key]
	if !exists {
		return 0
	}

	if count == 0 {
		// 移除所有匹配的元素
		newList := make([]ListItem[V], 0, len(list))
		removed := 0

		for _, item := range list {
			if !equals(item.Value, value) {
				newList = append(newList, item)
			} else {
				removed++
			}
		}

		shard.listItems[key] = newList
		c.notifyWaiters(shard, key) // 通知等待的goroutine

		// 如果列表为空，删除该键
		if len(shard.listItems[key]) == 0 {
			delete(shard.listItems, key)
			delete(shard.expiration, key)
		}

		return removed
	} else if count > 0 {
		// 从头往尾移除
		newList := make([]ListItem[V], 0, len(list))
		removed := 0

		for _, item := range list {
			if equals(item.Value, value) && removed < count {
				removed++
			} else {
				newList = append(newList, item)
			}
		}

		shard.listItems[key] = newList
		c.notifyWaiters(shard, key) // 通知等待的goroutine

		// 如果列表为空，删除该键
		if len(shard.listItems[key]) == 0 {
			delete(shard.listItems, key)
			delete(shard.expiration, key)
		}

		return removed
	} else {
		// 从尾往头移除
		count = -count
		length := len(list)
		newList := make([]ListItem[V], 0, length)
		removed := 0

		for i := length - 1; i >= 0; i-- {
			if equals(list[i].Value, value) && removed < count {
				removed++
			} else {
				newList = append([]ListItem[V]{list[i]}, newList...)
			}
		}

		shard.listItems[key] = newList
		c.notifyWaiters(shard, key) // 通知等待的goroutine

		// 如果列表为空，删除该键
		if len(shard.listItems[key]) == 0 {
			delete(shard.listItems, key)
			delete(shard.expiration, key)
		}

		return removed
	}
}

// RPoplPush 移除列表的最后一个元素，并将该元素添加到另一个列表的头部并返回它
func (c *Cache[K, V]) RPoplPush(source K, destination K) (V, bool) {
	// 获取源分片
	sourceShard := c.getShard(source)
	// 获取目标分片
	destShard := c.getShard(destination)

	sourceShard.mu.Lock()
	defer sourceShard.mu.Unlock()

	var zero V

	// 检查源列表是否过期
	if sourceShard.isExpired(source) {
		delete(sourceShard.listItems, source)
		delete(sourceShard.expiration, source)
		return zero, false
	}

	// 获取源列表
	sourceList, exists := sourceShard.listItems[source]
	if !exists || len(sourceList) == 0 {
		return zero, false
	}

	// 获取最后一个元素
	lastIndex := len(sourceList) - 1
	value := sourceList[lastIndex].Value

	// 从源列表中移除
	sourceShard.listItems[source] = sourceList[:lastIndex]

	// 如果源列表为空，删除该键
	if len(sourceShard.listItems[source]) == 0 {
		delete(sourceShard.listItems, source)
		delete(sourceShard.expiration, source)
	}

	// 检查目标列表是否过期
	if destShard.isExpired(destination) {
		delete(destShard.listItems, destination)
		delete(destShard.expiration, destination)
	}

	// 获取目标列表
	destList, exists := destShard.listItems[destination]
	if !exists {
		destList = make([]ListItem[V], 0)
	}

	// 将元素添加到目标列表的头部
	destShard.listItems[destination] = append([]ListItem[V]{{Value: value}}, destList...)
	c.notifyWaiters(destShard, destination) // 通知等待的goroutine

	return value, true
}

// BLPop 阻塞版本的LPop，使用通知机制代替轮询
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BLPop(key K, timeout time.Duration) (V, bool) {
	var zero V

	// 先尝试一次非阻塞获取
	value, found := c.LPop(key)
	if found {
		return value, true
	}

	// 如果超时为0，立即返回
	if timeout == 0 {
		return zero, false
	}

	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()

	// 创建通知通道
	notify := c.addNotify(shard, key)

	// 释放锁，等待通知或超时
	shard.mu.Unlock()

	// 设置超时
	var timer *time.Timer
	var timerC <-chan time.Time

	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	// 等待通知或超时
	select {
	case <-notify:
		// 收到通知，再次尝试获取
		return c.LPop(key)
	case <-timerC:
		// 超时
		return zero, false
	}
}

// BRPop 阻塞版本的RPop，使用通知机制代替轮询
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BRPop(key K, timeout time.Duration) (V, bool) {
	var zero V

	// 先尝试一次非阻塞获取
	value, found := c.RPop(key)
	if found {
		return value, true
	}

	// 如果超时为0，立即返回
	if timeout == 0 {
		return zero, false
	}

	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()

	// 创建通知通道
	notify := c.addNotify(shard, key)

	// 释放锁，等待通知或超时
	shard.mu.Unlock()

	// 设置超时
	var timer *time.Timer
	var timerC <-chan time.Time

	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	// 等待通知或超时
	select {
	case <-notify:
		// 收到通知，再次尝试获取
		return c.RPop(key)
	case <-timerC:
		// 超时
		return zero, false
	}
}

// BRPopLPush 阻塞版本的RPoplPush，使用通知机制代替轮询
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BRPopLPush(source K, destination K, timeout time.Duration) (V, bool) {
	var zero V

	// 先尝试一次非阻塞获取
	value, found := c.RPoplPush(source, destination)
	if found {
		return value, true
	}

	// 如果超时为0，立即返回
	if timeout == 0 {
		return zero, false
	}

	// 获取对应分片
	shard := c.getShard(source)

	shard.mu.Lock()

	// 创建通知通道
	notify := c.addNotify(shard, source)

	// 释放锁，等待通知或超时
	shard.mu.Unlock()

	// 设置超时
	var timer *time.Timer
	var timerC <-chan time.Time

	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	// 等待通知或超时
	select {
	case <-notify:
		// 收到通知，再次尝试获取
		return c.RPoplPush(source, destination)
	case <-timerC:
		// 超时
		return zero, false
	}
}

// DeleteList 删除列表
func (c *Cache[K, V]) DeleteList(key K) {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if _, exists := shard.listItems[key]; exists {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		c.stats.deletedCount.Add(1)
		c.notifyWaiters(shard, key) // 通知等待的goroutine
		c.markDirty()
	}
}

// ListKeys 返回所有的列表键
func (c *Cache[K, V]) ListKeys() []K {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	keys := make(map[K]struct{})
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k := range shard.listItems {
			keys[k] = struct{}{}
		}
		shard.mu.RUnlock()
	}

	result := make([]K, 0, len(keys))
	for k := range keys {
		result = append(result, k)
	}
	return result
}

// ListCount 返回列表数量
func (c *Cache[K, V]) ListCount() int {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	count := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		count += len(shard.listItems)
		shard.mu.RUnlock()
	}
	return count
}

// HasList 检查列表键是否存在且未过期
func (c *Cache[K, V]) HasList(key K) bool {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if shard.isExpired(key) {
		return false
	}

	_, exists := shard.listItems[key]
	return exists
}

// ForEachList 遍历所有未过期的列表
func (c *Cache[K, V]) ForEachList(fn func(key K, list []V) bool) {
	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()

		for k, items := range shard.listItems {
			if shard.isExpired(k) {
				continue
			}

			// 转换为值列表
			values := make([]V, len(items))
			for i, item := range items {
				values[i] = item.Value
			}

			// 执行回调函数，如果返回false则停止遍历
			if !fn(k, values) {
				shard.mu.RUnlock()
				return
			}
		}

		shard.mu.RUnlock()
	}
}

// LSet 通过索引来设置列表元素的值
func (c *Cache[K, V]) LSet(key K, index int, value V) bool {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		return false
	}

	list, exists := shard.listItems[key]
	if !exists {
		return false
	}

	length := len(list)
	if index < 0 {
		// 处理负索引，如-1表示最后一个元素
		index = length + index
	}

	if index < 0 || index >= length {
		return false
	}

	list[index] = ListItem[V]{Value: value}
	c.notifyWaiters(shard, key) // 通知等待的goroutine
	return true
}

// LInsert 在列表的指定位置插入元素
// before == true表示在pivot之前插入
// before == false表示在pivot之后插入
func (c *Cache[K, V]) LInsert(key K, before bool, pivot V, value V, equals func(a, b V) bool) int {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		return 0
	}

	list, exists := shard.listItems[key]
	if !exists {
		return 0
	}

	for i, item := range list {
		if equals(item.Value, pivot) {
			if before {
				// 在pivot之前插入
				newList := make([]ListItem[V], len(list)+1)
				copy(newList, list[:i])
				newList[i] = ListItem[V]{Value: value}
				copy(newList[i+1:], list[i:])
				shard.listItems[key] = newList
			} else {
				// 在pivot之后插入
				newList := make([]ListItem[V], len(list)+1)
				copy(newList, list[:i+1])
				newList[i+1] = ListItem[V]{Value: value}
				copy(newList[i+2:], list[i+1:])
				shard.listItems[key] = newList
			}
			c.notifyWaiters(shard, key) // 通知等待的goroutine
			return len(shard.listItems[key])
		}
	}

	return -1 // pivot不存在
}

// LTrim 对一个列表进行修剪，只保留指定区间内的元素
func (c *Cache[K, V]) LTrim(key K, start, stop int) bool {
	// 获取对应分片
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.isExpired(key) {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		return false
	}

	list, exists := shard.listItems[key]
	if !exists {
		return false
	}

	length := len(list)

	// 处理负索引
	if start < 0 {
		start = length + start
		if start < 0 {
			start = 0
		}
	}

	if stop < 0 {
		stop = length + stop
	}

	// 确保索引在有效范围内
	if start >= length || start > stop {
		// 删除整个列表
		delete(shard.listItems, key)
		delete(shard.expiration, key)
		c.notifyWaiters(shard, key) // 通知等待的goroutine
		c.markDirty()
		return true
	}

	if stop >= length {
		stop = length - 1
	}

	// 截取子列表
	shard.listItems[key] = list[start : stop+1]
	c.notifyWaiters(shard, key) // 通知等待的goroutine

	// 如果列表为空，删除该键
	if len(shard.listItems[key]) == 0 {
		delete(shard.listItems, key)
		delete(shard.expiration, key)
	}

	return true
}

// AddToListWithLimit 将元素添加到列表，并在超出限制时修剪列表
func (c *Cache[K, V]) AddToListWithLimit(key K, value V, maxSize int) {
	// 将新元素推入列表
	c.RPush(key, value)

	// 获取列表长度是否超限
	if c.LLen(key) > maxSize {
		// 修剪列表到最大大小
		c.LTrim(key, -maxSize, -1)
	}
}

//------------------------------------------------------------------------------
// 事务支持
//------------------------------------------------------------------------------

// Transaction 表示一个缓存事务
type Transaction[K comparable, V any] struct {
	cache           *Cache[K, V]
	items           map[K]CacheItem[V]
	listItems       map[K][]ListItem[V]
	expiration      map[K]int64
	itemsToAdd      map[K]CacheItem[V]
	itemsToRemove   map[K]struct{}
	listsToAdd      map[K][]ListItem[V]
	listsToRemove   map[K]struct{}
	expirationToSet map[K]int64
}

// BeginTransaction 开始一个新事务
func (c *Cache[K, V]) BeginTransaction() *Transaction[K, V] {
	c.globalMu.RLock()
	defer c.globalMu.RUnlock()

	// 创建事务对象并复制当前数据快照
	t := &Transaction[K, V]{
		cache:           c,
		items:           make(map[K]CacheItem[V]),
		listItems:       make(map[K][]ListItem[V]),
		expiration:      make(map[K]int64),
		itemsToAdd:      make(map[K]CacheItem[V]),
		itemsToRemove:   make(map[K]struct{}),
		listsToAdd:      make(map[K][]ListItem[V]),
		listsToRemove:   make(map[K]struct{}),
		expirationToSet: make(map[K]int64),
	}

	// 复制普通缓存项
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.items {
			t.items[k] = v
		}
		shard.mu.RUnlock()
	}

	// 复制列表缓存项
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.listItems {
			listCopy := make([]ListItem[V], len(v))
			copy(listCopy, v)
			t.listItems[k] = listCopy
		}
		shard.mu.RUnlock()
	}

	// 复制过期时间
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.expiration {
			t.expiration[k] = v
		}
		shard.mu.RUnlock()
	}

	return t
}

// Set 在事务中设置缓存项
func (t *Transaction[K, V]) Set(key K, value V, duration time.Duration) {
	var expiration int64

	if duration == 0 {
		duration = t.cache.defaultExpiration
	}

	if duration > 0 {
		expiration = time.Now().Add(duration).UnixNano()
	} else {
		expiration = -1
	}

	t.itemsToAdd[key] = CacheItem[V]{
		Value:      value,
		Expiration: expiration,
	}
	delete(t.itemsToRemove, key)
}

// Delete 在事务中删除缓存项
func (t *Transaction[K, V]) Delete(key K) {
	t.itemsToRemove[key] = struct{}{}
	delete(t.itemsToAdd, key)
}

// LPush 在事务中将值插入列表头部
func (t *Transaction[K, V]) LPush(key K, values ...V) {
	// 获取对应分片
	shard := t.cache.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	list, exists := shard.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
		// 删除待删除列表中的记录（如果存在）
		delete(t.listsToRemove, key)
	} else if toAdd, exists := t.listsToAdd[key]; exists {
		// 使用当前事务中的列表
		list = toAdd
	}

	newList := make([]ListItem[V], len(values))
	for i, v := range values {
		newList[i] = ListItem[V]{Value: v}
	}

	t.listsToAdd[key] = append(newList, list...)
}

// DeleteList 在事务中删除列表
func (t *Transaction[K, V]) DeleteList(key K) {
	t.listsToRemove[key] = struct{}{}
	delete(t.listsToAdd, key)
}

// SetListExpiration 在事务中设置列表过期时间
func (t *Transaction[K, V]) SetListExpiration(key K, duration time.Duration) {
	var expiration int64

	if duration > 0 {
		expiration = time.Now().Add(duration).UnixNano()
	} else if duration == 0 {
		expiration = 0
	} else {
		expiration = -1
	}

	t.expirationToSet[key] = expiration
}

// Commit 提交事务
func (t *Transaction[K, V]) Commit() {
	t.cache.globalMu.Lock()
	defer t.cache.globalMu.Unlock()

	// 应用增加的项目
	for _, shard := range t.cache.shards {
		shard.mu.Lock()
		for k, v := range t.itemsToAdd {
			shard.items[k] = v
		}
		shard.mu.Unlock()
	}

	// 应用删除的项目
	for k := range t.itemsToRemove {
		for _, shard := range t.cache.shards {
			shard.mu.Lock()
			delete(shard.items, k)
			shard.mu.Unlock()
		}
	}

	// 应用增加的列表
	for _, shard := range t.cache.shards {
		shard.mu.Lock()
		for k, v := range t.listsToAdd {
			shard.listItems[k] = v
		}
		shard.mu.Unlock()
	}

	// 应用删除的列表
	for k := range t.listsToRemove {
		for _, shard := range t.cache.shards {
			shard.mu.Lock()
			delete(shard.listItems, k)
			delete(shard.expiration, k)
			shard.mu.Unlock()
		}
	}

	// 应用设置的过期时间
	for _, shard := range t.cache.shards {
		shard.mu.Lock()
		for k, v := range t.expirationToSet {
			shard.expiration[k] = v
		}
		shard.mu.Unlock()
	}

	// 标记缓存为已修改
	t.cache.markDirty()
}

// Rollback 回滚事务（什么也不做，因为事务只在Commit时才会应用）
func (t *Transaction[K, V]) Rollback() {
	// 清空所有事务操作
	t.itemsToAdd = make(map[K]CacheItem[V])
	t.itemsToRemove = make(map[K]struct{})
	t.listsToAdd = make(map[K][]ListItem[V])
	t.listsToRemove = make(map[K]struct{})
	t.expirationToSet = make(map[K]int64)
}
