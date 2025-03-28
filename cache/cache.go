package cache

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
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

// Cache 是一个综合的缓存实现，支持内存缓存和列表缓存
type Cache[K comparable, V any] struct {
	// 基本内存缓存项
	items map[K]CacheItem[V]
	// 列表缓存项
	listItems map[K][]ListItem[V]
	// 通用过期时间映射（主要用于列表缓存）
	expiration map[K]int64
	// 互斥锁
	mu sync.RWMutex
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

	// 统计信息
	stats struct {
		hitCount     uint64    // 命中次数
		missCount    uint64    // 未命中次数
		creationTime time.Time // 创建时间
		expiredCount uint64    // 过期项目计数
		deletedCount uint64    // 删除项目计数
	}
}

// NewCache 创建一个新的综合缓存
// defaultExpiration: 默认的过期时间
// cleanupInterval: 清理过期项的间隔时间
func NewCache[K comparable, V any](defaultExpiration, cleanupInterval time.Duration) *Cache[K, V] {
	cache := &Cache[K, V]{
		items:             make(map[K]CacheItem[V]),
		listItems:         make(map[K][]ListItem[V]),
		expiration:        make(map[K]int64),
		mu:                sync.RWMutex{},
		cleanupInterval:   cleanupInterval,
		defaultExpiration: defaultExpiration,
		stopCleanup:       make(chan bool),
		stopAutoPersist:   make(chan bool),
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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

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

// Save 保存缓存到文件
func (c *Cache[K, V]) Save() error {
	if c.persistPath == "" {
		return errors.New("persistence path not set")
	}

	c.mu.RLock()
	data := PersistenceData[K, V]{
		Items:             make(map[K]CacheItem[V]),
		ListItems:         make(map[K][]ListItem[V]),
		Expiration:        make(map[K]int64),
		DefaultExpiration: c.defaultExpiration,
	}

	// 只保存未过期的项目
	now := time.Now().UnixNano()
	for k, v := range c.items {
		if v.Expiration <= 0 || v.Expiration > now {
			data.Items[k] = v
		}
	}

	for k, v := range c.listItems {
		exp, hasExp := c.expiration[k]
		if !hasExp || exp <= 0 || exp > now {
			data.ListItems[k] = v
			if hasExp {
				data.Expiration[k] = exp
			}
		}
	}
	c.mu.RUnlock()

	// 创建临时文件
	tempFile := c.persistPath + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("error creating temporary file: %w", err)
	}

	// 使用gob编码数据
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		file.Close()
		return fmt.Errorf("error encoding cache data: %w", err)
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("error syncing file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("error closing file: %w", err)
	}

	// 重命名临时文件（原子操作）
	if err := os.Rename(tempFile, c.persistPath); err != nil {
		return fmt.Errorf("error renaming temporary file: %w", err)
	}

	c.mu.Lock()
	c.lastSaveTime = time.Now()
	c.dirty.Store(false)
	c.mu.Unlock()

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
	defer file.Close()

	var data PersistenceData[K, V]
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if err == io.EOF {
			return nil // 空文件不是错误
		}
		return fmt.Errorf("error decoding persistence data: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 清空当前数据
	c.items = make(map[K]CacheItem[V])
	c.listItems = make(map[K][]ListItem[V])
	c.expiration = make(map[K]int64)

	// 只加载未过期的项
	now := time.Now().UnixNano()
	for k, v := range data.Items {
		if v.Expiration <= 0 || v.Expiration > now {
			c.items[k] = v
		}
	}

	for k, v := range data.ListItems {
		exp, hasExp := data.Expiration[k]
		if !hasExp || exp <= 0 || exp > now {
			c.listItems[k] = v
			if hasExp {
				c.expiration[k] = exp
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
func (c *Cache[K, V]) DeleteExpired() {
	now := time.Now().UnixNano()
	removed := 0

	c.mu.Lock()
	defer c.mu.Unlock()

	// 清理普通缓存项
	for k, v := range c.items {
		if v.Expiration > 0 && now > v.Expiration {
			delete(c.items, k)
			removed++
		}
	}

	// 清理列表项
	for k, exp := range c.expiration {
		if exp > 0 && now > exp {
			delete(c.listItems, k)
			delete(c.expiration, k)
			removed++
		}
	}

	if removed > 0 {
		atomic.AddUint64(&c.stats.expiredCount, uint64(removed))
		c.markDirty()
	}
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

// isExpired 检查键是否过期（用于列表缓存）
func (c *Cache[K, V]) isExpired(key K) bool {
	exp, exists := c.expiration[key]
	if !exists {
		return false
	}

	if exp < 0 {
		return false // 永不过期
	}

	return exp > 0 && time.Now().UnixNano() > exp
}

// GetStats 获取缓存统计信息
func (c *Cache[K, V]) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var memUsage uint64

	// 简单估计内存使用量，不精确
	memUsage = uint64(len(c.items) * 64) // 假设每个键值对平均64字节

	for _, items := range c.listItems {
		memUsage += uint64(len(items) * 32) // 假设列表中每个项目平均32字节
	}

	return Stats{
		ItemsCount:    len(c.items),
		ListsCount:    len(c.listItems),
		HitCount:      atomic.LoadUint64(&c.stats.hitCount),
		MissCount:     atomic.LoadUint64(&c.stats.missCount),
		LastSaveTime:  c.lastSaveTime,
		LastLoadTime:  c.lastLoadTime,
		CreationTime:  c.stats.creationTime,
		MemoryUsage:   memUsage,
		ExpiredCount:  atomic.LoadUint64(&c.stats.expiredCount),
		DeletedCount:  atomic.LoadUint64(&c.stats.deletedCount),
		PersistPath:   c.persistPath,
		IsAutoPersist: c.autoPersistEnabled,
		SaveInterval:  c.autoPersistInterval,
	}
}

// Flush 清除所有数据并删除持久化文件
func (c *Cache[K, V]) Flush() error {
	c.mu.Lock()
	c.items = make(map[K]CacheItem[V])
	c.listItems = make(map[K][]ListItem[V])
	c.expiration = make(map[K]int64)
	c.mu.Unlock()

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
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
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
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.listItems[key]
	if !exists {
		return 0, false
	}

	exp, hasExp := c.expiration[key]
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

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = CacheItem[V]{
		Value:      value,
		Expiration: expiration,
	}

	c.markDirty()
}

// Get 获取缓存项
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		var zero V
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	// 检查是否过期
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		var zero V
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	atomic.AddUint64(&c.stats.hitCount, 1)
	return item.Value, true
}

// GetWithTTL 获取缓存项及其剩余生存时间
func (c *Cache[K, V]) GetWithTTL(key K) (V, time.Duration, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		var zero V
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, 0, false
	}

	// 检查是否过期
	now := time.Now().UnixNano()
	if item.Expiration > 0 && now > item.Expiration {
		var zero V
		atomic.AddUint64(&c.stats.missCount, 1)
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

	atomic.AddUint64(&c.stats.hitCount, 1)
	return item.Value, ttl, true
}

// Delete 删除缓存项
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[key]; exists {
		delete(c.items, key)
		atomic.AddUint64(&c.stats.deletedCount, 1)
		c.markDirty()
	}
}

// ForEach 遍历所有未过期的缓存项并对每一项执行指定的函数
func (c *Cache[K, V]) ForEach(fn func(key K, value V) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UnixNano()
	for k, item := range c.items {
		// 跳过已过期的项
		if item.Expiration > 0 && now > item.Expiration {
			continue
		}

		// 执行回调函数，如果返回false则停止遍历
		if !fn(k, item.Value) {
			break
		}
	}
}

// Clear 清空缓存
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[K]CacheItem[V])
	c.listItems = make(map[K][]ListItem[V])
	c.expiration = make(map[K]int64)

	c.markDirty()
}

// Count 返回缓存中的普通项目数量
func (c *Cache[K, V]) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.items)
}

// Keys 返回所有的普通缓存键
func (c *Cache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]K, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	return keys
}

// Has 检查键是否存在且未过期
func (c *Cache[K, V]) Has(key K) bool {
	_, exists := c.Get(key)
	return exists
}

// Increment 对数值类型进行增加操作
func (c *Cache[K, V]) Increment(key K, increment any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	item, found := c.items[key]

	// 处理值存在的情况
	if found {
		// 检查是否过期
		if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
			found = false
		}
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

	c.items[key] = item
	c.markDirty()

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

	c.mu.Lock()
	defer c.mu.Unlock()

	c.expiration[key] = expiration
	c.markDirty()
}

// LPush 将一个或多个值插入到列表头部
func (c *Cache[K, V]) LPush(key K, values ...V) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
	}

	list, exists := c.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
	}

	newList := make([]ListItem[V], len(values))
	for i, v := range values {
		newList[i] = ListItem[V]{Value: v}
	}

	c.listItems[key] = append(newList, list...)
	c.markDirty()

	return len(c.listItems[key])
}

// RPush 将一个或多个值插入到列表尾部
func (c *Cache[K, V]) RPush(key K, values ...V) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
	}

	list, exists := c.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
	}

	for _, v := range values {
		list = append(list, ListItem[V]{Value: v})
	}

	c.listItems[key] = list
	c.markDirty()

	return len(c.listItems[key])
}

// LPop 移除并返回列表头部的元素
func (c *Cache[K, V]) LPop(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	list, exists := c.listItems[key]
	if !exists || len(list) == 0 {
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	value := list[0].Value
	c.listItems[key] = list[1:]
	c.markDirty()

	// 如果列表为空，删除该键
	if len(c.listItems[key]) == 0 {
		delete(c.listItems, key)
		delete(c.expiration, key)
	}

	atomic.AddUint64(&c.stats.hitCount, 1)
	return value, true
}

// RPop 移除并返回列表尾部的元素
func (c *Cache[K, V]) RPop(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	list, exists := c.listItems[key]
	if !exists || len(list) == 0 {
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	lastIndex := len(list) - 1
	value := list[lastIndex].Value
	c.listItems[key] = list[:lastIndex]
	c.markDirty()

	// 如果列表为空，删除该键
	if len(c.listItems[key]) == 0 {
		delete(c.listItems, key)
		delete(c.expiration, key)
	}

	atomic.AddUint64(&c.stats.hitCount, 1)
	return value, true
}

// LIndex 通过索引获取列表中的元素
func (c *Cache[K, V]) LIndex(key K, index int) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero V

	if c.isExpired(key) {
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	list, exists := c.listItems[key]
	if !exists {
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	length := len(list)
	if index < 0 {
		// 处理负索引，如-1表示最后一个元素
		index = length + index
	}

	if index < 0 || index >= length {
		atomic.AddUint64(&c.stats.missCount, 1)
		return zero, false
	}

	atomic.AddUint64(&c.stats.hitCount, 1)
	return list[index].Value, true
}

// LRange 获取列表指定范围内的元素
func (c *Cache[K, V]) LRange(key K, start, stop int) []V {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isExpired(key) {
		atomic.AddUint64(&c.stats.missCount, 1)
		return []V{}
	}

	list, exists := c.listItems[key]
	if !exists {
		atomic.AddUint64(&c.stats.missCount, 1)
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

	atomic.AddUint64(&c.stats.hitCount, 1)
	return result
}

// LLen 获取列表长度
func (c *Cache[K, V]) LLen(key K) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isExpired(key) {
		return 0
	}

	list, exists := c.listItems[key]
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
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		return 0
	}

	list, exists := c.listItems[key]
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

		c.listItems[key] = newList
		c.markDirty()

		// 如果列表为空，删除该键
		if len(c.listItems[key]) == 0 {
			delete(c.listItems, key)
			delete(c.expiration, key)
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

		c.listItems[key] = newList
		c.markDirty()

		// 如果列表为空，删除该键
		if len(c.listItems[key]) == 0 {
			delete(c.listItems, key)
			delete(c.expiration, key)
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

		c.listItems[key] = newList
		c.markDirty()

		// 如果列表为空，删除该键
		if len(c.listItems[key]) == 0 {
			delete(c.listItems, key)
			delete(c.expiration, key)
		}

		return removed
	}
}

// RPoplPush 移除列表的最后一个元素，并将该元素添加到另一个列表的头部并返回它
func (c *Cache[K, V]) RPoplPush(source K, destination K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V

	// 检查源列表是否过期
	if c.isExpired(source) {
		delete(c.listItems, source)
		delete(c.expiration, source)
		return zero, false
	}

	// 获取源列表
	sourceList, exists := c.listItems[source]
	if !exists || len(sourceList) == 0 {
		return zero, false
	}

	// 获取最后一个元素
	lastIndex := len(sourceList) - 1
	value := sourceList[lastIndex].Value

	// 从源列表中移除
	c.listItems[source] = sourceList[:lastIndex]

	// 如果源列表为空，删除该键
	if len(c.listItems[source]) == 0 {
		delete(c.listItems, source)
		delete(c.expiration, source)
	}

	// 检查目标列表是否过期
	if c.isExpired(destination) {
		delete(c.listItems, destination)
		delete(c.expiration, destination)
	}

	// 获取目标列表
	destList, exists := c.listItems[destination]
	if !exists {
		destList = make([]ListItem[V], 0)
	}

	// 将元素添加到目标列表的头部
	c.listItems[destination] = append([]ListItem[V]{{Value: value}}, destList...)
	c.markDirty()

	return value, true
}

// BLPop 阻塞版本的LPop，不支持真正的阻塞，但可以模拟轮询
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BLPop(key K, timeout time.Duration) (V, bool) {
	startTime := time.Now()
	var zero V

	for {
		value, found := c.LPop(key)
		if found {
			return value, true
		}

		// 如果超时，返回
		if timeout > 0 && time.Since(startTime) > timeout {
			return zero, false
		}

		// 短暂休眠，避免CPU占用过高
		time.Sleep(10 * time.Millisecond)
	}
}

// BRPop 阻塞版本的RPop，不支持真正的阻塞，但可以模拟轮询
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BRPop(key K, timeout time.Duration) (V, bool) {
	startTime := time.Now()
	var zero V

	for {
		value, found := c.RPop(key)
		if found {
			return value, true
		}

		// 如果超时，返回
		if timeout > 0 && time.Since(startTime) > timeout {
			return zero, false
		}

		// 短暂休眠，避免CPU占用过高
		time.Sleep(10 * time.Millisecond)
	}
}

// BRPopLPush 阻塞版本的RPoplPush
// timeout为等待时间，0表示无限等待
func (c *Cache[K, V]) BRPopLPush(source K, destination K, timeout time.Duration) (V, bool) {
	startTime := time.Now()
	var zero V

	for {
		value, found := c.RPoplPush(source, destination)
		if found {
			return value, true
		}

		// 如果超时，返回
		if timeout > 0 && time.Since(startTime) > timeout {
			return zero, false
		}

		// 短暂休眠，避免CPU占用过高
		time.Sleep(10 * time.Millisecond)
	}
}

// DeleteList 删除列表
func (c *Cache[K, V]) DeleteList(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.listItems[key]; exists {
		delete(c.listItems, key)
		delete(c.expiration, key)
		atomic.AddUint64(&c.stats.deletedCount, 1)
		c.markDirty()
	}
}

// ListKeys 返回所有的列表键
func (c *Cache[K, V]) ListKeys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]K, 0, len(c.listItems))
	for k := range c.listItems {
		if !c.isExpired(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// ListCount 返回列表数量
func (c *Cache[K, V]) ListCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for k := range c.listItems {
		if !c.isExpired(k) {
			count++
		}
	}
	return count
}

// HasList 检查列表键是否存在且未过期
func (c *Cache[K, V]) HasList(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isExpired(key) {
		return false
	}

	_, exists := c.listItems[key]
	return exists
}

// ForEachList 遍历所有未过期的列表
func (c *Cache[K, V]) ForEachList(fn func(key K, list []V) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for k, items := range c.listItems {
		if c.isExpired(k) {
			continue
		}

		// 转换为值列表
		values := make([]V, len(items))
		for i, item := range items {
			values[i] = item.Value
		}

		// 执行回调函数，如果返回false则停止遍历
		if !fn(k, values) {
			break
		}
	}
}

// LSet 通过索引来设置列表元素的值
func (c *Cache[K, V]) LSet(key K, index int, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		return false
	}

	list, exists := c.listItems[key]
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
	c.markDirty()
	return true
}

// LInsert 在列表的指定位置插入元素
// before == true表示在pivot之前插入
// before == false表示在pivot之后插入
func (c *Cache[K, V]) LInsert(key K, before bool, pivot V, value V, equals func(a, b V) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		return 0
	}

	list, exists := c.listItems[key]
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
				c.listItems[key] = newList
			} else {
				// 在pivot之后插入
				newList := make([]ListItem[V], len(list)+1)
				copy(newList, list[:i+1])
				newList[i+1] = ListItem[V]{Value: value}
				copy(newList[i+2:], list[i+1:])
				c.listItems[key] = newList
			}
			c.markDirty()
			return len(c.listItems[key])
		}
	}

	return -1 // pivot不存在
}

// LTrim 对一个列表进行修剪，只保留指定区间内的元素
func (c *Cache[K, V]) LTrim(key K, start, stop int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isExpired(key) {
		delete(c.listItems, key)
		delete(c.expiration, key)
		return false
	}

	list, exists := c.listItems[key]
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
		delete(c.listItems, key)
		delete(c.expiration, key)
		c.markDirty()
		return true
	}

	if stop >= length {
		stop = length - 1
	}

	// 截取子列表
	c.listItems[key] = list[start : stop+1]
	c.markDirty()

	// 如果列表为空，删除该键
	if len(c.listItems[key]) == 0 {
		delete(c.listItems, key)
		delete(c.expiration, key)
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
	c.mu.RLock()
	defer c.mu.RUnlock()

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
	for k, v := range c.items {
		t.items[k] = v
	}

	// 复制列表缓存项
	for k, v := range c.listItems {
		listCopy := make([]ListItem[V], len(v))
		copy(listCopy, v)
		t.listItems[k] = listCopy
	}

	// 复制过期时间
	for k, v := range c.expiration {
		t.expiration[k] = v
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
	list, exists := t.listItems[key]
	if !exists {
		list = make([]ListItem[V], 0, len(values))
		// 检查是否在待删除列表中
		if _, toRemove := t.listsToRemove[key]; toRemove {
			delete(t.listsToRemove, key)
		}
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
	t.cache.mu.Lock()
	defer t.cache.mu.Unlock()

	// 应用增加的项目
	for k, v := range t.itemsToAdd {
		t.cache.items[k] = v
	}

	// 应用删除的项目
	for k := range t.itemsToRemove {
		delete(t.cache.items, k)
	}

	// 应用增加的列表
	for k, v := range t.listsToAdd {
		t.cache.listItems[k] = v
	}

	// 应用删除的列表
	for k := range t.listsToRemove {
		delete(t.cache.listItems, k)
		delete(t.cache.expiration, k)
	}

	// 应用设置的过期时间
	for k, v := range t.expirationToSet {
		t.cache.expiration[k] = v
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
