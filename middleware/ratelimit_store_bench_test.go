package middleware

import (
	"strconv"
	"sync/atomic"
	"testing"
)

func BenchmarkMemoryRateLimitStoreAllowParallelSameKey(b *testing.B) {
	store := newMemoryRateLimitStore()
	defer func() {
		if err := store.Close(); err != nil {
			b.Errorf("failed to close rate limit store: %v", err)
		}
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Allow("same-key", 1000, 100)
		}
	})
}

func BenchmarkMemoryRateLimitStoreAllowParallelMultiKey(b *testing.B) {
	store := newMemoryRateLimitStore()
	defer func() {
		if err := store.Close(); err != nil {
			b.Errorf("failed to close rate limit store: %v", err)
		}
	}()

	var counter uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := atomic.AddUint64(&counter, 1)
			key := "key-" + strconv.FormatUint(id%1024, 10)
			store.Allow(key, 1000, 100)
		}
	})
}
