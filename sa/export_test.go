package sa

import (
	"sync/atomic"
	"testing"

	memory "github.com/darkit/gin/pkg/token/storage"
)

func TestDefaultManagerInitialized(t *testing.T) {
	if GetManager() == nil {
		t.Fatal("default manager should be initialized via init")
	}
}

type countingProvider struct {
	count int32
}

func (p *countingProvider) Provide() Storage {
	atomic.AddInt32(&p.count, 1)
	return memory.NewStorage()
}

func TestUseStorageProvider(t *testing.T) {
	provider := &countingProvider{}
	UseStorageProvider(provider, nil)

	if atomic.LoadInt32(&provider.count) == 0 {
		t.Fatal("custom storage provider should be invoked")
	}

	if GetManager() == nil {
		t.Fatal("manager should be reconfigured when using custom storage provider")
	}
}
