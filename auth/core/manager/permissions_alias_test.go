package manager

import (
	"testing"

	"github.com/darkit/gin/auth/core/config"
	"github.com/darkit/gin/auth/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToStringSlice_CopiesStringSlice(t *testing.T) {
	mgr := NewManager(memory.NewStorage(), config.DefaultConfig())

	original := []string{"user:read", "user:write"}
	cloned := mgr.toStringSlice(original)

	require.Len(t, cloned, len(original))
	require.Equal(t, original, cloned)

	cloned[0] = "admin:all"
	assert.Equal(t, "user:read", original[0], "mutating returned slice should not affect original")
}

func TestToStringSlice_ConvertsAnySlice(t *testing.T) {
	mgr := NewManager(memory.NewStorage(), config.DefaultConfig())

	converted := mgr.toStringSlice([]any{"user:read", "user:write", 1})
	assert.Equal(t, []string{"user:read", "user:write"}, converted)
}
