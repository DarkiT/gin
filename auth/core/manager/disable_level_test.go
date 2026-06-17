package manager

import (
	"errors"
	"testing"
	"time"

	"github.com/darkit/gin/auth/core/config"
	"github.com/darkit/gin/auth/core/errs"
	"github.com/darkit/gin/auth/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisableLevel_IsolationAndCheck(t *testing.T) {
	st := memory.NewStorage()
	cfg := config.DefaultConfig()
	m := NewManager(st, cfg)

	require.NoError(t, m.DisableLevel("u1", "svc-a", 2, time.Hour))
	assert.Equal(t, 2, m.GetDisableLevel("u1", "svc-a"))
	assert.False(t, m.IsDisableLevel("u1", "svc-b", 1))

	err := m.CheckDisableLevel("u1", "svc-a", 3)
	assert.NoError(t, err)

	err = m.CheckDisableLevel("u1", "svc-a", 2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errs.ErrDisableLevelExceeded))
}
