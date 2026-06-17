package oauth2

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/storage/memory"
)

type stringStorage struct {
	data map[string]string
	ttl  map[string]time.Time
}

func newStringStorage() adapter.Storage {
	return &stringStorage{
		data: make(map[string]string),
		ttl:  make(map[string]time.Time),
	}
}

func (s *stringStorage) Set(key string, value any, expiration time.Duration) error {
	payload, err := stringify(value)
	if err != nil {
		return err
	}
	s.data[key] = payload
	if expiration > 0 {
		s.ttl[key] = time.Now().Add(expiration)
	} else {
		delete(s.ttl, key)
	}
	return nil
}

func (s *stringStorage) SetKeepTTL(key string, value any) error {
	payload, err := stringify(value)
	if err != nil {
		return err
	}
	if _, ok := s.data[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	s.data[key] = payload
	return nil
}

func (s *stringStorage) Get(key string) (any, error) {
	if exp, ok := s.ttl[key]; ok && time.Now().After(exp) {
		delete(s.data, key)
		delete(s.ttl, key)
		return nil, fmt.Errorf("key not found: %s", key)
	}
	value, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return value, nil
}

func (s *stringStorage) Delete(keys ...string) error {
	for _, key := range keys {
		delete(s.data, key)
		delete(s.ttl, key)
	}
	return nil
}

func (s *stringStorage) Exists(key string) bool {
	_, err := s.Get(key)
	return err == nil
}

func (s *stringStorage) Keys(pattern string) ([]string, error) {
	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *stringStorage) Expire(key string, expiration time.Duration) error {
	if _, ok := s.data[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	if expiration > 0 {
		s.ttl[key] = time.Now().Add(expiration)
	} else {
		delete(s.ttl, key)
	}
	return nil
}

func (s *stringStorage) TTL(key string) (time.Duration, error) {
	exp, ok := s.ttl[key]
	if !ok {
		if _, exists := s.data[key]; exists {
			return -1, nil
		}
		return -2, fmt.Errorf("key not found: %s", key)
	}
	return time.Until(exp), nil
}

func (s *stringStorage) Clear() error {
	s.data = make(map[string]string)
	s.ttl = make(map[string]time.Time)
	return nil
}

func (s *stringStorage) Ping() error {
	return nil
}

func stringify(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case interface{ MarshalBinary() ([]byte, error) }:
		payload, err := v.MarshalBinary()
		if err != nil {
			return "", err
		}
		return string(payload), nil
	default:
		return "", fmt.Errorf("unsupported value type %T", value)
	}
}

func TestOAuth2AuthorizationCodeFlowAcrossStorageBackends(t *testing.T) {
	testCases := []struct {
		name    string
		storage adapter.Storage
	}{
		{name: "memory", storage: memory.NewStorage()},
		{name: "string-backed", storage: newStringStorage()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			registrar := NewOAuth2Server(tc.storage, "test:")
			err := registrar.RegisterClient(&Client{
				ClientID:     "client-1",
				ClientSecret: "secret-1",
				RedirectURIs: []string{"https://example.com/callback"},
			})
			if err != nil {
				t.Fatalf("register client: %v", err)
			}

			server := NewOAuth2Server(tc.storage, "test:")
			client, err := server.GetClient("client-1")
			if err != nil {
				t.Fatalf("get persisted client: %v", err)
			}
			if client.ClientSecret != "secret-1" {
				t.Fatalf("client secret = %q, want %q", client.ClientSecret, "secret-1")
			}

			authCode, err := server.GenerateAuthorizationCode(
				"client-1",
				"https://example.com/callback",
				"user-1",
				[]string{"profile:read"},
			)
			if err != nil {
				t.Fatalf("generate auth code: %v", err)
			}

			token, err := server.ExchangeCodeForToken(
				authCode.Code,
				"client-1",
				"secret-1",
				"https://example.com/callback",
			)
			if err != nil {
				t.Fatalf("exchange code: %v", err)
			}

			if _, err := server.ExchangeCodeForToken(
				authCode.Code,
				"client-1",
				"secret-1",
				"https://example.com/callback",
			); err != ErrAuthCodeUsed {
				t.Fatalf("reuse auth code err = %v, want %v", err, ErrAuthCodeUsed)
			}

			validated, err := server.ValidateAccessToken(token.Token)
			if err != nil {
				t.Fatalf("validate access token: %v", err)
			}
			if validated.UserID != "user-1" {
				t.Fatalf("validated userID = %q, want %q", validated.UserID, "user-1")
			}

			refreshed, err := server.RefreshAccessToken(token.RefreshToken, "client-1", "secret-1")
			if err != nil {
				t.Fatalf("refresh access token: %v", err)
			}
			if refreshed.Token == token.Token {
				t.Fatal("expected refreshed token to differ from original token")
			}
			if refreshed.RefreshToken == token.RefreshToken {
				t.Fatal("expected rotated refresh token to differ from original refresh token")
			}

			if _, err := server.ValidateAccessToken(refreshed.Token); err != nil {
				t.Fatalf("validate refreshed token: %v", err)
			}
			if _, err := server.ValidateAccessToken(token.Token); err != ErrInvalidAccessToken {
				t.Fatalf("validate original token err = %v, want %v", err, ErrInvalidAccessToken)
			}
			if _, err := server.RefreshAccessToken(token.RefreshToken, "client-1", "secret-1"); err != ErrInvalidRefreshToken {
				t.Fatalf("reuse refresh token err = %v, want %v", err, ErrInvalidRefreshToken)
			}

			if err := server.RevokeToken(refreshed.Token); err != nil {
				t.Fatalf("revoke token: %v", err)
			}
			if _, err := server.ValidateAccessToken(refreshed.Token); err != ErrInvalidAccessToken {
				t.Fatalf("validate revoked token err = %v, want %v", err, ErrInvalidAccessToken)
			}
			if _, err := server.RefreshAccessToken(refreshed.RefreshToken, "client-1", "secret-1"); err != ErrInvalidRefreshToken {
				t.Fatalf("validate revoked refresh token err = %v, want %v", err, ErrInvalidRefreshToken)
			}
		})
	}
}

func TestOAuth2ExchangeCodeForTokenSingleUseUnderConcurrency(t *testing.T) {
	server := NewOAuth2Server(memory.NewStorage(), "test:")
	if err := server.RegisterClient(&Client{
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		RedirectURIs: []string{"https://example.com/callback"},
	}); err != nil {
		t.Fatalf("register client: %v", err)
	}

	authCode, err := server.GenerateAuthorizationCode(
		"client-1",
		"https://example.com/callback",
		"user-1",
		[]string{"profile:read"},
	)
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)

	exchange := func() {
		defer wg.Done()
		<-start
		_, err := server.ExchangeCodeForToken(
			authCode.Code,
			"client-1",
			"secret-1",
			"https://example.com/callback",
		)
		results <- err
	}

	wg.Add(2)
	go exchange()
	go exchange()
	close(start)
	wg.Wait()
	close(results)

	successCount := 0
	usedCount := 0
	for err := range results {
		switch err {
		case nil:
			successCount++
		case ErrAuthCodeUsed:
			usedCount++
		default:
			t.Fatalf("unexpected exchange result: %v", err)
		}
	}

	if successCount != 1 || usedCount != 1 {
		t.Fatalf("successCount=%d usedCount=%d, want 1/1", successCount, usedCount)
	}
}

func TestDecodeHelpers_CopyPointerInput(t *testing.T) {
	t.Run("authorization code", func(t *testing.T) {
		original := &AuthorizationCode{
			Code:        "code-1",
			ClientID:    "client-1",
			RedirectURI: "https://example.com/callback",
			UserID:      "user-1",
			Scopes:      []string{"profile:read"},
			CreateTime:  1,
			ExpiresIn:   60,
			Used:        false,
		}

		decoded, err := decodeAuthorizationCode(original)
		if err != nil {
			t.Fatalf("decodeAuthorizationCode() error = %v", err)
		}
		if decoded == nil {
			t.Fatal("decodeAuthorizationCode() returned nil")
		}
		if decoded == original {
			t.Fatal("decodeAuthorizationCode() should return a copy for pointer input")
		}

		decoded.Used = true
		if original.Used {
			t.Fatal("mutating decoded authorization code should not affect original")
		}
	})

	t.Run("access token", func(t *testing.T) {
		original := &AccessToken{
			Token:        "token-1",
			TokenType:    TokenTypeBearer,
			ExpiresIn:    3600,
			RefreshToken: "refresh-1",
			Scopes:       []string{"profile:read"},
			UserID:       "user-1",
			ClientID:     "client-1",
		}

		decoded, err := decodeAccessToken(original)
		if err != nil {
			t.Fatalf("decodeAccessToken() error = %v", err)
		}
		if decoded == nil {
			t.Fatal("decodeAccessToken() returned nil")
		}
		if decoded == original {
			t.Fatal("decodeAccessToken() should return a copy for pointer input")
		}

		decoded.Token = "token-2"
		if original.Token != "token-1" {
			t.Fatal("mutating decoded access token should not affect original")
		}
	})

	t.Run("client", func(t *testing.T) {
		original := &Client{
			ClientID:     "client-1",
			ClientSecret: "secret-1",
			RedirectURIs: []string{"https://example.com/callback"},
			GrantTypes:   []GrantType{GrantTypeAuthorizationCode},
			Scopes:       []string{"profile:read"},
		}

		decoded, err := decodeClient(original)
		if err != nil {
			t.Fatalf("decodeClient() error = %v", err)
		}
		if decoded == nil {
			t.Fatal("decodeClient() returned nil")
		}
		if decoded == original {
			t.Fatal("decodeClient() should return a copy for pointer input")
		}

		decoded.ClientSecret = "secret-2"
		if original.ClientSecret != "secret-1" {
			t.Fatal("mutating decoded client should not affect original")
		}
	})
}
