package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/darkit/gin/pkg/token/config"
)

func TestGenerateHash(t *testing.T) {
	cfg := &config.Config{
		TokenStyle: config.TokenStyleHash,
		Timeout:    3600,
	}
	gen := NewGenerator(cfg)

	token1, err := gen.Generate("user1000", "default")
	if err != nil {
		t.Fatalf("Failed to generate hash token: %v", err)
	}

	if len(token1) != 64 {
		t.Errorf("Hash token should be 64 characters, got %d", len(token1))
	}

	// Generate another token, should be different
	token2, err := gen.Generate("user1000", "default")
	if err != nil {
		t.Fatalf("Failed to generate second hash token: %v", err)
	}

	if token1 == token2 {
		t.Error("Hash tokens should be different due to randomness")
	}

	t.Logf("Hash Token 1: %s", token1)
	t.Logf("Hash Token 2: %s", token2)
}

func TestGenerateTimestamp(t *testing.T) {
	cfg := &config.Config{
		TokenStyle: config.TokenStyleTimestamp,
		Timeout:    3600,
	}
	gen := NewGenerator(cfg)

	token, err := gen.Generate("user1000", "default")
	if err != nil {
		t.Fatalf("Failed to generate timestamp token: %v", err)
	}

	// Timestamp token format: timestamp_loginID_random
	if len(token) < 20 {
		t.Errorf("Timestamp token seems too short: %s", token)
	}

	t.Logf("Timestamp Token: %s", token)
}

func TestGenerateTik(t *testing.T) {
	cfg := &config.Config{
		TokenStyle: config.TokenStyleTik,
		Timeout:    3600,
	}
	gen := NewGenerator(cfg)

	token, err := gen.Generate("user1000", "default")
	if err != nil {
		t.Fatalf("Failed to generate tik token: %v", err)
	}

	if len(token) != 11 {
		t.Errorf("Tik token should be 11 characters, got %d", len(token))
	}

	// Check all characters are alphanumeric
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			t.Errorf("Tik token should only contain alphanumeric characters, got: %c in %s", c, token)
		}
	}

	t.Logf("Tik Token: %s", token)
}

func TestAllTokenStyles(t *testing.T) {
	styles := []config.TokenStyle{
		config.TokenStyleUUID,
		config.TokenStyleSimple,
		config.TokenStyleRandom32,
		config.TokenStyleRandom64,
		config.TokenStyleRandom128,
		config.TokenStyleJWT,
		config.TokenStyleHash,
		config.TokenStyleTimestamp,
		config.TokenStyleTik,
	}

	for _, style := range styles {
		t.Run(string(style), func(t *testing.T) {
			cfg := &config.Config{
				TokenStyle:   style,
				Timeout:      3600,
				JwtSecretKey: "test-secret-key",
			}
			gen := NewGenerator(cfg)

			token, err := gen.Generate("user1000", "default")
			if err != nil {
				t.Fatalf("Failed to generate %s token: %v", style, err)
			}

			if token == "" {
				t.Errorf("%s token should not be empty", style)
			}

			t.Logf("%s Token: %s (length: %d)", style, token, len(token))
		})
	}

	t.Run("JWT-RS256", func(t *testing.T) {
		privPEM, pubPEM := mustGenerateRSAKeyPEM(t)
		cfg := &config.Config{
			TokenStyle:    config.TokenStyleJWT,
			Timeout:       3600,
			JwtAlgorithm:  "RS256",
			JwtPrivateKey: privPEM,
			JwtPublicKey:  pubPEM,
		}

		gen := NewGenerator(cfg)
		token, err := gen.Generate("user1000", "default")
		if err != nil {
			t.Fatalf("Failed to generate RS256 jwt: %v", err)
		}
		if token == "" {
			t.Fatalf("RS256 jwt should not be empty")
		}
		if _, err := gen.ParseJWT(token); err != nil {
			t.Fatalf("Parse RS256 jwt failed: %v", err)
		}
	})
}

// 动态生成测试用 RSA 密钥，避免 PEM 解析问题
func mustGenerateRSAKeyPEM(t *testing.T) (string, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}))
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal rsa public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	return privPEM, pubPEM
}
