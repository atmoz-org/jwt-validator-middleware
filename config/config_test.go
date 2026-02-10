package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_RefreshInterval(t *testing.T) {
	assert.Equal(t, DefaultJWKSRefreshInterval, (&Config{}).RefreshInterval())
	assert.Equal(t, 2*time.Minute, (&Config{JWKSRefreshInterval: 2 * time.Minute}).RefreshInterval())
}

func TestEnvConfig_MissingVars(t *testing.T) {
	os.Unsetenv("JWT_ISSUER")
	os.Unsetenv("JWT_AUDIENCE")
	os.Unsetenv("JWKS_REFRESH_INTERVAL")

	cfg, err := EnvConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.Issuer)
	assert.Empty(t, cfg.Audience)
	assert.Zero(t, cfg.JWKSRefreshInterval)
}

func TestEnvConfig_InvalidDuration(t *testing.T) {
	os.Setenv("JWT_ISSUER", "https://iss.example.com")
	os.Setenv("JWT_AUDIENCE", "api")
	os.Setenv("JWKS_REFRESH_INTERVAL", "not-a-duration")
	defer func() {
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
		os.Unsetenv("JWKS_REFRESH_INTERVAL")
	}()

	_, err := EnvConfig()
	require.Error(t, err)
}

func TestEnvConfig_Success(t *testing.T) {
	os.Setenv("JWT_ISSUER", "https://iss.example.com")
	os.Setenv("JWT_AUDIENCE", "api")
	os.Setenv("JWKS_REFRESH_INTERVAL", "10m")
	defer func() {
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
		os.Unsetenv("JWKS_REFRESH_INTERVAL")
	}()

	cfg, err := EnvConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://iss.example.com", cfg.Issuer)
	assert.Equal(t, "api", cfg.Audience)
	assert.Equal(t, 10*time.Minute, cfg.JWKSRefreshInterval)
}
