package config

import (
	"os"
	"time"
)

// Config holds parameters to initialize the JWT middleware.
// Issuer must match the "iss" claim in access tokens (e.g. JWT_ISSUER).
// Audience must match the "aud" claim in access tokens (e.g. JWT_AUDIENCE).
// JWKSRefreshInterval is optional; if zero, 5m is used.
type Config struct {
	Issuer              string        // JWT_ISSUER
	Audience            string        // JWT_AUDIENCE
	JWKSRefreshInterval time.Duration // Optional, e.g. 5*time.Minute; 0 = 5m default
}

// DefaultJWKSRefreshInterval is used when Config.JWKSRefreshInterval is zero.
const DefaultJWKSRefreshInterval = 5 * time.Minute

// RefreshInterval returns the effective refresh interval (never zero).
func (c *Config) RefreshInterval() time.Duration {
	if c.JWKSRefreshInterval > 0 {
		return c.JWKSRefreshInterval
	}
	return DefaultJWKSRefreshInterval
}

// EnvConfig reads config from environment:
//   - JWT_ISSUER (required)
//   - JWT_AUDIENCE (required)
//   - JWKS_REFRESH_INTERVAL (optional Go duration, e.g. 5m, 1h)
func EnvConfig() (Config, error) {
	issuer := os.Getenv("JWT_ISSUER")
	audience := os.Getenv("JWT_AUDIENCE")
	intervalStr := os.Getenv("JWKS_REFRESH_INTERVAL")

	var interval time.Duration
	if intervalStr != "" {
		var err error
		interval, err = time.ParseDuration(intervalStr)
		if err != nil {
			return Config{}, err
		}
	}

	return Config{
		Issuer:              issuer,
		Audience:            audience,
		JWKSRefreshInterval: interval,
	}, nil
}
