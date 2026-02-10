package jwkscache

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultRefreshInterval = 5 * time.Minute

var ErrKeyNotFound = errors.New("jwks key not found")

// Claims represents the JWT claims used by this middleware (OIDC-style: iss, aud, sub, email, etc.).
type Claims struct {
	Email string   `json:"email,omitempty"`
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// JWKSCache caches JWKS keys and verifies tokens.
type JWKSCache struct {
	jwksURL         string
	issuer          string
	audience        string
	refreshInterval time.Duration
	httpClient      *http.Client

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWKSCache creates a JWKS cache. refreshInterval <= 0 defaults to 5m. httpClient may be nil for default.
func NewJWKSCache(issuer, audience string, refreshInterval time.Duration, httpClient *http.Client) (*JWKSCache, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	if refreshInterval <= 0 {
		refreshInterval = defaultRefreshInterval
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &JWKSCache{
		jwksURL:         buildJWKSURL(issuer),
		issuer:          issuer,
		audience:        audience,
		refreshInterval: refreshInterval,
		httpClient:      httpClient,
		keys:            make(map[string]*rsa.PublicKey),
	}, nil
}

// Start begins background JWKS refresh. Stops when ctx is cancelled.
func (c *JWKSCache) Start(ctx context.Context) {
	ticker := time.NewTicker(c.refreshInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = c.Refresh(ctx)
			}
		}
	}()
}

// Refresh fetches the current JWKS and updates the cache.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("create jwks request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var payload jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, key := range payload.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		pubKey, err := jwkToPublicKey(key)
		if err != nil {
			return fmt.Errorf("parse jwk %s: %w", key.Kid, err)
		}
		keys[key.Kid] = pubKey
	}

	c.mu.Lock()
	c.keys = keys
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return nil
}

// VerifyToken parses and validates the token, returning claims or an error.
func (c *JWKSCache) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		c.keyFunc,
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.audience),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
	)
	if err == nil {
		return claims, nil
	}

	if errors.Is(err, ErrKeyNotFound) {
		if refreshErr := c.Refresh(ctx); refreshErr != nil {
			return nil, fmt.Errorf("refresh jwks after kid miss: %w", refreshErr)
		}
		claims = &Claims{}
		_, retryErr := jwt.ParseWithClaims(
			tokenString,
			claims,
			c.keyFunc,
			jwt.WithIssuer(c.issuer),
			jwt.WithAudience(c.audience),
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		)
		if retryErr != nil {
			return nil, retryErr
		}
		return claims, nil
	}

	return nil, err
}

func (c *JWKSCache) keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kidValue, ok := token.Header["kid"]
	if !ok {
		return nil, errors.New("missing kid header")
	}
	kid, ok := kidValue.(string)
	if !ok || kid == "" {
		return nil, errors.New("invalid kid header")
	}

	if key := c.getKey(kid); key != nil {
		return key, nil
	}

	return nil, ErrKeyNotFound
}

func (c *JWKSCache) getKey(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

func buildJWKSURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/oauth/v2/keys"
}

func jwkToPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %s", key.Kty)
	}
	if key.N == "" || key.E == "" {
		return nil, errors.New("missing modulus or exponent")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		return nil, errors.New("invalid exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}
