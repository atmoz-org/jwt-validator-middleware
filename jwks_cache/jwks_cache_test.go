package jwkscache

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWKSCache_EmptyIssuer(t *testing.T) {
	_, err := NewJWKSCache("", "api", time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestNewJWKSCache_EmptyAudience(t *testing.T) {
	_, err := NewJWKSCache("https://iss.example.com", "", time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestNewJWKSCache_DefaultInterval(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, 0, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)
	assert.Equal(t, 5*time.Minute, cache.refreshInterval)
}

func TestNewJWKSCache_NilClient(t *testing.T) {
	cache, err := NewJWKSCache("https://x.com", "api", time.Minute, nil)
	require.NoError(t, err)
	require.NotNil(t, cache.httpClient)
}

func TestJWKSCache_Refresh_Success(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, time.Minute, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = cache.Refresh(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, cache.getKey("kid-1"))
}

func TestJWKSCache_Refresh_Non200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL, "api", time.Minute, nil)
	require.NoError(t, err)

	err = cache.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestJWKSCache_Refresh_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL, "api", time.Minute, nil)
	require.NoError(t, err)

	err = cache.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode jwks")
}

func TestJWKSCache_Refresh_InvalidJWK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": "x", "n": "", "e": "AQAB"},
			},
		})
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL, "api", time.Minute, nil)
	require.NoError(t, err)

	err = cache.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse jwk")
}

func TestJWKSCache_Refresh_UnsupportedKeyType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "EC", "kid": "x", "crv": "P-256"},
			},
		})
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL, "api", time.Minute, nil)
	require.NoError(t, err)

	err = cache.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestJWKSCache_VerifyToken_Success(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, cache.Refresh(context.Background()))

	token := testSignToken(t, key, issuer, audience, "user-1", "u@ex.com", "kid-1")
	claims, err := cache.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, "u@ex.com", claims.Email)
}

func TestJWKSCache_VerifyToken_InvalidSignature(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, cache.Refresh(context.Background()))

	otherKey := testGenerateKey(t)
	token := testSignToken(t, otherKey, issuer, audience, "user-1", "u@ex.com", "kid-1")

	_, err = cache.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSCache_VerifyToken_WrongAudience(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, cache.Refresh(context.Background()))

	token := testSignToken(t, key, issuer, "other-audience", "user-1", "u@ex.com", "kid-1")
	_, err = cache.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSCache_VerifyToken_KeyNotFoundThenRefresh(t *testing.T) {
	key := testGenerateKey(t)
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		callCount++
		kid := "kid-other"
		if callCount > 1 {
			kid = "kid-1"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse(key.PublicKey, kid))
	}))
	defer server.Close()
	issuer, audience := server.URL, "api"

	cache, err := NewJWKSCache(issuer, audience, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, cache.Refresh(context.Background()))

	token := testSignToken(t, key, issuer, audience, "user-1", "u@ex.com", "kid-1")
	claims, err := cache.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, 2, callCount)
}

func TestJWKSCache_Start_StopsOnContextCancel(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	cache, err := NewJWKSCache(issuer, audience, 100*time.Millisecond, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cache.Start(ctx)
	cancel()
	time.Sleep(150 * time.Millisecond)
}

// TestJWKSCache_Start_PeriodicRefresh verifies that the background ticker triggers Refresh
// after the interval (covers the ticker branch at line 90-91).
func TestJWKSCache_Start_PeriodicRefresh(t *testing.T) {
	key := testGenerateKey(t)
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse(key.PublicKey, "kid-1"))
	}))
	defer server.Close()
	issuer, audience := server.URL, "api"

	// Short interval so the test finishes quickly (one tick after ~25ms)
	refreshInterval := 25 * time.Millisecond
	cache, err := NewJWKSCache(issuer, audience, refreshInterval, nil)
	require.NoError(t, err)

	// Initial refresh
	require.NoError(t, cache.Refresh(context.Background()))
	assert.Equal(t, int32(1), requestCount.Load(), "expected one request after initial Refresh")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)

	// Wait for at least one ticker fire (slightly more than one interval)
	time.Sleep(refreshInterval + 15*time.Millisecond)

	count := requestCount.Load()
	assert.GreaterOrEqual(t, count, int32(2), "expected at least two JWKS requests (initial + one from ticker)")
}

// Test keyFunc error branches (unexpected method, missing kid, invalid kid).
func TestJWKSCache_keyFunc_UnexpectedSigningMethod(t *testing.T) {
	cache, err := NewJWKSCache("https://x.com", "api", time.Minute, nil)
	require.NoError(t, err)

	token := &jwt.Token{
		Method: jwt.SigningMethodHS256,
		Header: map[string]interface{}{"alg": "HS256"},
	}
	_, err = cache.keyFunc(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

func TestJWKSCache_keyFunc_MissingKidHeader(t *testing.T) {
	cache, err := NewJWKSCache("https://x.com", "api", time.Minute, nil)
	require.NoError(t, err)

	token := &jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{"alg": "RS256"},
	}
	_, err = cache.keyFunc(token)
	require.Error(t, err)
	assert.Equal(t, "missing kid header", err.Error())
}

func TestJWKSCache_keyFunc_InvalidKidHeaderNotString(t *testing.T) {
	cache, err := NewJWKSCache("https://x.com", "api", time.Minute, nil)
	require.NoError(t, err)

	token := &jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{"alg": "RS256", "kid": 123},
	}
	_, err = cache.keyFunc(token)
	require.Error(t, err)
	assert.Equal(t, "invalid kid header", err.Error())
}

func TestJWKSCache_keyFunc_InvalidKidHeaderEmptyString(t *testing.T) {
	cache, err := NewJWKSCache("https://x.com", "api", time.Minute, nil)
	require.NoError(t, err)

	token := &jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{"alg": "RS256", "kid": ""},
	}
	_, err = cache.keyFunc(token)
	require.Error(t, err)
	assert.Equal(t, "invalid kid header", err.Error())
}

func TestBuildJWKSURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/v2/keys", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL, "api", time.Minute, nil)
	require.NoError(t, err)
	err = cache.Refresh(context.Background())
	require.NoError(t, err)
}

func TestBuildJWKSURL_TrimTrailingSlash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/v2/keys", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	cache, err := NewJWKSCache(server.URL+"/", "api", time.Minute, nil)
	require.NoError(t, err)
	err = cache.Refresh(context.Background())
	require.NoError(t, err)
}
