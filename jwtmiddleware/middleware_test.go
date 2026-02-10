package jwtmiddleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/atmoz-org/jwt-validator-middleware/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_FailInitialRefresh(t *testing.T) {
	_, err := New("https://invalid.example.invalid", "api", time.Minute)
	require.Error(t, err)
}

func TestNew_Success(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestNewFromConfig_EmptyIssuer(t *testing.T) {
	_, err := NewFromConfig(config.Config{Audience: "api"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestNewFromConfig_EmptyAudience(t *testing.T) {
	_, err := NewFromConfig(config.Config{Issuer: "https://iss.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestNewFromConfig_Success(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	m, err := NewFromConfig(config.Config{
		Issuer:              issuer,
		Audience:            audience,
		JWKSRefreshInterval: time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestNewFromEnv_MissingIssuer(t *testing.T) {
	os.Unsetenv("JWT_ISSUER")
	os.Setenv("JWT_AUDIENCE", "api")
	os.Unsetenv("JWKS_REFRESH_INTERVAL")
	defer os.Unsetenv("JWT_AUDIENCE")

	_, err := NewFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestNewFromEnv_Success(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	os.Setenv("JWT_ISSUER", issuer)
	os.Setenv("JWT_AUDIENCE", audience)
	os.Unsetenv("JWKS_REFRESH_INTERVAL")
	defer func() {
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
	}()

	m, err := NewFromEnv()
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestMiddleware_RequireAuth_MissingHeader(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	nextCalled := false
	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing authorization")
}

func TestMiddleware_RequireAuth_InvalidFormat(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc")
	rec := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid authorization")
}

func TestMiddleware_RequireAuth_EmptyBearer(t *testing.T) {
	server, issuer, audience := testJWKSServer(t, "kid-1")
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "empty bearer")
}

func TestMiddleware_RequireAuth_InvalidToken(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	token := testSignToken(t, key, issuer, "wrong-aud", "user-1", "u@ex.com", "kid-1")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid token")
}

func TestMiddleware_RequireAuth_ValidToken(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	token := testSignToken(t, key, issuer, audience, "user-1", "user@example.com", "kid-1")

	var gotToken, gotUserID, gotEmail string
	var gotClaims *Claims
	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, _ = GetAccessToken(r.Context())
		gotUserID, _ = GetUserID(r.Context())
		gotEmail, _ = GetUserEmail(r.Context())
		gotClaims, _ = GetClaims(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, "user-1", gotUserID)
	assert.Equal(t, "user@example.com", gotEmail)
	require.NotNil(t, gotClaims)
	assert.Equal(t, "user-1", gotClaims.Subject)
	assert.Equal(t, "user@example.com", gotClaims.Email)
}

func TestMiddleware_VerifyToken(t *testing.T) {
	key := testGenerateKey(t)
	server, issuer, audience := testJWKSServerWithKey(t, "kid-1", key)
	defer server.Close()

	m, err := New(issuer, audience, time.Minute)
	require.NoError(t, err)

	token := testSignToken(t, key, issuer, audience, "sub-1", "a@b.com", "kid-1")
	claims, err := m.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "sub-1", claims.Subject)
	assert.Equal(t, "a@b.com", claims.Email)
}

func TestGetAccessToken_NotFound(t *testing.T) {
	_, ok := GetAccessToken(context.Background())
	assert.False(t, ok)
}

func TestGetUserID_NotFound(t *testing.T) {
	_, ok := GetUserID(context.Background())
	assert.False(t, ok)
}

func TestGetUserEmail_NotFound(t *testing.T) {
	_, ok := GetUserEmail(context.Background())
	assert.False(t, ok)
}

func TestGetClaims_NotFound(t *testing.T) {
	_, ok := GetClaims(context.Background())
	assert.False(t, ok)
}

func TestSendErrorResponse_JSON(t *testing.T) {
	rec := httptest.NewRecorder()
	sendErrorResponse(rec, "test message", http.StatusForbidden)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "test message")
	assert.Contains(t, rec.Body.String(), "Unauthorized")
}
