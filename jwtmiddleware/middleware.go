package jwtmiddleware

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nextgen-platform/jwt-validator-middleware/config"
	"github.com/nextgen-platform/jwt-validator-middleware/jwks_cache"
)

// Context key types to avoid collisions.
type contextKey string

const (
	contextKeyAccessToken contextKey = "access_token"
	contextKeyUserID      contextKey = "user_id"
	contextKeyUserEmail   contextKey = "user_email"
	contextKeyClaims      contextKey = "jwt_claims"
)

// Exported context keys for testing and advanced usage.
var (
	ContextKeyAccessToken = contextKeyAccessToken
	ContextKeyUserID      = contextKeyUserID
	ContextKeyUserEmail   = contextKeyUserEmail
	ContextKeyClaims      = contextKeyClaims
)

// ErrorResponse is the JSON body returned on auth errors.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// Claims is the JWT claims type (re-exported from jwks_cache for convenience).
type Claims = jwkscache.Claims

// Middleware validates JWT access tokens (e.g. from any OIDC/OAuth2 identity provider) and injects claims into context.
type Middleware struct {
	cache *jwkscache.JWKSCache
}

// New creates a Middleware with the given issuer, audience, and JWKS refresh interval.
// Issuer must match the "iss" claim; audience must match the "aud" claim.
// refreshInterval <= 0 defaults to 5m. It performs an initial JWKS fetch before returning.
func New(issuer, audience string, refreshInterval time.Duration) (*Middleware, error) {
	cache, err := jwkscache.NewJWKSCache(issuer, audience, refreshInterval, nil)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cache.Refresh(ctx); err != nil {
		return nil, err
	}

	cache.Start(context.Background())

	return &Middleware{cache: cache}, nil
}

// NewFromConfig creates a Middleware from config. It fetches JWKS once before returning.
func NewFromConfig(cfg config.Config) (*Middleware, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("audience is required")
	}
	return New(cfg.Issuer, cfg.Audience, cfg.RefreshInterval())
}

// NewFromEnv creates a Middleware using config.EnvConfig(). Convenient for services that
// configure via JWT_ISSUER, JWT_AUDIENCE, and optional JWKS_REFRESH_INTERVAL.
func NewFromEnv() (*Middleware, error) {
	cfg, err := config.EnvConfig()
	if err != nil {
		return nil, err
	}
	return NewFromConfig(cfg)
}

// RequireAuth returns an http.Handler that validates the Bearer token and calls next with claims in context.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := extractToken(r)
		if err != nil {
			sendErrorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, validateErr := m.cache.VerifyToken(r.Context(), tokenString)
		if validateErr != nil {
			log.Printf("Auth: token validation failed: %v", validateErr)
			sendErrorResponse(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := withClaims(r.Context(), tokenString, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// VerifyToken parses and validates a token string (for use outside HTTP middleware).
func (m *Middleware) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	return m.cache.VerifyToken(ctx, tokenString)
}

// GetAccessToken returns the raw access token from context, if set.
func GetAccessToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(contextKeyAccessToken).(string)
	return token, ok
}

// GetUserID returns the subject (user ID) from context, if set.
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(contextKeyUserID).(string)
	return userID, ok
}

// GetUserEmail returns the email claim from context, if set.
func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(contextKeyUserEmail).(string)
	return email, ok
}

// GetClaims returns the full claims from context, if set.
func GetClaims(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(contextKeyClaims).(*Claims)
	return claims, ok
}

func withClaims(ctx context.Context, tokenString string, claims *jwkscache.Claims) context.Context {
	ctx = context.WithValue(ctx, contextKeyAccessToken, tokenString)
	ctx = context.WithValue(ctx, contextKeyUserID, claims.Subject)
	ctx = context.WithValue(ctx, contextKeyUserEmail, claims.Email)
	ctx = context.WithValue(ctx, contextKeyClaims, claims)
	return ctx
}

func sendErrorResponse(w http.ResponseWriter, message string, code int) {
	response := ErrorResponse{
		Error:   "Unauthorized",
		Message: message,
		Code:    code,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(response)
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", errors.New("empty bearer token")
	}

	return token, nil
}
