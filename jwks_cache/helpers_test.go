package jwkscache

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func testGenerateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func testBigEndianInt(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var out []byte
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}
	return out
}

func testJWKSResponse(pub rsa.PublicKey, kid string) map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(testBigEndianInt(pub.E))
	return map[string]interface{}{
		"keys": []map[string]string{
			{"use": "sig", "kty": "RSA", "kid": kid, "alg": "RS256", "n": n, "e": e},
		},
	}
}

func testJWKSServer(t *testing.T, kid string) (*httptest.Server, string, string) {
	t.Helper()
	key := testGenerateKey(t)
	return testJWKSServerWithKey(t, kid, key)
}

func testJWKSServerWithKey(t *testing.T, kid string, key *rsa.PrivateKey) (*httptest.Server, string, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse(key.PublicKey, kid))
	}))
	return server, server.URL, "api"
}

func testSignToken(t *testing.T, key *rsa.PrivateKey, issuer, audience, subject, email, kid string) string {
	t.Helper()
	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}
