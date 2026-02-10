# JWT Validator Middleware

Shared Go package for validating JWT access tokens from any OIDC/OAuth2 identity provider (e.g. Auth0, Keycloak, Okta, Zitadel) and exposing claims in request context. Use this package as a dependency in Go services that need to protect APIs with Bearer token auth.

## Configuration

The middleware needs:

| Env / Param | Description |
|-------------|-------------|
| **JWT_ISSUER** | Must match the `iss` claim in access tokens (e.g. `https://your-tenant.auth0.com/`) |
| **JWT_AUDIENCE** | Must match the `aud` claim in access tokens (your API audience) |
| **JWKS_REFRESH_INTERVAL** | Optional. Go duration for JWKS refresh (e.g. `5m`, `1h`). Default: `5m` |

## Layout

- **config/** – Configuration (Config, EnvConfig for JWT_ISSUER, JWT_AUDIENCE, JWKS_REFRESH_INTERVAL).
- **jwks_cache/** – JWKS fetch/cache and token verification (RS256, issuer/audience).
- **jwtmiddleware/** – HTTP middleware and public API (New, RequireAuth, GetUserID, etc.). This is the main package consumers use.

## Installation

In your Go service:

```bash
go get github.com/nextgen-platform/jwt-validator-middleware
```

## Usage

### From environment variables

Set `JWT_ISSUER`, `JWT_AUDIENCE`, and optionally `JWKS_REFRESH_INTERVAL`, then:

```go
import "github.com/nextgen-platform/jwt-validator-middleware/jwtmiddleware"

mw, err := jwtmiddleware.NewFromEnv()
if err != nil {
    log.Fatal(err)
}
http.Handle("/api/", mw.RequireAuth(yourHandler))
```

### From config (issuer, audience, refresh interval)

```go
import (
    "github.com/nextgen-platform/jwt-validator-middleware/config"
    "github.com/nextgen-platform/jwt-validator-middleware/jwtmiddleware"
)

mw, err := jwtmiddleware.New("https://your-issuer.example.com/", "your_api_audience_here", 5*time.Minute)
// or
mw, err := jwtmiddleware.NewFromConfig(config.Config{
    Issuer:              "https://your-issuer.example.com/",
    Audience:            "your_api_audience_here",
    JWKSRefreshInterval: 5 * time.Minute, // 0 = default 5m
})
```

### Reading claims in handlers

```go
userID, ok := jwtmiddleware.GetUserID(r.Context())
email, ok := jwtmiddleware.GetUserEmail(r.Context())
claims, ok := jwtmiddleware.GetClaims(r.Context())
token, ok := jwtmiddleware.GetAccessToken(r.Context())
```

### Verify token without HTTP (e.g. gRPC or custom logic)

```go
claims, err := mw.VerifyToken(ctx, tokenString)
```

## Tests

```bash
make test      # run all tests
make coverage  # run tests with coverage summary 
make clean     # remove coverage.out, coverage.html
```

## License

See [LICENSE](LICENSE).
