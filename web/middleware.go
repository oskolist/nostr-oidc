package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// contextKey for storing user data in the request context
type contextKey string

const userContextKey contextKey = "user"

// AuthMiddleware authenticates requests using a JWT from the Authorization header.
func (s *adminHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // No "Bearer " prefix found
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// Use oidc.ParseToken to parse the token string into oidc.IDTokenClaims
		idToken := new(oidc.IDTokenClaims)
		_, err := oidc.ParseToken(tokenString, idToken)
		if err != nil {
			slog.Error("Failed to parse and decode ID token", slog.String("error", err.Error()))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// Basic validation based on spec and common practices
		// Check Issuer
		expectedIssuer := s.server.OIDCProvider.IssuerFromRequest(r)
		if idToken.Issuer != expectedIssuer {
			slog.Error("Token issuer mismatch", slog.String("expected", expectedIssuer), slog.String("actual", idToken.Issuer))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// Validate Audience (aud) claim
		foundAud := false
		for _, aud := range idToken.Audience {
			if aud == storage.OICD_ADMIN_DASHBOARD_CLIENT_ID {
				foundAud = true
				break
			}
		}
		if !foundAud {
			slog.Error("Token audience mismatch", slog.Any("audience", idToken.Audience), slog.String("required", storage.OICD_ADMIN_DASHBOARD_CLIENT_ID))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// Corrected time-based validations using AsTime()
		current := time.Now()
		if idToken.Expiration.AsTime().Before(current) {
			slog.Error("ID token has expired", slog.Time("expiry", idToken.Expiration.AsTime()), slog.Time("current", current))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		if idToken.IssuedAt.AsTime().After(current) {
			slog.Error("ID token issued in the future", slog.Time("issued_at", idToken.IssuedAt.AsTime()), slog.Time("current", current))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		if idToken.NotBefore.AsTime().After(current) {
			slog.Error("ID token not yet valid", slog.Time("not_before", idToken.NotBefore.AsTime()), slog.Time("current", current))
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// Store Token Information in Context
		ctx := context.WithValue(r.Context(), userContextKey, idToken)

		// Call Next Handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
