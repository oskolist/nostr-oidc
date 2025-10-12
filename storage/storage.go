package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// storage implements the op.Storage interface
// typically you would implement this as a layer on top of your database
// for simplicity this example keeps everything in-memory
type Storage struct {
	signingKey signingKey
	db         storageDB
}

func NewStorage(db *sql.DB) (Storage, error) {
	if db == nil {
		log.Panicf("database instance should not be nil")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Storage{}, fmt.Errorf("ecdsa.GenerateKey(elliptic.P256(), rand.Reader). %w", err)
	}
	return Storage{
		db: storageDB{db: db},
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.ES256,
			key:       privateKey,
		},
	}, nil
}

// CreateAuthRequest implements the op.Storage interface
// it will be called after parsing and validation of the authentication request
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		// With prompt=none, there is no way for the user to log in
		// so return error right away.
		return nil, oidc.ErrLoginRequired()
	}

	// typically, you'll fill your storage / storage model with the information of the passed object
	request := authRequestToInternal(authReq, userID)

	// you'll also have to create a unique id for the request (this might be done by your database; we'll use a uuid)
	request.ID = uuid.NewString()
	//
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	err = s.db.AddAuthRequest(tx, request)
	if err != nil {
		return nil, fmt.Errorf("s.db.AddAuthRequest(tx, request). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}

	return request, nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	authReq, err := s.db.SearchAuthRequestByID(tx, id)
	if err != nil {
		return nil, fmt.Errorf("s.db.AddAuthRequest(tx, request). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}
	return authReq, nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	authReq, err := s.db.SearchAuthRequestByID(tx, code)
	if err != nil {
		return nil, fmt.Errorf("s.db.AddAuthRequest(tx, request). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}
	return authReq, nil
}

// SaveAuthCode implements the op.Storage interface
// it will be called after the authentication has been successful and before redirecting the user agent to the redirect_uri
// (in an authorization code flow)
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Update the auth request to include the code challenge
	err = s.db.SaveAuthCode(tx, id, code)
	if err != nil {
		return fmt.Errorf("s.db.SaveAuthCode(tx, %s, %s). %+v", id, code, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}
	return nil
}

// DeleteAuthRequest implements the op.Storage interface
// it will be called after creating the token response (id and access tokens) for a valid
// - authentication request (in an implicit flow)
// - token request (in an authorization code flow)
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	err = s.db.DeleteAuthRequest(tx, id)
	if err != nil {
		return fmt.Errorf("s.db.DeleteAuthRequest(tx, id). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}
	return nil

}

// CreateAccessToken implements the op.Storage interface
// it will be called for all requests able to return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, ...)
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	// Generate new access token ID
	tokenID := uuid.NewString()

	// We'll implement a simplified approach similar to what was in the old comment
	// For this implementation, we'll:
	// 1. Create a new token based on the request context
	// 2. Store it in the database
	// 3. Return token ID and expiration

	now := time.Now()
	expiration := now.Add(1 * time.Hour) // 1 hour expiration

	// Determine the application ID and other necessary information from the request
	var applicationID string
	var subject string
	var audience []string
	var scopes []string

	switch req := request.(type) {
	case *AuthRequest:
		applicationID = req.ApplicationID
		subject = req.UserID
		audience = req.Scopes // Note: this should be the actual audience list
		scopes = req.Scopes
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
		subject = req.GetSubject()
		audience = req.GetAudience()
		scopes = req.GetScopes()
	default:
		applicationID = ""
		subject = ""
		audience = []string{}
		scopes = []string{}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Create the access token in the database
	token := &Token{
		ID:             tokenID,
		ApplicationID:  applicationID,
		Subject:        subject,
		RefreshTokenID: "", // Not relevant for access-only token
		Audience:       audience,
		Expiration:     expiration,
		Scopes:         scopes,
	}

	err = s.db.AddToken(tx, token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("s.db.AddToken(tx, token). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("tx.Commit(). %+v", err)
	}

	return tokenID, expiration, nil
}

// CreateAccessAndRefreshTokens implements the op.Storage interface
// it will be called for all requests able to return an access and refresh token (Authorization Code Flow, Refresh Token Request)
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	if currentRefreshToken == "" {
		// Code Flow: Create new refresh token and access token
		accessTokenID = uuid.NewString()
		newRefreshToken = uuid.NewString()

		now := time.Now()
		expiration := now.Add(1 * time.Hour)         // 1 hour for access token
		refreshExpiration := now.Add(24 * time.Hour) // 24 hours for refresh token

		// Get relevant information from request
		var applicationID string
		var subject string
		var audience []string
		var scopes []string

		switch req := request.(type) {
		case *AuthRequest:
			applicationID = req.ApplicationID
			subject = req.UserID
			audience = req.Scopes // Use Scopes instead of Audience
			scopes = req.Scopes
		case op.TokenExchangeRequest:
			applicationID = req.GetClientID()
			subject = req.GetSubject()
			audience = req.GetAudience()
			scopes = req.GetScopes()
		default:
			err = fmt.Errorf("unsupported request type: %T", req)
			return "", "", time.Time{}, err
		}

		// Create access token in DB
		accessToken := &Token{
			ID:             accessTokenID,
			ApplicationID:  applicationID,
			Subject:        subject,
			RefreshTokenID: newRefreshToken,
			Audience:       audience,
			Expiration:     expiration,
			Scopes:         scopes,
		}

		err = s.db.AddToken(tx, accessToken)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("s.db.AddToken(tx, accessToken). %+v", err)
		}

		// Create refresh token in DB
		refreshToken := &RefreshToken{
			ID:            newRefreshToken,
			Token:         newRefreshToken, // Use ID as token for ownership
			AuthTime:      now,
			AMR:           []string{}, // Empty for now (was Amr -> AMR)
			Audience:      audience,
			UserID:        subject,
			ApplicationID: applicationID,
			Expiration:    refreshExpiration,
			Scopes:        scopes,
			AccessToken:   accessTokenID, // Link to access token
		}

		err = s.db.AddRefreshToken(tx, refreshToken)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("s.db.AddRefreshToken(tx, refreshToken). %+v", err)
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %+v", err)
		}

		return accessTokenID, newRefreshToken, expiration, nil
	} else {
		// Refresh token flow: renew tokens
		// For this simplified implementation, we'll create new refresh token ID but reuse old token data
		newRefreshToken = uuid.NewString()

		// Get current refresh token information
		oldRefreshToken, err := s.db.SearchRefreshTokenByID(tx, currentRefreshToken)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %+v", currentRefreshToken, err)
		}

		// Additional validation would go here in full implementation
		// ...

		// Create new access token
		accessTokenID = uuid.NewString()
		now := time.Now()
		expiration := now.Add(1 * time.Hour)

		accessToken := &Token{
			ID:             accessTokenID,
			ApplicationID:  oldRefreshToken.ApplicationID,
			Subject:        oldRefreshToken.UserID,
			RefreshTokenID: newRefreshToken,
			Audience:       oldRefreshToken.Audience,
			Expiration:     expiration,
			Scopes:         oldRefreshToken.Scopes,
		}

		err = s.db.AddToken(tx, accessToken)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("s.db.AddToken(tx, accessToken). %+v", err)
		}

		// Update refresh token to new ID
		updatedRefreshToken := &RefreshToken{
			ID:            newRefreshToken,
			Token:         newRefreshToken,
			AuthTime:      oldRefreshToken.AuthTime, // Keep original auth time
			AMR:           oldRefreshToken.AMR,      // Changed from Amr to AMR
			Audience:      oldRefreshToken.Audience,
			UserID:        oldRefreshToken.UserID,
			ApplicationID: oldRefreshToken.ApplicationID,
			Expiration:    oldRefreshToken.Expiration, // Keep same expiration, but should be extended
			Scopes:        oldRefreshToken.Scopes,
			AccessToken:   accessTokenID,
		}

		err = s.db.AddRefreshToken(tx, updatedRefreshToken)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("s.db.AddRefreshToken(tx, updatedRefreshToken). %+v", err)
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %+v", err)
		}

		return accessTokenID, newRefreshToken, expiration, nil
	}
}

func (s *Storage) exchangeRefreshToken(ctx context.Context, request op.TokenExchangeRequest) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Get the current refresh token
	currentRefreshToken, err := s.db.SearchRefreshTokenByID(tx, request.GetSubject())
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %+v", request.GetSubject(), err)
	}

	// Generate new tokens
	accessTokenID = uuid.NewString()
	newRefreshToken = uuid.NewString()

	now := time.Now()
	expiration = now.Add(1 * time.Hour)          // 1 hour for access token
	refreshExpiration := now.Add(24 * time.Hour) // 24 hours for refresh token

	// Create new access token
	accessToken := &Token{
		ID:             accessTokenID,
		ApplicationID:  currentRefreshToken.ApplicationID,
		Subject:        currentRefreshToken.UserID,
		RefreshTokenID: newRefreshToken,
		Audience:       currentRefreshToken.Audience,
		Expiration:     expiration,
		Scopes:         request.GetScopes(),
	}

	err = s.db.AddToken(tx, accessToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.AddToken(tx, accessToken). %+v", err)
	}

	// Create new refresh token
	refreshToken := &RefreshToken{
		ID:            newRefreshToken,
		Token:         newRefreshToken, // Use ID as token for ownership
		AuthTime:      now,
		AMR:           []string{}, // Empty for now (was Amr -> AMR)
		Audience:      currentRefreshToken.Audience,
		UserID:        currentRefreshToken.UserID,
		ApplicationID: currentRefreshToken.ApplicationID,
		Expiration:    refreshExpiration,
		Scopes:        request.GetScopes(),
		AccessToken:   accessTokenID, // Link to access token
	}

	err = s.db.AddRefreshToken(tx, refreshToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.AddRefreshToken(tx, refreshToken). %+v", err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %+v", err)
	}

	return accessTokenID, newRefreshToken, expiration, nil
}

// TokenRequestByRefreshToken implements the op.Storage interface
// it will be called after parsing and validation of the refresh token request
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	refreshTokenData, err := s.db.SearchRefreshTokenByID(tx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %+v", refreshToken, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Return the refresh token request data using the wrapper function
	return RefreshTokenRequestFromBusiness(refreshTokenData), nil
}

// TerminateSession implements the op.Storage interface
// it will be called after the user signed out, therefore the access and refresh token of the user of this client must be removed
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Delete all tokens matching user and client
	err = s.db.DeleteTokensByUserAndClient(tx, userID, clientID)
	if err != nil {
		return fmt.Errorf("s.db.DeleteTokensByUserAndClient(tx, %s, %s). %+v", userID, clientID, err)
	}

	// Delete all refresh tokens matching user and client
	err = s.db.DeleteRefreshTokensByUserAndClient(tx, userID, clientID)
	if err != nil {
		return fmt.Errorf("s.db.DeleteRefreshTokensByUserAndClient(tx, %s, %s). %+v", userID, clientID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}

	return nil
}

// GetRefreshTokenInfo looks up a refresh token and returns the token id and user id.
// If given something that is not a refresh token, it must return error.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	refreshToken, err := s.db.SearchRefreshTokenByID(tx, token)
	if err != nil {
		return "", "", fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %+v", token, err)
	}

	err = tx.Commit()
	if err != nil {
		return "", "", fmt.Errorf("tx.Commit(). %+v", err)
	}

	return refreshToken.UserID, refreshToken.ID, nil
}

// RevokeToken implements the op.Storage interface
// it will be called after parsing and validation of the token revocation request
func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oidc.ErrInvalidRequest().WithDescription("Internal server error")
	}
	defer tx.Rollback()

	// First, try to find if this is an access token (by ID)
	token, err := s.db.SearchTokenByID(tx, tokenIDOrToken)
	if err == nil {
		// We found an access token; now make sure it belongs to the right client and user
		if token.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}

		// Delete the access token
		err = s.db.DeleteToken(tx, token.ID)
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		// If token has a refresh token, delete it too (as a best practice in OIDC)
		// The refresh token ID would be in the RefreshTokenID field of the access token
		if token.RefreshTokenID != "" {
			err = s.db.DeleteRefreshToken(tx, token.RefreshTokenID)
			if err != nil {
				return oidc.ErrInvalidRequest().WithDescription("Internal server error")
			}
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		return nil
	}

	// If not found as access token, try to find as refresh token ( directly by token content)
	refreshToken, err := s.db.SearchRefreshTokenByID(tx, tokenIDOrToken)
	if err == nil {
		// We found a refresh token; make sure it belongs to the right client and user
		if refreshToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}

		// Delete the refresh token
		err = s.db.DeleteRefreshToken(tx, refreshToken.ID)
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		// Also delete the corresponding access token using the AccessToken field in refresh token
		if refreshToken.AccessToken != "" {
			err = s.db.DeleteToken(tx, refreshToken.AccessToken)
			if err != nil {
				return oidc.ErrInvalidRequest().WithDescription("Internal server error")
			}
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		return nil
	}

	// Token not found (neither access nor refresh token)
	// In OAuth2/OIDC, we return success when the token is not valid to avoid revealing information
	return nil
}

// SigningKey implements the op.Storage interface
// it will be called when creating the OpenID Provider
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	// // in this example the signing key is a static rsa.PrivateKey and the algorithm used is RS256
	// // you would obviously have a more complex implementation and store / retrieve the key from your database as well
	return &s.signingKey, nil
}

// SignatureAlgorithms implements the op.Storage interface
// it will be called to get the sign
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

// KeySet implements the op.Storage interface
// it will be called to get the current (public) keys, among others for the keys_endpoint or for validating access_tokens on the userinfo_endpoint, ...
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	// // as mentioned above, this example only has a single signing key without key rotation,
	// // so it will directly use its public key
	// //
	// // when using key rotation you typically would store the public keys alongside the private keys in your database
	// // and give both of them an expiration date, with the public key having a longer lifetime
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// GetClientByClientID implements the op.Storage interface
// it will be called whenever information (type, redirect_uris, ...) about the client behind the client_id is needed
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	log.Printf("\n clientid: %+v", clientID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	client, err := s.db.SearchClientByID(tx, clientID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchClientByID(tx, %s). %+v", clientID, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}
	log.Printf("\n client: %+v", client)

	// Client already implements op.Client interface
	return client, nil
}

// AuthorizeClientIDSecret implements the op.Storage interface
// it will be called for validating the client_id, client_secret on token or introspection requests
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()
	log.Printf("\n clientid: %+v", clientID)

	_, err = s.db.SearchClientByID(tx, clientID)
	if err != nil {
		return fmt.Errorf("s.db.AddAuthRequest(tx, request). %+v", err)
	}
	// log.Printf("\n client: %+v", )

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}
	return nil
}

// SetUserinfoFromScopes implements the op.Storage interface.
// It populates the userinfo based on the requested scopes
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Fetch user from database
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %+v", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Set the subject (always included)
	userinfo.Subject = user.ID

	// Process each requested scope
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			// Subject is already set above

		case oidc.ScopeProfile:
			// Set profile information
			// Set locale from user's preferred language
			if user.PreferredLanguage != language.Und {
				locale := oidc.NewLocale(user.PreferredLanguage)
				userinfo.Locale = locale
			}

			// If we have npub, we can use it as preferred_username
			if user.Npub != nil {
				// Convert public key to hex for npub encoding
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:]) // Skip the first byte (02 or 03)
				userinfo.PreferredUsername = pubkeyHex
			}

		case CustomScope:
			// Add custom claim
			userinfo.AppendClaims(CustomClaim, "custom_claim_value")

		// Handle other standard scopes if needed
		case oidc.ScopeEmail:
			// Email scope - not implemented in this user model

		case oidc.ScopePhone:
			// Phone scope - not implemented in this user model

		case oidc.ScopeAddress:
			// Address scope - not implemented in this user model
		}
	}

	// Add admin status as a custom claim if needed
	if user.IsAdmin {
		userinfo.AppendClaims("admin", true)
	}

	return nil
}

// SetUserinfoFromRequest implements the op.CanSetUserinfoFromRequest interface.  In the
// next major release, it will be required for op.Storage.
// It will be called for the creation of an id_token, so we'll just pass it to the private function without any further check
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	// Get the subject (user ID) from the token request
	userID := token.GetSubject()
	clientID := token.GetClientID()

	// Use SetUserinfoFromScopes to populate userinfo
	return s.SetUserinfoFromScopes(ctx, userinfo, userID, clientID, scopes)
}

// SetUserinfoFromToken implements the op.Storage interface
// it will be called for the userinfo endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	// Start a transaction to fetch user and token data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Fetch user from database using the subject
	user, err := s.db.SearchUserByID(tx, subject)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %+v", subject, err)
	}

	// Fetch token to get scopes
	token, err := s.db.SearchTokenByID(tx, tokenID)
	if err != nil {
		return fmt.Errorf("s.db.SearchTokenByID(tx, %s). %+v", tokenID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Set the subject (always included)
	userinfo.Subject = user.ID

	// Process each scope from the token
	for _, scope := range token.Scopes {
		switch scope {
		case oidc.ScopeOpenID:
			// Subject is already set above

		case oidc.ScopeProfile:
			// Set profile information
			// Set locale from user's preferred language
			if user.PreferredLanguage != language.Und {
				locale := oidc.NewLocale(user.PreferredLanguage)
				userinfo.Locale = locale
			}

			// If we have npub, we can use it as preferred_username
			if user.Npub != nil {
				// Convert public key to hex for npub encoding
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:]) // Skip the first byte (02 or 03)
				userinfo.PreferredUsername = pubkeyHex
			}

		case CustomScope:
			// Add custom claim
			userinfo.AppendClaims(CustomClaim, "custom_claim_value")

		// Handle other standard scopes if needed
		case oidc.ScopeEmail:
			// Email scope - not implemented in this user model

		case oidc.ScopePhone:
			// Phone scope - not implemented in this user model

		case oidc.ScopeAddress:
			// Address scope - not implemented in this user model
		}
	}

	// Add admin status as a custom claim if needed
	if user.IsAdmin {
		userinfo.AppendClaims("admin", true)
	}

	return nil
}

// SetIntrospectionFromToken implements the op.Storage interface
// it will be called for the introspection endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	// Start a transaction to fetch token data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Fetch token from database
	token, err := s.db.SearchTokenByID(tx, tokenID)
	if err != nil {
		return fmt.Errorf("s.db.SearchTokenByID(tx, %s). %+v", tokenID, err)
	}

	// Fetch user to get additional information
	user, err := s.db.SearchUserByID(tx, subject)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %+v", subject, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Populate introspection response
	introspection.Active = time.Now().Before(token.Expiration)
	introspection.Scope = token.Scopes
	introspection.ClientID = token.ApplicationID
	introspection.TokenType = oidc.BearerToken
	introspection.Expiration = oidc.FromTime(token.Expiration)
	introspection.Subject = token.Subject
	introspection.Audience = token.Audience

	// Add username from user data
	if user.Npub != nil {
		pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:])
		introspection.Username = pubkeyHex
	}

	// Set locale if available
	if user.PreferredLanguage != language.Und {
		locale := oidc.NewLocale(user.PreferredLanguage)
		introspection.Locale = locale
	}

	// Add admin claim if user is admin
	if user.IsAdmin {
		if introspection.Claims == nil {
			introspection.Claims = make(map[string]any)
		}
		introspection.Claims["admin"] = true
	}

	return nil
}

// GetPrivateClaimsFromScopes implements the op.Storage interface
// it will be called for the creation of a JWT access token to assert claims for custom scopes
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Fetch user from database
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByID(tx, %s). %+v", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Initialize claims map
	claims = make(map[string]any)

	// Process each requested scope and add corresponding claims
	for _, scope := range scopes {
		switch scope {
		case CustomScope:
			// Add custom claim for custom scope
			claims[CustomClaim] = "custom_claim_value"

		case oidc.ScopeProfile:
			// Add profile-related claims
			if user.PreferredLanguage != language.Und {
				claims["locale"] = user.PreferredLanguage.String()
			}
			if user.Npub != nil {
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:])
				claims["preferred_username"] = pubkeyHex
			}

		// Other scopes could be handled here
		case oidc.ScopeEmail:
			// Email claims - not implemented in current user model

		case oidc.ScopePhone:
			// Phone claims - not implemented in current user model
		}
	}

	// Always add admin claim if user is admin
	if user.IsAdmin {
		claims["admin"] = true
	}

	return claims, nil
}

// GetKeyByIDAndClientID implements the op.Storage interface
// it will be called to validate the signatures of a JWT (JWT Profile Grant and Authentication)
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	// JWT Profile Grant requires public keys to be registered for clients
	// In a production system, you would:
	// 1. Add a client_keys table to store public keys with their key IDs
	// 2. Fetch the key from database: SELECT key_data FROM client_keys WHERE client_id = ? AND key_id = ?
	// 3. Parse and return the JSONWebKey
	//
	// For this implementation, JWT Profile Grant is not supported
	// Clients should use client_secret_post or client_secret_basic instead
	return nil, fmt.Errorf("JWT Profile Grant not supported: key '%s' not found for client '%s'", keyID, clientID)
}

// ValidateJWTProfileScopes implements the op.Storage interface
// it will be called to validate the scopes of a JWT Profile Authorization Grant request
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	// Fetch user to check permissions
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByID(tx, %s). %+v", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %+v", err)
	}

	// Validate and filter scopes based on user permissions
	validScopes := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		// Check if scope is allowed
		switch scope {
		case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeAddress:
			// Standard OIDC scopes are always allowed
			validScopes = append(validScopes, scope)

		case CustomScope:
			// Custom scope is always allowed
			validScopes = append(validScopes, scope)

		default:
			// Check for custom scope patterns (e.g., "custom_scope:impersonate:*")
			if len(scope) > len(CustomScopeImpersonatePrefix) && scope[:len(CustomScopeImpersonatePrefix)] == CustomScopeImpersonatePrefix {
				// Impersonation scope - only allowed for admin users
				if user.IsAdmin {
					validScopes = append(validScopes, scope)
				}
				// Otherwise, skip this scope (not allowed for non-admin users)
			} else {
				// Unknown scope - could be allowed or rejected based on policy
				// For now, we'll allow unknown scopes
				validScopes = append(validScopes, scope)
			}
		}
	}

	return validScopes, nil
}

// Health implements the op.Storage interface
func (s *Storage) Health(ctx context.Context) error {
	// Check database connectivity by performing a simple query
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %+v", err)
	}
	defer tx.Rollback()

	// Perform health check query
	err = s.db.HealthCheck(tx)
	if err != nil {
		return fmt.Errorf("database health check failed: %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit health check transaction: %+v", err)
	}

	return nil
}
func (s *Storage) CheckUserNpub(publicKey *btcec.PublicKey) error {

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %+v", err)
	}
	defer tx.Rollback()

	_, err = s.db.SearchUserByNpub(tx, publicKey)
	if err != nil {
		return fmt.Errorf("s.db.AddAuthRequest(tx, request). %+v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %+v", err)
	}
	return nil
	// return nil
}

// Device Code auth flow

func (s *Storage) CheckNostrEventSignature(event nostr.Event) error {
	valid, err := event.CheckSignature()
	if err != nil {
		return fmt.Errorf("event.CheckSignature(). %+v", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	panic(" StoreDeviceAuthorization unimplemented")
	// s.lock.Lock()
	// defer s.lock.Unlock()
	//
	// if _, ok := s.clients[clientID]; !ok {
	// 	return errors.New("client not found")
	// }
	//
	// if _, ok := s.userCodes[userCode]; ok {
	// 	return op.ErrDuplicateUserCode
	// }
	//
	// s.deviceCodes[deviceCode] = deviceAuthorizationEntry{
	// 	deviceCode: deviceCode,
	// 	userCode:   userCode,
	// 	state: &op.DeviceAuthorizationState{
	// 		ClientID: clientID,
	// 		Scopes:   scopes,
	// 		Expires:  expires,
	// 	},
	// }
	//
	// s.userCodes[userCode] = deviceCode
	// return nil
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	panic(" GetDeviceAuthorizatonState unimplemented")
	// if ctx.Err() != nil {
	// 	return nil, ctx.Err()
	// }
	//
	// s.lock.Lock()
	// defer s.lock.Unlock()
	//
	// entry, ok := s.deviceCodes[deviceCode]
	// if !ok || entry.state.ClientID != clientID {
	// 	return nil, errors.New("device code not found for client") // is there a standard not found error in the framework?
	// }
	//
	// return entry.state, nil
}

func (s *Storage) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	panic(" GetDeviceAuthorizationByUserCode unimplemented")
	// s.lock.Lock()
	// defer s.lock.Unlock()
	//
	// entry, ok := s.deviceCodes[s.userCodes[userCode]]
	// if !ok {
	// 	return nil, errors.New("user code not found")
	// }
	//
	// return entry.state, nil
}

func (s *Storage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	panic(" CompleteDeviceAuthorization unimplemented")
	// s.lock.Lock()
	// defer s.lock.Unlock()
	//
	// entry, ok := s.deviceCodes[s.userCodes[userCode]]
	// if !ok {
	// 	return errors.New("user code not found")
	// }
	//
	// entry.state.Subject = subject
	// entry.state.Done = true
	// return nil
}

func (s *Storage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	panic(" DenyDeviceAuthorization unimplemented")
	// s.lock.Lock()
	// defer s.lock.Unlock()
	//
	// s.deviceCodes[s.userCodes[userCode]].state.Denied = true
	// return nil
}
