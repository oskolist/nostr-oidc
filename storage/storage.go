package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// storage implements the op.Storage interface
// typically you would implement this as a layer on top of your database
// for simplicity this example keeps everything in-memory
type Storage struct {
	signingKey signingKey
}

func NewStorage() (Storage, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Storage{}, fmt.Errorf("ecdsa.GenerateKey(elliptic.P256(), rand.Reader). %w", err)
	}
	return Storage{
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
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		// With prompt=none, there is no way for the user to log in
		// so return error right away.
		return nil, oidc.ErrLoginRequired()
	}

	// typically, you'll fill your storage / storage model with the information of the passed object
	request := authRequestToInternal(authReq, userID)

	// you'll also have to create a unique id for the request (this might be done by your database; we'll use a uuid)
	request.ID = uuid.NewString()

	// and save it in your database (for demonstration purposed we will use a simple map)
	s.authRequests[request.ID] = request

	// finally, return the request (which implements the AuthRequest interface of the OP
	return request, nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	request, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("request not found")
	}
	return request, nil
}

// AuthRequestByCode implements the op.Storage interface
// it will be called after parsing and validation of the token request (in an authorization code flow)
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// for this example we read the id by code and then get the request by id
	requestID, ok := func() (string, bool) {
		s.lock.Lock()
		defer s.lock.Unlock()
		requestID, ok := s.codes[code]
		return requestID, ok
	}()
	if !ok {
		return nil, fmt.Errorf("code invalid or expired")
	}
	return s.AuthRequestByID(ctx, requestID)
}

// SaveAuthCode implements the op.Storage interface
// it will be called after the authentication has been successful and before redirecting the user agent to the redirect_uri
// (in an authorization code flow)
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	// for this example we'll just save the authRequestID to the code
	s.lock.Lock()
	defer s.lock.Unlock()
	s.codes[code] = id
	return nil
}

// DeleteAuthRequest implements the op.Storage interface
// it will be called after creating the token response (id and access tokens) for a valid
// - authentication request (in an implicit flow)
// - token request (in an authorization code flow)
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	// you can simply delete all reference to the auth request
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.authRequests, id)
	for code, requestID := range s.codes {
		if id == requestID {
			delete(s.codes, code)
			return nil
		}
	}
	return nil
}

// CreateAccessToken implements the op.Storage interface
// it will be called for all requests able to return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, ...)
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var applicationID string
	switch req := request.(type) {
	case *AuthRequest:
		// if authenticated for an app (auth code / implicit flow) we must save the client_id to the token
		applicationID = req.ApplicationID
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
	}

	token, err := s.accessToken(applicationID, "", request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expiration, nil
}

// CreateAccessAndRefreshTokens implements the op.Storage interface
// it will be called for all requests able to return an access and refresh token (Authorization Code Flow, Refresh Token Request)
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// generate tokens via token exchange flow if request is relevant
	if teReq, ok := request.(op.TokenExchangeRequest); ok {
		return s.exchangeRefreshToken(ctx, teReq)
	}

	// get the information depending on the request type / implementation
	applicationID, authTime, amr := getInfoFromRequest(request)

	// if currentRefreshToken is empty (Code Flow) we will have to create a new refresh token
	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken, err := s.createRefreshToken(accessToken, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return accessToken.ID, refreshToken, accessToken.Expiration, nil
	}

	// if we get here, the currentRefreshToken was not empty, so the call is a refresh token request
	// we therefore will have to check the currentRefreshToken and renew the refresh token

	newRefreshToken = uuid.NewString()

	accessToken, err := s.accessToken(applicationID, newRefreshToken, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err := s.renewRefreshToken(currentRefreshToken, newRefreshToken, accessToken.ID); err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken.ID, newRefreshToken, accessToken.Expiration, nil
}

func (s *Storage) exchangeRefreshToken(ctx context.Context, request op.TokenExchangeRequest) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	applicationID := request.GetClientID()
	authTime := request.GetAuthTime()

	refreshTokenID := uuid.NewString()
	accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := s.createRefreshToken(accessToken, nil, authTime)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken.ID, refreshToken, accessToken.Expiration, nil
}

// TokenRequestByRefreshToken implements the op.Storage interface
// it will be called after parsing and validation of the refresh token request
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	token, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("invalid refresh_token")
	}
	return RefreshTokenRequestFromBusiness(token), nil
}

// TerminateSession implements the op.Storage interface
// it will be called after the user signed out, therefore the access and refresh token of the user of this client must be removed
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, token := range s.tokens {
		if token.ApplicationID == clientID && token.Subject == userID {
			delete(s.tokens, token.ID)
			delete(s.refreshTokens, token.RefreshTokenID)
		}
	}
	return nil
}

// GetRefreshTokenInfo looks up a refresh token and returns the token id and user id.
// If given something that is not a refresh token, it must return error.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	refreshToken, ok := s.refreshTokens[token]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.UserID, refreshToken.ID, nil
}

// RevokeToken implements the op.Storage interface
// it will be called after parsing and validation of the token revocation request
func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// a single token was requested to be removed
	s.lock.Lock()
	defer s.lock.Unlock()
	accessToken, ok := s.tokens[tokenIDOrToken] // tokenID
	if ok {
		if accessToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		// if it is an access token, just remove it
		// you could also remove the corresponding refresh token if really necessary
		delete(s.tokens, accessToken.ID)
		return nil
	}
	refreshToken, ok := s.refreshTokens[tokenIDOrToken] // token
	if !ok {
		// if the token is neither an access nor a refresh token, just ignore it, the expected behaviour of
		// being not valid (anymore) is achieved
		return nil
	}
	if refreshToken.ApplicationID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	delete(s.refreshTokens, refreshToken.ID)
	// if it is a refresh token, you will have to remove the access token as well
	delete(s.tokens, refreshToken.AccessToken)
	return nil
}

// SigningKey implements the op.Storage interface
// it will be called when creating the OpenID Provider
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	// in this example the signing key is a static rsa.PrivateKey and the algorithm used is RS256
	// you would obviously have a more complex implementation and store / retrieve the key from your database as well
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
	// as mentioned above, this example only has a single signing key without key rotation,
	// so it will directly use its public key
	//
	// when using key rotation you typically would store the public keys alongside the private keys in your database
	// and give both of them an expiration date, with the public key having a longer lifetime
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// GetClientByClientID implements the op.Storage interface
// it will be called whenever information (type, redirect_uris, ...) about the client behind the client_id is needed
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return RedirectGlobsClient(client), nil
}

// AuthorizeClientIDSecret implements the op.Storage interface
// it will be called for validating the client_id, client_secret on token or introspection requests
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}
	// for this example we directly check the secret
	// obviously you would not have the secret in plain text, but rather hashed and salted (e.g. using bcrypt)
	if client.secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

// SetUserinfoFromScopes implements the op.Storage interface.
// Provide an empty implementation and use SetUserinfoFromRequest instead.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequests implements the op.CanSetUserinfoFromRequest interface.  In the
// next major release, it will be required for op.Storage.
// It will be called for the creation of an id_token, so we'll just pass it to the private function without any further check
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, token.GetSubject(), token.GetClientID(), scopes)
}

// SetUserinfoFromToken implements the op.Storage interface
// it will be called for the userinfo endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	panic("SetUserinfoFromToken. not yet implemented")
	// token, ok := func() (*Token, bool) {
	// 	s.lock.Lock()
	// 	defer s.lock.Unlock()
	// 	token, ok := s.tokens[tokenID]
	// 	return token, ok
	// }()
	// if !ok {
	// 	return fmt.Errorf("token is invalid or has expired")
	// }
	// the userinfo endpoint should support CORS. If it's not possible to specify a specific origin in the CORS handler,
	// and you have to specify a wildcard (*) origin, then you could also check here if the origin which called the userinfo endpoint here directly
	// note that the origin can be empty (if called by a web client)
	//
	// if origin != "" {
	//	client, ok := s.clients[token.ApplicationID]
	//	if !ok {
	//		return fmt.Errorf("client not found")
	//	}
	//	if err := checkAllowedOrigins(client.allowedOrigins, origin); err != nil {
	//		return err
	//	}
	//}
	// if token.Expiration.Before(time.Now()) {
	// 	return fmt.Errorf("token is expired")
	// }
	// return s.setUserinfo(ctx, userinfo, token.Subject, token.ApplicationID, token.Scopes)
}

// SetIntrospectionFromToken implements the op.Storage interface
// it will be called for the introspection endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	panic("SetIntrospectionFromToken. not yet implemented")
	// token, ok := func() (*Token, bool) {
	// 	s.lock.Lock()
	// 	defer s.lock.Unlock()
	// 	token, ok := s.tokens[tokenID]
	// 	return token, ok
	// }()
	// if !ok {
	// 	return fmt.Errorf("token is invalid or has expired")
	// }
	// // check if the client is part of the requested audience
	// for _, aud := range token.Audience {
	// 	if aud == clientID {
	// 		// the introspection response only has to return a boolean (active) if the token is active
	// 		// this will automatically be done by the library if you don't return an error
	// 		// you can also return further information about the user / associated token
	// 		// e.g. the userinfo (equivalent to userinfo endpoint)
	//
	// 		userInfo := new(oidc.UserInfo)
	// 		err := s.setUserinfo(ctx, userInfo, subject, clientID, token.Scopes)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		introspection.SetUserInfo(userInfo)
	// 		//...and also the requested scopes...
	// 		introspection.Scope = token.Scopes
	// 		//...and the client the token was issued to
	// 		introspection.ClientID = token.ApplicationID
	// 		return nil
	// 	}
	// }
	// return fmt.Errorf("token is not valid for this client")
}

// GetPrivateClaimsFromScopes implements the op.Storage interface
// it will be called for the creation of a JWT access token to assert claims for custom scopes
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	panic("GetPrivateClaimsFromScopes. not yet implemented")
	return s.getPrivateClaimsFromScopes(ctx, userID, clientID, scopes)
}

func (s *Storage) getPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	panic("getPrivateClaimsFromScopes. not yet implemented")
	// for _, scope := range scopes {
	// 	switch scope {
	// 	case CustomScope:
	// 		claims = appendClaim(claims, CustomClaim, customClaim(clientID))
	// 	}
	// }
	// return claims, nil
}

// GetKeyByIDAndClientID implements the op.Storage interface
// it will be called to validate the signatures of a JWT (JWT Profile Grant and Authentication)
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	panic("GetKeyByIDAndClientID. not yet implemented")
}

// ValidateJWTProfileScopes implements the op.Storage interface
// it will be called to validate the scopes of a JWT Profile Authorization Grant request
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	panic("ValidateJWTProfileScopes. not yet implemented")

}

// Health implements the op.Storage interface
func (s *Storage) Health(ctx context.Context) error {
	return nil
}
