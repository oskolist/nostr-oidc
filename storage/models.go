package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// Client represents the storage model of an OAuth/OIDC client
// this could also be your database model
type Client struct {
	id                             string
	secret                         string
	redirectURIs                   []string
	applicationType                op.ApplicationType
	authMethod                     oidc.AuthMethod
	loginURL                       func(string) string
	responseTypes                  []oidc.ResponseType
	grantTypes                     []oidc.GrantType
	accessTokenType                op.AccessTokenType
	devMode                        bool
	idTokenUserinfoClaimsAssertion bool
	clockSkew                      time.Duration
	postLogoutRedirectURIGlobs     []string
	redirectURIGlobs               []string
}

func (c *Client) GetID() string {
	return c.id
}

func (c *Client) RedirectURIs() []string {
	return c.redirectURIs
}

func (c *Client) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *Client) ApplicationType() op.ApplicationType {
	return c.applicationType
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

func (c *Client) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *Client) LoginURL(id string) string {
	return c.loginURL(id)
}

func (c *Client) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

func (c *Client) IDTokenLifetime() time.Duration {
	return 1 * time.Hour
}

func (c *Client) DevMode() bool {
	return c.devMode
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) IsScopeAllowed(scope string) bool {
	// Allow standard OIDC scopes
	// Note: "offline_access" is the correct scope for requesting refresh tokens,
	// not "refresh_token" which is a grant type, not a scope
	allowedScopes := []string{
		oidc.ScopeOpenID,
		oidc.ScopeProfile,
		oidc.ScopeEmail,
		oidc.ScopeAddress,
		oidc.ScopePhone,
		oidc.ScopeOfflineAccess,
	}

	for _, allowedScope := range allowedScopes {
		if scope == allowedScope {
			return true
		}
	}

	return false
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return c.idTokenUserinfoClaimsAssertion
}

func (c *Client) ClockSkew() time.Duration {
	return c.clockSkew
}

// ScanRow implements a pgx-style row scanner for Client
// This method scans a database row directly into the Client struct fields
// Expected column order: id, secret, redirect_uris, application_type, auth_method, response_types,
// grant_types, access_token_type, dev_mode, id_token_userinfo_claims_assertion, clock_skew,
// post_logout_redirect_uri_globs, redirect_uri_globs
func (c *Client) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var applicationTypeInt, accessTokenTypeInt int
	var clockSkewNanos int64
	var redirectURIsJSON, responseTypesJSON, grantTypesJSON, postLogoutRedirectURIsJSON, redirectURIsGlobsJSON []byte

	err := row.Scan(
		&c.id, &c.secret, &redirectURIsJSON, &applicationTypeInt, &c.authMethod,
		&responseTypesJSON, &grantTypesJSON, &accessTokenTypeInt, &c.devMode,
		&c.idTokenUserinfoClaimsAssertion, &clockSkewNanos, &postLogoutRedirectURIsJSON, &redirectURIsGlobsJSON,
	)
	if err != nil {
		return err
	}

	// Convert integers back to enum types
	c.applicationType = op.ApplicationType(applicationTypeInt)
	c.accessTokenType = op.AccessTokenType(accessTokenTypeInt)
	c.clockSkew = time.Duration(clockSkewNanos)

	// Unmarshal JSON fields
	if err := json.Unmarshal(redirectURIsJSON, &c.redirectURIs); err != nil {
		return fmt.Errorf("json.Unmarshal(redirectURIs): %w", err)
	}
	if err := json.Unmarshal(responseTypesJSON, &c.responseTypes); err != nil {
		return fmt.Errorf("json.Unmarshal(responseTypes): %w", err)
	}
	if err := json.Unmarshal(grantTypesJSON, &c.grantTypes); err != nil {
		return fmt.Errorf("json.Unmarshal(grantTypes): %w", err)
	}
	if err := json.Unmarshal(postLogoutRedirectURIsJSON, &c.postLogoutRedirectURIGlobs); err != nil {
		return fmt.Errorf("json.Unmarshal(postLogoutRedirectURIGlobs): %w", err)
	}
	if err := json.Unmarshal(redirectURIsGlobsJSON, &c.redirectURIGlobs); err != nil {
		return fmt.Errorf("json.Unmarshal(redirectURIGlobs): %w", err)
	}

	return nil
}

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     time.Time
	Scopes         []string
}

// ScanRow implements a pgx-style row scanner for Token
// This method scans a database row directly into the Token struct fields
// Expected column order: id, application_id, subject, refresh_token_id, audience, expiration, scopes
func (t *Token) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var audienceJSON, scopesJSON []byte

	err := row.Scan(
		&t.ID, &t.ApplicationID, &t.Subject, &t.RefreshTokenID,
		&audienceJSON, &t.Expiration, &scopesJSON,
	)
	if err != nil {
		return err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(audienceJSON, &t.Audience); err != nil {
		return fmt.Errorf("json.Unmarshal(audienceJSON): %w", err)
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return fmt.Errorf("json.Unmarshal(scopesJSON): %w", err)
	}

	return nil
}

type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string // Token.ID
}

// ScanRow implements a pgx-style row scanner for RefreshToken
// This method scans a database row directly into the RefreshToken struct fields
// Expected column order: id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token
func (rt *RefreshToken) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var amrJSON, audienceJSON, scopesJSON []byte

	err := row.Scan(
		&rt.ID, &rt.Token, &rt.AuthTime, &amrJSON,
		&audienceJSON, &rt.UserID, &rt.ApplicationID, &rt.Expiration,
		&scopesJSON, &rt.AccessToken,
	)
	if err != nil {
		return err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(amrJSON, &rt.AMR); err != nil {
		return fmt.Errorf("json.Unmarshal(amrJSON): %w", err)
	}
	if err := json.Unmarshal(audienceJSON, &rt.Audience); err != nil {
		return fmt.Errorf("json.Unmarshal(audienceJSON): %w", err)
	}
	if err := json.Unmarshal(scopesJSON, &rt.Scopes); err != nil {
		return fmt.Errorf("json.Unmarshal(scopesJSON): %w", err)
	}

	return nil
}

type User struct {
	ID                string
	Npub              *btcec.PublicKey
	PreferredLanguage language.Tag
	IsAdmin           bool
	Active            bool
}

// ScanRow implements a pgx-style row scanner for User
// This method scans a database row directly into the User struct fields
// Expected column order: id, npub, preferred_language, is_admin, active
func (u *User) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var npubBytes []byte
	var langStr string

	err := row.Scan(&u.ID, &npubBytes, &langStr, &u.IsAdmin, &u.Active)
	if err != nil {
		return err
	}

	// Parse npub bytes to PublicKey
	if len(npubBytes) > 0 {
		u.Npub, err = btcec.ParsePubKey(npubBytes)
		if err != nil {
			return fmt.Errorf("btcec.ParsePubKey: %w", err)
		}
	}

	// Parse language tag
	u.PreferredLanguage, err = language.Parse(langStr)
	if err != nil {
		return fmt.Errorf("language.Parse: %w", err)
	}

	return nil
}

type deviceAuthorizationEntry struct {
	deviceCode string
	userCode   string
	state      *op.DeviceAuthorizationState
}

// ScanRow implements a pgx-style row scanner for deviceAuthorizationEntry
// This method scans a database row directly into the deviceAuthorizationEntry struct fields
// Expected column order: device_code, user_code, state
func (d *deviceAuthorizationEntry) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var stateJSON []byte

	err := row.Scan(&d.deviceCode, &d.userCode, &stateJSON)
	if err != nil {
		return err
	}

	// Unmarshal the state JSON
	d.state = &op.DeviceAuthorizationState{}
	if err := json.Unmarshal(stateJSON, d.state); err != nil {
		return fmt.Errorf("json.Unmarshal(stateJSON): %w", err)
	}

	return nil
}

// // ExampleClientID is only used in the example server
// func (u userStore) ExampleClientID() string {
// 	return ServiceUserID
// }
//
// func (u userStore) GetUserByID(id string) *User {
// 	return u.users[id]
// }
//
// func (u userStore) GetUserByNpub(pubkey *btcec.PublicKey) *User {
// 	for _, user := range u.users {
// 		if user.Npub.IsEqual(pubkey) {
// 			return user
// 		}
// 	}
// 	return nil
// }
