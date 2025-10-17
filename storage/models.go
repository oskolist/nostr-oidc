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

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     time.Time
	Scopes         []string
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

type User struct {
	ID                string
	Npub              *btcec.PublicKey
	PreferredLanguage language.Tag
	IsAdmin           bool
}

// ScanRow implements a pgx-style row scanner for User
// This method scans a database row directly into the User struct fields
// Expected column order: id, npub, preferred_language, is_admin
func (u *User) ScanRow(row interface{ Scan(...interface{}) error }) error {
	var npubBytes []byte
	var langStr string

	err := row.Scan(&u.ID, &npubBytes, &langStr, &u.IsAdmin)
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
