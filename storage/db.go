package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/text/language"
)

type storageDB struct {
	db *sql.DB
}

// BeginTx starts a new database transaction
func (s *storageDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if s.db == nil {
		panic("db cannot be nil")
	}
	return s.db.BeginTx(ctx, opts)
}

// AddAuthRequest inserts a new auth request into the database
func (s *storageDB) AddAuthRequest(tx *sql.Tx, authReq *AuthRequest) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	// Marshal slice fields to JSON
	promptJSON, err := json.Marshal(authReq.Prompt)
	if err != nil {
		return err
	}
	uiLocalesJSON, err := json.Marshal(authReq.UiLocales)
	if err != nil {
		return err
	}
	scopesJSON, err := json.Marshal(authReq.Scopes)
	if err != nil {
		return err
	}

	// Handle MaxAuthAge (pointer to duration)
	var maxAuthAgeStr sql.NullString
	if authReq.MaxAuthAge != nil {
		maxAuthAgeStr.String = authReq.MaxAuthAge.String()
		maxAuthAgeStr.Valid = true
	}

	// Handle CodeChallenge (pointer)
	var challenge, method sql.NullString
	if authReq.CodeChallenge != nil {
		challenge.String = authReq.CodeChallenge.Challenge
		challenge.Valid = true
		method.String = authReq.CodeChallenge.Method
		method.Valid = true
	}

	query := `
		INSERT INTO auth_requests (
			id, creation_date, application_id, callback_uri, transfer_state, prompt,
			ui_locales, login_hint, max_auth_age, user_id, scopes, response_type,
			response_mode, nonce, code_challenge_challenge, code_challenge_method
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		authReq.ID, authReq.CreationDate, authReq.ApplicationID, authReq.CallbackURI, authReq.TransferState, string(promptJSON),
		string(uiLocalesJSON), authReq.LoginHint, maxAuthAgeStr, authReq.UserID, string(scopesJSON), string(authReq.ResponseType),
		string(authReq.ResponseMode), authReq.Nonce, challenge, method,
	)
	return err
}

// SearchAuthRequestByID retrieves an auth request by ID
func (s *storageDB) SearchAuthRequestByID(tx *sql.Tx, id string) (*AuthRequest, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `
		SELECT id, creation_date, application_id, callback_uri, transfer_state, prompt,
			   ui_locales, login_hint, max_auth_age, user_id, scopes, response_type,
			   response_mode, nonce, code_challenge_challenge, code_challenge_method
		FROM auth_requests WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var authReq AuthRequest
	var maxAuthAgeStr, challenge, method sql.NullString
	var promptJSON, uiLocalesJSON, scopesJSON []byte

	err = stmt.QueryRow(id).Scan(
		&authReq.ID, &authReq.CreationDate, &authReq.ApplicationID, &authReq.CallbackURI, &authReq.TransferState, &promptJSON,
		&uiLocalesJSON, &authReq.LoginHint, &maxAuthAgeStr, &authReq.UserID, &scopesJSON, 
		(*string)(&authReq.ResponseType), (*string)(&authReq.ResponseMode), &authReq.Nonce, &challenge, &method,
	)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(promptJSON, &authReq.Prompt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(uiLocalesJSON, &authReq.UiLocales); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &authReq.Scopes); err != nil {
		return nil, err
	}

	// Handle MaxAuthAge
	if maxAuthAgeStr.Valid {
		dur, err := time.ParseDuration(maxAuthAgeStr.String)
		if err != nil {
			return nil, err
		}
		authReq.MaxAuthAge = &dur
	}

	// Handle CodeChallenge
	if challenge.Valid || method.Valid {
		authReq.CodeChallenge = &OIDCCodeChallenge{
			Challenge: challenge.String,
			Method:    method.String,
		}
	}

	return &authReq, nil
}

// DeleteAuthRequest removes an auth request by ID
func (s *storageDB) DeleteAuthRequest(tx *sql.Tx, id string) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `DELETE FROM auth_requests WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

// AddClient inserts a new client into the database
func (s *storageDB) AddClient(tx *sql.Tx, client *Client) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	// Marshal slice fields to JSON
	redirectURIsJSON, err := json.Marshal(client.redirectURIs)
	if err != nil {
		return err
	}
	responseTypesJSON, err := json.Marshal(client.responseTypes)
	if err != nil {
		return err
	}
	grantTypesJSON, err := json.Marshal(client.grantTypes)
	if err != nil {
		return err
	}
	postLogoutRedirectURIsJSON, err := json.Marshal(client.postLogoutRedirectURIGlobs)
	if err != nil {
		return err
	}
	redirectURIsGlobsJSON, err := json.Marshal(client.redirectURIGlobs)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO clients (
			id, secret, redirect_uris, application_type, auth_method, response_types,
			grant_types, access_token_type, dev_mode, id_token_userinfo_claims_assertion,
			clock_skew, post_logout_redirect_uri_globs, redirect_uri_globs
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		client.id, client.secret, string(redirectURIsJSON), string(client.applicationType),
		string(client.authMethod), string(responseTypesJSON), string(grantTypesJSON),
		string(client.accessTokenType), client.devMode, client.idTokenUserinfoClaimsAssertion,
		client.clockSkew.String(), string(postLogoutRedirectURIsJSON), string(redirectURIsGlobsJSON),
	)
	return err
}

// SearchClientByID retrieves a client by ID
func (s *storageDB) SearchClientByID(tx *sql.Tx, id string) (*Client, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `
		SELECT id, secret, redirect_uris, application_type, auth_method, response_types,
			   grant_types, access_token_type, dev_mode, id_token_userinfo_claims_assertion,
			   clock_skew, post_logout_redirect_uri_globs, redirect_uri_globs
		FROM clients WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var client Client
	var clockSkewStr string
	var redirectURIsJSON, responseTypesJSON, grantTypesJSON, postLogoutRedirectURIsJSON, redirectURIsGlobsJSON []byte

	err = stmt.QueryRow(id).Scan(
		&client.id, &client.secret, &redirectURIsJSON, &client.applicationType, &client.authMethod,
		&responseTypesJSON, &grantTypesJSON, &client.accessTokenType, &client.devMode,
		&client.idTokenUserinfoClaimsAssertion, &clockSkewStr, &postLogoutRedirectURIsJSON, &redirectURIsGlobsJSON,
	)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(redirectURIsJSON, &client.redirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(responseTypesJSON, &client.responseTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(grantTypesJSON, &client.grantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(postLogoutRedirectURIsJSON, &client.postLogoutRedirectURIGlobs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(redirectURIsGlobsJSON, &client.redirectURIGlobs); err != nil {
		return nil, err
	}

	client.clockSkew, err = time.ParseDuration(clockSkewStr)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

// DeleteClient removes a client by ID
func (s *storageDB) DeleteClient(tx *sql.Tx, id string) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `DELETE FROM clients WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

// AddUser inserts a new user into the database
func (s *storageDB) AddUser(tx *sql.Tx, user *User) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	// Serialize public key to bytes
	var npubBytes []byte
	if user.Npub != nil {
		npubBytes = user.Npub.SerializeCompressed()
	}

	query := `INSERT INTO users (id, npub, preferred_language, is_admin) VALUES (?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.ID, npubBytes, user.PreferredLanguage.String(), user.IsAdmin)
	return err
}

// SearchUserByID retrieves a user by ID
func (s *storageDB) SearchUserByID(tx *sql.Tx, id string) (*User, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `SELECT id, npub, preferred_language, is_admin FROM users WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var user User
	var npubBytes []byte
	var preferredLangStr string

	err = stmt.QueryRow(id).Scan(&user.ID, &npubBytes, &preferredLangStr, &user.IsAdmin)
	if err != nil {
		return nil, err
	}

	// Deserialize public key
	if len(npubBytes) > 0 {
		user.Npub, err = btcec.ParsePubKey(npubBytes)
		if err != nil {
			return nil, err
		}
	}

	user.PreferredLanguage, err = language.Parse(preferredLangStr)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// SearchUserByNpub retrieves a user by their public key
func (s *storageDB) SearchUserByNpub(tx *sql.Tx, npub *btcec.PublicKey) (*User, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}
	if npub == nil {
		panic("npub cannot be nil")
	}

	// Serialize public key to bytes for database lookup
	npubBytes := npub.SerializeCompressed()

	query := `SELECT id, npub, preferred_language, is_admin FROM users WHERE npub = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var user User
	var dbNpubBytes []byte
	var preferredLangStr string

	err = stmt.QueryRow(npubBytes).Scan(&user.ID, &dbNpubBytes, &preferredLangStr, &user.IsAdmin)
	if err != nil {
		return nil, err
	}

	// Deserialize public key (should match the input)
	user.Npub, err = btcec.ParsePubKey(dbNpubBytes)
	if err != nil {
		return nil, err
	}

	user.PreferredLanguage, err = language.Parse(preferredLangStr)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// DeleteUser removes a user by ID
func (s *storageDB) DeleteUser(tx *sql.Tx, id string) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `DELETE FROM users WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

// AddToken inserts a new token into the database
func (s *storageDB) AddToken(tx *sql.Tx, token *Token) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	// Marshal slice fields to JSON
	audienceJSON, err := json.Marshal(token.Audience)
	if err != nil {
		return err
	}
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO tokens (id, application_id, subject, refresh_token_id, audience, expiration, scopes)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		token.ID, token.ApplicationID, token.Subject, token.RefreshTokenID,
		string(audienceJSON), token.Expiration, string(scopesJSON),
	)
	return err
}

// SearchTokenByID retrieves a token by ID
func (s *storageDB) SearchTokenByID(tx *sql.Tx, id string) (*Token, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `SELECT id, application_id, subject, refresh_token_id, audience, expiration, scopes FROM tokens WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var token Token
	var audienceJSON, scopesJSON []byte

	err = stmt.QueryRow(id).Scan(
		&token.ID, &token.ApplicationID, &token.Subject, &token.RefreshTokenID,
		&audienceJSON, &token.Expiration, &scopesJSON,
	)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(audienceJSON, &token.Audience); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &token.Scopes); err != nil {
		return nil, err
	}

	return &token, nil
}

// DeleteToken removes a token by ID
func (s *storageDB) DeleteToken(tx *sql.Tx, id string) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `DELETE FROM tokens WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

// AddRefreshToken inserts a new refresh token into the database
func (s *storageDB) AddRefreshToken(tx *sql.Tx, refreshToken *RefreshToken) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	// Marshal slice fields to JSON
	amrJSON, err := json.Marshal(refreshToken.AMR)
	if err != nil {
		return err
	}
	audienceJSON, err := json.Marshal(refreshToken.Audience)
	if err != nil {
		return err
	}
	scopesJSON, err := json.Marshal(refreshToken.Scopes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO refresh_tokens (
			id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		refreshToken.ID, refreshToken.Token, refreshToken.AuthTime, string(amrJSON),
		string(audienceJSON), refreshToken.UserID, refreshToken.ApplicationID, refreshToken.Expiration,
		string(scopesJSON), refreshToken.AccessToken,
	)
	return err
}

// SearchRefreshTokenByID retrieves a refresh token by ID
func (s *storageDB) SearchRefreshTokenByID(tx *sql.Tx, id string) (*RefreshToken, error) {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `
		SELECT id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token
		FROM refresh_tokens WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var refreshToken RefreshToken
	var amrJSON, audienceJSON, scopesJSON []byte

	err = stmt.QueryRow(id).Scan(
		&refreshToken.ID, &refreshToken.Token, &refreshToken.AuthTime, &amrJSON,
		&audienceJSON, &refreshToken.UserID, &refreshToken.ApplicationID, &refreshToken.Expiration,
		&scopesJSON, &refreshToken.AccessToken,
	)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(amrJSON, &refreshToken.AMR); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(audienceJSON, &refreshToken.Audience); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &refreshToken.Scopes); err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

// DeleteRefreshToken removes a refresh token by ID
func (s *storageDB) DeleteRefreshToken(tx *sql.Tx, id string) error {
	if tx == nil {
		panic("tx cannot be nil")
	}

	query := `DELETE FROM refresh_tokens WHERE id = ?`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}
