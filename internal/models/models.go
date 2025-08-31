package models

import "time"

const (
	UserTypeAdmin         = "ADMIN"
	UserTypeRelayingParty = "RELAYING_PARTY"
	UserTypeEndUser       = "END_USER"
)

type User struct {
	ID        int64     `json:"id"`
	PublicKey string    `json:"public_key"`
	Type      string    `json:"type"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsAdmin reports whether the user has ADMIN type.
func (u *User) IsAdmin() bool {
	return u.Type == UserTypeAdmin
}

type Session struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}
