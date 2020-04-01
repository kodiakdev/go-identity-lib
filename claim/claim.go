package claim

import "github.com/dgrijalva/jwt-go"

type IdentityClaim struct {
	UserID      string         `json:"user_id,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	Permissions map[string]int `json:"permissions"`
	jwt.StandardClaims
}
