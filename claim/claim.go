package claim

import "github.com/dgrijalva/jwt-go"

type IdentityClaim struct {
	UserID      string         `json:"user_id,omitempty"`
	Tenant      string         `json:"tenant,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	Permissions map[string]int `json:"permissions"`
	jwt.StandardClaims
}
