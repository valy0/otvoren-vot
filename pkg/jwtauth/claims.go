package jwtauth

import "github.com/golang-jwt/jwt/v5"

const (
	Issuer   = "otvoren-vot-auth"
	Audience = "otvoren-vot-collection"
)

// SessionClaims are the JWT claims for a voter session.
type SessionClaims struct {
	jwt.RegisteredClaims
	ElectionID string `json:"eid"`
}
