package jwtauth

import (
	"crypto/ed25519"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Verify parses and validates a JWT signed with Ed25519.
func Verify(tokenStr string, pubKey ed25519.PublicKey) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &SessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

// Sign creates a signed JWT for the given session.
func Sign(claims *SessionClaims, privKey ed25519.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(privKey)
}
