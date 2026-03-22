package codes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
)

// CodeMapping maps party names to verification codes for a session.
type CodeMapping struct {
	SessionID string            `json:"session_id"`
	Codes     map[string]string `json:"codes"` // party_name -> 8-digit code
}

// GenerateCodeMapping creates a per-session code mapping for all parties.
// The masterSecret is the reconstructed Ristretto255 scalar from threshold key shares.
// Each party receives a deterministic 8-digit code derived via domain-separated HMAC.
func GenerateCodeMapping(sessionID string, parties []string, masterSecret *edwards25519.Scalar) *CodeMapping {
	mapping := &CodeMapping{
		SessionID: sessionID,
		Codes:     make(map[string]string),
	}
	for _, party := range parties {
		code := deriveCode(masterSecret, sessionID, party)
		mapping.Codes[party] = code
	}
	return mapping
}

// DeriveReturnCode computes the return code for an encrypted ballot.
// The code is deterministic: same ciphertext + same master secret = same code.
// Uses domain-separated HMAC with the master secret's 32-byte scalar representation.
func DeriveReturnCode(masterSecret *edwards25519.Scalar, sessionID string, encryptedBallotBytes []byte) string {
	mac := hmac.New(sha256.New, masterSecret.Bytes())
	mac.Write([]byte("otvoren-vot.return-code\x00"))
	mac.Write([]byte(sessionID))
	mac.Write([]byte("\x00"))
	mac.Write(encryptedBallotBytes)
	hash := mac.Sum(nil)
	return fmt.Sprintf("%08d", binary.BigEndian.Uint64(hash[:8])%100_000_000)
}

// VerifyReturnCode checks if a return code matches the expected code for a party.
func VerifyReturnCode(mapping *CodeMapping, returnCode string) (string, bool) {
	for party, code := range mapping.Codes {
		if code == returnCode {
			return party, true
		}
	}
	return "", false
}

func deriveCode(masterSecret *edwards25519.Scalar, sessionID, party string) string {
	mac := hmac.New(sha256.New, masterSecret.Bytes())
	mac.Write([]byte("otvoren-vot.code-mapping\x00"))
	mac.Write([]byte(sessionID))
	mac.Write([]byte("\x00"))
	mac.Write([]byte(party))
	hash := mac.Sum(nil)
	return fmt.Sprintf("%08d", binary.BigEndian.Uint64(hash[:8])%100_000_000)
}
