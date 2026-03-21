package codes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// CodeMapping maps party names to verification codes for a session.
type CodeMapping struct {
	SessionID string            `json:"session_id"`
	Codes     map[string]string `json:"codes"` // party_name -> 4-digit code
}

// GenerateCodeMapping creates a per-session code mapping for all parties.
// In production, this involves threshold computation among verification trustees.
// For now, uses HMAC with a shared secret (simulating a single trustee).
func GenerateCodeMapping(sessionID string, parties []string, secret []byte) *CodeMapping {
	mapping := &CodeMapping{
		SessionID: sessionID,
		Codes:     make(map[string]string),
	}
	for _, party := range parties {
		code := deriveCode(secret, sessionID, party)
		mapping.Codes[party] = code
	}
	return mapping
}

// DeriveReturnCode computes the return code for an encrypted ballot.
// The code is deterministic: same ciphertext + same secret = same code.
// In production, this is threshold-computed by verification trustees.
func DeriveReturnCode(secret []byte, sessionID string, encryptedBallotBytes []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("otvoren-vot.return-code"))
	mac.Write([]byte(sessionID))
	mac.Write(encryptedBallotBytes)
	hash := mac.Sum(nil)
	return fmt.Sprintf("%04d", binary.BigEndian.Uint32(hash[:4])%10000)
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

func deriveCode(secret []byte, sessionID, party string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("otvoren-vot.code-mapping"))
	mac.Write([]byte(sessionID))
	mac.Write([]byte(party))
	hash := mac.Sum(nil)
	return fmt.Sprintf("%04d", binary.BigEndian.Uint32(hash[:4])%10000)
}
