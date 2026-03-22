package provider

// Identity represents an authenticated voter.
type Identity struct {
	EGN         string `json:"egn"`          // ЕГН (Bulgarian personal ID number)
	Name        string `json:"name"`         // Full name
	IsEligible  bool   `json:"is_eligible"`  // Eligible to vote in this election
}

// Provider is the interface for authentication backends.
type Provider interface {
	// Authenticate validates credentials and returns the voter identity.
	// Returns nil, nil if credentials are invalid.
	Authenticate(token string) (*Identity, error)

	// Name returns the provider name (e.g., "eAuth 2.0", "mock").
	Name() string
}
