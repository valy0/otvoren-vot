package provider

import (
	"fmt"
	"strings"
)

// MockProvider simulates eAuth 2.0 for development and testing.
// Accepts tokens in the format "mock-{EGN}" and returns a synthetic identity.
type MockProvider struct{}

func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) Name() string {
	return "mock"
}

func (m *MockProvider) Authenticate(token string) (*Identity, error) {
	if !strings.HasPrefix(token, "mock-") {
		return nil, nil // Invalid token format
	}
	egn := strings.TrimPrefix(token, "mock-")
	if len(egn) != 10 {
		return nil, nil // EGN must be 10 digits
	}
	for _, c := range egn {
		if c < '0' || c > '9' {
			return nil, nil
		}
	}

	return &Identity{
		EGN:        egn,
		Name:       fmt.Sprintf("Тест Потребител %s", egn[:4]),
		IsEligible: true,
	}, nil
}
