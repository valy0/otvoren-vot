package provider

import "testing"

func TestMockValidToken(t *testing.T) {
	m := NewMockProvider()
	id, err := m.Authenticate("mock-8501011234")
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("should return identity for valid token")
	}
	if id.EGN != "8501011234" {
		t.Fatalf("expected EGN 8501011234, got %s", id.EGN)
	}
	if !id.IsEligible {
		t.Fatal("mock users should be eligible")
	}
}

func TestMockInvalidToken(t *testing.T) {
	m := NewMockProvider()
	id, _ := m.Authenticate("invalid-token")
	if id != nil {
		t.Fatal("invalid token should return nil")
	}
}

func TestMockShortEGN(t *testing.T) {
	m := NewMockProvider()
	id, _ := m.Authenticate("mock-12345")
	if id != nil {
		t.Fatal("short EGN should return nil")
	}
}

func TestMockNonNumericEGN(t *testing.T) {
	m := NewMockProvider()
	id, _ := m.Authenticate("mock-abcdefghij")
	if id != nil {
		t.Fatal("non-numeric EGN should return nil")
	}
}

func TestMockProviderName(t *testing.T) {
	m := NewMockProvider()
	if m.Name() != "mock" {
		t.Fatalf("expected 'mock', got %s", m.Name())
	}
}
