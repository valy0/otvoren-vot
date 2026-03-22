package main

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	patterns := []string{"http://localhost:*"}

	tests := []struct {
		name   string
		uri    string
		wantOK bool
	}{
		{"localhost any port", "http://localhost:3000", true},
		{"localhost 8080", "http://localhost:8080", true},
		{"localhost no port", "http://localhost", true},
		{"wrong scheme", "https://localhost:3000", false},
		{"wrong host", "http://example.com:3000", false},
		{"userinfo attack", "http://user@evil.com", false},
		{"empty", "", false},
		{"no scheme", "localhost:3000", false},
		{"production exact", "https://izbori.bg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateRedirectURI(tt.uri, patterns)
			if got != tt.wantOK {
				t.Errorf("validateRedirectURI(%q) = %v, want %v", tt.uri, got, tt.wantOK)
			}
		})
	}
}

func TestValidateRedirectURIProduction(t *testing.T) {
	patterns := []string{"https://izbori.bg", "https://vote.izbori.bg"}

	tests := []struct {
		uri    string
		wantOK bool
	}{
		{"https://izbori.bg", true},
		{"https://vote.izbori.bg", true},
		{"https://evil.izbori.bg", false},
		{"http://izbori.bg", false},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := validateRedirectURI(tt.uri, patterns)
			if got != tt.wantOK {
				t.Errorf("got %v, want %v", got, tt.wantOK)
			}
		})
	}
}
