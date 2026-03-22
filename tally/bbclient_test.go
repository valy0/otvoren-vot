package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/valy0/otvoren-vot/tally/ceremony"
)

func TestIsSealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/board/root" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"root_sha256": "abc123",
				"sealed":      true,
				"count":       42,
			},
		})
	}))
	defer srv.Close()

	client := NewBBClient(srv.URL, nil)
	sealed, err := client.IsSealed(context.Background())
	if err != nil {
		t.Fatalf("IsSealed() error: %v", err)
	}
	if !sealed {
		t.Fatal("expected sealed=true, got false")
	}
}

func TestIsNotSealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"root_sha256": "",
				"sealed":      false,
				"count":       0,
			},
		})
	}))
	defer srv.Close()

	client := NewBBClient(srv.URL, nil)
	sealed, err := client.IsSealed(context.Background())
	if err != nil {
		t.Fatalf("IsSealed() error: %v", err)
	}
	if sealed {
		t.Fatal("expected sealed=false, got true")
	}
}

func TestFetchAllBallots(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/board" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		callCount++
		w.Header().Set("Content-Type", "application/json")

		cursor := r.URL.Query().Get("cursor")

		switch {
		case cursor == "": // First page
			json.NewEncoder(w).Encode(map[string]any{
				"data": []ceremony.SerializedBallot{
					{BallotID: "b1", EncryptedBallot: json.RawMessage(`{"party_vector":["aa"]}`)},
					{BallotID: "b2", EncryptedBallot: json.RawMessage(`{"party_vector":["bb"]}`)},
				},
				"meta": map[string]any{
					"cursor": "page2cursor",
					"total":  3,
				},
			})
		case cursor == "page2cursor": // Second page (last)
			json.NewEncoder(w).Encode(map[string]any{
				"data": []ceremony.SerializedBallot{
					{BallotID: "b3", EncryptedBallot: json.RawMessage(`{"party_vector":["cc"]}`)},
				},
				"meta": map[string]any{
					"cursor": "",
					"total":  3,
				},
			})
		default:
			t.Errorf("unexpected cursor: %s", cursor)
			http.Error(w, "bad cursor", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	client := NewBBClient(srv.URL, nil)
	ballots, err := client.FetchAllBallots(context.Background())
	if err != nil {
		t.Fatalf("FetchAllBallots() error: %v", err)
	}

	if got := len(ballots); got != 3 {
		t.Fatalf("expected 3 ballots, got %d", got)
	}

	wantIDs := []string{"b1", "b2", "b3"}
	for i, want := range wantIDs {
		if ballots[i].BallotID != want {
			t.Errorf("ballot[%d].BallotID = %q, want %q", i, ballots[i].BallotID, want)
		}
	}

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", callCount)
	}
}

func TestFetchAllBallotsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []ceremony.SerializedBallot{},
			"meta": map[string]any{
				"cursor": "",
				"total":  0,
			},
		})
	}))
	defer srv.Close()

	client := NewBBClient(srv.URL, nil)
	ballots, err := client.FetchAllBallots(context.Background())
	if err != nil {
		t.Fatalf("FetchAllBallots() error: %v", err)
	}
	if len(ballots) != 0 {
		t.Fatalf("expected 0 ballots, got %d", len(ballots))
	}
}
