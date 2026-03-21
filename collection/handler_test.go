package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/valy0/otvoren-vot/collection/votermap"
)

func TestSubmitBallot(t *testing.T) {
	// Mock bulletin board
	bb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"position": 1, "merkle_root": "abc"},
		})
	}))
	defer bb.Close()

	vm := votermap.New()
	h := NewCollectionHandler(vm, bb.URL, "test-key")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp submitResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.IsOverride {
		t.Fatal("first vote should not be an override")
	}

	// Verify voter map was updated
	if !vm.HasVoted("8501011234") {
		t.Fatal("voter should be recorded")
	}
}

func TestSubmitOverride(t *testing.T) {
	bb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"position": 1, "merkle_root": "abc"},
		})
	}))
	defer bb.Close()

	vm := votermap.New()
	h := NewCollectionHandler(vm, bb.URL, "test-key")

	// First vote
	req1 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`))
	req1.Header.Set("X-Voter-EGN", "8501011234")
	w1 := httptest.NewRecorder()
	h.HandleSubmit(w1, req1)

	// Override
	req2 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b2","encrypted_ballot":{},"zk_proofs":{}}`))
	req2.Header.Set("X-Voter-EGN", "8501011234")
	w2 := httptest.NewRecorder()
	h.HandleSubmit(w2, req2)

	var resp submitResponse
	json.NewDecoder(w2.Body).Decode(&resp)
	if !resp.IsOverride {
		t.Fatal("second vote should be an override")
	}

	id, _ := vm.GetActiveBallotID("8501011234")
	if id != "b2" {
		t.Fatalf("active ballot should be b2, got %s", id)
	}
}

func TestSubmitMissingIdentity(t *testing.T) {
	vm := votermap.New()
	h := NewCollectionHandler(vm, "http://unused", "key")

	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`))
	// No X-Voter-EGN header
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestActiveSet(t *testing.T) {
	vm := votermap.New()
	vm.Record("1111111111", "b1", "online", 1000)
	vm.Record("2222222222", "b2", "online", 1000)

	h := NewCollectionHandler(vm, "http://unused", "key")
	req := httptest.NewRequest("GET", "/active-set", nil)
	w := httptest.NewRecorder()
	h.HandleActiveSet(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if int(resp["size"].(float64)) != 2 {
		t.Fatalf("expected size 2, got %v", resp["size"])
	}
}
