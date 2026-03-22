package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/threshold"
	"github.com/valy0/otvoren-vot/tally/ceremony"
)

// testSetup holds everything needed for a full ceremony integration test:
// DKG output, encrypted ballots as the BB would serve them, expected vote
// counts, and the trustee key set.
type testSetup struct {
	dkg         *threshold.DKGResult
	ballots     []ceremony.SerializedBallot
	expected    []int
	numParties  int
	trusteeKeys *TrusteeKeySet
}

// newTestSetup runs DKG(5,9), encrypts 5 ballots for 3 parties, and builds
// the trustee key set. Returns a fully populated testSetup.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	dkg, err := threshold.RunDKG(5, 9)
	if err != nil {
		t.Fatal(err)
	}

	numParties := 3
	votes := []int{0, 0, 1, 2, 2} // expected: [2, 1, 2]
	expected := []int{2, 1, 2}

	ballots := make([]ceremony.SerializedBallot, len(votes))
	for i, party := range votes {
		b := elgamal.EncodeBallot(dkg.ElectionPublicKey, numParties, party)
		pvHex := make([]string, numParties)
		for j, ct := range b.PartyVector {
			pvHex[j] = hex.EncodeToString(ct.Bytes())
		}
		encBallot, _ := json.Marshal(ceremony.BallotData{PartyVector: pvHex})
		ballots[i] = ceremony.SerializedBallot{
			BallotID:        fmt.Sprintf("ballot-%d", i),
			EncryptedBallot: encBallot,
		}
	}

	// Build trustee key set from DKG participants.
	keys := make(map[int]*edwards25519.Point, len(dkg.Participants))
	for _, p := range dkg.Participants {
		keys[p.ID] = p.VerificationKey
	}

	return &testSetup{
		dkg:         dkg,
		ballots:     ballots,
		expected:    expected,
		numParties:  numParties,
		trusteeKeys: &TrusteeKeySet{Keys: keys},
	}
}

// mockBB creates an httptest.Server that mimics a sealed bulletin board
// serving the given ballots in a single page.
func mockBB(t *testing.T, sealed bool, ballots []ceremony.SerializedBallot) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1/board/root":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"root_sha256": "abc123",
					"sealed":      sealed,
					"count":       len(ballots),
				},
			})
		case "/api/v1/board":
			json.NewEncoder(w).Encode(map[string]any{
				"data": ballots,
				"meta": map[string]any{
					"cursor": "",
					"total":  len(ballots),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

// newHandlerWithMockBB creates a CeremonyHandler wired to a mock BB.
func newHandlerWithMockBB(t *testing.T, bbServer *httptest.Server, trusteeKeys *TrusteeKeySet) (*CeremonyHandler, *http.ServeMux) {
	t.Helper()

	bbClient := NewBBClient(bbServer.URL, nil)
	stateDir := t.TempDir()

	handler, err := NewCeremonyHandler(bbClient, trusteeKeys, "test-election", stateDir)
	if err != nil {
		t.Fatalf("NewCeremonyHandler: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return handler, mux
}

// startCeremony sends a POST to /api/v1/ceremony/start and returns the
// ceremony ID. It fails the test if the response is not 202.
func startCeremony(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	body, _ := json.Marshal(startRequest{
		ActiveSet: []string{"voter-1", "voter-2", "voter-3"},
	})

	resp, err := http.Post(srv.URL+"/api/v1/ceremony/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("start request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("expected 202, got %d: %v", resp.StatusCode, errResp)
	}

	var sr startResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.CeremonyID == "" {
		t.Fatal("empty ceremony_id in start response")
	}
	return sr.CeremonyID
}

// pollUntilPhase polls the status endpoint until the ceremony reaches the
// desired phase or the timeout expires.
func pollUntilPhase(t *testing.T, srv *httptest.Server, ceremonyID, wantPhase string, timeout time.Duration) statusResponse {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(srv.URL + "/api/v1/ceremony/" + ceremonyID)
		if err != nil {
			t.Fatalf("status request failed: %v", err)
		}

		var sr statusResponse
		json.NewDecoder(resp.Body).Decode(&sr)
		resp.Body.Close()

		if sr.Phase == wantPhase {
			return sr
		}
		if sr.Phase == PhaseError {
			t.Fatalf("ceremony entered error phase while waiting for %s", wantPhase)
		}

		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for phase %s", wantPhase)
	return statusResponse{}
}

// --- Tests ---

func TestStartCeremony(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)

	// Poll until the ceremony reaches awaiting_trustees.
	status := pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	if status.BallotCount != len(ts.ballots) {
		t.Errorf("ballot count: got %d, want %d", status.BallotCount, len(ts.ballots))
	}
	if status.PartyCount != ts.numParties {
		t.Errorf("party count: got %d, want %d", status.PartyCount, ts.numParties)
	}
}

func TestStartCeremonyNotSealed(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, false, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(startRequest{
		ActiveSet: []string{"voter-1"},
	})
	resp, err := http.Post(srv.URL+"/api/v1/ceremony/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "board_not_sealed" {
		t.Errorf("expected code board_not_sealed, got %v", errObj["code"])
	}
}

func TestStartCeremonyDouble(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// First start — should succeed.
	startCeremony(t, srv)

	// Wait for it to enter awaiting_trustees (or at least be in progress).
	time.Sleep(100 * time.Millisecond)

	// Second start — should get 409.
	body, _ := json.Marshal(startRequest{
		ActiveSet: []string{"voter-1"},
	})
	resp, err := http.Post(srv.URL+"/api/v1/ceremony/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "ceremony_in_progress" {
		t.Errorf("expected code ceremony_in_progress, got %v", errObj["code"])
	}
}

func TestPartialDecryptionAndDecrypt(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	handler, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Need to get the tally result to compute correct partial decryptions.
	// The handler has it in memory after tally computation.
	handler.mu.Lock()
	cs := handler.ceremony
	tallyResult := cs.TallyResult()
	handler.mu.Unlock()

	if tallyResult == nil {
		t.Fatal("tally result is nil after awaiting_trustees")
	}

	// Submit partials from trustees 1..5 (the first 5 out of 9).
	trusteeIndices := []int{1, 2, 3, 4, 5}
	for _, tidx := range trusteeIndices {
		participant := ts.dkg.Participants[tidx-1]

		partials := make([]partialDecryptionElement, ts.numParties)
		for j, encSum := range tallyResult.EncryptedSums {
			pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
			partials[j] = partialDecryptionElement{
				PartyIndex: j,
				Point:      hex.EncodeToString(pd.D.Bytes()),
			}
		}

		body, _ := json.Marshal(partialDecryptionRequest{
			TrusteeIndex: tidx,
			Partials:     partials,
		})

		resp, err := http.Post(
			srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("trustee %d request: %v", tidx, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errBody map[string]any
			json.NewDecoder(resp.Body).Decode(&errBody)
			t.Fatalf("trustee %d: expected 200, got %d: %v", tidx, resp.StatusCode, errBody)
		}

		var pr partialDecryptionResponse
		json.NewDecoder(resp.Body).Decode(&pr)
		if pr.Status != "accepted" {
			t.Errorf("trustee %d: expected status accepted, got %s", tidx, pr.Status)
		}
	}

	// After 5 partials, auto-decryption should have triggered.
	// Check that the ceremony is now in phase decrypted.
	handler.mu.Lock()
	phase := handler.ceremony.Phase
	results := handler.ceremony.Results
	handler.mu.Unlock()

	if phase != PhaseDecrypted {
		t.Fatalf("expected phase %s, got %s", PhaseDecrypted, phase)
	}

	if len(results) != ts.numParties {
		t.Fatalf("expected %d results, got %d", ts.numParties, len(results))
	}
	for i, want := range ts.expected {
		if results[i] != want {
			t.Errorf("party %d: expected %d votes, got %d", i, want, results[i])
		}
	}
}

func TestPartialDecryptionIdempotent(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	handler, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	handler.mu.Lock()
	tallyResult := handler.ceremony.TallyResult()
	handler.mu.Unlock()

	// Submit from trustee 1.
	participant := ts.dkg.Participants[0] // trustee index 1
	partials := make([]partialDecryptionElement, ts.numParties)
	for j, encSum := range tallyResult.EncryptedSums {
		pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
		partials[j] = partialDecryptionElement{
			PartyIndex: j,
			Point:      hex.EncodeToString(pd.D.Bytes()),
		}
	}

	body, _ := json.Marshal(partialDecryptionRequest{
		TrusteeIndex: 1,
		Partials:     partials,
	})

	// First submission.
	resp1, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first submission: expected 200, got %d", resp1.StatusCode)
	}

	// Second submission (same trustee) — should get idempotent response.
	resp2, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second submission: expected 200, got %d", resp2.StatusCode)
	}

	var pr partialDecryptionResponse
	json.NewDecoder(resp2.Body).Decode(&pr)
	if pr.Status != "already_submitted" {
		t.Errorf("expected status already_submitted, got %s", pr.Status)
	}
}

func TestResultsBeforeDecryption(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Try to get results before decryption — should be 409.
	resp, err := http.Get(srv.URL + "/api/v1/ceremony/" + ceremonyID + "/results")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "not_decrypted" {
		t.Errorf("expected code not_decrypted, got %v", errObj["code"])
	}
}

func TestResultsAfterDecryption(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	handler, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	handler.mu.Lock()
	tallyResult := handler.ceremony.TallyResult()
	handler.mu.Unlock()

	// Submit 5 partials to trigger auto-decryption.
	for tidx := 1; tidx <= 5; tidx++ {
		participant := ts.dkg.Participants[tidx-1]
		partials := make([]partialDecryptionElement, ts.numParties)
		for j, encSum := range tallyResult.EncryptedSums {
			pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
			partials[j] = partialDecryptionElement{
				PartyIndex: j,
				Point:      hex.EncodeToString(pd.D.Bytes()),
			}
		}

		body, _ := json.Marshal(partialDecryptionRequest{
			TrusteeIndex: tidx,
			Partials:     partials,
		})

		resp, err := http.Post(
			srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	// Now get results.
	resp, err := http.Get(srv.URL + "/api/v1/ceremony/" + ceremonyID + "/results")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errBody)
	}

	var rr resultsResponse
	json.NewDecoder(resp.Body).Decode(&rr)

	if rr.CeremonyID != ceremonyID {
		t.Errorf("ceremony_id: got %s, want %s", rr.CeremonyID, ceremonyID)
	}
	if rr.ElectionID != "test-election" {
		t.Errorf("election_id: got %s, want test-election", rr.ElectionID)
	}
	if rr.Phase != PhaseDecrypted {
		t.Errorf("phase: got %s, want %s", rr.Phase, PhaseDecrypted)
	}
	if rr.BallotCount != len(ts.ballots) {
		t.Errorf("ballot_count: got %d, want %d", rr.BallotCount, len(ts.ballots))
	}
	if len(rr.Results) != ts.numParties {
		t.Fatalf("expected %d results, got %d", ts.numParties, len(rr.Results))
	}
	for i, want := range ts.expected {
		if rr.Results[i] != want {
			t.Errorf("party %d: expected %d votes, got %d", i, want, rr.Results[i])
		}
	}
}

func TestFinalize(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	handler, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	handler.mu.Lock()
	tallyResult := handler.ceremony.TallyResult()
	handler.mu.Unlock()

	// Submit 5 partials.
	for tidx := 1; tidx <= 5; tidx++ {
		participant := ts.dkg.Participants[tidx-1]
		partials := make([]partialDecryptionElement, ts.numParties)
		for j, encSum := range tallyResult.EncryptedSums {
			pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
			partials[j] = partialDecryptionElement{
				PartyIndex: j,
				Point:      hex.EncodeToString(pd.D.Bytes()),
			}
		}

		body, _ := json.Marshal(partialDecryptionRequest{
			TrusteeIndex: tidx,
			Partials:     partials,
		})

		resp, err := http.Post(
			srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	// Finalize.
	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/finalize",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errBody)
	}

	var fr finalizeResponse
	json.NewDecoder(resp.Body).Decode(&fr)
	if fr.Status != "finalized" {
		t.Errorf("expected status finalized, got %s", fr.Status)
	}

	// Verify the ceremony is now in finalized phase.
	handler.mu.Lock()
	phase := handler.ceremony.Phase
	handler.mu.Unlock()

	if phase != PhaseFinalized {
		t.Errorf("expected phase %s, got %s", PhaseFinalized, phase)
	}

	// Results should still be available after finalization.
	resultsResp, err := http.Get(srv.URL + "/api/v1/ceremony/" + ceremonyID + "/results")
	if err != nil {
		t.Fatal(err)
	}
	defer resultsResp.Body.Close()

	if resultsResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for results after finalize, got %d", resultsResp.StatusCode)
	}

	// Finalize again — should fail with wrong_phase since already finalized.
	resp2, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/finalize",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("double finalize: expected 409, got %d", resp2.StatusCode)
	}
}

// newHandlerWithMockBBAndStateDir creates a CeremonyHandler wired to a mock BB
// using a caller-supplied stateDir, enabling crash-recovery tests.
func newHandlerWithMockBBAndStateDir(t *testing.T, bbServer *httptest.Server, trusteeKeys *TrusteeKeySet, stateDir string) (*CeremonyHandler, *http.ServeMux) {
	t.Helper()

	bbClient := NewBBClient(bbServer.URL, nil)

	handler, err := NewCeremonyHandler(bbClient, trusteeKeys, "test-election", stateDir)
	if err != nil {
		t.Fatalf("NewCeremonyHandler: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return handler, mux
}

// submitPartials is a test helper that submits partial decryptions for the
// given trustee indices and returns the number successfully accepted.
func submitPartials(t *testing.T, srv *httptest.Server, ceremonyID string, ts *testSetup, tallyResult *ceremony.TallyResult, trusteeIndices []int) {
	t.Helper()
	for _, tidx := range trusteeIndices {
		participant := ts.dkg.Participants[tidx-1]
		partials := make([]partialDecryptionElement, ts.numParties)
		for j, encSum := range tallyResult.EncryptedSums {
			pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
			partials[j] = partialDecryptionElement{
				PartyIndex: j,
				Point:      hex.EncodeToString(pd.D.Bytes()),
			}
		}

		body, _ := json.Marshal(partialDecryptionRequest{
			TrusteeIndex: tidx,
			Partials:     partials,
		})

		resp, err := http.Post(
			srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("trustee %d request: %v", tidx, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("trustee %d: expected 200, got %d", tidx, resp.StatusCode)
		}
	}
}

// --- State persistence and crash recovery ---

func TestCrashRecoveryAtAwaitingTrustees(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	// Use a shared stateDir so a second handler can recover from it.
	stateDir := t.TempDir()

	handler1, mux1 := newHandlerWithMockBBAndStateDir(t, bb, ts.trusteeKeys, stateDir)
	srv1 := httptest.NewServer(mux1)
	defer srv1.Close()

	ceremonyID := startCeremony(t, srv1)
	pollUntilPhase(t, srv1, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Capture metadata from the original ceremony.
	handler1.mu.Lock()
	origBallotCount := handler1.ceremony.BallotCount
	origPartyCount := handler1.ceremony.PartyCount
	origActiveSet := handler1.ceremony.ActiveSet
	handler1.mu.Unlock()

	// Simulate crash: close the server, create a NEW handler from the same stateDir.
	srv1.Close()

	handler2, _ := newHandlerWithMockBBAndStateDir(t, bb, ts.trusteeKeys, stateDir)

	// The recovered handler should have the ceremony state.
	handler2.mu.Lock()
	cs := handler2.ceremony
	handler2.mu.Unlock()

	if cs == nil {
		t.Fatal("expected ceremony to be recovered, got nil")
	}
	if cs.ID != ceremonyID {
		t.Errorf("recovered ceremony ID: got %s, want %s", cs.ID, ceremonyID)
	}
	if cs.Phase != PhaseAwaitingTrustees {
		t.Errorf("recovered phase: got %s, want %s", cs.Phase, PhaseAwaitingTrustees)
	}
	if cs.BallotCount != origBallotCount {
		t.Errorf("recovered ballot count: got %d, want %d", cs.BallotCount, origBallotCount)
	}
	if cs.PartyCount != origPartyCount {
		t.Errorf("recovered party count: got %d, want %d", cs.PartyCount, origPartyCount)
	}
	if len(cs.ActiveSet) != len(origActiveSet) {
		t.Errorf("recovered active set length: got %d, want %d", len(cs.ActiveSet), len(origActiveSet))
	}
	if cs.ElectionID != "test-election" {
		t.Errorf("recovered election ID: got %s, want test-election", cs.ElectionID)
	}
}

func TestCrashRecoveryPreservesPartials(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	stateDir := t.TempDir()

	handler1, mux1 := newHandlerWithMockBBAndStateDir(t, bb, ts.trusteeKeys, stateDir)
	srv1 := httptest.NewServer(mux1)
	defer srv1.Close()

	ceremonyID := startCeremony(t, srv1)
	pollUntilPhase(t, srv1, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	handler1.mu.Lock()
	tallyResult := handler1.ceremony.TallyResult()
	handler1.mu.Unlock()

	// Submit 2 partial decryptions (below threshold of 5).
	submitPartials(t, srv1, ceremonyID, ts, tallyResult, []int{1, 2})

	// Verify partials are stored before crash.
	handler1.mu.Lock()
	partialCountBefore := len(handler1.ceremony.Partials)
	trusteeOrderBefore := make([]int, len(handler1.ceremony.TrusteeOrder))
	copy(trusteeOrderBefore, handler1.ceremony.TrusteeOrder)
	handler1.mu.Unlock()

	if partialCountBefore != 2 {
		t.Fatalf("expected 2 partials before crash, got %d", partialCountBefore)
	}

	// Simulate crash: close the server, create a NEW handler from the same stateDir.
	srv1.Close()

	handler2, _ := newHandlerWithMockBBAndStateDir(t, bb, ts.trusteeKeys, stateDir)

	handler2.mu.Lock()
	cs := handler2.ceremony
	handler2.mu.Unlock()

	if cs == nil {
		t.Fatal("expected ceremony to be recovered, got nil")
	}

	// Verify the partials survived the crash.
	if len(cs.Partials) != partialCountBefore {
		t.Errorf("recovered partial count: got %d, want %d", len(cs.Partials), partialCountBefore)
	}

	// Check the trustee order is preserved.
	if len(cs.TrusteeOrder) != len(trusteeOrderBefore) {
		t.Errorf("recovered trustee order length: got %d, want %d", len(cs.TrusteeOrder), len(trusteeOrderBefore))
	}
	for i, want := range trusteeOrderBefore {
		if i < len(cs.TrusteeOrder) && cs.TrusteeOrder[i] != want {
			t.Errorf("trustee order[%d]: got %d, want %d", i, cs.TrusteeOrder[i], want)
		}
	}

	// Verify the partial decryption points are actual non-nil edwards points.
	for _, tidx := range trusteeOrderBefore {
		pds, ok := cs.Partials[tidx]
		if !ok {
			t.Errorf("recovered partials missing trustee %d", tidx)
			continue
		}
		if len(pds) != ts.numParties {
			t.Errorf("trustee %d: expected %d partial points, got %d", tidx, ts.numParties, len(pds))
		}
		for j, pd := range pds {
			if pd == nil || pd.D == nil {
				t.Errorf("trustee %d, party %d: partial decryption point is nil", tidx, j)
			}
		}
	}
}

// --- Error scenarios ---

func TestPartialDecryptionInvalidTrusteeIndex(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Trustee index 999 does not exist in the key set (we have 1..9).
	body, _ := json.Marshal(partialDecryptionRequest{
		TrusteeIndex: 999,
		Partials: []partialDecryptionElement{
			{PartyIndex: 0, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
			{PartyIndex: 1, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
			{PartyIndex: 2, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
		},
	})

	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "unknown_trustee" {
		t.Errorf("expected code unknown_trustee, got %v", errObj["code"])
	}
}

func TestPartialDecryptionWrongPartyCount(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Submit only 1 partial when 3 parties are expected.
	body, _ := json.Marshal(partialDecryptionRequest{
		TrusteeIndex: 1,
		Partials: []partialDecryptionElement{
			{PartyIndex: 0, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
		},
	})

	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "wrong_party_count" {
		t.Errorf("expected code wrong_party_count, got %v", errObj["code"])
	}
}

func TestPartialDecryptionNonexistentCeremony(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Don't start any ceremony — just try to submit a partial.
	body, _ := json.Marshal(partialDecryptionRequest{
		TrusteeIndex: 1,
		Partials: []partialDecryptionElement{
			{PartyIndex: 0, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
		},
	})

	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/nonexistent-ceremony/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "not_found" {
		t.Errorf("expected code not_found, got %v", errObj["code"])
	}
}

func TestStatusNonexistentCeremony(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/ceremony/nonexistent-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "not_found" {
		t.Errorf("expected code not_found, got %v", errObj["code"])
	}
}

// --- Phase enforcement ---

func TestPartialDecryptionBeforeCeremonyReachesAwaitingTrustees(t *testing.T) {
	ts := newTestSetup(t)

	// Use a BB that is slow to respond (simulating a long ballot fetch),
	// so the ceremony stays in fetching/tallying phase when we submit.
	slowBB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/board/root":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"root_sha256": "abc123",
					"sealed":      true,
					"count":       len(ts.ballots),
				},
			})
		case "/api/v1/board":
			// Delay the ballot response so the ceremony stays in fetching phase.
			time.Sleep(2 * time.Second)
			json.NewEncoder(w).Encode(map[string]any{
				"data": ts.ballots,
				"meta": map[string]any{
					"cursor": "",
					"total":  len(ts.ballots),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer slowBB.Close()

	_, mux := newHandlerWithMockBB(t, slowBB, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)

	// Immediately try to submit a partial (ceremony should be in fetching phase).
	body, _ := json.Marshal(partialDecryptionRequest{
		TrusteeIndex: 1,
		Partials: []partialDecryptionElement{
			{PartyIndex: 0, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
			{PartyIndex: 1, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
			{PartyIndex: 2, Point: hex.EncodeToString(edwards25519.NewIdentityPoint().Bytes())},
		},
	})

	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "wrong_phase" {
		t.Errorf("expected code wrong_phase, got %v", errObj["code"])
	}
}

func TestFinalizeBeforeDecryption(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	// Try to finalize while still in awaiting_trustees phase.
	resp, err := http.Post(
		srv.URL+"/api/v1/ceremony/"+ceremonyID+"/finalize",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "wrong_phase" {
		t.Errorf("expected code wrong_phase, got %v", errObj["code"])
	}
	if !strings.Contains(errObj["message"].(string), PhaseAwaitingTrustees) {
		t.Errorf("expected message to mention %s, got %v", PhaseAwaitingTrustees, errObj["message"])
	}
}

func TestStartCeremonyEmptyActiveSet(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	_, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(startRequest{
		ActiveSet: []string{},
	})

	resp, err := http.Post(srv.URL+"/api/v1/ceremony/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	json.NewDecoder(resp.Body).Decode(&errBody)
	errObj, ok := errBody["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errBody)
	}
	if errObj["code"] != "empty_active_set" {
		t.Errorf("expected code empty_active_set, got %v", errObj["code"])
	}
}

// --- Concurrent operations ---

func TestConcurrentPartialDecryptions(t *testing.T) {
	ts := newTestSetup(t)
	bb := mockBB(t, true, ts.ballots)
	defer bb.Close()

	handler, mux := newHandlerWithMockBB(t, bb, ts.trusteeKeys)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ceremonyID := startCeremony(t, srv)
	pollUntilPhase(t, srv, ceremonyID, PhaseAwaitingTrustees, 10*time.Second)

	handler.mu.Lock()
	tallyResult := handler.ceremony.TallyResult()
	handler.mu.Unlock()

	if tallyResult == nil {
		t.Fatal("tally result is nil after awaiting_trustees")
	}

	// Submit partials from 5 trustees concurrently.
	var wg sync.WaitGroup
	errs := make([]error, 5)
	statuses := make([]int, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tidx := idx + 1
			participant := ts.dkg.Participants[tidx-1]

			partials := make([]partialDecryptionElement, ts.numParties)
			for j, encSum := range tallyResult.EncryptedSums {
				pd := threshold.PartialDecrypt(participant.CombinedShare, encSum)
				partials[j] = partialDecryptionElement{
					PartyIndex: j,
					Point:      hex.EncodeToString(pd.D.Bytes()),
				}
			}

			body, _ := json.Marshal(partialDecryptionRequest{
				TrusteeIndex: tidx,
				Partials:     partials,
			})

			resp, err := http.Post(
				srv.URL+"/api/v1/ceremony/"+ceremonyID+"/partial-decryption",
				"application/json",
				bytes.NewReader(body),
			)
			if err != nil {
				errs[idx] = err
				return
			}
			defer resp.Body.Close()
			statuses[idx] = resp.StatusCode
		}(i)
	}

	wg.Wait()

	// All requests should succeed without errors.
	for i, err := range errs {
		if err != nil {
			t.Errorf("trustee %d: request error: %v", i+1, err)
		}
	}
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Errorf("trustee %d: expected 200, got %d", i+1, status)
		}
	}

	// After all 5 concurrent submissions, auto-decryption should have triggered.
	handler.mu.Lock()
	phase := handler.ceremony.Phase
	results := handler.ceremony.Results
	partialCount := len(handler.ceremony.Partials)
	handler.mu.Unlock()

	if partialCount != 5 {
		t.Errorf("expected 5 partials stored, got %d", partialCount)
	}
	if phase != PhaseDecrypted {
		t.Fatalf("expected phase %s, got %s", PhaseDecrypted, phase)
	}
	if len(results) != ts.numParties {
		t.Fatalf("expected %d results, got %d", ts.numParties, len(results))
	}
	for i, want := range ts.expected {
		if results[i] != want {
			t.Errorf("party %d: expected %d votes, got %d", i, want, results[i])
		}
	}
}
