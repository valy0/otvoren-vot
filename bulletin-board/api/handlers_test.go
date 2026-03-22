package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/valy0/otvoren-vot/bulletin-board/board"
	"github.com/valy0/otvoren-vot/bulletin-board/store"
)

const testAPIKey = "test-key"

func setupTestServer(t *testing.T) (*httptest.Server, *board.Board) {
	return setupTestServerWithOrigins(t, []string{"*"})
}

func setupTestServerWithOrigins(t *testing.T, allowedOrigins []string) (*httptest.Server, *board.Board) {
	t.Helper()
	ctx := context.Background()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"
	}

	s, err := store.New(ctx, dbURL, 25, 5)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	s.RunMigrations(ctx)
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE ballots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "DELETE FROM signed_roots")
	s.Pool().Exec(ctx, "DELETE FROM ballots")
	s.Pool().Exec(ctx, "DELETE FROM board_state")
	s.Pool().Exec(ctx, "ALTER TABLE ballots ENABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots ENABLE TRIGGER ALL")
	t.Cleanup(func() { s.Close() })

	b, err := board.New(ctx, s)
	if err != nil {
		t.Fatalf("create board: %v", err)
	}

	router := NewRouter(b, testAPIKey, allowedOrigins, "test-election")
	server := httptest.NewServer(router)
	t.Cleanup(func() { server.Close() })

	return server, b
}

// submitBallot is a test helper that submits a ballot via the internal API.
func submitBallot(t *testing.T, serverURL, ballotID string) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"ballot_id":        ballotID,
		"encrypted_ballot": map[string]interface{}{"v": []int{1, 0}},
		"zk_proofs":        map[string]interface{}{"p": []string{}},
	})
	req, _ := http.NewRequest("POST", serverURL+"/internal/v1/ballots", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit ballot %s: %v", ballotID, err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("submit ballot %s: expected 201, got %d", ballotID, resp.StatusCode)
	}
}

func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSubmitAndRetrieveBallot(t *testing.T) {
	server, _ := setupTestServer(t)

	// Submit
	body := `{"ballot_id":"test-1","encrypted_ballot":{"v":[1,0]},"zk_proofs":{"p":[]}}`
	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("submit: expected 201, got %d", resp.StatusCode)
	}

	// Retrieve
	resp, err = http.Get(server.URL + "/api/v1/board/test-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("get: expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Data == nil {
		t.Fatal("data should not be nil")
	}
}

func TestSubmitWithoutAPIKey(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"ballot_id":"x","encrypted_ballot":{},"zk_proofs":{}}`
	resp, _ := http.Post(server.URL+"/internal/v1/ballots", "application/json", bytes.NewBufferString(body))
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGetNonexistentBallot(t *testing.T) {
	server, _ := setupTestServer(t)
	resp, _ := http.Get(server.URL + "/api/v1/board/nonexistent")
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetRoot(t *testing.T) {
	server, _ := setupTestServer(t)
	resp, _ := http.Get(server.URL + "/api/v1/board/root")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestListBallots(t *testing.T) {
	server, _ := setupTestServer(t)

	// Submit 3 ballots
	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(map[string]interface{}{
			"ballot_id":        fmt.Sprintf("list-%d", i),
			"encrypted_ballot": map[string]int{"v": i},
			"zk_proofs":        map[string]string{},
		})
		req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Key", testAPIKey)
		http.DefaultClient.Do(req)
	}

	resp, _ := http.Get(server.URL + "/api/v1/board?limit=2")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/board — handleListBallots
// ---------------------------------------------------------------------------

func TestListBallots_EmptyBoard(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/board")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	// Data should be nil/null for an empty list (Go nil slice marshals to null)
	if result.Meta == nil {
		t.Fatal("meta should not be nil")
	}
	if result.Meta.Total != 0 {
		t.Fatalf("expected total 0, got %d", result.Meta.Total)
	}
	if result.Meta.Cursor != "" {
		t.Fatalf("expected empty cursor, got %q", result.Meta.Cursor)
	}
}

func TestListBallots_Pagination(t *testing.T) {
	server, _ := setupTestServer(t)

	// Submit 5 ballots
	for i := 0; i < 5; i++ {
		submitBallot(t, server.URL, fmt.Sprintf("page-%d", i))
	}

	// Request with limit=2
	resp, err := http.Get(server.URL + "/api/v1/board?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	// Should return exactly 2 ballots
	data, ok := result.Data.([]interface{})
	if !ok {
		t.Fatalf("data should be an array, got %T", result.Data)
	}
	if len(data) != 2 {
		t.Fatalf("expected 2 ballots, got %d", len(data))
	}

	// Total should reflect all 5 ballots
	if result.Meta.Total != 5 {
		t.Fatalf("expected total 5, got %d", result.Meta.Total)
	}

	// Cursor should be set (there are more results)
	if result.Meta.Cursor == "" {
		t.Fatal("expected non-empty cursor for paginated result")
	}
}

func TestListBallots_CursorPagination(t *testing.T) {
	server, _ := setupTestServer(t)

	// Submit 5 ballots
	for i := 0; i < 5; i++ {
		submitBallot(t, server.URL, fmt.Sprintf("cursor-%d", i))
	}

	// First page: limit=2
	resp, err := http.Get(server.URL + "/api/v1/board?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	var page1 Response
	json.NewDecoder(resp.Body).Decode(&page1)
	if page1.Meta.Cursor == "" {
		t.Fatal("expected cursor from page 1")
	}

	firstPageData := page1.Data.([]interface{})
	if len(firstPageData) != 2 {
		t.Fatalf("page 1: expected 2, got %d", len(firstPageData))
	}

	// Second page: use cursor from page 1
	resp, err = http.Get(server.URL + "/api/v1/board?limit=2&cursor=" + page1.Meta.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	var page2 Response
	json.NewDecoder(resp.Body).Decode(&page2)

	secondPageData := page2.Data.([]interface{})
	if len(secondPageData) != 2 {
		t.Fatalf("page 2: expected 2, got %d", len(secondPageData))
	}

	// Third page: use cursor from page 2
	resp, err = http.Get(server.URL + "/api/v1/board?limit=2&cursor=" + page2.Meta.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	var page3 Response
	json.NewDecoder(resp.Body).Decode(&page3)

	thirdPageData := page3.Data.([]interface{})
	if len(thirdPageData) != 1 {
		t.Fatalf("page 3: expected 1, got %d", len(thirdPageData))
	}

	// No more pages: cursor should be empty
	if page3.Meta.Cursor != "" {
		t.Fatalf("expected empty cursor on last page, got %q", page3.Meta.Cursor)
	}

	// Verify no overlap: collect ballot IDs from all pages
	allIDs := make(map[string]bool)
	for _, pages := range [][]interface{}{firstPageData, secondPageData, thirdPageData} {
		for _, item := range pages {
			m := item.(map[string]interface{})
			id := m["ballot_id"].(string)
			if allIDs[id] {
				t.Fatalf("duplicate ballot ID %q across pages", id)
			}
			allIDs[id] = true
		}
	}
	if len(allIDs) != 5 {
		t.Fatalf("expected 5 unique ballot IDs across pages, got %d", len(allIDs))
	}
}

func TestListBallots_InvalidLimit(t *testing.T) {
	server, _ := setupTestServer(t)

	// Submit 1 ballot so we have data
	submitBallot(t, server.URL, "limit-test")

	// Negative limit should be ignored (falls back to default 100)
	resp, err := http.Get(server.URL + "/api/v1/board?limit=-5")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for negative limit, got %d", resp.StatusCode)
	}

	// Zero limit should be ignored (falls back to default 100)
	resp, err = http.Get(server.URL + "/api/v1/board?limit=0")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for zero limit, got %d", resp.StatusCode)
	}

	// Non-numeric limit should be ignored
	resp, err = http.Get(server.URL + "/api/v1/board?limit=abc")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for non-numeric limit, got %d", resp.StatusCode)
	}

	// Over-max limit (>1000) should be ignored
	resp, err = http.Get(server.URL + "/api/v1/board?limit=5000")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for over-max limit, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/board/{ballot_id} — handleGetBallot
// ---------------------------------------------------------------------------

func TestGetBallot_WithMerkleProof(t *testing.T) {
	server, _ := setupTestServer(t)

	submitBallot(t, server.URL, "proof-ballot")

	resp, err := http.Get(server.URL + "/api/v1/board/proof-ballot")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data should be object, got %T", result.Data)
	}

	// Verify ballot_id is present
	if data["ballot_id"] != "proof-ballot" {
		t.Fatalf("expected ballot_id 'proof-ballot', got %v", data["ballot_id"])
	}

	// Verify merkle_proof field exists
	if _, exists := data["merkle_proof"]; !exists {
		t.Fatal("response should include merkle_proof field")
	}

	// Verify encrypted_ballot field exists
	if _, exists := data["encrypted_ballot"]; !exists {
		t.Fatal("response should include encrypted_ballot field")
	}

	// Verify zk_proofs field exists
	if _, exists := data["zk_proofs"]; !exists {
		t.Fatal("response should include zk_proofs field")
	}
}

func TestGetBallot_NotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/board/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error.Code != "ballot_not_found" {
		t.Fatalf("expected error code 'ballot_not_found', got %q", errResp.Error.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/board/root — handleGetRoot
// ---------------------------------------------------------------------------

func TestGetRoot_EmptyBoard(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/board/root")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data should be object, got %T", result.Data)
	}

	// Empty board should have empty root hash
	rootHash, _ := data["root_sha256"].(string)
	if rootHash != "" {
		t.Fatalf("expected empty root_sha256 for empty board, got %q", rootHash)
	}

	// Ballot count should be 0
	ballotCount, _ := data["ballot_count"].(float64)
	if ballotCount != 0 {
		t.Fatalf("expected ballot_count 0, got %v", ballotCount)
	}

	// Should not be sealed
	sealed, _ := data["sealed"].(bool)
	if sealed {
		t.Fatal("expected sealed=false for fresh board")
	}
}

func TestGetRoot_WithBallots(t *testing.T) {
	server, _ := setupTestServer(t)

	submitBallot(t, server.URL, "root-test-1")
	submitBallot(t, server.URL, "root-test-2")

	resp, err := http.Get(server.URL + "/api/v1/board/root")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	data := result.Data.(map[string]interface{})

	// Root hash should be a non-empty hex string
	rootHash, _ := data["root_sha256"].(string)
	if rootHash == "" {
		t.Fatal("expected non-empty root_sha256 after adding ballots")
	}
	if len(rootHash) != 64 {
		t.Fatalf("expected 64-char hex root hash, got %d chars: %q", len(rootHash), rootHash)
	}

	// Ballot count should be 2
	ballotCount, _ := data["ballot_count"].(float64)
	if ballotCount != 2 {
		t.Fatalf("expected ballot_count 2, got %v", ballotCount)
	}

	// Not sealed
	sealed, _ := data["sealed"].(bool)
	if sealed {
		t.Fatal("expected sealed=false")
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/election — handleGetElection
// ---------------------------------------------------------------------------

func TestGetElection(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/election")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Response
	json.NewDecoder(resp.Body).Decode(&result)

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data should be object, got %T", result.Data)
	}

	// election_id should match the one passed to NewRouter
	if data["election_id"] != "test-election" {
		t.Fatalf("expected election_id 'test-election', got %v", data["election_id"])
	}

	// public_key should be present and non-empty
	pk, _ := data["public_key"].(string)
	if pk == "" {
		t.Fatal("expected non-empty public_key")
	}

	// parties should be an array
	parties, ok := data["parties"].([]interface{})
	if !ok {
		t.Fatalf("parties should be an array, got %T", data["parties"])
	}
	if len(parties) == 0 {
		t.Fatal("expected at least one party")
	}

	// Each party should have name and candidates
	for i, p := range parties {
		party, ok := p.(map[string]interface{})
		if !ok {
			t.Fatalf("party %d should be an object, got %T", i, p)
		}
		name, _ := party["name"].(string)
		if name == "" {
			t.Fatalf("party %d: expected non-empty name", i)
		}
		candidates, ok := party["candidates"].([]interface{})
		if !ok {
			t.Fatalf("party %d: candidates should be an array, got %T", i, party["candidates"])
		}
		if len(candidates) == 0 {
			t.Fatalf("party %d: expected at least one candidate", i)
		}
	}
}

// ---------------------------------------------------------------------------
// CORS middleware — withCORS
// ---------------------------------------------------------------------------

func TestCORS_AllowedOrigin(t *testing.T) {
	server, _ := setupTestServerWithOrigins(t, []string{"https://vote.bg", "https://admin.vote.bg"})

	req, _ := http.NewRequest("GET", server.URL+"/api/v1/board/root", nil)
	req.Header.Set("Origin", "https://vote.bg")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "https://vote.bg" {
		t.Fatalf("expected ACAO 'https://vote.bg', got %q", acao)
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	server, _ := setupTestServerWithOrigins(t, []string{"https://vote.bg"})

	req, _ := http.NewRequest("GET", server.URL+"/api/v1/board/root", nil)
	req.Header.Set("Origin", "https://evil.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "" {
		t.Fatalf("expected no ACAO header for disallowed origin, got %q", acao)
	}
}

func TestCORS_VaryOriginHeader(t *testing.T) {
	server, _ := setupTestServerWithOrigins(t, []string{"https://vote.bg"})

	req, _ := http.NewRequest("GET", server.URL+"/api/v1/board/root", nil)
	req.Header.Set("Origin", "https://vote.bg")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	vary := resp.Header.Get("Vary")
	if vary != "Origin" {
		t.Fatalf("expected Vary: Origin, got %q", vary)
	}
}

func TestCORS_PreflightOptions(t *testing.T) {
	server, _ := setupTestServerWithOrigins(t, []string{"https://vote.bg"})

	req, _ := http.NewRequest("OPTIONS", server.URL+"/api/v1/board/root", nil)
	req.Header.Set("Origin", "https://vote.bg")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", resp.StatusCode)
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "https://vote.bg" {
		t.Fatalf("expected ACAO 'https://vote.bg' on preflight, got %q", acao)
	}

	methods := resp.Header.Get("Access-Control-Allow-Methods")
	if methods == "" {
		t.Fatal("expected Access-Control-Allow-Methods header on preflight")
	}
}

// ---------------------------------------------------------------------------
// POST /internal/v1/ballots — edge cases
// ---------------------------------------------------------------------------

func TestSubmit_WrongAPIKey(t *testing.T) {
	server, _ := setupTestServer(t)

	body := `{"ballot_id":"x","encrypted_ballot":{},"zk_proofs":{}}`
	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", "wrong-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for wrong API key, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error.Code != "unauthorized" {
		t.Fatalf("expected error code 'unauthorized', got %q", errResp.Error.Code)
	}
}

func TestSubmit_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer(t)

	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots",
		bytes.NewBufferString("this is not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error.Code != "invalid_body" {
		t.Fatalf("expected error code 'invalid_body', got %q", errResp.Error.Code)
	}
}

func TestSubmit_MissingBallotID(t *testing.T) {
	server, _ := setupTestServer(t)

	body := `{"encrypted_ballot":{"v":[1]},"zk_proofs":{"p":[]}}`
	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for missing ballot_id, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error.Code != "missing_ballot_id" {
		t.Fatalf("expected error code 'missing_ballot_id', got %q", errResp.Error.Code)
	}
}

func TestSubmit_EmptyBody(t *testing.T) {
	server, _ := setupTestServer(t)

	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots",
		bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for empty body, got %d", resp.StatusCode)
	}
}

func TestSubmit_DuplicateBallotID(t *testing.T) {
	server, _ := setupTestServer(t)

	submitBallot(t, server.URL, "dup-1")

	// Submit same ballot_id again
	body := `{"ballot_id":"dup-1","encrypted_ballot":{"v":[2]},"zk_proofs":{"p":[]}}`
	req, _ := http.NewRequest("POST", server.URL+"/internal/v1/ballots",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 for duplicate ballot, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error.Code != "duplicate_ballot" {
		t.Fatalf("expected error code 'duplicate_ballot', got %q", errResp.Error.Code)
	}
}
