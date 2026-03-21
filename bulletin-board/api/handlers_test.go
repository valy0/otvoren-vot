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
	t.Helper()
	ctx := context.Background()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"
	}

	s, err := store.New(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	s.RunMigrations(ctx)
	s.Pool().Exec(ctx, "DELETE FROM signed_roots")
	s.Pool().Exec(ctx, "DELETE FROM ballots")
	t.Cleanup(func() { s.Close() })

	b, err := board.New(ctx, s)
	if err != nil {
		t.Fatalf("create board: %v", err)
	}

	router := NewRouter(b, testAPIKey)
	server := httptest.NewServer(router)
	t.Cleanup(func() { server.Close() })

	return server, b
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
