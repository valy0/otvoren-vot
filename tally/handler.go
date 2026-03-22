package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/tally/ceremony"
)

// decryptionThreshold is the number of partial decryptions required
// to reconstruct the election result. This corresponds to the t
// parameter from the DKG ceremony.
const decryptionThreshold = 5

// maxStartBodyBytes limits the request body on the /start endpoint
// to prevent memory exhaustion from a large active_set payload.
const maxStartBodyBytes = 256 * 1024 * 1024 // 256 MiB

// CeremonyHandler implements the five ceremony HTTP endpoints.
type CeremonyHandler struct {
	bbClient    *BBClient
	trusteeKeys *TrusteeKeySet
	electionID  string
	stateDir    string

	mu       sync.Mutex
	ceremony *CeremonyState
}

// NewCeremonyHandler creates a handler. If a crash journal exists in stateDir,
// it is recovered (the in-memory tallies are NOT restored; only the metadata).
func NewCeremonyHandler(bbClient *BBClient, trusteeKeys *TrusteeKeySet, electionID, stateDir string) (*CeremonyHandler, error) {
	h := &CeremonyHandler{
		bbClient:    bbClient,
		trusteeKeys: trusteeKeys,
		electionID:  electionID,
		stateDir:    stateDir,
	}

	cs, err := LoadCeremonyState(stateDir)
	if err != nil {
		return nil, fmt.Errorf("recover ceremony state: %w", err)
	}
	if cs != nil {
		h.ceremony = cs
		slog.Info("recovered ceremony from journal",
			"id", cs.ID, "phase", cs.Phase)
	}

	return h, nil
}

// RegisterRoutes wires the ceremony endpoints onto the given mux.
func (h *CeremonyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/ceremony/start", h.handleStart)
	mux.HandleFunc("GET /api/v1/ceremony/{id}", h.handleStatus)
	mux.HandleFunc("POST /api/v1/ceremony/{id}/partial-decryption", h.handlePartialDecryption)
	mux.HandleFunc("GET /api/v1/ceremony/{id}/results", h.handleResults)
	mux.HandleFunc("POST /api/v1/ceremony/{id}/finalize", h.handleFinalize)
}

// --- request / response types ---

type startRequest struct {
	ActiveSet          []string `json:"active_set"`
	ActiveSetSignature string   `json:"active_set_signature"`
}

type startResponse struct {
	CeremonyID string `json:"ceremony_id"`
	Status     string `json:"status"`
}

type statusResponse struct {
	ID            string     `json:"id"`
	Phase         string     `json:"phase"`
	ElectionID    string     `json:"election_id"`
	BallotCount   int        `json:"ballot_count"`
	PartyCount    int        `json:"party_count"`
	TrusteeCount  int        `json:"trustee_count"`
	StartedAt     time.Time  `json:"started_at"`
	DecryptedAt   *time.Time `json:"decrypted_at,omitempty"`
	Results       []int      `json:"results,omitempty"`
}

type partialDecryptionRequest struct {
	TrusteeIndex int                        `json:"trustee_index"`
	Partials     []partialDecryptionElement `json:"partials"`
}

type partialDecryptionElement struct {
	PartyIndex int    `json:"party_index"`
	Point      string `json:"point"` // 64 hex chars = 32 bytes
}

type partialDecryptionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type resultsResponse struct {
	CeremonyID  string `json:"ceremony_id"`
	ElectionID  string `json:"election_id"`
	Phase       string `json:"phase"`
	BallotCount int    `json:"ballot_count"`
	Results     []int  `json:"results"`
}

type finalizeResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// --- handlers ---

func (h *CeremonyHandler) handleStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxStartBodyBytes)

	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "failed to parse request body")
		return
	}

	if len(req.ActiveSet) == 0 {
		writeError(w, http.StatusBadRequest, "empty_active_set", "active_set must not be empty")
		return
	}

	// TODO: verify active_set_signature

	h.mu.Lock()

	// Guard double-start: reject if a ceremony is already in progress
	// (any phase except error or finalized).
	if h.ceremony != nil {
		phase := h.ceremony.Phase
		if phase != PhaseError && phase != PhaseFinalized {
			h.mu.Unlock()
			writeError(w, http.StatusConflict, "ceremony_in_progress",
				fmt.Sprintf("ceremony %s is already in phase %s", h.ceremony.ID, phase))
			return
		}
	}

	// Check BB is sealed before starting.
	sealed, err := h.bbClient.IsSealed(r.Context())
	if err != nil {
		h.mu.Unlock()
		writeError(w, http.StatusBadGateway, "bb_unavailable",
			fmt.Sprintf("could not reach bulletin board: %v", err))
		return
	}
	if !sealed {
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "board_not_sealed",
			"bulletin board must be sealed before starting a ceremony")
		return
	}

	ceremonyID := fmt.Sprintf("ceremony-%d", time.Now().UnixNano())
	cs, err := NewCeremonyState(h.stateDir, ceremonyID, h.electionID)
	if err != nil {
		h.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "state_error",
			fmt.Sprintf("create ceremony state: %v", err))
		return
	}
	cs.ActiveSet = req.ActiveSet
	if err := cs.Save(); err != nil {
		h.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "state_error",
			fmt.Sprintf("save ceremony state: %v", err))
		return
	}

	h.ceremony = cs
	h.mu.Unlock()

	// Return 202 immediately; do the heavy work in the background.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(startResponse{
		CeremonyID: ceremonyID,
		Status:     PhaseFetching,
	})

	// Launch background goroutine. Use context.WithoutCancel so that the
	// work continues even if the HTTP client disconnects.
	bgCtx := context.WithoutCancel(r.Context())
	go h.runTally(bgCtx, cs)
}

// runTally fetches ballots from the BB, computes the homomorphic tally, and
// transitions the ceremony to awaiting_trustees.
func (h *CeremonyHandler) runTally(ctx context.Context, cs *CeremonyState) {
	slog.Info("fetching ballots", "ceremony", cs.ID)

	ballots, err := h.bbClient.FetchAllBallots(ctx)
	if err != nil {
		slog.Error("fetch ballots failed", "ceremony", cs.ID, "err", err)
		h.mu.Lock()
		_ = cs.SetPhase(PhaseError)
		h.mu.Unlock()
		return
	}

	if len(ballots) == 0 {
		slog.Error("no ballots on board", "ceremony", cs.ID)
		h.mu.Lock()
		_ = cs.SetPhase(PhaseError)
		h.mu.Unlock()
		return
	}

	h.mu.Lock()
	cs.BallotCount = len(ballots)
	cs.Phase = PhaseTallying
	if err := cs.Save(); err != nil {
		slog.Error("save state (tallying)", "ceremony", cs.ID, "err", err)
	}
	h.mu.Unlock()

	slog.Info("computing tally", "ceremony", cs.ID, "ballots", len(ballots))
	tallyResult, err := ceremony.ComputeTally(ballots)
	if err != nil {
		slog.Error("compute tally failed", "ceremony", cs.ID, "err", err)
		h.mu.Lock()
		_ = cs.SetPhase(PhaseError)
		h.mu.Unlock()
		return
	}

	h.mu.Lock()
	cs.SetTallyResult(tallyResult)
	cs.SetEncryptedSums(tallyResult.EncryptedSums)
	cs.PartyCount = tallyResult.NumParties
	cs.Partials = make(map[int][]*ceremony.PartialDecryptionData)
	cs.TrusteeOrder = nil
	if err := cs.SetPhase(PhaseAwaitingTrustees); err != nil {
		slog.Error("save state (awaiting_trustees)", "ceremony", cs.ID, "err", err)
	}
	h.mu.Unlock()

	slog.Info("tally complete, awaiting trustees",
		"ceremony", cs.ID, "parties", tallyResult.NumParties)
}

func (h *CeremonyHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.Lock()
	cs := h.ceremony
	h.mu.Unlock()

	if cs == nil || cs.ID != id {
		writeError(w, http.StatusNotFound, "not_found", "ceremony not found")
		return
	}

	h.mu.Lock()
	resp := statusResponse{
		ID:           cs.ID,
		Phase:        cs.Phase,
		ElectionID:   cs.ElectionID,
		BallotCount:  cs.BallotCount,
		PartyCount:   cs.PartyCount,
		TrusteeCount: len(cs.Partials),
		StartedAt:    cs.StartedAt,
		DecryptedAt:  cs.DecryptedAt,
		Results:      cs.Results,
	}
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *CeremonyHandler) handlePartialDecryption(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB

	var req partialDecryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "failed to parse request body")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	cs := h.ceremony
	if cs == nil || cs.ID != id {
		writeError(w, http.StatusNotFound, "not_found", "ceremony not found")
		return
	}

	if cs.Phase != PhaseAwaitingTrustees {
		writeError(w, http.StatusConflict, "wrong_phase",
			fmt.Sprintf("ceremony is in phase %s, expected %s", cs.Phase, PhaseAwaitingTrustees))
		return
	}

	// Validate trustee index exists in the key set.
	if _, ok := h.trusteeKeys.Keys[req.TrusteeIndex]; !ok {
		writeError(w, http.StatusBadRequest, "unknown_trustee",
			fmt.Sprintf("trustee index %d not found in key set", req.TrusteeIndex))
		return
	}

	// Idempotent: if this trustee already submitted, return previous result.
	if _, already := cs.Partials[req.TrusteeIndex]; already {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(partialDecryptionResponse{
			Status:  "already_submitted",
			Message: fmt.Sprintf("trustee %d has already submitted partial decryptions", req.TrusteeIndex),
		})
		return
	}

	// Validate the number of partials matches the party count.
	if len(req.Partials) != cs.PartyCount {
		writeError(w, http.StatusBadRequest, "wrong_party_count",
			fmt.Sprintf("expected %d partials, got %d", cs.PartyCount, len(req.Partials)))
		return
	}

	// Deserialize and validate each partial decryption point.
	pds := make([]*ceremony.PartialDecryptionData, cs.PartyCount)
	for _, p := range req.Partials {
		if p.PartyIndex < 0 || p.PartyIndex >= cs.PartyCount {
			writeError(w, http.StatusBadRequest, "invalid_party_index",
				fmt.Sprintf("party_index %d out of range [0, %d)", p.PartyIndex, cs.PartyCount))
			return
		}
		if pds[p.PartyIndex] != nil {
			writeError(w, http.StatusBadRequest, "duplicate_party_index",
				fmt.Sprintf("duplicate partial for party_index %d", p.PartyIndex))
			return
		}

		pointBytes, err := hex.DecodeString(p.Point)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_hex",
				fmt.Sprintf("party %d: invalid hex: %v", p.PartyIndex, err))
			return
		}
		if len(pointBytes) != 32 {
			writeError(w, http.StatusBadRequest, "invalid_point_length",
				fmt.Sprintf("party %d: expected 32 bytes, got %d", p.PartyIndex, len(pointBytes)))
			return
		}

		pt, err := new(edwards25519.Point).SetBytes(pointBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_point",
				fmt.Sprintf("party %d: invalid ristretto255 point: %v", p.PartyIndex, err))
			return
		}

		pds[p.PartyIndex] = &ceremony.PartialDecryptionData{D: pt}
	}

	// TODO: verify Chaum-Pedersen proof for each partial against trustee key

	cs.Partials[req.TrusteeIndex] = pds
	cs.TrusteeOrder = append(cs.TrusteeOrder, req.TrusteeIndex)
	if err := cs.Save(); err != nil {
		slog.Error("save partial decryption", "ceremony", cs.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "state_error", "failed to persist partial decryption")
		return
	}

	slog.Info("partial decryption accepted",
		"ceremony", cs.ID, "trustee", req.TrusteeIndex,
		"total", len(cs.Partials), "threshold", decryptionThreshold)

	// Auto-decrypt if we've reached the threshold.
	if len(cs.Partials) >= decryptionThreshold {
		if err := h.decryptLocked(cs); err != nil {
			slog.Error("auto-decrypt failed", "ceremony", cs.ID, "err", err)
			writeError(w, http.StatusInternalServerError, "decrypt_error",
				fmt.Sprintf("decryption failed: %v", err))
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(partialDecryptionResponse{
		Status:  "accepted",
		Message: fmt.Sprintf("trustee %d partial decryption recorded (%d/%d)", req.TrusteeIndex, len(cs.Partials), decryptionThreshold),
	})
}

// decryptLocked performs threshold decryption. Caller must hold h.mu.
func (h *CeremonyHandler) decryptLocked(cs *CeremonyState) error {
	if cs.TallyResult() == nil {
		return fmt.Errorf("tally result not available in memory")
	}

	// Reshape partials from CeremonyState format to DecryptTally format.
	//
	// CeremonyState.Partials:  map[trusteeIndex] -> []*PartialDecryptionData (per party)
	// DecryptTally wants:      []map[partyIndex]*PartialDecryptionData (indexed by position)
	//
	// trusteeIndices[i] = trustee index of the i-th contributor.
	trusteeIndices := cs.TrusteeOrder[:decryptionThreshold]
	partials := make([]map[int]*ceremony.PartialDecryptionData, decryptionThreshold)

	for i, tidx := range trusteeIndices {
		pds := cs.Partials[tidx]
		m := make(map[int]*ceremony.PartialDecryptionData, len(pds))
		for j, pd := range pds {
			m[j] = pd
		}
		partials[i] = m
	}

	results, err := ceremony.DecryptTally(cs.TallyResult(), partials, trusteeIndices)
	if err != nil {
		return fmt.Errorf("decrypt tally: %w", err)
	}

	now := time.Now()
	cs.Results = results
	cs.DecryptedAt = &now
	if err := cs.SetPhase(PhaseDecrypted); err != nil {
		return fmt.Errorf("persist decrypted phase: %w", err)
	}

	slog.Info("tally decrypted", "ceremony", cs.ID, "results", results)
	return nil
}

func (h *CeremonyHandler) handleResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.Lock()
	cs := h.ceremony
	h.mu.Unlock()

	if cs == nil || cs.ID != id {
		writeError(w, http.StatusNotFound, "not_found", "ceremony not found")
		return
	}

	h.mu.Lock()
	phase := cs.Phase
	results := cs.Results
	h.mu.Unlock()

	if phase != PhaseDecrypted && phase != PhaseFinalized {
		writeError(w, http.StatusConflict, "not_decrypted",
			fmt.Sprintf("results not yet available, ceremony is in phase %s", phase))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resultsResponse{
		CeremonyID:  cs.ID,
		ElectionID:  cs.ElectionID,
		Phase:       phase,
		BallotCount: cs.BallotCount,
		Results:     results,
	})
}

func (h *CeremonyHandler) handleFinalize(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.Lock()
	defer h.mu.Unlock()

	cs := h.ceremony
	if cs == nil || cs.ID != id {
		writeError(w, http.StatusNotFound, "not_found", "ceremony not found")
		return
	}

	if cs.Phase != PhaseDecrypted {
		writeError(w, http.StatusConflict, "wrong_phase",
			fmt.Sprintf("ceremony is in phase %s, expected %s", cs.Phase, PhaseDecrypted))
		return
	}

	// TODO: publish results to bulletin board

	if err := cs.SetPhase(PhaseFinalized); err != nil {
		writeError(w, http.StatusInternalServerError, "state_error",
			fmt.Sprintf("persist finalized phase: %v", err))
		return
	}

	slog.Info("ceremony finalized", "ceremony", cs.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalizeResponse{
		Status:  "finalized",
		Message: fmt.Sprintf("ceremony %s results finalized", cs.ID),
	})
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
