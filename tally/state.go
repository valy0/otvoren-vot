package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"

	"github.com/valy0/otvoren-vot/tally/ceremony"
)

// Phase constants for the decryption ceremony lifecycle.
const (
	PhaseFetching         = "fetching"
	PhaseTallying         = "tallying"
	PhaseAwaitingTrustees = "awaiting_trustees"
	PhaseDecrypted        = "decrypted"
	PhaseFinalized        = "finalized"
	PhaseError            = "error"
)

const journalFileName = "ceremony_state.json"

// CeremonyState tracks the full lifecycle of a decryption ceremony.
// It persists to a JSON crash journal after each mutation so the service
// can recover from crashes.
type CeremonyState struct {
	ID          string   `json:"id"`
	Phase       string   `json:"phase"`
	ElectionID  string   `json:"election_id"`
	ActiveSet   []string `json:"active_set"`
	BallotCount int      `json:"ballot_count"`
	PartyCount  int      `json:"party_count"`

	DedupProof   *ceremony.DedupProof                       `json:"dedup_proof,omitempty"`
	Partials     map[int][]*ceremony.PartialDecryptionData   `json:"-"` // custom serialization
	TrusteeOrder []int                                      `json:"trustee_order,omitempty"`
	Results      []int                                      `json:"results,omitempty"`

	StartedAt   time.Time  `json:"started_at"`
	DecryptedAt *time.Time `json:"decrypted_at,omitempty"`

	// Not serialized; reconstructed on recovery.
	encryptedSums []*elgamal.Ciphertext
	tallyResult   *ceremony.TallyResult

	// stateDir is the directory where the journal is written.
	stateDir string
}

// SetEncryptedSums stores the encrypted sums (not persisted to journal).
func (cs *CeremonyState) SetEncryptedSums(sums []*elgamal.Ciphertext) {
	cs.encryptedSums = sums
}

// EncryptedSums returns the encrypted sums (not persisted to journal).
func (cs *CeremonyState) EncryptedSums() []*elgamal.Ciphertext {
	return cs.encryptedSums
}

// SetTallyResult stores the tally result (not persisted to journal).
func (cs *CeremonyState) SetTallyResult(tr *ceremony.TallyResult) {
	cs.tallyResult = tr
}

// TallyResult returns the tally result (not persisted to journal).
func (cs *CeremonyState) TallyResult() *ceremony.TallyResult {
	return cs.tallyResult
}

// --- Custom JSON serialization for Partials ---

// partialJSON is the on-disk representation of a single PartialDecryptionData.
// The edwards25519.Point is hex-encoded as 32 bytes.
type partialJSON struct {
	D string `json:"d"` // hex-encoded 32-byte compressed point
}

// ceremonyStateJSON is the JSON-friendly mirror of CeremonyState, with
// Partials converted to hex-encoded strings.
type ceremonyStateJSON struct {
	ID          string               `json:"id"`
	Phase       string               `json:"phase"`
	ElectionID  string               `json:"election_id"`
	ActiveSet   []string             `json:"active_set"`
	BallotCount int                  `json:"ballot_count"`
	PartyCount  int                  `json:"party_count"`
	DedupProof  *ceremony.DedupProof `json:"dedup_proof,omitempty"`

	// map key is trustee index (as string because JSON keys must be strings);
	// value is a slice of hex-encoded partial decryptions.
	Partials map[string][]partialJSON `json:"partials,omitempty"`

	TrusteeOrder []int  `json:"trustee_order,omitempty"`
	Results      []int  `json:"results,omitempty"`
	StartedAt    string `json:"started_at"`
	DecryptedAt  string `json:"decrypted_at,omitempty"`
}

// MarshalJSON implements json.Marshaler for CeremonyState.
func (cs *CeremonyState) MarshalJSON() ([]byte, error) {
	j := ceremonyStateJSON{
		ID:           cs.ID,
		Phase:        cs.Phase,
		ElectionID:   cs.ElectionID,
		ActiveSet:    cs.ActiveSet,
		BallotCount:  cs.BallotCount,
		PartyCount:   cs.PartyCount,
		DedupProof:   cs.DedupProof,
		TrusteeOrder: cs.TrusteeOrder,
		Results:      cs.Results,
		StartedAt:    cs.StartedAt.Format(time.RFC3339Nano),
	}

	if cs.DecryptedAt != nil {
		j.DecryptedAt = cs.DecryptedAt.Format(time.RFC3339Nano)
	}

	if len(cs.Partials) > 0 {
		j.Partials = make(map[string][]partialJSON, len(cs.Partials))
		for idx, pds := range cs.Partials {
			key := fmt.Sprintf("%d", idx)
			encoded := make([]partialJSON, len(pds))
			for i, pd := range pds {
				encoded[i] = partialJSON{
					D: hex.EncodeToString(pd.D.Bytes()),
				}
			}
			j.Partials[key] = encoded
		}
	}

	return json.Marshal(j)
}

// UnmarshalJSON implements json.Unmarshaler for CeremonyState.
func (cs *CeremonyState) UnmarshalJSON(data []byte) error {
	var j ceremonyStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	cs.ID = j.ID
	cs.Phase = j.Phase
	cs.ElectionID = j.ElectionID
	cs.ActiveSet = j.ActiveSet
	cs.BallotCount = j.BallotCount
	cs.PartyCount = j.PartyCount
	cs.DedupProof = j.DedupProof
	cs.TrusteeOrder = j.TrusteeOrder
	cs.Results = j.Results

	t, err := time.Parse(time.RFC3339Nano, j.StartedAt)
	if err != nil {
		return fmt.Errorf("parse started_at: %w", err)
	}
	cs.StartedAt = t

	if j.DecryptedAt != "" {
		dt, err := time.Parse(time.RFC3339Nano, j.DecryptedAt)
		if err != nil {
			return fmt.Errorf("parse decrypted_at: %w", err)
		}
		cs.DecryptedAt = &dt
	}

	if len(j.Partials) > 0 {
		cs.Partials = make(map[int][]*ceremony.PartialDecryptionData, len(j.Partials))
		for key, pds := range j.Partials {
			var idx int
			if _, err := fmt.Sscanf(key, "%d", &idx); err != nil {
				return fmt.Errorf("parse trustee index %q: %w", key, err)
			}
			decoded := make([]*ceremony.PartialDecryptionData, len(pds))
			for i, pj := range pds {
				b, err := hex.DecodeString(pj.D)
				if err != nil {
					return fmt.Errorf("decode partial %d/%d D: %w", idx, i, err)
				}
				pt, err := new(edwards25519.Point).SetBytes(b)
				if err != nil {
					return fmt.Errorf("set point %d/%d: %w", idx, i, err)
				}
				decoded[i] = &ceremony.PartialDecryptionData{D: pt}
			}
			cs.Partials[idx] = decoded
		}
	}

	return nil
}

// --- Persistence ---

// Save atomically writes the ceremony state to the crash journal.
// It writes to a temporary file first, then renames to provide atomicity.
func (cs *CeremonyState) Save() error {
	if cs.stateDir == "" {
		return errors.New("state directory not set")
	}

	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ceremony state: %w", err)
	}

	target := filepath.Join(cs.stateDir, journalFileName)
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp journal: %w", err)
	}

	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("rename journal: %w", err)
	}

	return nil
}

// SetPhase transitions the ceremony to a new phase and persists the change.
func (cs *CeremonyState) SetPhase(phase string) error {
	cs.Phase = phase
	return cs.Save()
}

// LoadCeremonyState loads a ceremony state from the crash journal in stateDir.
// Returns (nil, nil) if no journal file exists, allowing fresh starts.
func LoadCeremonyState(stateDir string) (*CeremonyState, error) {
	target := filepath.Join(stateDir, journalFileName)

	data, err := os.ReadFile(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read ceremony journal: %w", err)
	}

	var cs CeremonyState
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("unmarshal ceremony journal: %w", err)
	}
	cs.stateDir = stateDir

	return &cs, nil
}

// NewCeremonyState creates a new ceremony state and persists it immediately.
func NewCeremonyState(stateDir, id, electionID string) (*CeremonyState, error) {
	cs := &CeremonyState{
		ID:         id,
		Phase:      PhaseFetching,
		ElectionID: electionID,
		StartedAt:  time.Now(),
		stateDir:   stateDir,
	}

	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	if err := cs.Save(); err != nil {
		return nil, err
	}

	return cs, nil
}
