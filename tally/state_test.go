package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

// stateFixture is one valid partial decryption of a one-slot tally, with the
// context, ciphertext and key it verifies under.
type stateFixture struct {
	sc      threshold.SlotContext
	ct      *elgamal.Ciphertext
	partial *threshold.Partial
	kp      *elgamal.KeyPair
}

func newStateFixture(t *testing.T) *stateFixture {
	t.Helper()
	kp := elgamal.GenerateKeyPair()
	ct, _, err := elgamal.Encrypt(kp.PublicKey, 1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	sc := threshold.SlotContext{
		ElectionID:  "test-election",
		SlotIndex:   0,
		TallyDigest: threshold.TallyDigest([]*elgamal.Ciphertext{ct}),
	}
	p, err := threshold.PartialDecrypt(sc, 1, kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	return &stateFixture{sc: sc, ct: ct, partial: p, kp: kp}
}

// wire returns the partial's d, u, v and z as the journal stores them.
func (f *stateFixture) wire() map[string]string {
	return map[string]string{
		"d": hex.EncodeToString(f.partial.D.Bytes()),
		"u": hex.EncodeToString(f.partial.Proof.U.Bytes()),
		"v": hex.EncodeToString(f.partial.Proof.V.Bytes()),
		"z": hex.EncodeToString(f.partial.Proof.Z.Bytes()),
	}
}

// writeJournal writes a one-slot awaiting_trustees journal in which trustee 1
// stored the single partial p, and returns its directory.
func writeJournal(t *testing.T, p map[string]string) string {
	t.Helper()
	journal := map[string]any{
		"id":            "ceremony-1",
		"phase":         PhaseAwaitingTrustees,
		"election_id":   "test-election",
		"active_set":    []string{"ballot-0"},
		"ballot_count":  1,
		"party_count":   1,
		"partials":      map[string]any{"1": []map[string]string{p}},
		"trustee_order": []int{1},
		"started_at":    time.Now().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatalf("marshal journal: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, journalFileName), data, 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	return dir
}

// TestStateLoadRejectsPartialWithoutProof: a journal partial must carry d, u, v
// and z, each decodable. Loading cannot re-verify the proof (the tally is not
// persisted), but it never yields a partial without one.
func TestStateLoadRejectsPartialWithoutProof(t *testing.T) {
	f := newStateFixture(t)
	valid := f.wire()

	without := func(fields ...string) map[string]string {
		p := make(map[string]string, len(valid))
		for k, v := range valid {
			p[k] = v
		}
		for _, k := range fields {
			delete(p, k)
		}
		return p
	}
	with := func(field, value string) map[string]string {
		p := without()
		p[field] = value
		return p
	}

	// The fixture itself loads, so each case below fails on its one change.
	t.Run("complete", func(t *testing.T) {
		cs, err := LoadCeremonyState(writeJournal(t, valid))
		if err != nil {
			t.Fatalf("LoadCeremonyState: %v", err)
		}
		got := cs.Partials[1]
		if len(got) != 1 || got[0] == nil || got[0].Proof == nil {
			t.Fatalf("loaded partials = %v, want one complete partial", got)
		}
		if got[0].TrusteeIndex != 1 {
			t.Errorf("TrusteeIndex = %d, want 1", got[0].TrusteeIndex)
		}
		if err := threshold.VerifyPartial(f.sc, f.ct, got[0], f.kp.PublicKey); err != nil {
			t.Errorf("loaded partial does not verify: %v", err)
		}
	})

	cases := []struct {
		name    string
		partial map[string]string
	}{
		{"only d", without("u", "v", "z")},
		{"missing d", without("d")},
		{"missing u", without("u")},
		{"missing v", without("v")},
		{"missing z", without("z")},
		{"d not hex", with("d", "zz"+valid["d"][2:])},
		{"u identity", with("u", strings.Repeat("00", 32))},
		{"v edwards basepoint", with("v", "58"+strings.Repeat("66", 31))},
		{"z not canonical", with("z", strings.Repeat("ff", 32))},
		{"z wrong length", with("z", valid["z"][:62])},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs, err := LoadCeremonyState(writeJournal(t, c.partial))
			if err == nil {
				t.Fatalf("LoadCeremonyState accepted %v (partials %v)", c.partial, cs.Partials)
			}
		})
	}
}

// TestStateSaveAndLoadKeepsPartialProofs: Save then Load round-trips every
// partial's D and proof, and the loaded partial still verifies.
func TestStateSaveAndLoadKeepsPartialProofs(t *testing.T) {
	f := newStateFixture(t)
	dir := t.TempDir()
	cs, err := NewCeremonyState(dir, "ceremony-1", "test-election")
	if err != nil {
		t.Fatalf("NewCeremonyState: %v", err)
	}
	cs.PartyCount = 1
	cs.Partials = map[int][]*threshold.Partial{1: {f.partial}}
	cs.TrusteeOrder = []int{1}
	if err := cs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadCeremonyState(dir)
	if err != nil {
		t.Fatalf("LoadCeremonyState: %v", err)
	}
	got := loaded.Partials[1]
	if len(got) != 1 {
		t.Fatalf("loaded %d partials for trustee 1, want 1", len(got))
	}
	p := got[0]
	if p.TrusteeIndex != 1 || p.D.Equal(f.partial.D) != 1 ||
		p.Proof.U.Equal(f.partial.Proof.U) != 1 || p.Proof.V.Equal(f.partial.Proof.V) != 1 ||
		p.Proof.Z.Equal(f.partial.Proof.Z) != 1 {
		t.Fatal("loaded partial differs from the saved one")
	}
	if err := threshold.VerifyPartial(f.sc, f.ct, p, f.kp.PublicKey); err != nil {
		t.Fatalf("loaded partial does not verify: %v", err)
	}
}

// TestStateSaveRejectsIncompletePartial: Save returns an error, rather than
// panicking or writing a partial without its proof.
func TestStateSaveRejectsIncompletePartial(t *testing.T) {
	f := newStateFixture(t)
	cs, err := NewCeremonyState(t.TempDir(), "ceremony-1", "test-election")
	if err != nil {
		t.Fatalf("NewCeremonyState: %v", err)
	}
	cs.PartyCount = 1
	cs.Partials = map[int][]*threshold.Partial{1: {{TrusteeIndex: 1, D: f.partial.D}}}
	if err := cs.Save(); err == nil {
		t.Fatal("Save accepted a partial without a proof")
	}
}
