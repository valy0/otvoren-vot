package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/valy0/otvoren-vot/collection/votermap"
)

// --- mock implementations ---

// mockChainProvider implements ChainProvider for testing.
type mockChainProvider struct {
	chains []votermap.OverrideChain
	size   int
}

func (m *mockChainProvider) GetAllOverrideChains(_ context.Context, fn func(votermap.OverrideChain) error) error {
	for _, c := range m.chains {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockChainProvider) Size(_ context.Context) (int, error) {
	return m.size, nil
}

// mockSigner implements ReportSigner using Ed25519.
type mockSigner struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

func newMockSigner() *mockSigner {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &mockSigner{privKey: priv, pubKey: pub}
}

func (s *mockSigner) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, data), nil
}

func (s *mockSigner) PublicKey() []byte {
	return s.pubKey
}

// --- test helpers ---

var testHistoryKey = []byte("test-history-key")

// buildChain constructs a valid OverrideChain with properly chained HMAC hashes.
func buildChain(egnHash string, ballots []string) votermap.OverrideChain {
	chain := votermap.OverrideChain{EgnHash: egnHash}
	prevHash := ""
	for i, bid := range ballots {
		seq := i + 1
		rowHash := votermap.ComputeRowHash(testHistoryKey, prevHash, egnHash, bid, seq)
		chain.Submissions = append(chain.Submissions, votermap.HistoryEntry{
			BallotID:    bid,
			Channel:     votermap.ChannelOnline,
			SubmittedAt: time.Unix(int64(1700000000+i*1000), 0),
			Seq:         seq,
			RowHash:     rowHash,
		})
		prevHash = rowHash
	}
	return chain
}

// --- tests ---

func TestGenerateEmptyReport(t *testing.T) {
	signer := newMockSigner()
	provider := &mockChainProvider{size: 100}
	gen := NewGenerator(provider, signer, "election-2026", testHistoryKey)

	var headerBuf, chainsBuf bytes.Buffer
	err := gen.Generate(context.Background(), "aabbccdd", &headerBuf, &chainsBuf)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var header ReportHeader
	if err := json.Unmarshal(headerBuf.Bytes(), &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	if header.ElectionID != "election-2026" {
		t.Errorf("election_id = %q, want %q", header.ElectionID, "election-2026")
	}
	if header.TotalVoters != 100 {
		t.Errorf("total_voters = %d, want 100", header.TotalVoters)
	}
	if header.TotalOverrides != 0 {
		t.Errorf("total_overrides = %d, want 0", header.TotalOverrides)
	}
	if header.BulletinBoardMerkleRoot != "aabbccdd" {
		t.Errorf("bb_merkle_root = %q, want %q", header.BulletinBoardMerkleRoot, "aabbccdd")
	}
	if header.Signature == "" {
		t.Error("signature should not be empty")
	}
	if header.SigningPublicKey == "" {
		t.Error("signing_public_key should not be empty")
	}
	if header.ReportNonce == "" {
		t.Error("report_nonce should not be empty")
	}
	if header.GeneratedAt == "" {
		t.Error("generated_at should not be empty")
	}

	// Chains file should be an empty JSON array.
	var chains []ChainDTO
	if err := json.Unmarshal(chainsBuf.Bytes(), &chains); err != nil {
		t.Fatalf("unmarshal chains: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("chains length = %d, want 0", len(chains))
	}
}

func TestGenerateWithOverrides(t *testing.T) {
	chain1 := buildChain("voter-hash-1", []string{"ballot-a", "ballot-b"})
	chain2 := buildChain("voter-hash-2", []string{"ballot-c", "ballot-d", "ballot-e"})

	signer := newMockSigner()
	provider := &mockChainProvider{
		chains: []votermap.OverrideChain{chain1, chain2},
		size:   500,
	}
	gen := NewGenerator(provider, signer, "election-2026", testHistoryKey)

	var headerBuf, chainsBuf bytes.Buffer
	err := gen.Generate(context.Background(), "bb-root-hex", &headerBuf, &chainsBuf)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var header ReportHeader
	if err := json.Unmarshal(headerBuf.Bytes(), &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	t.Run("header_counts", func(t *testing.T) {
		if header.TotalOverrides != 2 {
			t.Errorf("total_overrides = %d, want 2", header.TotalOverrides)
		}
		if header.TotalVoters != 500 {
			t.Errorf("total_voters = %d, want 500", header.TotalVoters)
		}
	})

	t.Run("merkle_root_nonempty", func(t *testing.T) {
		if header.OverrideChainsMerkleRoot == "" {
			t.Error("override_chains_merkle_root should not be empty")
		}
		if _, err := hex.DecodeString(header.OverrideChainsMerkleRoot); err != nil {
			t.Errorf("merkle root is not valid hex: %v", err)
		}
	})

	t.Run("signature_verifies", func(t *testing.T) {
		sigBytes, err := hex.DecodeString(header.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		pubBytes, err := hex.DecodeString(header.SigningPublicKey)
		if err != nil {
			t.Fatalf("decode public key: %v", err)
		}

		// Reconstruct the signed payload: header with empty signature, JCS-serialized.
		headerCopy := header
		headerCopy.Signature = ""
		raw, err := json.Marshal(headerCopy)
		if err != nil {
			t.Fatalf("marshal header copy: %v", err)
		}
		canonical, err := jcs.Transform(raw)
		if err != nil {
			t.Fatalf("canonicalize for verification: %v", err)
		}

		if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
			t.Error("Ed25519 signature does not verify")
		}
	})

	t.Run("chains_file_valid", func(t *testing.T) {
		var chains []ChainDTO
		if err := json.Unmarshal(chainsBuf.Bytes(), &chains); err != nil {
			t.Fatalf("unmarshal chains: %v", err)
		}
		if len(chains) != 2 {
			t.Fatalf("chains length = %d, want 2", len(chains))
		}
		for _, c := range chains {
			// chain_id should be 64 hex chars (32 bytes HMAC-SHA256).
			if len(c.ChainID) != 64 {
				t.Errorf("chain_id length = %d, want 64", len(c.ChainID))
			}
			if _, err := hex.DecodeString(c.ChainID); err != nil {
				t.Errorf("chain_id is not valid hex: %v", err)
			}
		}
	})

	t.Run("chains_file_sha256_matches", func(t *testing.T) {
		actual := sha256.Sum256(chainsBuf.Bytes())
		if header.ChainsFileSHA256 != hex.EncodeToString(actual[:]) {
			t.Errorf("chains_file_sha256 mismatch:\n  header: %s\n  actual: %s",
				header.ChainsFileSHA256, hex.EncodeToString(actual[:]))
		}
	})

	t.Run("chains_sorted_by_chain_id", func(t *testing.T) {
		var chains []ChainDTO
		if err := json.Unmarshal(chainsBuf.Bytes(), &chains); err != nil {
			t.Fatalf("unmarshal chains: %v", err)
		}
		for i := 1; i < len(chains); i++ {
			if chains[i].ChainID < chains[i-1].ChainID {
				t.Errorf("chains not sorted: %s comes after %s",
					chains[i].ChainID, chains[i-1].ChainID)
			}
		}
	})
}

func TestGenerateCorruptHashChain(t *testing.T) {
	chain := buildChain("voter-hash-1", []string{"ballot-a", "ballot-b"})
	// Corrupt the second entry's row hash.
	chain.Submissions[1].RowHash = "0000000000000000000000000000000000000000000000000000000000000000"

	signer := newMockSigner()
	provider := &mockChainProvider{
		chains: []votermap.OverrideChain{chain},
		size:   10,
	}
	gen := NewGenerator(provider, signer, "election-2026", testHistoryKey)

	var headerBuf, chainsBuf bytes.Buffer
	err := gen.Generate(context.Background(), "bb-root", &headerBuf, &chainsBuf)
	if err == nil {
		t.Fatal("Generate should fail with corrupt hash chain")
	}
	t.Logf("expected error: %v", err)
}

func TestChainIDUnlinkability(t *testing.T) {
	chain := buildChain("voter-hash-1", []string{"ballot-a", "ballot-b"})

	signer := newMockSigner()
	provider := &mockChainProvider{
		chains: []votermap.OverrideChain{chain},
		size:   10,
	}
	gen := NewGenerator(provider, signer, "election-2026", testHistoryKey)

	// Generate two reports. Each uses a fresh random nonce, so chain IDs must differ.
	var h1, c1, h2, c2 bytes.Buffer
	if err := gen.Generate(context.Background(), "bb1", &h1, &c1); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	if err := gen.Generate(context.Background(), "bb2", &h2, &c2); err != nil {
		t.Fatalf("second Generate: %v", err)
	}

	var chains1, chains2 []ChainDTO
	if err := json.Unmarshal(c1.Bytes(), &chains1); err != nil {
		t.Fatalf("unmarshal chains1: %v", err)
	}
	if err := json.Unmarshal(c2.Bytes(), &chains2); err != nil {
		t.Fatalf("unmarshal chains2: %v", err)
	}

	if len(chains1) != 1 || len(chains2) != 1 {
		t.Fatalf("expected 1 chain each, got %d and %d", len(chains1), len(chains2))
	}

	if chains1[0].ChainID == chains2[0].ChainID {
		t.Error("chain IDs should differ between reports (different nonces)")
	}
}

func TestMerkleRootDeterministic(t *testing.T) {
	leaves := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"b":2}`),
		[]byte(`{"c":3}`),
	}
	root1 := chainsMerkleRoot(leaves)
	root2 := chainsMerkleRoot(leaves)
	if !bytes.Equal(root1, root2) {
		t.Error("Merkle root should be deterministic for same input")
	}
}

func TestMerkleRootEmpty(t *testing.T) {
	root := chainsMerkleRoot(nil)
	if root != nil {
		t.Errorf("empty leaves should produce nil root, got %x", root)
	}
}

func TestVerifyHashChain(t *testing.T) {
	chain := buildChain("voter-x", []string{"b1", "b2", "b3"})
	if err := verifyHashChain(testHistoryKey, chain); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
}

func TestVerifyHashChainEmpty(t *testing.T) {
	chain := votermap.OverrideChain{EgnHash: "empty"}
	if err := verifyHashChain(testHistoryKey, chain); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

func TestHmacSHA256(t *testing.T) {
	key := []byte("test-key")
	data := []byte("test-data")
	h1 := hmacSHA256(key, data)
	h2 := hmacSHA256(key, data)
	if !bytes.Equal(h1, h2) {
		t.Error("same input should produce same HMAC")
	}
	if len(h1) != 32 {
		t.Errorf("HMAC-SHA256 should be 32 bytes, got %d", len(h1))
	}
	// Different key produces different output.
	h3 := hmacSHA256([]byte("other-key"), data)
	if bytes.Equal(h1, h3) {
		t.Error("different keys should produce different HMACs")
	}
}
