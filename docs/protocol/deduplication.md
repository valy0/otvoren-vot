# ZK Deduplication Proof (gnark SNARK)

**Status:** Draft
**References:** Design Spec sections 2.7, 6.3, 6.4

---

## 1. The Deduplication Problem

Otvoren-vot allows voters to re-vote (online-to-online, online-to-in-person, in-person-to-online). Every ballot ever cast remains on the append-only bulletin board. After polls close, only the **last** ballot per voter should count.

**Layer 1** (Identity Service) knows which voter cast which ballot IDs. It computes the **active set**: one ballot ID per voter, corresponding to the voter's final submission. Layer 1 publishes the active set (ballot IDs only, no voter identifiers) to Layer 2.

**Layer 2** (Ballot Service) filters the bulletin board, retaining only ballots whose IDs appear in the active set. The homomorphic tally is computed over this filtered set.

The zero-knowledge deduplication proof demonstrates that Layer 2 performed the filtering correctly -- that the filtered set is exactly the subset of the bulletin board corresponding to the active set -- without revealing:

- Which ballot IDs were filtered out (i.e., which ballots were superseded by re-votes)
- How many times any individual re-voted
- Any link between voters and ballot IDs

The proof is generated during the decryption ceremony (Section 7 of the design spec) and published on the bulletin board for anyone to verify.

---

## 2. What the Proof Hides vs. Reveals

### Hidden (private witness)

| Information | Why it must be hidden |
|---|---|
| Which ballot IDs are in the active set | Reveals re-voting patterns; could correlate with voter identity via timing |
| Which ballot IDs were excluded | Directly reveals who re-voted |
| Re-vote counts per voter | Leaks behavioral data about coercion or indecision |
| Voter-to-ballot-ID mapping | The fundamental Layer 1/Layer 2 separation invariant |

### Revealed (public inputs / verifiable outputs)

| Information | Why it is safe to reveal |
|---|---|
| Total number of active ballots (`N_active`) | Equals the number of unique voters; cross-checkable against electoral roll counts by observers |
| Bulletin board Merkle root | Already public |
| Filtered set Merkle root | Needed for tally verification |
| Active set commitment hash | Enables auditors to verify consistency |
| That the filtering was honest | The entire point of the proof |

---

## 3. Dual-Hash Merkle Tree

The bulletin board maintains **two parallel Merkle trees**, computed on every append:

### 3.1 Public tree (SHA-256)

- Standard SHA-256 hash function
- Used for all external verification: API responses, inclusion proofs, voter receipt verification
- Canonical for public auditability
- Any party can independently recompute this tree from the raw bulletin board data

### 3.2 SNARK tree (Poseidon over BN254)

- Poseidon hash function operating over the BN254 scalar field `F_p` where `p` is the BN254 base field prime
- Used exclusively inside the gnark deduplication circuit
- Exists solely to make the SNARK computationally tractable

### 3.3 Why two trees

SHA-256 inside a SNARK is prohibitively expensive. A single SHA-256 evaluation requires approximately **25,000 R1CS constraints** in a gnark circuit, because SHA-256's bitwise operations (rotations, XOR, additions modulo `2^32`) must be decomposed into arithmetic over `F_p`.

Poseidon is an algebraic hash function designed for arithmetic circuits. It operates natively over `F_p` using only field multiplications and additions. A single Poseidon evaluation requires approximately **250 R1CS constraints** -- a 100x reduction.

For a Merkle tree of depth `d`, each inclusion proof requires `d` hash evaluations. With `N = 4,000,000` ballots, `d = ceil(log2(N)) = 22`. A single Merkle inclusion proof costs:

- SHA-256: `22 * 25,000 = 550,000` constraints
- Poseidon: `22 * 250 = 5,500` constraints

Over 4 million ballots, this difference determines whether the proof is feasible at all.

### 3.4 Consistency guarantee

Both trees are built over the same ordered sequence of ballot entries. The public SHA-256 tree is the canonical reference. The SNARK tree's root is a derived value -- anyone with the bulletin board data and the Poseidon hash implementation can recompute it independently and verify it matches the root used in the proof.

### 3.5 Leaf format

Each leaf in both trees contains a deterministic serialization of the ballot entry:

```
leaf = Hash(ballot_id || encrypted_ballot || timestamp)
```

Where `Hash` is SHA-256 for the public tree and Poseidon for the SNARK tree. The `encrypted_ballot` is the full serialized ciphertext (all ElGamal pairs for party votes and candidate preferences). The `||` operator denotes concatenation (for SHA-256) or field-element packing (for Poseidon).

For Poseidon, the ballot data must be packed into BN254 scalar field elements. Each field element holds up to 253 bits. The serialized ballot is split into 253-bit chunks, each interpreted as an element of `F_p`.

---

## 4. gnark Circuit Specification

The deduplication circuit is implemented in Go using the `github.com/consensys/gnark` framework, compiled to the Groth16 proving system over the BN254 curve.

### 4.1 Public inputs

| Variable | Type | Description |
|---|---|---|
| `BB_root` | `frontend.Variable` | Poseidon Merkle root of the full bulletin board |
| `AS_commitment` | `frontend.Variable` | `Poseidon(sort(active_set))` -- commitment to the active set |
| `FS_root` | `frontend.Variable` | Poseidon Merkle root of the filtered set |
| `N_active` | `frontend.Variable` | Number of ballots in the active set |

### 4.2 Private witness

| Variable | Type | Description |
|---|---|---|
| `IDs[i]` | `[N_active]frontend.Variable` | The active ballot IDs |
| `MerkleProofs[i]` | `[N_active][d]MerkleProofNode` | Poseidon Merkle inclusion proof for each active ID in the bulletin board |
| `Ballots[i]` | `[N_active][B]frontend.Variable` | Encrypted ballot data for each active ID, packed into field elements |

Where:
- `d = ceil(log2(N_total))` is the Merkle tree depth
- `B` is the number of BN254 field elements needed to represent one encrypted ballot
- Each `MerkleProofNode` contains a sibling hash and a direction bit

### 4.3 Circuit constraints

The `Define` method of the gnark circuit enforces the following constraints:

#### (a) Merkle inclusion -- each active ID exists on the bulletin board

For each `i` in `[0, N_active)`:

```
ComputedRoot_i = PoseidonMerkleVerify(
    leaf = PoseidonHash(IDs[i] || Ballots[i]),
    proof = MerkleProofs[i],
    depth = d
)
api.AssertIsEqual(ComputedRoot_i, BB_root)
```

This proves that every ballot claimed to be in the active set actually exists on the bulletin board, at the position indicated by the Merkle proof.

#### (b) Active set commitment -- witness IDs match the committed set

The circuit verifies that the hash of the sorted witness IDs equals the public commitment:

```
// Verify IDs are in sorted order (prevents duplicates and ensures determinism)
for i in [0, N_active - 1):
    api.AssertIsLessOrEqual(IDs[i], IDs[i+1])  // strict: IDs[i] < IDs[i+1]

// Compute commitment over sorted IDs
ComputedCommitment = PoseidonHash(IDs[0], IDs[1], ..., IDs[N_active - 1])
api.AssertIsEqual(ComputedCommitment, AS_commitment)
```

The sorted-order constraint also enforces **uniqueness** -- no ballot ID can appear twice, since the ordering is strict.

**Note on `AssertIsLessOrEqual` in BN254:** Field comparison is not a native operation. It requires decomposing each field element into its binary representation and performing a lexicographic comparison. This adds approximately `254 * 2 = 508` constraints per comparison. For `N_active` IDs, this contributes `~508 * N_active` constraints.

#### (c) Filtered set root -- correctly computed from active ballots

```
ComputedFSRoot = BuildPoseidonMerkleTree(
    leaves = [PoseidonHash(IDs[i] || Ballots[i]) for i in [0, N_active)]
)
api.AssertIsEqual(ComputedFSRoot, FS_root)
```

This proves that the filtered set Merkle tree contains exactly the ballots corresponding to the active IDs, in the correct order.

Building a Merkle tree inside the circuit requires `N_active - 1` Poseidon hash evaluations (for a balanced binary tree). Each hash costs ~250 constraints, contributing `~250 * N_active` constraints total.

#### (d) Count match

```
api.AssertIsEqual(len(IDs), N_active)
```

In gnark, the circuit is parameterized at compile time with a fixed `N_active`. The public input `N_active` must match. If the actual active set is smaller than the compiled maximum, unused slots are filled with a distinguished "empty" value and the circuit logic accounts for padding.

### 4.4 Constraint summary (per ballot)

| Component | Constraints per ballot | Notes |
|---|---|---|
| Merkle inclusion proof | `d * 250 = 5,500` | `d = 22` for 4M ballots |
| Leaf hash (ballot ID + ciphertext) | `~250` | Single Poseidon invocation |
| Sorted-order check | `~508` | Binary decomposition + comparison |
| Filtered tree construction | `~250` | Amortized per leaf |
| Commitment hash | Amortized `~1` | Single hash over all IDs, spread across N |
| **Total per ballot** | **~6,500** | |

---

## 5. What Is Inside vs. Outside the SNARK

The otvoren-vot system uses two cryptographic groups that serve different purposes and **must not interact inside a circuit**:

### Inside the SNARK (BN254 / Poseidon)

All operations performed inside the gnark circuit use BN254-native field arithmetic:

- **Set membership verification:** Poseidon Merkle inclusion proofs against the bulletin board's SNARK tree root
- **Active set commitment check:** Poseidon hash of sorted ballot IDs compared to the public commitment
- **Filtered set construction:** Building a new Poseidon Merkle tree from the active ballots
- **Count verification:** Asserting the active set size matches the public input

The SNARK proves: "the filtered set is exactly the subset of the bulletin board that corresponds to the committed active set."

### Outside the SNARK (Ristretto255 / Sigma proofs)

All ballot-content operations use Ristretto255 (prime-order group derived from Curve25519):

- **Homomorphic product:** Element-wise multiplication of ElGamal ciphertexts over the filtered set, producing encrypted sums
- **Threshold decryption:** Each trustee computes partial decryptions using their HSM-held key share
- **Partial decryption proofs:** Chaum-Pedersen proofs that each trustee's partial decryption is honestly computed
- **Tally correctness proof:** Sigma proof that the plaintext results match the encrypted sums

These operations are verified by separate Sigma/Chaum-Pedersen proofs over the Ristretto255 group.

### Why no cross-group interaction

Performing Ristretto255 elliptic curve arithmetic inside a BN254 SNARK would require simulating Curve25519 field operations (~2^255 - 19 prime field) inside the BN254 scalar field (~2^254 prime field). This is technically possible via non-native field arithmetic, but the constraint cost is extreme -- a single Ristretto255 scalar multiplication would require millions of constraints. The entire deduplication circuit would become infeasible.

Instead, the system cleanly separates concerns:
1. The SNARK proves correct filtering (which ballots are included)
2. Sigma proofs verify correct tallying (what the ballots contain)
3. The two proof systems share a common anchor: the filtered set Merkle root, which the SNARK proves correct and the tally takes as input

---

## 6. Recursive Proof Composition

A single Groth16 circuit for 4 million ballots would require approximately 26 billion constraints (see Section 8). This exceeds the practical limits of a single proving instance. The solution is recursive proof composition.

### 6.1 Batch decomposition

The active set is partitioned into batches of approximately **10,000 ballots** each. For `N_active = 4,000,000`, this yields ~400 batches.

Each batch circuit proves:

- The 10,000 ballot IDs in this batch have valid Merkle inclusion proofs against `BB_root`
- The ballot IDs are sorted and unique within the batch
- A partial Poseidon Merkle subtree is correctly computed from the batch's ballots

### 6.2 Batch proof generation

Each batch is an independent Groth16 proof over the BN254 curve. Batch proofs can be generated in parallel -- each on a separate CPU core.

**Batch circuit public inputs:**
- `BB_root` (shared across all batches)
- `batch_index` (position of this batch in the partition)
- `batch_subtree_root` (Poseidon Merkle root of this batch's ballots)
- `batch_id_range` (min and max ballot ID in this batch, for verifying inter-batch ordering)

### 6.3 Aggregation circuit

A second-level circuit verifies all batch proofs and combines them:

```
for each batch_proof in batch_proofs:
    VerifyGroth16Proof(batch_proof, batch_public_inputs)

// Verify inter-batch ordering (batch N's max ID < batch N+1's min ID)
for i in [0, num_batches - 1):
    api.AssertIsLessOrEqual(batch_ranges[i].max, batch_ranges[i+1].min)

// Verify all batches use the same bulletin board root
for each batch:
    api.AssertIsEqual(batch.BB_root, BB_root)

// Compute overall commitment from batch subtree roots
OverallFSRoot = PoseidonMerkleFromSubtrees(batch_subtree_roots)
api.AssertIsEqual(OverallFSRoot, FS_root)

// Compute overall active set commitment from batch ID ranges
// (each batch also commits to its sorted IDs internally)
OverallCommitment = PoseidonHash(batch_commitments)
api.AssertIsEqual(OverallCommitment, AS_commitment)
```

gnark supports Groth16 proof verification inside a Groth16 circuit via `std/recursion/groth16`. The verification of a single Groth16 proof inside a BN254 circuit costs approximately **~1.5 million constraints** (dominated by the pairing check). For 400 batches, the aggregation circuit alone would be ~600 million constraints.

### 6.4 Multi-level recursion

If the aggregation circuit is too large for a single proof, it can itself be split into levels:

1. **Level 0 (leaf):** 400 batch proofs, each covering 10,000 ballots
2. **Level 1 (intermediate):** 20 aggregation proofs, each verifying 20 batch proofs
3. **Level 2 (root):** 1 final proof verifying 20 intermediate proofs

The final published proof is always a single Groth16 proof -- constant size regardless of the number of ballots.

### 6.5 Parallelism

- Level 0: all 400 batch proofs can be generated simultaneously across 400 CPU cores (or queued across available cores)
- Level 1: all 20 intermediate proofs can be generated simultaneously (after their input batch proofs complete)
- Level 2: single proof generation

With a 64-core server, Level 0 completes in `ceil(400/64) = 7` sequential rounds. Each round takes approximately 1-2 minutes per batch proof. Total Level 0 time: ~7-14 minutes.

---

## 7. Trusted Setup

Groth16 is a **pre-processing SNARK** -- it requires a per-circuit **structured reference string (SRS)**, sometimes called the **common reference string (CRS)**. The SRS contains encoded group elements that depend on secret randomness (the "toxic waste"). If anyone learns the toxic waste, they can forge proofs.

### 7.1 Phase 1: Powers-of-tau ceremony

A universal setup that produces powers of a secret `tau` in the group:

```
{[1]_1, [tau]_1, [tau^2]_1, ..., [tau^(n-1)]_1,
 [1]_2, [tau]_2, [tau^2]_2, ..., [tau^(n-1)]_2}
```

where `[x]_1` and `[x]_2` denote encodings in the two BN254 source groups `G_1` and `G_2`.

This ceremony is **reusable** across any circuit up to size `n`. The otvoren-vot deduplication circuit requires `n` to be at least as large as the number of constraints in the largest sub-circuit.

**Multi-party computation (MPC) protocol:** Each participant `P_j` samples random `tau_j`, multiplies it into the running product, and destroys `tau_j`. The final `tau = tau_1 * tau_2 * ... * tau_k`. Security requires only that **at least one participant honestly destroys their randomness**.

For otvoren-vot, the powers-of-tau ceremony should include participants from:
- Multiple political parties
- Independent NGOs
- Academic institutions
- International election observers
- Random members of the public (open participation round)

### 7.2 Phase 2: Circuit-specific setup

Given the Phase 1 output and the compiled circuit (R1CS representation), Phase 2 produces the **proving key** (used by the prover) and the **verification key** (used by verifiers).

Phase 2 is circuit-specific -- a new Phase 2 is required for each distinct circuit (batch circuit, aggregation circuit). It also uses an MPC protocol with the same security assumption: at least one honest participant.

### 7.3 Verification key publication

The verification key for each circuit level is published on the bulletin board before the election. It is a compact data structure (~1 KB) that anyone can use to verify proofs. It includes:
- BN254 group elements derived from the SRS
- The circuit's public input/output specification

### 7.4 SRS integrity

The full transcript of both MPC phases is published. Anyone can verify:
- Each participant's contribution was correctly incorporated
- The final SRS is consistent with the transcript
- The Phase 2 output is consistent with Phase 1 + the compiled circuit

gnark provides tooling for both phases via `github.com/consensys/gnark/backend/groth16/bn254/mpcsetup`.

---

## 8. Performance Estimates

### 8.1 Constraint counts

| Component | Per-ballot constraints | Total (4M ballots) |
|---|---|---|
| Merkle inclusion (depth 22, Poseidon) | 5,500 | 22,000,000,000 |
| Leaf hashing | 250 | 1,000,000,000 |
| Sorted-order check | 508 | 2,032,000,000 |
| Filtered tree construction | 250 | 1,000,000,000 |
| Commitment (amortized) | ~1 | 4,000,000 |
| **Total** | **~6,500** | **~26,000,000,000** |

~26 billion constraints total. This is infeasible without recursive decomposition.

### 8.2 Per-batch constraints

With batches of 10,000 ballots:

- Per-batch: `10,000 * 6,500 = 65,000,000` constraints
- This is within Groth16's practical range (~100M constraints per proof on commodity hardware)

### 8.3 Proving time

**Batch proof (65M constraints):**
- Estimated 1-2 minutes per proof on a modern CPU core (AMD EPYC or Intel Xeon, 3+ GHz)
- gnark's Groth16 prover is single-threaded per proof but highly optimized with assembly-level BN254 arithmetic

**Level 0 (400 batches on 64 cores):**
- `ceil(400 / 64) = 7` sequential rounds
- Per round: 1-2 minutes
- Total: **7-14 minutes**

**Aggregation (Level 1+2):**
- Recursion verification is expensive (~1.5M constraints per verified proof)
- 20 intermediate proofs, each verifying 20 batch proofs: ~30M constraints each
- Plus 1 final proof verifying 20 intermediate proofs: ~30M constraints
- Aggregation time: **5-10 minutes** with parallelism

**Total estimated proving time: 15-30 minutes** on a 64-core server. Worst case with overhead: **30-60 minutes**.

### 8.4 Verification time

A Groth16 proof is:
- **Constant size:** 3 BN254 `G_1` points + metadata = ~192 bytes (often cited as ~200 bytes)
- **Constant verification time:** 1 pairing check = **~2-5 milliseconds** on commodity hardware

Verification is independent of the number of ballots. A verifier running the CLI tool `otvoren-vot verify dedup` downloads the ~200-byte proof and the verification key, and confirms the proof in milliseconds.

### 8.5 Memory requirements

- Per-batch prover memory: ~2-4 GB (dominated by the R1CS witness and FFT buffers)
- 64 parallel batch proofs: ~128-256 GB RAM
- This fits within a single high-memory server (e.g., 512 GB RAM, 64 cores)

---

## 9. Active Set Commitment

### 9.1 Construction

After polls close, Layer 1 computes:

```
active_set = {ballot_id_i : ballot_id_i is the last ballot for voter_i}
sorted_set = sort(active_set)  // lexicographic sort of ballot IDs
AS_commitment = PoseidonHash(sorted_set[0], sorted_set[1], ..., sorted_set[N-1])
```

Layer 1 signs the commitment with the Collection Server's signing key:

```
signature = Sign(SK_collection, AS_commitment || N_active || election_id || timestamp)
```

The signed commitment is published on the bulletin board before the SNARK proof is generated.

### 9.2 What the commitment proves

The SNARK proves that the filtered set is **consistent with the commitment** -- that is, the ballot IDs used in the SNARK witness hash to exactly `AS_commitment`. This guarantees:

- Layer 2 did not add or remove any ballot IDs from the active set
- Layer 2 did not substitute one ballot's ciphertext for another's
- The filtered set size matches `N_active`

### 9.3 What the commitment does NOT prove

The SNARK does **not** prove that Layer 1 honestly computed the active set from its voter-to-ballot-ID database. A compromised Layer 1 could publish a fraudulent active set (e.g., excluding ballots from voters who chose a particular party, or including fabricated ballot IDs).

This is the **most critical trust assumption** in the system (see Design Spec Section 6.4).

### 9.4 Mitigations for active set integrity

Since the SNARK cannot enforce Layer 1's honesty, the following external checks provide defense in depth:

1. **Voter count cross-check:** `N_active` (published as a public input) must equal the number of voters marked as having voted in the electoral rolls. Political party observers independently count voters at polling stations. Any discrepancy is immediately flagged.

2. **Individual ballot inclusion verification:** Any voter can check that their ballot ID is in the filtered set by verifying a Merkle inclusion proof against `FS_root`. If a voter's ballot was dishonestly excluded from the active set, the voter would find their ballot ID missing from the filtered set (assuming they retained their ballot ID from the voting receipt).

3. **Post-election judicial audit:** Layer 1's `voter_id -> ballot_id` database is sealed and made available to court-appointed auditors under judicial order. Auditors can recompute the active set from the raw data and verify it matches `AS_commitment`.

4. **Dual-operator requirement:** The active set computation and commitment signing require sign-off from two CIK administrators (two-person rule), with both actions logged in the immutable audit trail.

5. **Parallel observation:** Political party representatives observe the deduplication process in real time, monitoring the total ballot count and flagging anomalies.

### 9.5 Residual risk

If Layer 1 is compromised and all mitigations fail (observers do not detect the discrepancy, no voters check inclusion, no judicial audit occurs), then Layer 1 can manipulate the election result by controlling which ballots are counted.

This risk is inherent to any system where a single authority manages voter-to-ballot mappings. The mitigations above make such an attack **detectable** (requiring collusion across multiple independent observers to suppress), even though the SNARK alone cannot prevent it.

---

## Appendix A: Data Flow Diagram

```
Polls Close
    |
    v
Layer 1: Compute active set (one ballot_id per voter)
    |
    v
Layer 1: Publish AS_commitment = PoseidonHash(sort(active_set)), signed
    |
    v
Layer 1 --> Layer 2: Transfer active set (ballot IDs only, no voter IDs)
    |
    v
Layer 2 (Tally Service): For each active ID, retrieve encrypted ballot from bulletin board
    |
    v
Layer 2: Generate batch SNARK proofs (parallel, ~400 batches of 10K)
    |
    v
Layer 2: Aggregate batch proofs into single Groth16 proof (recursive)
    |
    v
Publish on bulletin board:
  - Deduplication proof (~200 bytes)
  - AS_commitment
  - FS_root
  - N_active
    |
    v
Anyone: Verify proof in milliseconds using verification key
```

## Appendix B: gnark Circuit Pseudocode

```go
type DeduplicationCircuit struct {
    // Public inputs
    BBRoot       frontend.Variable `gnark:",public"`
    ASCommitment frontend.Variable `gnark:",public"`
    FSRoot       frontend.Variable `gnark:",public"`
    NActive      frontend.Variable `gnark:",public"`

    // Private witness
    IDs          [BatchSize]frontend.Variable
    MerkleProofs [BatchSize][TreeDepth]MerkleNode
    Ballots      [BatchSize][BallotFieldElems]frontend.Variable
}

type MerkleNode struct {
    Sibling   frontend.Variable
    Direction frontend.Variable // 0 = left child, 1 = right child
}

func (c *DeduplicationCircuit) Define(api frontend.API) error {
    poseidon, _ := poseidon.NewHasher(api)

    // (a) Verify Merkle inclusion for each ballot
    for i := 0; i < BatchSize; i++ {
        leaf := poseidon.Hash(append([]frontend.Variable{c.IDs[i]}, c.Ballots[i][:]...)...)
        computedRoot := leaf
        for d := 0; d < TreeDepth; d++ {
            left := api.Select(c.MerkleProofs[i][d].Direction, c.MerkleProofs[i][d].Sibling, computedRoot)
            right := api.Select(c.MerkleProofs[i][d].Direction, computedRoot, c.MerkleProofs[i][d].Sibling)
            computedRoot = poseidon.Hash(left, right)
        }
        api.AssertIsEqual(computedRoot, c.BBRoot)
    }

    // (b) Verify IDs are sorted (strict ordering, implies uniqueness)
    for i := 0; i < BatchSize-1; i++ {
        AssertIsStrictlyLess(api, c.IDs[i], c.IDs[i+1])
    }

    // (b) Verify active set commitment
    commitInput := make([]frontend.Variable, BatchSize)
    copy(commitInput, c.IDs[:])
    computedCommitment := poseidon.Hash(commitInput...)
    api.AssertIsEqual(computedCommitment, c.ASCommitment)

    // (c) Build filtered set Merkle tree and verify root
    leaves := make([]frontend.Variable, BatchSize)
    for i := 0; i < BatchSize; i++ {
        leaves[i] = poseidon.Hash(append([]frontend.Variable{c.IDs[i]}, c.Ballots[i][:]...)...)
    }
    computedFSRoot := BuildMerkleTree(api, poseidon, leaves)
    api.AssertIsEqual(computedFSRoot, c.FSRoot)

    return nil
}
```

**Note:** This pseudocode illustrates the batch circuit structure. The actual implementation must handle:
- Padding for batches smaller than `BatchSize`
- The aggregation circuit for recursive composition
- Efficient Poseidon parameterization for the BN254 scalar field
- Binary decomposition for field-element comparison (`AssertIsStrictlyLess`)
