package threshold

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// PartialDecryption holds a trustee's decryption share.
type PartialDecryption struct {
	D     *edwards25519.Point
	Proof *proof.ChaumPedersenProof
}

// PartialDecrypt computes d_i = c1^{x_i} without proof.
func PartialDecrypt(share *edwards25519.Scalar, ct *elgamal.Ciphertext) *PartialDecryption {
	d := new(edwards25519.Point).ScalarMult(share, ct.C1)
	return &PartialDecryption{D: d}
}

// PartialDecryptWithProof computes d_i with a Chaum-Pedersen proof
// that d_i is consistent with the verification key h_i = g^{x_i}.
func PartialDecryptWithProof(share *edwards25519.Scalar, ct *elgamal.Ciphertext, verificationKey *edwards25519.Point) *PartialDecryption {
	d := new(edwards25519.Point).ScalarMult(share, ct.C1)
	g := edwards25519.NewGeneratorPoint()
	p := proof.ProveChaumPedersen(g, ct.C1, verificationKey, d, share)
	return &PartialDecryption{D: d, Proof: p}
}

// VerifyPartialDecryption checks the Chaum-Pedersen proof.
func VerifyPartialDecryption(ct *elgamal.Ciphertext, pd *PartialDecryption, verificationKey *edwards25519.Point) bool {
	if pd.Proof == nil {
		return false
	}
	g := edwards25519.NewGeneratorPoint()
	return proof.VerifyChaumPedersen(g, ct.C1, verificationKey, pd.D, pd.Proof)
}

// CombinePartials combines threshold partial decryptions and recovers the plaintext.
// indices are 1-based trustee IDs.
func CombinePartials(ct *elgamal.Ciphertext, partials []*PartialDecryption, indices []int, maxPlaintext int) int {
	combined := edwards25519.NewIdentityPoint()
	for i := range partials {
		lambda := LagrangeCoefficient(indices, i)
		term := new(edwards25519.Point).ScalarMult(lambda, partials[i].D)
		combined.Add(combined, term)
	}

	// g^m = c2 - D
	negD := new(edwards25519.Point).Negate(combined)
	gm := new(edwards25519.Point).Add(ct.C2, negD)

	return internal.BabyStepGiantStep(gm, maxPlaintext)
}
