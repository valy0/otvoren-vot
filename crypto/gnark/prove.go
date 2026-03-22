package gnark

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CompileCircuit compiles the DeduplicationCircuit into an R1CS constraint
// system over the BN254 scalar field.
func CompileCircuit() (constraint.ConstraintSystem, error) {
	var circuit DeduplicationCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compiling circuit: %w", err)
	}
	return cs, nil
}

// Setup runs Groth16 trusted setup on the compiled constraint system,
// producing a proving key and verification key.
func Setup(cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("groth16 setup: %w", err)
	}
	return pk, vk, nil
}

// Prove generates a Groth16 proof from the compiled constraint system,
// proving key, and a fully populated circuit assignment.
func Prove(cs constraint.ConstraintSystem, pk groth16.ProvingKey, assignment *DeduplicationCircuit) (groth16.Proof, error) {
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("creating witness: %w", err)
	}
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("groth16 prove: %w", err)
	}
	return proof, nil
}

// Verify checks a Groth16 proof against the verification key and the public
// inputs extracted from the given circuit assignment.
func Verify(vk groth16.VerifyingKey, proof groth16.Proof, assignment *DeduplicationCircuit) error {
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("creating witness for verification: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("extracting public witness: %w", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("groth16 verify: %w", err)
	}
	return nil
}
