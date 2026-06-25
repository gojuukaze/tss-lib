// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
)

const (
	Iterations         = 80
	ProofModBytesParts = Iterations*2 + 3
	// Minimum modulus bit length accepted by Verify. Matches the keygen/
	// resharing wire-format checks for NTilde (paillierBitsLen = 2048).
	verifyMinModulusBitLen = 2048
	// Miller-Rabin rounds for the composite check; 30 gives ≤4^-30
	// false-positive rate against arbitrary composites.
	verifyPrimalityRounds = 30
	// fsDomainTag is the per-proof-type Fiat-Shamir domain separator
	// (see facproof.fsSession docstring for rationale).
	fsDomainTag = "tss-lib.v4.modproof"
)

var one = big.NewInt(1)

func fsSession(Session []byte) []byte {
	return append([]byte(fsDomainTag+"|"), Session...)
}

// sampleYModN deterministically derives Y_i ∈ [0, N) by seeding from the
// Fiat-Shamir transcript, expanding via SHA512_256 counter mode to the
// bit length of N, masking down to exactly N.BitLen() bits, and then
// rejecting candidates ≥ N. Rejection probability per attempt is at
// most 1/2 because N ∈ (2^{bitlen−1}, 2^bitlen], so the loop is bounded.
//
// This replaces the earlier `ModReduceHash(N, hash)` derivation, which
// silently produced Y_i in a 256-bit subset of [0, N) when N >> 2^256
// (e.g. for 2048-bit NTilde). The 256-bit support set was enough for
// the soundness error magnitude per iteration but did not match the
// `Y <- Z_N` distribution the paper's formal analysis assumes; the
// expand-then-reject sampler closes that gap. Wire-incompat with v3 by
// design — consumed by the v4 module bump.
func sampleYModN(Session []byte, N *big.Int, transcript []*big.Int) *big.Int {
	seedBig := common.SHA512_256i_TAGGED(fsSession(Session), transcript...)
	// Pad the seed to a fixed 32-byte width so the counter mixing below
	// is canonical regardless of leading-zero bytes in seedBig.Bytes().
	seed := seedBig.Bytes()
	if len(seed) < 32 {
		pad := make([]byte, 32-len(seed))
		seed = append(pad, seed...)
	}
	bitLen := N.BitLen()
	blocks := (bitLen + 255) / 256
	mask := new(big.Int).Lsh(one, uint(bitLen))
	mask.Sub(mask, one)
	counterBz := make([]byte, 4)
	for counter := uint32(0); counter < 1<<31; counter++ {
		binary.BigEndian.PutUint32(counterBz, counter)
		combined := make([]byte, 0, blocks*32)
		for j := 0; j < blocks; j++ {
			block := common.SHA512_256(seed, counterBz, []byte{byte(j)})
			combined = append(combined, block...)
		}
		candidate := new(big.Int).SetBytes(combined)
		candidate.And(candidate, mask)
		if candidate.Cmp(N) < 0 {
			return candidate
		}
	}
	// 1<<31 attempts at rejection rate ≤ 1/2 has failure probability
	// 2^-(2^31), which is far below any cryptographic concern; reaching
	// this point indicates a bug in N's bit-length / mask derivation.
	panic("modproof.sampleYModN: exhausted counter (mask/N invariant violated)")
}

type (
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)

// isQuadraticResidue checks Euler criterion
func isQuadraticResidue(X, N *big.Int) bool {
	return big.Jacobi(X, N) == 1
}

func NewProof(Session []byte, N, P, Q *big.Int, rand io.Reader) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuadraticNonResidue(rand, N)

	// Fig 16.2: Y_i ~ Z_N derived via expand-then-reject sampling so the
	// support set matches the paper's `Y <- Z_N` assumption rather than
	// landing in a 256-bit subset (see sampleYModN docstring).
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{W, N}, Y[:i]...))
	}

	// Fig 16.3
	modN := common.ModInt(N)

	var invN *big.Int
	var ctModN *common.CTModInt

	if common.IsConstantTimeEnabled() {
		// N^(-1) mod Phi: Phi is even so bigmod (which requires odd modulus) cannot be used.
		// This is a prover-side computation where we already hold P, Q — timing leakage from
		// ModInverse here doesn't expose secrets to external observers.
		invN = new(big.Int).ModInverse(N, Phi)
		ctModN = common.NewCTModInt(N)
	} else {
		invN = new(big.Int).ModInverse(N, Phi)
	}

	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}

	// for fourth-root: expo = ((Phi + 4) / 8)^2 mod Phi
	expo := new(big.Int).Add(Phi, big.NewInt(4))
	expo = new(big.Int).Rsh(expo, 3)
	expo = new(big.Int).Mul(expo, expo)
	expo = new(big.Int).Mod(expo, Phi)

	for i := range Y {
		var foundA, foundB int
		var foundXi, foundZi *big.Int
		found := false

		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}

			isQRP := isQuadraticResidue(Yi, P)
			isQRQ := isQuadraticResidue(Yi, Q)

			if isQRP && isQRQ {
				var Xi, Zi *big.Int
				if common.IsConstantTimeEnabled() {
					// Use constant-time exponentiation with secret-derived exponents
					Xi = ctModN.ExpCT(Yi, expo)
					Zi = ctModN.ExpCT(Y[i], invN)
				} else {
					Xi = modN.Exp(Yi, expo)
					Zi = modN.Exp(Y[i], invN)
				}

				if !found {
					foundXi, foundZi = Xi, Zi
					foundA, foundB = a, b
					found = true
				}
			}
		}

		if found {
			X[i], Z[i] = foundXi, foundZi
			A.SetBit(A, i, uint(foundA))
			B.SetBit(B, i, uint(foundB))
		}
	}

	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	// Validate N before any operation that requires it to be a positive odd
	// composite. big.Jacobi panics on nil/non-positive/even modulus, and
	// RejectionSample loops forever on N <= 1, so the original ordering
	// (which only checked oddness/compositeness at line ~192) left a panic
	// surface reachable from a malformed message.
	if N == nil || N.Sign() != 1 || N.Bit(0) == 0 ||
		N.BitLen() < verifyMinModulusBitLen || N.ProbablyPrime(verifyPrimalityRounds) {
		return false
	}
	if isQuadraticResidue(pf.W, N) {
		return false
	}
	if pf.W.Sign() != 1 || pf.W.Cmp(N) != -1 {
		return false
	}
	gcd := new(big.Int).GCD(nil, nil, pf.W, N)
	if gcd.Cmp(one) != 0 {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i].Sign() != 1 || pf.Z[i].Cmp(N) != -1 {
			return false
		}
		// Honest Z[i] = Y[i]^(N^-1 mod φ) is in Z_N*; rejecting non-units
		// closes the defense-in-depth gap where a malicious prover supplies
		// a non-coprime root that happens to satisfy the modexp identity.
		if new(big.Int).GCD(nil, nil, pf.Z[i], N).Cmp(one) != 0 {
			return false
		}
	}
	for i := range pf.X {
		if pf.X[i].Sign() != 1 || pf.X[i].Cmp(N) != -1 {
			return false
		}
		if new(big.Int).GCD(nil, nil, pf.X[i], N).Cmp(one) != 0 {
			return false
		}
	}
	if pf.A.BitLen() != Iterations+1 {
		return false
	}
	if pf.B.BitLen() != Iterations+1 {
		return false
	}

	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{pf.W, N}, Y[:i]...))
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)

		go func(i int) {
			a := pf.A.Bit(i)
			b := pf.B.Bit(i)
			if a != 0 && a != 1 {
				chs <- false
				return
			}
			if b != 0 && b != 1 {
				chs <- false
				return
			}
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			return false
		}
	}

	return true
}

func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		if pf.X[i] != nil {
			bzs[1+i] = pf.X[i].Bytes()
		}
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		if pf.Z[i] != nil {
			bzs[Iterations+3+i] = pf.Z[i].Bytes()
		}
	}
	return bzs
}
