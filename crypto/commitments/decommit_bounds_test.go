// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
)

// DeCommit hashes every part it is handed before anything looks at how many
// there are. The four call sites whose expected length is a function of the
// threshold -- {ecdsa,eddsa}/{keygen,resharing} -- could not state that length
// at the message layer, so they checked it on DeCommit's OUTPUT. This pins the
// cost that ordering carried, so the reason those call sites now check first
// does not have to be taken on trust.
//
// It asserts nothing about the library's own behaviour; it measures the
// primitive, which is why it lives here rather than in one of the four.
func TestDeCommitCostGrowsWithThePartCountItIsGiven(t *testing.T) {
	build := func(parts int) *HashCommitDecommit {
		D := make(HashDeCommitment, parts)
		for i := range D {
			D[i] = big.NewInt(int64(i + 1))
		}
		// A commitment that does not match, so Verify fails either way and the
		// only thing being measured is what it costs to find that out.
		return &HashCommitDecommit{C: big.NewInt(1), D: D}
	}
	measure := func(parts int) time.Duration {
		cmt := build(parts)
		best := time.Duration(1<<62 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			ok, _ := cmt.DeCommit()
			assert.False(t, ok, "a mismatched commitment must not open")
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	small := measure(7) // a threshold-2 committee: (2+1)*2 + 1
	large := measure(200000)

	t.Logf("DeCommit on a mismatched commitment: 7 parts=%s, 200000 parts=%s", small, large)
	assert.Greater(t, large, 20*small,
		"DeCommit is expected to scale with the part count (7=%s, 200000=%s); if it no "+
			"longer does, the four call sites that check the count before calling it "+
			"are still correct, but this test no longer says why", small, large)
}

// The part count is all that changes: DeCommit still opens a commitment whose
// decommitment matches, and still refuses one whose does not.
func TestDeCommitStillOpensAndRefuses(t *testing.T) {
	secrets := []*big.Int{big.NewInt(11), big.NewInt(22)}
	cmt := NewHashCommitmentWithRandomness(big.NewInt(99), secrets...)

	ok, values := cmt.DeCommit()
	assert.True(t, ok, "a matching decommitment must open")
	assert.Len(t, values, len(secrets), "the randomness is not part of the payload")

	tampered := &HashCommitDecommit{C: cmt.C, D: append(HashDeCommitment{big.NewInt(98)}, secrets...)}
	ok, _ = tampered.DeCommit()
	assert.False(t, ok, "a mismatched decommitment must not open")
}
