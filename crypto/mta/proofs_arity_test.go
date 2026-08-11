// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// tenNonEmptyParts is a well-formed ProofBob serialisation: exactly the arity
// ProofBobFromBytes accepts on its own.
func tenNonEmptyParts() [][]byte {
	bzs := make([][]byte, ProofBobBytesParts)
	for i := range bzs {
		bzs[i] = []byte{1}
	}
	return bzs
}

// ProofBobFromBytes accepts either arity by design, so ProofBobWCFromBytes may
// not rely on it to establish that parts 10 and 11 exist. Ten parts must be
// rejected with an error, not walk off the end of the slice.
func TestProofBobWCFromBytesRejectsProofBobArity(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of returning an error: %v", r)
		}
	}()

	pf, err := ProofBobWCFromBytes(btcec.S256(), tenNonEmptyParts())
	if err == nil {
		t.Fatal("expected an error for a ten-part input")
	}
	if pf != nil {
		t.Fatalf("expected a nil proof alongside the error, got %v", pf)
	}
}

// The plain ProofBob path must keep accepting ten parts, or the fix above would
// pass by tightening the wrong function.
func TestProofBobFromBytesStillAcceptsTenParts(t *testing.T) {
	if _, err := ProofBobFromBytes(tenNonEmptyParts()); err != nil {
		t.Fatalf("ProofBobFromBytes must still accept %d parts: %v", ProofBobBytesParts, err)
	}
}
