// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"
	"testing"
)

// The new committee cannot recompute the old committee's ssid: its pre-image is
// the OLD save data. sessionNonceHash is the one value it can check against
// something of its own, so it has to be a function of the nonce and nothing else.
func TestSessionNonceHashSeparatesSessions(t *testing.T) {
	h1 := sessionNonceHash(big.NewInt(1))
	h2 := sessionNonceHash(big.NewInt(2))
	if len(h1) == 0 || len(h2) == 0 {
		t.Fatal("hash must not be empty for a valid nonce")
	}
	if string(h1) == string(h2) {
		t.Fatal("two different session nonces must not produce the same hash")
	}
	if string(h1) != string(sessionNonceHash(big.NewInt(1))) {
		t.Fatal("the hash must be deterministic")
	}
	if sessionNonceHash(nil) != nil {
		t.Fatal("a nil nonce yields no hash rather than a hash of nothing")
	}
}

// ValidateBasic must REQUIRE the field. An absent hash is exactly what a
// transcript captured before this field existed carries, and it must not be
// laundered into "nothing to compare".
func TestDGRound1MessageRequiresSessionNonceHash(t *testing.T) {
	full := &DGRound1Message{
		EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4}, SessionNonceHash: []byte{5},
	}
	if !full.ValidateBasic() {
		t.Fatal("a complete message must still validate")
	}
	missing := &DGRound1Message{
		EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4},
	}
	if missing.ValidateBasic() {
		t.Fatal("a message with no session nonce hash must be rejected")
	}
}
