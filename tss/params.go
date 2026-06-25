// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/v4/common"
)

type (
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// sessionNonce provides per-session SSID uniqueness for GG20 session binding.
		// For signing, defaults to the message hash if not set.
		// For keygen/resharing, the caller SHOULD set this to a value agreed upon by
		// all parties (e.g., a coordinator-assigned session ID) to prevent cross-session
		// proof replay. If not set, falls back to 0 (no session binding).
		sessionNonce *big.Int
		// for legacy keygen/resharing compatibility only. This flag weakens
		// proof verification and should not be enabled in production.
		// NOTE: the former noProofMod flag was removed (SRC-2026-926) —
		// Paillier and NTilde ModProof verification is now mandatory, because
		// ModProof is the only check that proves a peer's modulus is a true
		// biprime (no small factors), without which a smooth/factorable
		// modulus enables full MtA key-share extraction.
		noProofFac bool
		// random sources
		partialKeyRand, rand io.Reader
	}

	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client.
//
// Panics on invalid threshold / partyCount inputs (threshold < 1,
// partyCount < 2, or threshold >= partyCount). These constraints come
// from Shamir VSS — a valid (t, n) threshold scheme requires
// 1 <= t < n with n >= 2. Invalid combinations would otherwise surface
// as opaque panics deep in protocol execution; failing here gives
// callers an immediate, clear signal.
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
	if partyCount < 2 {
		panic(fmt.Errorf("NewParameters: partyCount must be >= 2, got %d", partyCount))
	}
	if threshold < 1 {
		panic(fmt.Errorf("NewParameters: threshold must be >= 1, got %d", threshold))
	}
	if threshold >= partyCount {
		panic(fmt.Errorf("NewParameters: threshold must be < partyCount, got t=%d n=%d",
			threshold, partyCount))
	}
	// Reject PartyID sets whose keys collide modulo the curve order q.
	// SortPartyIDs dedups raw bytes, but Lagrange arithmetic downstream
	// (eddsa/ecdsa signing prepare.go, vss.Shares.ReConstruct) treats
	// ID as `ID mod q`. A malicious party registering key = honest_key + q
	// passes SortPartyIDs but causes `ModInverse((kj - ki) mod q, q)` to
	// hit a zero divisor and panic at signing time. Fail here instead so
	// the bad configuration never reaches a protocol round.
	if ctx != nil {
		assertDistinctIDsModQ(ec, ctx.IDs())
	}
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
		partialKeyRand:      rand.Reader,
		rand:                rand.Reader,
	}
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) Concurrency() int {
	return params.concurrency
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// The concurrency level must be >= 1.
func (params *Parameters) SetConcurrency(concurrency int) {
	params.concurrency = concurrency
}

func (params *Parameters) SetSafePrimeGenTimeout(timeout time.Duration) {
	params.safePrimeGenTimeout = timeout
}

func (params *Parameters) NoProofFac() bool {
	return params.noProofFac
}

func (params *Parameters) SetNoProofFac() {
	common.Logger.Warningf("SetNoProofFac enables legacy compatibility mode and weakens proof verification; do not use in production")
	params.noProofFac = true
}

func (params *Parameters) PartialKeyRand() io.Reader {
	return params.partialKeyRand
}

func (params *Parameters) Rand() io.Reader {
	return params.rand
}

func (params *Parameters) SetPartialKeyRand(rand io.Reader) {
	params.partialKeyRand = rand
}

func (params *Parameters) SetRand(rand io.Reader) {
	params.rand = rand
}

// SessionNonce returns the per-session nonce for SSID uniqueness.
// Returns nil if not set.
func (params *Parameters) SessionNonce() *big.Int {
	return params.sessionNonce
}

// SetSessionNonce sets a per-session nonce that all parties must agree on.
// This value is mixed into the SSID to provide GG20 session binding, preventing
// cross-session proof replay attacks. All parties in the same session MUST use
// the same nonce value. The caller is responsible for coordinating this.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	params.sessionNonce = nonce
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) *ReSharingParameters {
	params := NewParameters(ec, ctx, partyID, partyCount, threshold)
	// Apply the same mod-q distinctness check to the new committee. The
	// new committee participates in VSS and Lagrange too, so a collision
	// inside it would be just as fatal as one in the old committee.
	if newCtx != nil {
		assertDistinctIDsModQ(ec, newCtx.IDs())
	}
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}
}

// assertDistinctIDsModQ panics if any two ids share the same `KeyInt() mod q`
// residue, or if any single id reduces to 0 mod q.
//
// Mod-q collisions would later trigger a `ModInverse(0, q)` zero-divisor
// panic deep inside signing / VSS reconstruction.
//
// A zero residue is fatal in a different way: in Shamir secret sharing
// the polynomial is evaluated at the party's key, and f(0) is the
// shared secret itself. A party with `KeyInt() mod q == 0` would,
// post-Lagrange, either receive the raw secret as their share (if
// keygen flowed through `vss.Create` directly without `CheckIndexes`)
// or cause peer Lagrange coefficients to collapse to 0 / nil at
// signing time (see `ecdsa/signing/prepare.go` `iota = ksc *
// ModInverse(...)` — when `ksc mod q == 0`, `iota == 0`, and
// `bigWj.ScalarMult(0)` returns nil, panicking on the next chained
// op). vss.Create already rejects zero IDs via `CheckIndexes`, but
// rejecting here as well gives a clear, locally-attributable error
// and defends external direct-API consumers that bypass `vss.Create`
// (e.g. loading legacy `LocalPartySaveData` and going straight to
// signing).
func assertDistinctIDsModQ(ec elliptic.Curve, ids []*PartyID) {
	if ec == nil {
		return
	}
	q := ec.Params().N
	seen := make(map[string]string, len(ids))
	for _, id := range ids {
		if id == nil || id.KeyInt() == nil {
			continue
		}
		residueBig := new(big.Int).Mod(id.KeyInt(), q)
		if residueBig.Sign() == 0 {
			panic(fmt.Errorf("NewParameters: party key %s is congruent to 0 mod q; this would reveal the Shamir secret as the party's share and would cause zero Lagrange coefficients at signing time",
				id.KeyInt().Text(16)))
		}
		residue := residueBig.Text(16)
		if prior, exists := seen[residue]; exists {
			panic(fmt.Errorf("NewParameters: party keys %s and %s collide mod q (residue 0x%s); the Lagrange interpolation would hit a zero divisor at signing time",
				prior, id.KeyInt().Text(16), residue))
		}
		seen[residue] = id.KeyInt().Text(16)
	}
}

func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	return rgParams.partyCount
}

func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}
