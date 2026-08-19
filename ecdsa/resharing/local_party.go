// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.ReSharingParameters

		temp        localTempData
		input, save keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *keygen.LocalPartySaveData
	}

	localMessageStore struct {
		dgRound1Messages,
		dgRound2Message1s,
		dgRound2Message2s,
		dgRound3Message1s,
		dgRound3Message2s,
		dgRound4Message1s,
		dgRound4Message2s []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after rounds)
		NewVs     vss.Vs
		NewShares vss.Shares
		VD        cmt.HashDeCommitment

		// temporary storage of data that is persisted by the new party in round 5 if all "ACK" messages are received
		newXi     *big.Int
		newKs     []*big.Int
		newBigXjs []*crypto.ECPoint // Xj to save in round 5

		ssid      []byte
		ssidNonce *big.Int
	}
)

// Exported, used in `tss` client
// The `key` is READ FROM and never written to. An old-committee party works on
// a deep copy of `key.LocalSecrets`, so nothing this library does reaches the
// caller's own save data. The copy is not total: LocalPreParams (PaillierSK,
// NTildei, H1i, H2i, Alpha, Beta, P, Q) is still shared with the caller.
// This library does not erase your pre-re-share secret -- and could not time it
// if it did. See doc/maintenance-invariants.md section 7.
//
// You may optionally generate and set the LocalPreParams if you would like to use pre-generated safe primes and Paillier secret.
// (This is similar to providing the `optionalPreParams` to `keygen.LocalParty`).
//
// PRE-PARAMS ARE REUSED, NOT ROTATED. If key.LocalPreParams validates in full it
// is kept, and this party carries the same Paillier private key and the same
// NTilde trapdoor, h1 and h2 into the new committee, byte for byte. Skipping
// minutes of safe-prime generation is the whole point of passing them in, but it
// is a trade-off and it is the caller's to make: re-sharing refreshes the VSS
// shares and refreshes NOTHING in LocalPreParams. A host re-sharing in order to
// recover from a suspected compromise of a party's Paillier key or NTilde
// trapdoor must leave LocalPreParams unset for that party, so that round 2
// generates a fresh set.
//
// An incomplete LocalPreParams -- Validate() true but ValidateWithProof() false,
// which is what an older version of tss-lib produced before it stored P, Q,
// Alpha and Beta -- cannot be used at all, because the round-2 DLN proofs need
// exactly those fields. It is dropped here and round 2 generates a fresh set,
// costing the caller the safe-prime generation they were trying to avoid. That
// is logged, not fatal. Note the asymmetry, which is deliberate but easy to trip
// over: keygen.NewLocalParty panics on the same bytes.
func NewLocalParty(
	params *tss.ReSharingParameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *keygen.LocalPartySaveData,
) tss.Party {
	oldPartyCount := len(params.OldParties().IDs())
	subset := key
	if params.IsOldCommittee() {
		subset = keygen.BuildLocalSaveDataSubset(key, params.OldParties().IDs())
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		input:     subset,
		save:      keygen.NewLocalPartySaveData(params.NewPartyCount()),
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.dgRound1Messages = make([]tss.ParsedMessage, oldPartyCount)           // from t+1 of Old Committee
	p.temp.dgRound2Message1s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound2Message2s = make([]tss.ParsedMessage, params.NewPartyCount()) // "
	p.temp.dgRound3Message1s = make([]tss.ParsedMessage, oldPartyCount)          // from t+1 of Old Committee
	p.temp.dgRound3Message2s = make([]tss.ParsedMessage, oldPartyCount)          // "
	p.temp.dgRound4Message1s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound4Message2s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	// save data init
	if key.LocalPreParams.ValidateWithProof() {
		p.save.LocalPreParams = key.LocalPreParams
	} else if key.LocalPreParams.Validate() {
		// Present but unusable. Dropping it without a word costs the caller a
		// fresh safe-prime generation in round 2 and gives them nothing to
		// explain it: this is the only place the discard is visible, because
		// round 2 sees the zero value and cannot tell it apart from "the caller
		// passed nothing".
		common.Logger.Warningf(
			"%s: the supplied LocalPreParams is incomplete (missing: %s) and is being discarded; "+
				"round 2 will generate a fresh set, which is the cost that passing pre-params was meant to avoid. "+
				"keygen.NewLocalParty panics on the same input",
			params.PartyID(), strings.Join(missingPreParamFields(key.LocalPreParams), ", "))
	}
	return p
}

// missingPreParamFields names the fields ValidateWithProof requires that
// Validate does not. It is meaningful only for a LocalPreParams that already
// passed Validate, which is what guarantees PaillierSK is non-nil here.
func missingPreParamFields(pre keygen.LocalPreParams) []string {
	fields := []struct {
		name string
		set  bool
	}{
		{"PaillierSK.P", pre.PaillierSK.P != nil},
		{"PaillierSK.Q", pre.PaillierSK.Q != nil},
		{"Alpha", pre.Alpha != nil},
		{"Beta", pre.Beta != nil},
		{"P", pre.P != nil},
		{"Q", pre.Q != nil},
	}
	missing := make([]string, 0, len(fields))
	for _, f := range fields {
		if !f.set {
			missing = append(missing, f.name)
		}
	}
	return missing
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.input, &p.save, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	var maxFromIdx int
	switch msg.Content().(type) {
	case *DGRound2Message1, *DGRound2Message2, *DGRound4Message1, *DGRound4Message2:
		maxFromIdx = len(p.params.NewParties().IDs()) - 1
	default:
		maxFromIdx = len(p.params.OldParties().IDs()) - 1
	}
	if maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round.
	// Each branch rejects intra-session message replacement: once a slot is
	// filled, a different-content message for it is rejected (idempotent
	// identical re-sends are tolerated via tss.IsSameMessage).
	//
	// Resharing spans two independent, overlapping committee index spaces:
	// old-committee-sourced slots (dgRound1Messages, dgRound3Message1s,
	// dgRound3Message2s) are indexed by the sender's OLD index, new-sourced
	// slots (dgRound2*, dgRound4*) by the sender's NEW index. A peer's index in
	// one committee can numerically equal this party's index in the other, so
	// p.PartyID().Index is NOT a safe self-echo discriminator: it would mis-read
	// a colliding cross-committee peer as "self" and skip the duplicate guard.
	// Detect our own echoes by sender IDENTITY (key) instead of by index.
	isDup := msg.GetFrom().KeyInt().Cmp(p.PartyID().KeyInt()) != 0

	dupErr := func() (bool, *tss.Error) {
		return false, p.WrapError(
			fmt.Errorf("duplicate %T from party %d", msg.Content(), fromPIdx),
			msg.GetFrom())
	}
	switch msg.Content().(type) {
	case *DGRound1Message:
		if isDup && p.temp.dgRound1Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound1Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound1Messages[fromPIdx] = msg
	case *DGRound2Message1:
		if isDup && p.temp.dgRound2Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound2Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound2Message1s[fromPIdx] = msg
	case *DGRound2Message2:
		if isDup && p.temp.dgRound2Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound2Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound2Message2s[fromPIdx] = msg
	case *DGRound3Message1:
		if isDup && p.temp.dgRound3Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message1s[fromPIdx] = msg
	case *DGRound3Message2:
		if isDup && p.temp.dgRound3Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message2s[fromPIdx] = msg
	case *DGRound4Message1:
		if isDup && p.temp.dgRound4Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound4Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound4Message1s[fromPIdx] = msg
	case *DGRound4Message2:
		if isDup && p.temp.dgRound4Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound4Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound4Message2s[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
