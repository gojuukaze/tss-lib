// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

var (
	eight    = big.NewInt(8)
	eightInv = new(big.Int).ModInverse(eight, edwards.Edwards().Params().N)
)

// Creates a new ECPoint and checks that the given coordinates are on the elliptic curve.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

// Creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	// SECURITY (SRC-2026-641): a nil operand means an upstream
	// ScalarMult/ScalarBaseMult returned nil (identity / off-curve result).
	// Return an error instead of dereferencing nil via X()/Y() so callers can
	// attribute the failure to the responsible peer rather than crashing the
	// process. Every Add call site already checks the returned error.
	if p == nil || p1 == nil {
		return nil, errors.New("ECPoint.Add: nil operand")
	}
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

// ScalarMult returns p * k. When k ≡ 0 mod n (identity) or any other input
// produces an off-curve representation, ScalarMult returns nil rather than
// panicking. Callers MUST check the returned pointer before use; pairs of
// hardened call sites (Schnorr / VSS / MtA Verify) validate scalars upstream,
// so a nil return here indicates either an unvalidated direct API consumer
// or a degenerate honest case (zero contribution) that should be treated as
// an error by the protocol.
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	// 旧版合并了https://github.com/bnb-chain/tss-lib/pull/295/files 这个修改，
	// 不确定v4版是否需要
	if p == nil || k == nil {
		return nil
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	newP, err := NewECPoint(p.curve, x, y)
	if err != nil {
		return nil
	}
	return newP
}

// ScalarMultErr is the explicit-error variant of ScalarMult. Returns
// (*ECPoint, error) instead of the nil-on-error convention; useful for
// internal callers that want to propagate the curve error.
func (p *ECPoint) ScalarMultErr(k *big.Int) (*ECPoint, error) {
	if p == nil {
		return nil, errors.New("ScalarMultErr: receiver is nil")
	}
	if k == nil {
		return nil, errors.New("ScalarMultErr: scalar k is nil")
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) ToECDSAPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

func (p *ECPoint) IsOnCurve() bool {
	return isOnCurve(p.curve, p.coords[0], p.coords[1])
}

func (p *ECPoint) Curve() elliptic.Curve {
	return p.curve
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve() && !p.IsIdentity()
}

// IsIdentity reports whether p represents the identity element of its
// curve. The two affine representations checked here cover both curve
// families used by tss-lib:
//
//   - Edwards-form curves (Ed25519 via decred/dcrd/dcrec/edwards/v2):
//     the affine identity is (0, 1) and IS on-curve, so it passes the
//     isOnCurve test alone. Without this check, a malicious party can
//     submit (0, 1) as a Schnorr proof's commitment or as a VSS share
//     and the verifier accepts a degenerate proof.
//   - Weierstrass-form curves (secp256k1, NIST): the identity is the
//     point-at-infinity, conventionally (0, 0) in affine form. That
//     coordinate is NOT on-curve and is already rejected by isOnCurve.
//     The (0, 0) branch here is defense-in-depth in case future curve
//     code surfaces a different infinity representation.
//
// Returns false for nil points (no coordinate to inspect).
func (p *ECPoint) IsIdentity() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil {
		return false
	}
	if p.coords[0].Sign() != 0 {
		return false
	}
	return p.coords[1].Sign() == 0 || p.coords[1].Cmp(big.NewInt(1)) == 0
}

// IsInPrimeOrderSubgroup reports whether p lies in the prime-order
// subgroup of its curve, i.e. `[curve.N] * p == identity` where
// `curve.N` is the prime subgroup order.
//
// For prime-order curves (cofactor 1 — secp256k1 / NIST), every on-curve
// point trivially satisfies this by Lagrange's theorem; the explicit
// computation here just confirms it at the cost of one extra ScalarMult.
//
// For composite-cofactor curves (Ed25519, cofactor 8) the check is
// load-bearing: on-curve membership alone admits 8 small-order points
// (the cofactor subgroup) that an adversary can submit as a Schnorr
// commitment, VSS share, etc. to mount small-subgroup attacks. Callers
// in those code paths should use this check (typically via
// ValidateInSubgroup) on every untrusted EC point.
//
// Returns false for nil points or points whose [N]·p does not yield the
// identity element.
func (p *ECPoint) IsInPrimeOrderSubgroup() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil || p.curve == nil {
		return false
	}
	n := p.curve.Params().N
	np := p.ScalarMult(n)
	if np == nil {
		// ScalarMult returns nil when the curve.ScalarMult result is the
		// point-at-infinity (rejected by isOnCurve on Weierstrass). That
		// IS the identity / prime-order witness for those curves.
		return true
	}
	return np.IsIdentity()
}

// ValidateInSubgroup is the stricter sibling of ValidateBasic for
// untrusted EC points on curves with composite cofactor. It runs the
// basic on-curve / non-identity / non-nil checks and additionally
// requires the point to live in the prime-order subgroup. On
// prime-order curves (cofactor 1) the subgroup check is structurally
// guaranteed by IsOnCurve and is skipped to save a ScalarMult.
//
// Callers consuming attacker-controlled EC points (Schnorr Alpha / X /
// V / R, VSS vs[j], MtA ProofBobWC pf.U, etc.) should prefer this over
// ValidateBasic.
func (p *ECPoint) ValidateInSubgroup() bool {
	if !p.ValidateBasic() {
		return false
	}
	if !tss.HasCompositeCofactor(p.curve) {
		return true
	}
	return p.IsInPrimeOrderSubgroup()
}

func (p *ECPoint) EightInvEight() *ECPoint {
	q := p.ScalarMult(eight)
	if q == nil {
		return nil
	}
	return q.ScalarMult(eightInv)
}

// ScalarBaseMult returns g * k (curve base point times k). On any error
// (including k ≡ 0 mod n which yields the off-curve identity) returns nil.
// See ScalarMult doc for the nil-on-error rationale.
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	// 旧版合并了https://github.com/bnb-chain/tss-lib/pull/295/files 这个修改，
	// 不确定v4版是否需要
	if curve == nil || k == nil {
		return nil
	}
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, err := NewECPoint(curve, x, y)
	if err != nil {
		return nil
	}
	return p
}

// ScalarBaseMultErr is the explicit-error variant of ScalarBaseMult.
func ScalarBaseMultErr(curve elliptic.Curve, k *big.Int) (*ECPoint, error) {
	if curve == nil {
		return nil, errors.New("ScalarBaseMultErr: curve is nil")
	}
	if k == nil {
		return nil, errors.New("ScalarBaseMultErr: scalar k is nil")
	}
	x, y := curve.ScalarBaseMult(k.Bytes())
	return NewECPoint(curve, x, y)
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	// Reject coordinates outside [0, P) to prevent non-canonical point representations
	// from bypassing the curve equation check via modular reduction (SRC-2026-573).
	P := c.Params().P
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
		return false
	}
	return c.IsOnCurve(x, y)
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

// ----- //
// Gob helpers for if you choose to encode messages with Gob.

func (p *ECPoint) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	x, err := p.coords[0].GobEncode()
	if err != nil {
		return nil, err
	}
	y, err := p.coords[1].GobEncode()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(len(x)))
	if err != nil {
		return nil, err
	}
	buf.Write(x)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(y)))
	if err != nil {
		return nil, err
	}
	buf.Write(y)

	return buf.Bytes(), nil
}

func (p *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	x := make([]byte, length)
	n, err := reader.Read(x)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	y := make([]byte, length)
	n, err = reader.Read(y)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}

	X := new(big.Int)
	if err := X.GobDecode(x); err != nil {
		return err
	}
	Y := new(big.Int)
	if err := Y.GobDecode(y); err != nil {
		return err
	}
	p.curve = tss.EC()
	p.coords = [2]*big.Int{X, Y}
	if !p.IsOnCurve() {
		return errors.New("ECPoint.UnmarshalJSON: the point is not on the elliptic curve")
	}
	return nil
}

// ----- //

// crypto.ECPoint is not inherently json marshal-able
func (p *ECPoint) MarshalJSON() ([]byte, error) {
	ecName, ok := tss.GetCurveName(p.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", p.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: p.coords,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		p.curve = ec
	} else {
		// forward compatible, use global ec as default value
		p.curve = tss.EC()
	}

	if !p.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", p.curve)
	}

	return nil
}
