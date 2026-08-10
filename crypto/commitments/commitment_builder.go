// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments

import (
	"errors"
	"fmt"
	"math/big"
)

const (
	PartsCap    = 3
	MaxPartSize = int64(1 * 1024 * 1024) // 1 MB - rather liberal
)

type builder struct {
	parts [][]*big.Int
}

func NewBuilder() *builder {
	b := new(builder)
	b.parts = make([][]*big.Int, 0, PartsCap)
	return b
}

func (b *builder) Parts() [][]*big.Int {
	return b.parts[:]
}

func (b *builder) AddPart(part []*big.Int) *builder {
	b.parts = append(b.parts, part[:])
	return b
}

func (b *builder) Secrets() ([]*big.Int, error) {
	secretsLen := 0
	if len(b.parts) > PartsCap {
		return nil, fmt.Errorf("builder.Secrets: too many commitment parts provided: got %d, max %d", len(b.parts), PartsCap)
	}
	for _, p := range b.parts {
		secretsLen += 1 + len(p) // +1 to accommodate length prefix element
	}
	secrets := make([]*big.Int, 0, secretsLen)
	for i, p := range b.parts {
		partLen := int64(len(p))
		if MaxPartSize < partLen {
			return nil, fmt.Errorf("builder.Secrets: commitment part too large: part %d, size %d", i, partLen)
		}
		secrets = append(secrets, big.NewInt(partLen))
		secrets = append(secrets, p...)
	}
	return secrets, nil
}

func ParseSecrets(secrets []*big.Int) ([][]*big.Int, error) {
	if secrets == nil || len(secrets) < 2 {
		return nil, errors.New("ParseSecrets: secrets == nil or is too small")
	}
	var el, nextPartLen int64
	parts := make([][]*big.Int, 0, PartsCap)
	isLenEl := true // are we looking at a length prefix element? (first one is)
	inLen := int64(len(secrets))
	for el < inLen {
		if el < 0 {
			return nil, errors.New("ParseSecrets: `el` overflow")
		}
		if isLenEl {
			nextPartLen = secrets[el].Int64()
			// The slice expression below, secrets[el : el+nextPartLen], requires
			// 0 <= el <= el+nextPartLen <= len(secrets). `el` is guarded above;
			// the upper end is guarded by MaxPartSize plus the length check in
			// the data branch. The LOWER end of nextPartLen was unguarded.
			//
			// A length prefix is only ever produced by builder.Secrets() above,
			// as big.NewInt(int64(len(p))), and len() of a Go slice is never
			// negative, so this library never emits a negative prefix. The prefix
			// decoded here, however, comes off the wire via big.Int.SetBytes, and
			// Int64() reinterprets the low 64 bits: any prefix with bit 63 set
			// decodes to a NEGATIVE length, which "MaxPartSize < nextPartLen"
			// does not catch and which reaches the slice expression.
			//
			// Deliberately narrow: this rejects only the negative case, so every
			// input the parser accepted before is still accepted, unchanged.
			// In particular a prefix >= 2^64 whose low 64 bits are non-negative
			// still truncates silently, exactly as it did before this check.
			if nextPartLen < 0 {
				return nil, fmt.Errorf("ParseSecrets: negative commitment part length: part %d, decoded %d (bitLen %d)", len(parts), nextPartLen, secrets[el].BitLen())
			}
			if MaxPartSize < nextPartLen {
				return nil, fmt.Errorf("ParseSecrets: commitment part too large: part %d, size %d", len(parts), nextPartLen)
			}
			el += 1
		} else {
			if PartsCap <= len(parts) {
				return nil, fmt.Errorf("ParseSecrets: commitment has too many parts: part %d, max %d", len(parts), PartsCap)
			}
			if inLen < el+nextPartLen {
				return nil, errors.New("ParseSecrets: not enough data to consume stated data length")
			}
			part := secrets[el : el+nextPartLen]
			parts = append(parts, part)
			el += nextPartLen
		}
		isLenEl = !isLenEl
	}
	return parts, nil
}
