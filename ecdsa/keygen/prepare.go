// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 8 * time.Second
	// Safe big len using random for ssid
	SafeBitLen = 1024
)

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the timeout, an error is returned.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return GeneratePreParamsWithContext(ctx, optionalConcurrency...)
}

// GeneratePreParamsWithContext finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the context is done, an error is returned.
func GeneratePreParamsWithContext(ctx context.Context, optionalConcurrency ...int) (*LocalPreParams, error) {
	return GeneratePreParamsWithContextAndRandom(ctx, rand.Reader, optionalConcurrency...)
}

// GeneratePreParamsWithContextAndRandom finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the context is done, an error is returned.
func GeneratePreParamsWithContextAndRandom(ctx context.Context, rand io.Reader, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if len(optionalConcurrency) > 0 {
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.GOMAXPROCS(0)
	}
	// paiSK, sgps, err := gen(ctx, rand, concurrency)
	paiSK, sgps, err := gen2(ctx, rand, concurrency)

	if err != nil {
		return nil, err
	}

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(rand, NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(rand, NTildei)
	beta := modPQ.ModInverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}

func gen(ctx context.Context, rand io.Reader, concurrency int) (*paillier.PrivateKey, []*common.GermainSafePrime, error) {
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}
	g := &errgroup.Group{}
	// 4. generate Paillier public key E_i, private key and proof
	var paiSK *paillier.PrivateKey

	g.Go(func() error {
		var err error
		common.Logger.Info("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		paiSK, _, err = paillier.GenerateKeyPair(ctx, rand, paillierModulusLen, concurrency*2)
		if err != nil {
			return errors.Wrap(err, "GenerateKeyPair")
		}
		common.Logger.Infof("paillier modulus generated. took %s\n", time.Since(start))
		if paiSK == nil {
			return errors.New("timeout or error while generating the Paillier secret key")
		}
		return nil
	})

	// 5-7. generate safe primes for ZKPs used later on
	var sgps []*common.GermainSafePrime
	g.Go(func() error {
		var err error
		common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
		start := time.Now()
		sgps, err = common.GetRandomSafePrimesConcurrent(ctx, safePrimeBitLen, 2, concurrency, rand)
		if err != nil {
			return errors.Wrap(err, "GetRandomSafePrimesConcurrent")
		}
		common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))
		if sgps == nil ||
			sgps[0] == nil || sgps[1] == nil ||
			!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
			!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
			return errors.New("timeout or error while generating the safe primes")
		}
		return nil
	})
	err := g.Wait()
	return paiSK, sgps, err
}

func gen2(ctx context.Context, rand io.Reader, concurrency int) (*paillier.PrivateKey, []*common.GermainSafePrime, error) {
	// 生成paillier和safe prime用相同并发数，一方完成后，另一方可以使用全部cpu资源并发生成
	// 经测试，这种方式比gen方式更快一些
	if concurrency < 2 {
		concurrency = 2
	}
	g := &errgroup.Group{}
	// 4. generate Paillier public key E_i, private key and proof
	var paiSK *paillier.PrivateKey

	g.Go(func() error {
		var err error
		common.Logger.Info("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		paiSK, _, err = paillier.GenerateKeyPair(ctx, rand, paillierModulusLen, concurrency)
		if err != nil {
			return errors.Wrap(err, "GenerateKeyPair")
		}
		common.Logger.Infof("paillier modulus generated. took %s\n", time.Since(start))
		if paiSK == nil {
			return errors.New("timeout or error while generating the Paillier secret key")
		}
		return nil
	})

	// 5-7. generate safe primes for ZKPs used later on
	var sgps []*common.GermainSafePrime
	g.Go(func() error {
		var err error
		common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
		start := time.Now()
		sgps, err = common.GetRandomSafePrimesConcurrent(ctx, safePrimeBitLen, 2, concurrency, rand)
		if err != nil {
			return errors.Wrap(err, "GetRandomSafePrimesConcurrent")
		}
		common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))
		if sgps == nil ||
			sgps[0] == nil || sgps[1] == nil ||
			!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
			!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
			return errors.New("timeout or error while generating the safe primes")
		}
		return nil
	})
	err := g.Wait()
	return paiSK, sgps, err
}
