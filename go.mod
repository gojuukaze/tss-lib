module github.com/bnb-chain/tss-lib/v4

go 1.25.3

require (
	filippo.io/bigmod v0.1.0
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12
	github.com/btcsuite/btcd v0.25.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.6
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.4
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ipfs/go-log v1.0.5
	github.com/otiai10/primes v0.4.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.49.0
	golang.org/x/sync v0.20.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
