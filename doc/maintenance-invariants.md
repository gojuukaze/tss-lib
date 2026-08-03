# Maintenance invariants

Properties that the implementation depends on and that are **not** obvious from
the code they live in. Every item below reads like a harmless cleanup,
simplification or optimisation when viewed locally. None of them is.

If you are about to change something on this list, the change may still be
right — but it needs analysis first, not just a green test run. The test suite
does not cover most of these.

---

## 1. `crypto/dlnproof` — keep the proof bidirectional

The proof shows that the two bases generate the *same* group; it does not show
*which* group. That reads like an incompleteness worth tightening, and it is a
natural target for anyone reconciling the comments with what the code enforces.

Leave it alone. That "same group" property is what the surrounding construction
relies on, and it is verified in both directions for a reason. Removing either
direction, or replacing the pair with a single stronger-looking check, changes
which rings production keygen will accept.

## 2. `crypto/mta` — do not shrink the `betaPrm` sampling interval

`BobMid` and `BobMidWC` sample the additive mask from `[0, q^5)`. A smaller
interval means smaller ciphertexts and less bandwidth, so it looks like free
savings.

The interval width *is* the security margin here: it exceeds the range of the
masked product by `2·log2(q)` = 512 bits, and narrowing the interval consumes
that margin one bit for one bit. Note also that the value being masked is not
of the same nature on both paths — on the `BobMidWC` side it is long-lived — so
an argument that holds for one call site does not automatically hold for the
other.

## 3. `crypto/modproof` — `K = 80` is a security parameter

Eighty iterations of modular exponentiation is the dominant cost of
`ProofMod.Verify`, which makes `K` look like a tuning knob.

`Verify` contains no direct structural test of the modulus — the property it
attests is forced only indirectly, through those iterations, and the strength
degrades as `K` falls. Treat it the same way you would treat a hash output
length.

## 4. `ecdsa/signing` — the nonce convention is load-bearing

The library derives `R` from the *inverse* of the nonce. This is not an
arbitrary implementation choice: several analyses of this code depend on it, and
changing it to the direct form alters the algebraic relation that downstream
reasoning is built on. Do not switch conventions as part of a refactor.

## 5. `crypto/facproof` — read the scope note before relying on it

See the block comment above `ProofFac` in `crypto/facproof/proof.go`. It bounds
the shape of a declared factorisation, not the primality of its parts. The
checks that cover factor size live in `crypto/modproof` and `crypto/paillier`,
which is why neither of those may be skipped (the `NoProofMod` and `NoProofFac`
compatibility switches have both been removed).

---

## Implementation note: signing round 2 is not seed-deterministic

`ecdsa/signing/round_2.go` runs `BobMid` and `BobMidWC` in two concurrent
goroutines that **share a single `round.Rand()` reader**. Under a fixed seed the
values drawn on each side therefore differ from run to run, while round 1
(single-threaded) is byte-for-byte reproducible.

Any test or diagnostic that asserts "two runs must agree byte for byte" has to
account for this, or it will report the library's own concurrency as a
reproducibility failure.
