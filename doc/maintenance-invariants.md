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

## 6. `tss` re-sharing — the committees must stay disjoint

`tss.NewReSharingParameters` panics when a party key appears in both the old
and the new committee. It reads like over-strict input validation: nothing in
the maths forbids the same person holding a share before and after, and the
obvious "fix" for a caller who trips over it is to delete the check.

Deleting it silently re-opens a whole cascade, and **no test in this tree would
catch it**. Five `ok`-tracker pre-sets in the re-sharing rounds are gated on the
predicate for the SENDER role in that round, not on the negation of the
predicate for the RECEIVER role:

| site | pre-set | gated on | correct gate |
| --- | --- | --- | --- |
| `ecdsa/resharing/round_1_old_step_1.go:67` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `ecdsa/resharing/round_3_old_step_2.go:27` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `eddsa/resharing/round_1_old_step_1.go:66` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `eddsa/resharing/round_2_new_step_1.go:27` | `allNewOK()` | `IsNewCommittee()` | `!IsOldCommittee()` |
| `eddsa/resharing/round_3_old_step_2.go:27` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |

For a party in exactly one committee the two gates coincide, which is why the
code has always looked correct. For a party in both, each of those five lines
marks a message it is genuinely waiting for as already received. The party then
walks into the next round with empty message slots and dereferences them.

Those five lines are correct **only because the constructor now guarantees the
two committees are disjoint**. They are not defended by anything local to them.
If you need to change the disjointness rule, fix the five gates first.

The constructor's guarantee holds **at construction time only**.
`tss.NewPeerContext` keeps the caller's slice by reference,
`(*tss.PeerContext).SetIDs` replaces it wholesale, and the `*PartyID` values
remain owned by the caller — so a dual-role party can still be produced after
`NewReSharingParameters` has returned. The `rejectDualRole` guards at the top of
`Start()` and `Update()` in both `round_1_old_step_1.go` files exist for that
case. They are defence in depth, not redundancy: they stop the party before any
tracker bit is set and report **no culprits**, because a local misconfiguration
must not be attributed to an honest peer.

Related: `ecdsa/resharing/round_2_new_step_1.go:152-169` contains an
`IsOldCommittee() && IsNewCommittee()` branch written in 2019 for the dual-role
case. It is retained deliberately, as the record of what this rule replaces.

---

## Implementation note: signing round 2 is not seed-deterministic

`ecdsa/signing/round_2.go` runs `BobMid` and `BobMidWC` in two concurrent
goroutines that **share a single `round.Rand()` reader**. Under a fixed seed the
values drawn on each side therefore differ from run to run, while round 1
(single-threaded) is byte-for-byte reproducible.

Any test or diagnostic that asserts "two runs must agree byte for byte" has to
account for this, or it will report the library's own concurrency as a
reproducibility failure.
