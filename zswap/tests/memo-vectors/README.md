# Frozen conformance vectors — spend-proof memo binding

These files pin every deterministic byte mapping the `midnight_zswap::memo`
helpers perform: the `MemoHashV1` derivation, the `AnchorV1` ciphertext layout
and its untagged wire form, and the off-chain `MemoWrapperV1` container — and,
since `statement.txt`, the **complete 68-row public spend statement** those
helpers restate from `Input::<Proof>::well_formed`.

`tests/memo_vectors.rs` replays all of them. **Nothing in this crate generates
them.** They are byte-exact copies of an *external* implementation's frozen
vectors, which is the whole point: a conformance vector produced by the code it
is meant to check proves only that the code is self-consistent.

| File | Records | SHA-256 | Origin |
| --- | --- | --- | --- |
| `memo-hash.txt` | 18 | `3a359f37aef19ef3e7c1e50fc73f1d887154f5a19019f4c74c1dde3f04b7ce6b` | external toolkit |
| `anchor.txt` | 6 | `091073b2f6f4dd12e523b51583505bd1c2e9c87665bb3c0a692e65fc1b42bbc3` | external toolkit |
| `wrapper.txt` | 6 | `35c630086b66413363a241ea3d82fd034bff9be47a01386edd052729dd018563` | external toolkit |
| `statement.txt` | 18 | `caa3e6709b3511dbd8df07cc6563481892de0212d36bf0eecbb1a637f9fee2e7` | external toolkit |
| `inherited/00001-memo-hash.txt` | 6 | `1e9b9378e28e1833e5ea040219cd3029c77ebe800a0b7e883752ce90b71ed115` | a *third* implementation's published conformance table |
| `inherited/00002-packing.txt` | 6 | `4ab3704e6e78027c5dbe401f5a240ad243639bae5e5f8dce57e3aa0dcdbb2d5a` | a *fourth* implementation, byte-exact copy |
| `inherited/00003-phase0-anchor.txt` | 1 | `86b2f27b8aaf7934252cc6c6d48262e3dc63f2619fa1308367526839190f2d48` | an anchor the **unmodified node** validated, applied and finalized |

`inherited/PROVENANCE.md` carries the full provenance of the last three.

The `inherited/00003-phase0-anchor.txt` row is worth reading twice. That
anchor's ciphertext is not a value some library agreed with itself about — it is
the exact ciphertext that went into a transaction an unmodified node accepted.
Reproducing it here means these helpers emit bytes a live network has already
settled.

`statement.txt` is the one file that pins **meaning** rather than a byte layout.
Each record carries the source public fields of one spend — nullifier,
merkle-tree root, value-commitment coordinates, contract address or `-`, segment
— plus a row-0 specification (`zero`, or memo bytes whose `MemoHashV1` is the
override), and then all 68 rows those fields derive. `tests/memo_vectors.rs`
replays it by rebuilding a proof-free `Input` from the source fields and
re-deriving every row through `verify::spend_statement`: nothing is re-hashed,
no frozen row is fed back into the derivation, and `h` is computed from the memo
bytes rather than read. The external toolkit wrote its restatement of
`Input::<Proof>::well_formed` separately from this crate's, so agreement across
{user, contract} × segments {0, 1, 3, 65535} × row 0 ∈ {0, `h`} is a genuine
cross-implementation result. Its final record, `statement/wrapper-binding`, is a
complete wrapper container whose statement section is a real derived statement
tail — the link between the codec files and this one.

No prover, key material or randomness is involved in any value in
`statement.txt`; the derivation is a pure function of public inputs.

## Format

Records are separated by blank lines. Every non-comment line is `key: value`;
`#` starts a comment. Byte strings are single-line lowercase hex with no
separators. Field elements are 32-byte **little-endian** encodings of `Fr`.
Keys may repeat (`field:`), and repeats are read in order.

## Do not edit

If a change here is ever needed, it is a format change, and every implementation
that speaks this format has to change with it. Editing a vector to make a test
pass would destroy the only property these files have.
