# Frozen conformance vectors — spend-proof memo binding

These files pin every deterministic byte mapping the `midnight_zswap::memo`
helpers perform: the `MemoHashV1` derivation, the `AnchorV1` ciphertext layout
and its untagged wire form, and the off-chain `MemoWrapperV1` container.

`tests/memo_vectors.rs` replays all of them. **Nothing in this crate generates
them.** They are byte-exact copies of an *external* implementation's frozen
vectors, which is the whole point: a conformance vector produced by the code it
is meant to check proves only that the code is self-consistent.

| File | Records | SHA-256 | Origin |
| --- | --- | --- | --- |
| `memo-hash.txt` | 18 | `3a359f37aef19ef3e7c1e50fc73f1d887154f5a19019f4c74c1dde3f04b7ce6b` | external toolkit |
| `anchor.txt` | 6 | `091073b2f6f4dd12e523b51583505bd1c2e9c87665bb3c0a692e65fc1b42bbc3` | external toolkit |
| `wrapper.txt` | 6 | `35c630086b66413363a241ea3d82fd034bff9be47a01386edd052729dd018563` | external toolkit |
| `inherited/00001-memo-hash.txt` | 6 | `1e9b9378e28e1833e5ea040219cd3029c77ebe800a0b7e883752ce90b71ed115` | a *third* implementation's published conformance table |
| `inherited/00002-packing.txt` | 6 | `4ab3704e6e78027c5dbe401f5a240ad243639bae5e5f8dce57e3aa0dcdbb2d5a` | a *fourth* implementation, byte-exact copy |
| `inherited/00003-phase0-anchor.txt` | 1 | `86b2f27b8aaf7934252cc6c6d48262e3dc63f2619fa1308367526839190f2d48` | an anchor the **unmodified node** validated, applied and finalized |

`inherited/PROVENANCE.md` carries the full provenance of the last three.

The last row is worth reading twice. That anchor's ciphertext is not a value
some library agreed with itself about — it is the exact ciphertext that went
into a transaction an unmodified node accepted. Reproducing it here means these
helpers emit bytes a live network has already settled.

## Format

Records are separated by blank lines. Every non-comment line is `key: value`;
`#` starts a comment. Byte strings are single-line lowercase hex with no
separators. Field elements are 32-byte **little-endian** encodings of `Fr`.
Keys may repeat (`field:`), and repeats are read in order.

## Do not edit

If a change here is ever needed, it is a format change, and every implementation
that speaks this format has to change with it. Editing a vector to make a test
pass would destroy the only property these files have.
