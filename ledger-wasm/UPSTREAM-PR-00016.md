# Upstream proposal: cut a collapsed update from a `DustLocalState`

Branch `feat/00016-dust-collapsed-updates`, a fast-forward of
`feat/expose-system-transaction-hash` @ `ebe6aa53`.

## The gap

A `MerkleTreeCollapsedUpdate` lets one party hand another the aligned subtree hashes for a range
of leaves the second party does not need to see individually. The ledger already supports both
halves of that exchange for DUST — except from the side that actually has the data.

| | commitment tree | generating tree |
|---|---|---|
| **produce** an update from the **chain** state | `MerkleTreeCollapsedUpdate::new(&DustUtxoState.commitments, …)`, wasm `DustStateMerkleTreeCollapsedUpdate.newFromCommitmentTree` | `…new(&DustGenerationState.generating_tree, …)`, wasm `…newFromGenerationTree` |
| **produce** an update from a **`DustLocalState`** | *missing* | *missing* |
| **apply** an update to a `DustLocalState` | `apply_commitment_collapsed_update`, wasm `applyCommitmentCollapsedUpdate` | `apply_generation_collapsed_update`, wasm `applyGenerationCollapsedUpdate` |

The producing side of a wallet-sync service is not a node holding a `LedgerState`. Replaying the
chain's DUST ledger events into a `DustLocalState` with a key that owns nothing reproduces both
trees leaf for leaf — every leaf is collapsed individually, so every internal node survives, which
is exactly the shape a collapsed update is cut from — and costs one replay for all wallets rather
than one full ledger replay per wallet. Today that state can *apply* updates but cannot *cut*
them, so the service has to keep a chain-side `DustUtxoState`/`DustGenerationState` it has no
other use for, or reconstruct a `LedgerState` from blocks.

## The change

Two methods on `DustLocalState`, the exact inverses of the `apply_*_collapsed_update` pair
already on the type, plus the two `first_free` accessors a caller needs to form a range they will
accept (the fields are private and had no getter):

```rust
pub fn collapsed_commitment_update(&self, start: u64, end: u64)
    -> Result<MerkleTreeCollapsedUpdate, DustLocalStateError>;
pub fn collapsed_generation_update(&self, start: u64, end: u64)
    -> Result<MerkleTreeCollapsedUpdate, DustLocalStateError>;
pub fn commitment_tree_first_free(&self) -> u64;
pub fn generating_tree_first_free(&self) -> u64;
```

```ts
collapsedCommitmentUpdate(commitmentIndexStart: bigint, commitmentIndexEnd: bigint): DustStateMerkleTreeCollapsedUpdate;
collapsedGenerationUpdate(generationIndexStart: bigint, generationIndexEnd: bigint): DustStateMerkleTreeCollapsedUpdate;
readonly commitmentTreeFirstFree: bigint;
readonly generatingTreeFirstFree: bigint;
```

Nothing existing changes behaviour; `DustLocalStateError` is `#[non_exhaustive]` and gains one
variant.

## Why the range is checked here and not left to `MerkleTreeCollapsedUpdate::new`

`new` refuses `end < start` and an `end` outside the tree's `2^height` bounds, and nothing else.
A range above `first_free` walks into the tree's stub region: `partial_index` usually fails with
`StubUpdate`, but when a step lands exactly on a whole stub subtree it returns that subtree's
default hash and `new` succeeds. The resulting update is well-formed and wrong — applying it sets
the receiver's `first_free` past leaves the chain has not written yet, and the receiver's next
`insert_commitment` fails with `NonLinearInsertion` far from the cause.

`DustLocalStateError::CollapsedUpdateRangeInvalid` refuses both that case and the empty range, so
the accepted range is exactly the populated `[0, first_free - 1]` and a caller can predict it.
The only remaining failure a caller can provoke is cutting across a range this state has
`collapse`d away, which is reported as `MerkleTreeError(CollapsedIndex)`. No input reaches a
panic: the one `unreachable!()` on the path (`partial_index`'s `Leaf` arm) requires a tree that
violates `MerkleTreeNode::invariant`, and the height-32 bound means `end + 1` inside
`apply_*_collapsed_update` cannot overflow.

## Tests

`ledger/src/dust.rs`, module `collapsed_update_tests` (`cargo test -p midnight-ledger --lib`):

- a mirror of nine leaves with two of them owned; the three gaps are cut, applied to a blank
  state interleaved with the two owned leaves, and both tree roots must equal the source's —
  once for the commitment tree, once for the generating tree;
- a whole-range cut rebuilds a state that owns nothing;
- every out-of-range form is an error: reversed, `end == first_free`, far past it, `u64::MAX`,
  and any range at all on an empty state;
- a cut across a collapsed subtree reports the merkle-tree error rather than panicking.

`ledger-wasm/verification/verify-dust-collapsed-update.mts` runs the same round trip against the
**live preprod chain** through a built artifact: the first 5 000 DUST ledger events of the chain
are replayed into a mirror, three `dustInitialUtxo` leaves are treated as someone else's, the
mirror cuts the ranges around them, a second state applies the cuts and inserts only those three
leaves from the event payloads, and both roots must equal the mirror's. Each segment is
serialized and deserialized on the way, so the proof covers the wire form. The error cases are
asserted through the JavaScript boundary, where a missing range check would answer instead of
throwing.
