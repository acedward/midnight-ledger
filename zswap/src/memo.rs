// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Old-node-compatible **spend-proof memo binding**: additive, explicitly
//! detached helpers for authenticating an application memo against the secret
//! that controls a Zswap input, without changing anything an existing node
//! validates.
//!
//! # What this is
//!
//! A spender who wants to authenticate a memo `m` against one user-owned input:
//!
//! 1. derives `h = MemoHashV1(m)` ([`memo_hash_v1`]);
//! 2. adds one ordinary **zero-value** output whose `CoinCiphertext` is the
//!    versioned [`anchor::AnchorV1`] for `(N, h)`, where `N` is the input's
//!    nullifier ([`crate::Output::new_memo_anchor`]);
//! 3. proves the offer exactly as today — the canonical input proof still binds
//!    `binding_input = 0`, so **every unmodified node accepts the transaction**;
//! 4. additionally produces a **detached companion spend proof** over the very
//!    same finalized preimage with `binding_input = h`
//!    ([`crate::Input::prove_memo_companion`]);
//! 5. ships the memo, the companion proof and the statement metadata in an
//!    off-chain [`wrapper::MemoWrapperV1`], canonically as raw bytes and
//!    optionally rendered as bech32m ([`bech32m`]).
//!
//! A reader verifies the companion proof under the **shipped** `SPEND_VK` with
//! statement row 0 replaced by `h`
//! ([`crate::verify::verify_memo_companion`]) and matches it against the
//! offer's anchors by decoded `(N, h)`. Whether the transaction carrying that
//! offer settled is a separate, caller-attested question
//! ([`crate::verify::Confirmation`]) — presence of an anchor is publication,
//! never settlement.
//!
//! # What this is NOT
//!
//! Nothing here is on a consensus path.
//!
//! * `Input::<Proof>::well_formed` is untouched: it still builds statement row 0
//!   as the constant zero and never inspects an anchor. A companion proof placed
//!   in `Input.proof` is therefore **rejected** by an unmodified node — which is
//!   the property that keeps the canonical transaction old-node compatible.
//! * No circuit, prover key, verifier key, trusted setup, wire tag, `Tagged`
//!   version, activation rule or ledger-state format changes. The anchor reuses
//!   the *existing* `CoinCiphertext` slot of an ordinary output, and the
//!   companion proof is produced by the *existing* `overwrite_binding_input`
//!   hook of [`transient_crypto::proofs::ProvingProvider`].
//! * An anchor alone authenticates nothing. It is **strip evidence**:
//!   it shows that a memo commitment was published for that nullifier, not who
//!   wrote the memo, what it said, or whether a wrapper was deliberately
//!   withheld. Only a verified companion proof authenticates memo bytes.
//!
//! # The reserved zero
//!
//! `h = 0` is reserved: it is exactly the row-0 value every unmodified verifier
//! derives for "no memo". [`BindingElement`] cannot hold zero, and every
//! boundary that accepts an `h` funnels through it — construction
//! ([`BindingElement::for_memo`]), anchor decode
//! ([`anchor::AnchorV1::decode`]) and verification
//! ([`crate::verify::admit_companion_row0`]).

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use transient_crypto::curve::{FR_BYTES, Fr};
use transient_crypto::hash::{transient_commit, transient_hash};

pub mod anchor;
pub mod bech32m;
pub mod wrapper;

// The claims that can only be made with REAL proofs against the shipped keys.
#[cfg(all(test, feature = "proof-verifying"))]
mod companion_tests;

/// The version 1 memo domain separator: 23 ASCII bytes.
///
/// **Frozen.** This string is what makes `h` reproducible across
/// implementations; the conformance vectors exist so that it never moves.
pub const MEMO_DOMAIN_SEP: &[u8] = b"midnight:zswap-memo[v1]";

/// The largest permitted memo, in bytes.
pub const MAX_MEMO_BYTES: usize = 512;

/// The smallest permitted memo, in bytes.
///
/// One, not zero: *absence* has exactly one representation — no memo at all —
/// so a zero-length memo is rejected rather than encoded.
pub const MIN_MEMO_BYTES: usize = 1;

/// How many memo bytes are packed into each field element.
///
/// One below the field's byte width, so a full chunk's little-endian value is
/// at most `2^248 - 1` and every chunk converts without reduction.
pub const MEMO_BYTES_PER_FIELD: usize = 31;

const _: () = assert!(MEMO_BYTES_PER_FIELD < FR_BYTES);

/// Why a byte string is not a valid memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// Zero-length. Absence is spelled "no memo", never "a memo of length
    /// zero".
    Empty,
    /// Longer than [`MAX_MEMO_BYTES`].
    TooLarge {
        /// The rejected length.
        len: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl Display for MemoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MemoError::Empty => write!(
                f,
                "memo is empty: a memo is {MIN_MEMO_BYTES}..={MAX_MEMO_BYTES} bytes, and absence \
                 is represented by having no memo at all"
            ),
            MemoError::TooLarge { len, limit } => {
                write!(f, "memo is {len} bytes, over the {limit}-byte limit")
            }
        }
    }
}

impl Error for MemoError {}

/// The single place the memo length rule is decided.
///
/// It takes a *length* rather than bytes precisely so a decoder can apply it to
/// an attacker-supplied declared length **before allocating anything**.
pub const fn check_memo_len(len: usize) -> Result<(), MemoError> {
    if len < MIN_MEMO_BYTES {
        Err(MemoError::Empty)
    } else if len > MAX_MEMO_BYTES {
        Err(MemoError::TooLarge {
            len,
            limit: MAX_MEMO_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Opaque application bytes bound to one user-owned Zswap input, 1..=512 bytes.
///
/// The crate never interprets the bytes: whether they are UTF-8, a ciphertext,
/// or hostile input is an application concern. Every constructor re-checks the
/// range, so a value of this type is in range by construction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Memo(Vec<u8>);

impl Memo {
    /// Wraps `bytes`, rejecting anything outside 1..=[`MAX_MEMO_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, MemoError> {
        check_memo_len(bytes.len())?;
        Ok(Memo(bytes))
    }

    /// Copies `bytes` into a memo, **checking the length before allocating**.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MemoError> {
        check_memo_len(bytes.len())?;
        Ok(Memo(bytes.to_vec()))
    }

    /// The memo bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The memo length in bytes; always in 1..=[`MAX_MEMO_BYTES`].
    #[inline]
    #[allow(clippy::len_without_is_empty)] // a `Memo` is never empty, by construction.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Consumes the memo, returning the owned bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Memo {
    type Error = MemoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, MemoError> {
        Memo::new(bytes)
    }
}

impl TryFrom<&[u8]> for Memo {
    type Error = MemoError;
    fn try_from(bytes: &[u8]) -> Result<Self, MemoError> {
        Memo::from_slice(bytes)
    }
}

/// Renders the memo as its length plus lowercase hex — never as raw bytes.
///
/// Memo bytes are untrusted and may contain terminal control sequences; a
/// derived `Debug` would paste them into logs verbatim.
impl Debug for Memo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Memo(len={}, hex={})", self.0.len(), hex_lower(&self.0))
    }
}

/// The number of field elements the packing produces for an `n`-byte memo:
/// `1 + ceil(n / 31)`, the length prefix plus one element per chunk.
pub const fn packed_field_count(memo_len: usize) -> usize {
    1 + memo_len.div_ceil(MEMO_BYTES_PER_FIELD)
}

/// The largest field-element count any valid memo can produce.
pub const MAX_PACKED_FIELDS: usize = packed_field_count(MAX_MEMO_BYTES);

/// The frozen packing, over a valid memo.
///
/// ```text
/// pack(m) = [Fr(len(m))] ++ [Fr(le(m[0..31])), Fr(le(m[31..62])), ...]
/// ```
///
/// Only the FINAL chunk is zero-padded. The length prefix is what makes the
/// packing injective: without it, `m` and `m ++ [0x00]` would pack identically
/// whenever the padding absorbed the extra byte.
pub fn pack_memo(memo: &Memo) -> Vec<Fr> {
    pack_memo_bytes(memo.as_bytes())
}

/// The packing, over a raw byte slice.
///
/// Prefer [`pack_memo`]; this exists for conformance vectors and for tests that
/// need to pack a byte string which is not a valid memo. It is deliberately
/// **not** a way around the memo length rule — nothing on the derivation path
/// calls it with unvalidated input.
pub fn pack_memo_bytes(bytes: &[u8]) -> Vec<Fr> {
    let mut fields = Vec::with_capacity(packed_field_count(bytes.len()));
    fields.push(Fr::from(bytes.len() as u64));
    for chunk in bytes.chunks(MEMO_BYTES_PER_FIELD) {
        let mut buf = [0u8; MEMO_BYTES_PER_FIELD];
        buf[..chunk.len()].copy_from_slice(chunk);
        fields.push(
            Fr::from_le_bytes(&buf)
                .expect("a 31-byte little-endian value is always below the field modulus"),
        );
    }
    fields
}

/// The domain separator as a field element.
pub fn memo_domain_field() -> Fr {
    Fr::from_le_bytes(MEMO_DOMAIN_SEP)
        .expect("the memo domain separator is 23 bytes, hence in range for the field")
}

/// The commitment opening, `transient_hash([dom_sep])`.
///
/// A one-element preimage: version 1 binds the memo and nothing else — no offer
/// digest, transaction hash, request identifier or wrapper context.
pub fn memo_hash_opening() -> Fr {
    transient_hash(&[memo_domain_field()])
}

/// **The** memo derivation: `h = transient_commit(pack(m), opening)`.
///
/// Total and deterministic for every valid [`Memo`]. Deliberately infallible:
/// the reserved-zero rule *excludes an output* of this function and lives in
/// [`BindingElement`], so that the derivation itself never depends on a policy.
pub fn memo_hash_v1(memo: &Memo) -> Fr {
    memo_hash_v1_from_packed(&pack_memo(memo))
}

/// [`memo_hash_v1`] with the packing supplied directly.
///
/// The same function through a different entry point, not a second derivation.
pub fn memo_hash_v1_from_packed(packed: &[Fr]) -> Fr {
    transient_commit(packed, memo_hash_opening())
}

/// The field element `0`, reserved for "no memo".
///
/// Every unmodified verifier derives statement row 0 as exactly this value
/// (`Input::<Proof>::well_formed`), which is why it can never also mean "a memo
/// whose hash happens to be zero".
pub fn reserved_absence_element() -> Fr {
    Fr::from(0u64)
}

/// The typed rejection of the reserved zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedBindingElement;

impl Display for ReservedBindingElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(
            "binding element is the reserved zero field element, which means \"no memo\" and is \
             never valid memo evidence",
        )
    }
}

impl Error for ReservedBindingElement {}

/// A binding element that is **known to be nonzero**.
///
/// This is the type every helper takes wherever the protocol says `h`. There is
/// no way to build one holding zero, so the reserved-zero rule is enforced by
/// the type system rather than by a check each boundary could forget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingElement(Fr);

impl BindingElement {
    /// Wraps a field element, rejecting the reserved zero.
    pub fn new(h: Fr) -> Result<Self, ReservedBindingElement> {
        if h == reserved_absence_element() {
            Err(ReservedBindingElement)
        } else {
            Ok(BindingElement(h))
        }
    }

    /// `MemoHashV1(memo)`, rejected if it lands on the reserved zero.
    pub fn for_memo(memo: &Memo) -> Result<Self, ReservedBindingElement> {
        Self::new(memo_hash_v1(memo))
    }

    /// The underlying field element. Always nonzero.
    #[inline]
    pub fn get(self) -> Fr {
        self.0
    }
}

impl From<BindingElement> for Fr {
    fn from(b: BindingElement) -> Fr {
        b.0
    }
}

/// Why a detached companion proof could not be produced.
///
/// Every variant is a refusal that happens **before** the prover is called,
/// except [`MemoCompanionError::Proving`] and
/// [`MemoCompanionError::Serialization`], so an invalid request costs no
/// proving work and emits nothing.
#[derive(Debug)]
#[non_exhaustive]
pub enum MemoCompanionError {
    /// The stored preimage already carried a nonzero `binding_input`.
    ///
    /// This matters more than it looks. `prove(P, None)` **retains** whatever
    /// `P.binding_input` holds, so a preimage that arrived with a nonzero row 0
    /// would be "canonically" proved with that nonzero row and rejected by
    /// every unmodified node — at settlement, far from the mistake.
    StoredBindingInputNotZero {
        /// The offending value, little-endian.
        found: [u8; 32],
    },
    /// The preimage is not a Zswap spend preimage.
    WrongKeyLocation {
        /// The key location found.
        found: String,
        /// The key location required.
        expected: &'static str,
    },
    /// The carrier is contract-owned. A memo is authenticated by the secret
    /// that controls a **user** input; a contract has no such secret.
    ContractOwnedCarrier {
        /// The offending input's nullifier.
        nullifier: coin_structure::coin::Nullifier,
    },
    /// The proving provider failed, or refused the override.
    Proving(transient_crypto::proofs::ProvingError),
    /// Serializing the detached proof failed.
    Serialization {
        /// The underlying message, verbatim.
        reason: String,
    },
    /// **The freshly produced companion verifies at row 0 = 0.**
    ///
    /// The backend accepted the `Some(h)` override and then proved the caller's
    /// original row-0-zero preimage anyway. Accepting the parameter is not
    /// evidence that it was honoured, so
    /// [`Input::prove_memo_companion`](crate::structure::Input) measures the
    /// answer instead of documenting the risk.
    SilentRowZeroProof,
    /// **The freshly produced companion does not verify at row 0 = `h`.**
    ///
    /// The backend proved some third statement, or returned bytes that are not
    /// a proof of this circuit at all. Either way the artifact authenticates no
    /// memo.
    ProofDoesNotBindTheMemo,
    /// **The requested segment is not the one the carrier's own final statement
    /// encodes.**
    ///
    /// A companion's statement rows `1..` are derived from the input at a
    /// segment; asking for a segment the carrier was not retargeted to yields a
    /// statement no verifier can ever rebuild from that input, so the companion
    /// could never verify. Refused before the prover is called, so a pre-retarget
    /// request costs no proving work.
    SegmentMismatch {
        /// The segment the carrier's preimage encodes.
        found: Option<u16>,
        /// The segment requested.
        requested: u16,
    },
}

impl Display for MemoCompanionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MemoCompanionError::StoredBindingInputNotZero { found } => write!(
                f,
                "the spend preimage already carries binding_input {}; a canonical spend preimage \
                 must store zero",
                hex_lower(found)
            ),
            MemoCompanionError::WrongKeyLocation { found, expected } => {
                write!(f, "preimage key location is {found:?}, not {expected:?}")
            }
            MemoCompanionError::ContractOwnedCarrier { nullifier } => write!(
                f,
                "input {} is contract-owned and cannot carry an authenticated memo",
                hex_lower(&nullifier.0.0)
            ),
            MemoCompanionError::Proving(e) => write!(f, "companion proving failed: {e}"),
            MemoCompanionError::Serialization { reason } => {
                write!(
                    f,
                    "serializing the detached companion proof failed: {reason}"
                )
            }
            MemoCompanionError::SilentRowZeroProof => f.write_str(
                "the produced companion verifies at row 0 = 0: the backend accepted the override \
                 and proved the original preimage anyway, so this is not a companion",
            ),
            MemoCompanionError::ProofDoesNotBindTheMemo => f.write_str(
                "the produced companion does not verify at row 0 = h, so it binds no memo",
            ),
            MemoCompanionError::SegmentMismatch { found, requested } => write!(
                f,
                "the carrier's final statement encodes segment {found:?}, not the requested \
                 segment {requested}"
            ),
        }
    }
}

impl Error for MemoCompanionError {}

/// Why a companion wrapper did not authenticate a memo.
///
/// Every variant is a refusal, and the first five are reached **before** any
/// proof work: an attacker cannot make a verifier spend a pairing check by
/// sending a malformed wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoVerifyError {
    /// No input in the offer carries the wrapper's nullifier.
    AttributedInputNotFound {
        /// The nullifier the wrapper claimed.
        nullifier: coin_structure::coin::Nullifier,
    },
    /// The attributed input is contract-owned.
    ContractOwnedCarrier {
        /// The offending input's nullifier.
        nullifier: coin_structure::coin::Nullifier,
    },
    /// The wrapper's claimed segment is not the settled one, so its companion
    /// was proved against a statement that no longer exists.
    SegmentMismatch {
        /// What the wrapper claimed.
        claimed: u16,
        /// What was settled.
        settled: u16,
    },
    /// `MemoHashV1` of the wrapper's memo bytes is the reserved zero.
    ReservedBindingElement,
    /// The wrapper carried the wrong number of statement rows.
    StatementRowCount {
        /// How many it carried.
        found: usize,
        /// How many the settled input needs.
        expected: usize,
    },
    /// A carried statement row disagrees with the row rebuilt from the settled
    /// input.
    StatementRowMismatch {
        /// Which row, 1-based (row 0 is never carried).
        row: usize,
    },
    /// The companion proof bytes are not a readable proof.
    MalformedCompanionProof {
        /// The underlying message, verbatim.
        reason: String,
    },
    /// The companion proof did not verify against the rebuilt statement.
    ///
    /// This is what memo tampering, a grafted proof, a re-attributed nullifier
    /// and a pre-retarget companion all collapse to.
    CompanionProofRejected {
        /// The underlying message, verbatim.
        reason: String,
    },
    /// The offer carries the wrapper's nullifier more than once, so there is no
    /// single attributed input to rebuild the statement from.
    ///
    /// Added by 00006 (review finding F3): the carrier used to be resolved with
    /// `.find()`, which silently picked the first match.
    DuplicateAttributedInput {
        /// The repeated nullifier.
        nullifier: coin_structure::coin::Nullifier,
        /// How many inputs carried it.
        count: usize,
    },
}

impl Display for MemoVerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MemoVerifyError::AttributedInputNotFound { nullifier } => write!(
                f,
                "no input with nullifier {} in this offer",
                hex_lower(&nullifier.0.0)
            ),
            MemoVerifyError::ContractOwnedCarrier { nullifier } => write!(
                f,
                "input {} is contract-owned and cannot carry an authenticated memo",
                hex_lower(&nullifier.0.0)
            ),
            MemoVerifyError::SegmentMismatch { claimed, settled } => write!(
                f,
                "wrapper claims segment {claimed}, but the settled segment is {settled}"
            ),
            MemoVerifyError::ReservedBindingElement => {
                f.write_str("the memo hashes to the reserved zero binding element")
            }
            MemoVerifyError::StatementRowCount { found, expected } => write!(
                f,
                "wrapper carries {found} statement row(s); the settled input needs {expected}"
            ),
            MemoVerifyError::StatementRowMismatch { row } => write!(
                f,
                "statement row {row} disagrees with the row rebuilt from the settled input"
            ),
            MemoVerifyError::MalformedCompanionProof { reason } => {
                write!(f, "companion proof is not readable: {reason}")
            }
            MemoVerifyError::CompanionProofRejected { reason } => {
                write!(f, "companion proof does not bind this memo: {reason}")
            }
            MemoVerifyError::DuplicateAttributedInput { nullifier, count } => write!(
                f,
                "this offer carries nullifier {} {count} times; there is no single \
                 attributed input",
                hex_lower(&nullifier.0.0)
            ),
        }
    }
}

impl Error for MemoVerifyError {}

impl From<ReservedBindingElement> for MemoVerifyError {
    fn from(_: ReservedBindingElement) -> Self {
        MemoVerifyError::ReservedBindingElement
    }
}

/// A field element's fixed 32-byte little-endian form.
///
/// `Fr::as_le_bytes` returns the minimal encoding; the wrapper container and
/// the conformance vectors both use the fixed width, so this pads it.
pub fn fr_le32(f: Fr) -> [u8; FR_BYTES] {
    let mut out = [0u8; FR_BYTES];
    let le = f.as_le_bytes();
    out[..le.len()].copy_from_slice(&le);
    out
}

/// Lowercase hex, without pulling a dependency into the crate for it.
///
/// `hex` is only a dev-dependency of this crate, and the `Debug` impls here
/// must not render raw untrusted bytes, so they need an encoder in normal
/// builds too.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(*b >> 4) as usize] as char);
        out.push(DIGITS[(*b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo(bytes: &[u8]) -> Memo {
        Memo::from_slice(bytes).expect("test memo in range")
    }

    #[test]
    fn boundary_matrix_at_every_constructor() {
        for len in [0usize, 513, 1024, MAX_MEMO_BYTES * 4] {
            let bytes = vec![0x5a; len];
            assert!(Memo::new(bytes.clone()).is_err(), "new accepted len {len}");
            assert!(
                Memo::from_slice(&bytes).is_err(),
                "from_slice accepted len {len}"
            );
            assert!(Memo::try_from(bytes.clone()).is_err());
            assert!(Memo::try_from(&bytes[..]).is_err());
            assert!(check_memo_len(len).is_err());
        }
        for len in [1usize, 31, 32, 511, 512] {
            let bytes = vec![0x5a; len];
            assert_eq!(Memo::new(bytes.clone()).unwrap().len(), len);
            assert_eq!(Memo::from_slice(&bytes).unwrap().as_bytes(), &bytes[..]);
            assert!(check_memo_len(len).is_ok());
            assert!(BindingElement::for_memo(&memo(&bytes)).is_ok());
        }
    }

    #[test]
    fn zero_and_oversize_have_distinct_typed_errors() {
        assert_eq!(Memo::new(Vec::new()).unwrap_err(), MemoError::Empty);
        assert_eq!(
            Memo::new(vec![0u8; 513]).unwrap_err(),
            MemoError::TooLarge {
                len: 513,
                limit: MAX_MEMO_BYTES
            }
        );
    }

    /// The length rule must be decidable from a DECLARED length alone, so a
    /// hostile four-gigabyte length is refused before any allocation.
    #[test]
    fn oversize_is_rejected_before_allocation() {
        assert_eq!(
            check_memo_len(usize::MAX),
            Err(MemoError::TooLarge {
                len: usize::MAX,
                limit: MAX_MEMO_BYTES
            })
        );
        assert!(check_memo_len(0).is_err());
    }

    #[test]
    fn absence_is_not_an_empty_memo() {
        assert!(Memo::new(Vec::new()).is_err());
        let one_zero = memo(&[0x00]);
        assert_ne!(one_zero, memo(&[0x00, 0x00]));
        assert_ne!(memo_hash_v1(&one_zero), memo_hash_v1(&memo(&[0x00, 0x00])));
        assert_eq!(reserved_absence_element(), Fr::from(0u64));
        assert!(BindingElement::new(reserved_absence_element()).is_err());
    }

    #[test]
    fn field_count_is_one_plus_ceil_len_over_31() {
        for (len, expected) in [
            (1usize, 2usize),
            (30, 2),
            (31, 2),
            (32, 3),
            (61, 3),
            (62, 3),
            (63, 4),
            (511, 18),
            (512, 18),
        ] {
            assert_eq!(packed_field_count(len), expected, "count for len {len}");
            assert_eq!(pack_memo(&memo(&vec![0x07; len])).len(), expected);
        }
        assert_eq!(MAX_PACKED_FIELDS, 18);
    }

    #[test]
    fn first_element_is_the_length_prefix_and_chunks_are_little_endian() {
        for len in [1usize, 31, 32, 511, 512] {
            assert_eq!(pack_memo(&memo(&vec![0xff; len]))[0], Fr::from(len as u64));
        }
        assert_eq!(pack_memo(&memo(&[0x01]))[1], Fr::from(1u64));
        assert_eq!(pack_memo(&memo(&[0x00, 0x01]))[1], Fr::from(256u64));
        assert_eq!(pack_memo(&memo(&[0x00, 0x00, 0x01]))[1], Fr::from(65536u64));
    }

    /// Only the FINAL chunk is zero-padded — full chunks survive intact.
    #[test]
    fn only_the_final_chunk_is_padded() {
        let packed = pack_memo(&memo(&vec![0xff; 512]));
        let full = Fr::from_le_bytes(&[0xff; MEMO_BYTES_PER_FIELD]).unwrap();
        for (i, f) in packed[1..=16].iter().enumerate() {
            assert_eq!(*f, full, "chunk {i} was reduced, truncated or padded");
        }
        let mut tail = [0u8; MEMO_BYTES_PER_FIELD];
        tail[..16].fill(0xff);
        assert_eq!(packed[17], Fr::from_le_bytes(&tail).unwrap());
    }

    #[test]
    fn length_prefix_makes_the_packing_injective_over_trailing_zeros() {
        assert_ne!(pack_memo(&memo(&[0x00])), pack_memo(&memo(&[0x00, 0x00])));
        assert_ne!(pack_memo(&memo(b"hi")), pack_memo(&memo(b"hi\0")));
        assert_eq!(
            pack_memo_bytes(&[0x00])[1..],
            pack_memo_bytes(&[0x00, 0x00])[1..],
            "the chunk vectors alone are NOT injective — that is the prefix's job"
        );
    }

    /// A SECOND derivation, transcribed from the protocol description rather
    /// than from the code above: `H([opening, n, c_0, ..., c_{k-1}])`, calling
    /// `transient_hash` directly instead of `transient_commit`. Conformance
    /// vectors alone cannot catch a change made on both sides at once; this
    /// can.
    fn memo_hash_per_spec(memo_bytes: &[u8]) -> Fr {
        let dom = Fr::from_le_bytes(b"midnight:zswap-memo[v1]").expect("23 bytes in range");
        let opening = transient_hash(&[dom]);
        let mut elems = vec![opening, Fr::from(memo_bytes.len() as u64)];
        for chunk in memo_bytes.chunks(31) {
            let mut padded = [0u8; 31];
            padded[..chunk.len()].copy_from_slice(chunk);
            elems.push(Fr::from_le_bytes(&padded).expect("31 bytes in range"));
        }
        transient_hash(&elems)
    }

    #[test]
    fn independent_derivation_agrees() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x00; 1],
            vec![0x00; 2],
            b"midnight offer memo".to_vec(),
            b"hello world".to_vec(),
            vec![0x07; 30],
            vec![0x07; 31],
            vec![0x07; 32],
            vec![0x07; 62],
            vec![0xff; 511],
            vec![0xa5; 512],
            b"a\x00b\x00c".to_vec(),
            vec![0x80, 0xff, 0xfe, 0x00, 0xc0],
            b"\x1b[2Jerased\x00".to_vec(),
        ];
        for m in &cases {
            assert_eq!(
                memo_hash_v1(&memo(m)),
                memo_hash_per_spec(m),
                "derivations disagree for a {}-byte memo",
                m.len()
            );
        }
    }

    #[test]
    fn derivation_entry_points_agree_and_are_deterministic() {
        let m = memo(b"midnight offer memo");
        let h = memo_hash_v1(&m);
        assert_eq!(h, memo_hash_v1(&m));
        assert_eq!(h, memo_hash_v1_from_packed(&pack_memo(&m)));
        assert_eq!(h, transient_commit(&pack_memo(&m)[..], memo_hash_opening()));
    }

    #[test]
    fn domain_separator_is_frozen_and_distinct_from_its_neighbours() {
        assert_eq!(MEMO_DOMAIN_SEP, b"midnight:zswap-memo[v1]");
        assert_eq!(MEMO_DOMAIN_SEP.len(), 23);
        let ours = memo_domain_field();
        for other in [
            &b"midnight:zswap-memo-attest[v1]"[..],
            b"midnight:zswap-ciphertext",
            b"midnight:zswap-cn[v1]",
            b"midnight:zswap-cc[v1]",
            b"midnight:zswap-anchor",
            b"midnight:field_hash",
        ] {
            let other_fr = Fr::from_le_bytes(other).expect("short separators are in range");
            assert_ne!(ours, other_fr);
        }
    }

    #[test]
    fn hash_binds_the_exact_memo_bytes() {
        let base = memo_hash_v1(&memo(b"hello world"));
        assert_ne!(base, memo_hash_v1(&memo(b"hello worlds")), "extend");
        assert_ne!(base, memo_hash_v1(&memo(b"hello worl")), "truncate");
        assert_ne!(base, memo_hash_v1(&memo(b"Hello world")), "alter");
        assert_ne!(
            base,
            memo_hash_v1(&memo(b"hello world\0")),
            "trailing zero must not be absorbed"
        );
    }

    #[test]
    fn hostile_bytes_are_ordinary_memo_bytes() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x00],
            vec![0x00, 0x00],
            vec![0xff, 0xfe, 0xfd],
            b"a\x00b".to_vec(),
            b"\x1b]0;title\x07".to_vec(),
            b"<script>alert(1)</script>".to_vec(),
            "\u{202e}gnp.exe".as_bytes().to_vec(),
            vec![0xc3, 0x28],
        ];
        let mut seen = Vec::new();
        for c in &cases {
            let h = memo_hash_v1(&memo(c));
            assert!(!seen.contains(&h), "collision on {c:02x?}");
            assert_ne!(h, reserved_absence_element());
            seen.push(h);
        }
    }

    #[test]
    fn debug_never_emits_raw_memo_bytes() {
        let hostile = memo(b"\x1b[2Jerased\x00");
        let rendered = format!("{hostile:?}");
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\0'));
        assert_eq!(rendered, "Memo(len=11, hex=1b5b324a65726173656400)");
    }

    /// The forced-zero test double: no hash preimage is needed to reach the
    /// rejection, at boundary 1 of 3 (construction).
    #[test]
    fn forced_zero_is_rejected_at_the_construction_boundary() {
        assert_eq!(
            BindingElement::new(Fr::from(0u64)).unwrap_err(),
            ReservedBindingElement
        );
        assert_eq!(
            BindingElement::new(reserved_absence_element()).unwrap_err(),
            ReservedBindingElement
        );
        for h in [Fr::from(1u64), Fr::from(u64::MAX), memo_hash_opening()] {
            assert_eq!(BindingElement::new(h).unwrap().get(), h);
        }
    }

    #[test]
    fn real_memos_never_derive_the_reserved_zero() {
        for len in [1usize, 2, 31, 32, 63, 511, 512] {
            for fill in [0x00u8, 0x07, 0xff] {
                let h = memo_hash_v1(&memo(&vec![fill; len]));
                assert_ne!(h, reserved_absence_element(), "len {len} fill {fill:#x}");
            }
        }
    }

    #[test]
    fn hex_lower_matches_the_hex_crate() {
        for bytes in [
            vec![],
            vec![0x00],
            vec![0xff, 0x0f, 0xf0],
            (0u16..=255).map(|b| b as u8).collect::<Vec<_>>(),
        ] {
            assert_eq!(hex_lower(&bytes), hex::encode(&bytes));
        }
    }

    #[test]
    fn fr_le32_is_the_fixed_width_encoding() {
        assert_eq!(fr_le32(Fr::from(0u64)), [0u8; FR_BYTES]);
        let mut one = [0u8; FR_BYTES];
        one[0] = 1;
        assert_eq!(fr_le32(Fr::from(1u64)), one);
        for f in [memo_hash_opening(), memo_domain_field()] {
            assert_eq!(Fr::from_le_bytes(&fr_le32(f)).unwrap(), f);
        }
    }
}
