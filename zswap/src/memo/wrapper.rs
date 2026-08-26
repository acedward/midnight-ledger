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

//! The versioned **off-chain companion wrapper**.
//!
//! Version 1 represents EXACTLY ONE memo-bearing input; several memo-bearing
//! inputs use several independently verified wrappers, which is why nothing
//! here is a list.
//!
//! # What it carries
//!
//! | Section | Why |
//! | --- | --- |
//! | marker + version | container identity |
//! | memo | the payload |
//! | nullifier `N` | which input this is about |
//! | segment | statement row content |
//! | statement tail | rows `1..INPUT_PIS` |
//! | companion proof | the authentication |
//! | locator | transport convenience, NEVER trusted |
//!
//! The statement tail is carried as the statement rows **themselves** —
//! `INPUT_PIS - 1` field elements — rather than as a re-encoding of the input's
//! merkle root, value commitment and contract address. **Carrying them is not
//! trusting them**: a verifier reconstructs rows `1..` from the canonical
//! settled input and *requires the wrapper's copy to equal it*, so the carried
//! copy is a cross-check that fails closed, never an input to the verification
//! statement (see [`crate::verify::verify_memo_companion`]).
//!
//! # What it MUST NOT carry
//!
//! No private witness data, no Merkle path secrets, no spend keys, no output
//! randomness, no proof preimages. That is structural: the struct has exactly
//! the six fields above, none of which is a `ProofPreimage`, a `SecretKeys` or
//! a merkle path.
//!
//! # Container layout
//!
//! ```text
//! magic          27 bytes   "midnight:zswap-memo-wrapper"
//! version        u16 LE     1
//! section_count  u16 LE     bounded by MAX_SECTIONS
//! sections       section_count x:
//!     tag        u16 LE
//!     len        u32 LE     bounded by MAX_SECTION_BYTES *and* by the bytes left
//!     payload    len bytes
//! (exactly consumed — trailing bytes are a typed reject)
//! ```
//!
//! Tags at or below [`MANDATORY_SECTION_MAX`] are MANDATORY: an unknown one is
//! a typed reject. Tags above it are optional and an unknown one is ignored, so
//! a later version can add optional sections without breaking a version 1
//! reader. Sections must appear in **strictly ascending tag order** and the
//! container must be **exactly consumed**, which together make the encoding
//! canonical: exactly one byte string per wrapper value, with `encode` and
//! `decode` inverse in both directions.
//!
//! # Bounded before allocation
//!
//! Decoding walks the input as a `&[u8]` and allocates nothing until every
//! header has been validated: each declared length is checked against
//! [`MAX_SECTION_BYTES`] and against the bytes actually remaining before any
//! copy is made, and the memo length rule is applied to the *declared* length
//! rather than to a materialized buffer. A declared length of `u32::MAX` is a
//! typed error, not a four-gigabyte allocation.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use base_crypto::hash::HashOutput;
use coin_structure::coin::Nullifier;
use transient_crypto::curve::{FR_BYTES, Fr};

use crate::memo::{Memo, MemoError, check_memo_len, fr_le32, hex_lower};
use crate::structure::{INPUT_PIS, MemoCompanion};

/// The wrapper's format marker: 27 bytes.
///
/// Deliberately distinct from the memo domain separator and from the anchor
/// marker: the three live in different roles and must never be
/// interchangeable.
pub const WRAPPER_MAGIC: &[u8] = b"midnight:zswap-memo-wrapper";

/// The only wrapper version this codec accepts.
pub const WRAPPER_VERSION_V1: u16 = 1;

/// Bytes of fixed header: magic, version, section count.
pub const WRAPPER_HEADER_BYTES: usize = WRAPPER_MAGIC.len() + 2 + 2;

/// Bytes of per-section header: tag, length.
pub const SECTION_HEADER_BYTES: usize = 2 + 4;

/// Hard ceiling on a whole wrapper, checked before anything else.
pub const MAX_WRAPPER_BYTES: usize = 32 * 1024;

/// Hard ceiling on one section's payload.
pub const MAX_SECTION_BYTES: usize = 16 * 1024;

/// Hard ceiling on the number of sections. Bounds the index pass.
pub const MAX_SECTIONS: usize = 32;

/// Hard ceiling on the detached companion proof bytes.
pub const MAX_COMPANION_PROOF_BYTES: usize = 16 * 1024;

/// Hard ceiling on the never-trusted locator.
pub const MAX_LOCATOR_BYTES: usize = 256;

/// Tags at or below this are MANDATORY: a reader that does not know one must
/// refuse the wrapper. Above it, an unknown tag is ignored.
pub const MANDATORY_SECTION_MAX: u16 = 0x0FFF;

/// The exact memo bytes (mandatory).
pub const SECTION_MEMO: u16 = 0x0001;
/// The attributed nullifier, 32 raw bytes (mandatory).
pub const SECTION_NULLIFIER: u16 = 0x0002;
/// The final segment, `u16` little-endian (mandatory).
pub const SECTION_SEGMENT: u16 = 0x0003;
/// Statement rows `1..INPUT_PIS`, 32-byte little-endian field elements
/// (mandatory).
pub const SECTION_STATEMENT_TAIL: u16 = 0x0004;
/// The detached shipped-format spend proof, tagged (mandatory).
pub const SECTION_COMPANION_PROOF: u16 = 0x0005;
/// An optional transaction/offer locator. NEVER trusted as proof.
pub const SECTION_LOCATOR: u16 = 0x1001;

/// Every mandatory section a version 1 wrapper must carry, in tag order.
pub const REQUIRED_SECTIONS: [u16; 5] = [
    SECTION_MEMO,
    SECTION_NULLIFIER,
    SECTION_SEGMENT,
    SECTION_STATEMENT_TAIL,
    SECTION_COMPANION_PROOF,
];

/// How many statement rows the wrapper carries: every row after row 0.
pub const STATEMENT_TAIL_ROWS: usize = INPUT_PIS - 1;

/// The exact byte length of the statement-tail section.
pub const STATEMENT_TAIL_BYTES: usize = STATEMENT_TAIL_ROWS * FR_BYTES;

/// Why some bytes are not a version 1 companion wrapper.
///
/// Every variant is a refusal: none is recoverable, none leaves a partially
/// trusted value behind, and reaching any of them costs no proof work.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrapperError {
    /// The artifact is larger than [`MAX_WRAPPER_BYTES`]. Checked first.
    Oversized {
        /// The length offered.
        len: usize,
        /// The ceiling.
        limit: usize,
    },
    /// The leading bytes are not [`WRAPPER_MAGIC`].
    BadMagic,
    /// The version is not [`WRAPPER_VERSION_V1`].
    UnsupportedVersion {
        /// The version found.
        found: u16,
    },
    /// The input ended before a structure it declared.
    Truncated {
        /// What was being read.
        context: &'static str,
        /// How many bytes that needed.
        needed: usize,
        /// How many were left.
        available: usize,
    },
    /// More sections were declared than [`MAX_SECTIONS`].
    TooManySections {
        /// The count declared.
        declared: usize,
        /// The ceiling.
        limit: usize,
    },
    /// A section declared a payload longer than [`MAX_SECTION_BYTES`].
    OversizedSection {
        /// The offending tag.
        tag: u16,
        /// The length declared.
        len: u64,
        /// The ceiling.
        limit: usize,
    },
    /// The same tag appeared twice.
    DuplicateSection {
        /// The repeated tag.
        tag: u16,
    },
    /// Sections are not in strictly ascending tag order.
    SectionsOutOfOrder {
        /// The tag that came before.
        previous: u16,
        /// The tag that followed it.
        found: u16,
    },
    /// A tag in the mandatory range that this version does not know.
    UnknownMandatorySection {
        /// The offending tag.
        tag: u16,
    },
    /// A mandatory section is absent.
    MissingMandatorySection {
        /// The absent tag.
        tag: u16,
    },
    /// A fixed-width section had the wrong width.
    BadSectionLength {
        /// The offending tag.
        tag: u16,
        /// The length found.
        found: usize,
        /// The length required.
        expected: usize,
    },
    /// The memo bytes are not 1..=512. Decided on the DECLARED length, before
    /// any copy.
    Memo(MemoError),
    /// A statement row is not a canonical little-endian field element.
    NonCanonicalStatementRow {
        /// The statement row number (1-based; row 0 is never carried).
        row: usize,
    },
    /// The companion proof section is empty.
    EmptyCompanionProof,
    /// Serializing the detached companion proof into a wrapper failed. Only
    /// reachable while BUILDING a wrapper, never while decoding one.
    CompanionProofSerialization {
        /// The underlying message, verbatim.
        reason: String,
    },
    /// Bytes remained after the declared sections. A wrapper is exactly
    /// consumed.
    TrailingBytes {
        /// How many bytes were left over.
        extra: usize,
    },
    /// **`memo_hash_v1(memo)` is not the companion's binding element** (00006
    /// F2.3).
    ///
    /// Only reachable while BUILDING a wrapper. A verifier derives `h` from the
    /// memo bytes itself and never reads it out of a wrapper, so a mismatched
    /// pair authenticates nothing anywhere — emitting it would only move the
    /// failure to the reader.
    MemoDoesNotMatchTheCompanionsBinding {
        /// `memo_hash_v1(memo)`, little-endian.
        memo_hash: [u8; FR_BYTES],
        /// The companion's binding element, little-endian.
        binding: [u8; FR_BYTES],
    },
}

impl Display for WrapperError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WrapperError::Oversized { len, limit } => {
                write!(f, "wrapper is {len} bytes, over the {limit}-byte ceiling")
            }
            WrapperError::BadMagic => f.write_str("not a zswap memo companion wrapper (bad magic)"),
            WrapperError::UnsupportedVersion { found } => write!(
                f,
                "wrapper version {found} is not supported (this reader speaks {WRAPPER_VERSION_V1})"
            ),
            WrapperError::Truncated {
                context,
                needed,
                available,
            } => write!(
                f,
                "truncated while reading {context}: needed {needed} byte(s), {available} left"
            ),
            WrapperError::TooManySections { declared, limit } => write!(
                f,
                "wrapper declares {declared} sections, over the {limit}-section ceiling"
            ),
            WrapperError::OversizedSection { tag, len, limit } => write!(
                f,
                "section {tag:#06x} declares {len} bytes, over the {limit}-byte ceiling"
            ),
            WrapperError::DuplicateSection { tag } => {
                write!(f, "section {tag:#06x} appears more than once")
            }
            WrapperError::SectionsOutOfOrder { previous, found } => write!(
                f,
                "section {found:#06x} follows {previous:#06x}; sections must ascend"
            ),
            WrapperError::UnknownMandatorySection { tag } => write!(
                f,
                "section {tag:#06x} is mandatory and unknown to this reader"
            ),
            WrapperError::MissingMandatorySection { tag } => {
                write!(f, "mandatory section {tag:#06x} is missing")
            }
            WrapperError::BadSectionLength {
                tag,
                found,
                expected,
            } => write!(
                f,
                "section {tag:#06x} is {found} bytes, but must be exactly {expected}"
            ),
            WrapperError::Memo(e) => write!(f, "invalid memo section: {e}"),
            WrapperError::NonCanonicalStatementRow { row } => write!(
                f,
                "statement row {row} is not a canonical little-endian field element"
            ),
            WrapperError::EmptyCompanionProof => {
                f.write_str("the companion proof section is empty")
            }
            WrapperError::CompanionProofSerialization { reason } => {
                write!(
                    f,
                    "serializing the detached companion proof failed: {reason}"
                )
            }
            WrapperError::TrailingBytes { extra } => {
                write!(f, "{extra} trailing byte(s) after the wrapper")
            }
            WrapperError::MemoDoesNotMatchTheCompanionsBinding { memo_hash, binding } => write!(
                f,
                "memo_hash_v1(memo) is {}, but the companion binds {}; a verifier derives h from \
                 the memo, so this wrapper could never authenticate anything",
                hex_lower(memo_hash),
                hex_lower(binding)
            ),
        }
    }
}

impl Error for WrapperError {}

impl From<MemoError> for WrapperError {
    fn from(e: MemoError) -> Self {
        WrapperError::Memo(e)
    }
}

/// An optional transport hint — a transaction hash, an offer file name, a
/// URL — that is **never** trusted as proof of anything.
///
/// The type name is the warning and the API keeps it honest: the only accessor
/// says `untrusted` in its name, verification never reads it, and `Display` is
/// deliberately not implemented so a locator cannot be printed by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedLocator(Vec<u8>);

impl UntrustedLocator {
    /// Wraps `bytes`, rejecting anything over [`MAX_LOCATOR_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, WrapperError> {
        Self::check_len(bytes.len())?;
        Ok(UntrustedLocator(bytes))
    }

    /// Copies `bytes`, checking the length **before** allocating.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WrapperError> {
        Self::check_len(bytes.len())?;
        Ok(UntrustedLocator(bytes.to_vec()))
    }

    fn check_len(len: usize) -> Result<(), WrapperError> {
        if len > MAX_LOCATOR_BYTES {
            return Err(WrapperError::OversizedSection {
                tag: SECTION_LOCATOR,
                len: len as u64,
                limit: MAX_LOCATOR_BYTES,
            });
        }
        Ok(())
    }

    /// The raw bytes. The name is the contract.
    #[inline]
    pub fn as_untrusted_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Never renders the locator's bytes: it is attacker-supplied like the memo.
impl Debug for UntrustedLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UntrustedLocator(len={}, NEVER TRUSTED AS PROOF)",
            self.0.len()
        )
    }
}

/// A version 1 off-chain companion wrapper: exactly one memo-bearing input.
///
/// Every field is private and the accessors are named so that a caller cannot
/// mistake parsed data for verified data: the memo comes out of
/// [`MemoWrapperV1::unverified_memo`], and the only thing that turns it into an
/// authenticated memo is a successful
/// [`crate::verify::verify_memo_companion`].
#[derive(Clone, PartialEq, Eq)]
pub struct MemoWrapperV1 {
    memo: Memo,
    nullifier: Nullifier,
    segment: u16,
    statement_tail: Vec<Fr>,
    companion_proof: Vec<u8>,
    locator: Option<UntrustedLocator>,
}

impl MemoWrapperV1 {
    /// Builds a wrapper from a real construction: the detached companion proof
    /// and its statement.
    ///
    /// The statement tail is taken from the companion's own statement rather
    /// than from caller-supplied metadata, so an honestly built wrapper is
    /// consistent by construction; the verifier still rebuilds and compares it.
    ///
    /// # The cross-wiring this refuses (00006 F2.3)
    ///
    /// `memo_hash_v1(memo)` must be the companion's binding element. A verifier
    /// derives `h` from the memo bytes and never reads it out of a wrapper, so
    /// pairing a memo with another memo's companion produces an artifact whose
    /// only possible future is a reader's rejection. This was previously
    /// unchecked: `build` looked only at tail length and proof shape.
    pub fn build(
        memo: Memo,
        companion: &MemoCompanion,
        locator: Option<UntrustedLocator>,
    ) -> Result<Self, WrapperError> {
        let memo_hash = crate::memo::memo_hash_v1(&memo);
        if memo_hash != companion.binding().get() {
            return Err(WrapperError::MemoDoesNotMatchTheCompanionsBinding {
                memo_hash: fr_le32(memo_hash),
                binding: fr_le32(companion.binding().get()),
            });
        }

        let proof_bytes = companion.detached_proof_bytes().map_err(|e| {
            WrapperError::CompanionProofSerialization {
                reason: e.to_string(),
            }
        })?;
        MemoWrapperV1::from_parts(
            memo,
            companion.nullifier(),
            companion.segment(),
            companion.statement_tail().to_vec(),
            proof_bytes,
            locator,
        )
    }

    /// Assembles a wrapper from already-separated parts.
    ///
    /// Used by conformance vectors and tamper harnesses; production callers
    /// want [`MemoWrapperV1::build`].
    ///
    /// # Deliberately permissive (00006 F2.3)
    ///
    /// This checks only what the ENCODING requires — tail row count, proof
    /// present and within the size ceiling — and never the memo↔binding relation
    /// [`MemoWrapperV1::build`] enforces. A wrapper arriving over the wire is
    /// exactly a bag of parts with no relation guaranteed, `decode` builds one
    /// through this path, and the tamper harnesses' whole job is to assemble
    /// wrappers a verifier must reject. Nothing here is trusted downstream:
    /// `verify_memo_companion` derives `h` from the memo bytes and rebuilds the
    /// statement tail from the settled input.
    pub fn from_parts(
        memo: Memo,
        nullifier: Nullifier,
        segment: u16,
        statement_tail: Vec<Fr>,
        companion_proof: Vec<u8>,
        locator: Option<UntrustedLocator>,
    ) -> Result<Self, WrapperError> {
        if statement_tail.len() != STATEMENT_TAIL_ROWS {
            return Err(WrapperError::BadSectionLength {
                tag: SECTION_STATEMENT_TAIL,
                found: statement_tail.len() * FR_BYTES,
                expected: STATEMENT_TAIL_BYTES,
            });
        }
        if companion_proof.is_empty() {
            return Err(WrapperError::EmptyCompanionProof);
        }
        if companion_proof.len() > MAX_COMPANION_PROOF_BYTES {
            return Err(WrapperError::OversizedSection {
                tag: SECTION_COMPANION_PROOF,
                len: companion_proof.len() as u64,
                limit: MAX_COMPANION_PROOF_BYTES,
            });
        }
        Ok(MemoWrapperV1 {
            memo,
            nullifier,
            segment,
            statement_tail,
            companion_proof,
            locator,
        })
    }

    /// The memo bytes **as parsed** — not as authenticated.
    #[inline]
    pub fn unverified_memo(&self) -> &Memo {
        &self.memo
    }

    /// The attributed nullifier the wrapper claims.
    #[inline]
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// The final segment the wrapper claims.
    #[inline]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// The carried statement rows `1..INPUT_PIS`. **A claim, not a fact** — the
    /// verifier rebuilds these from the canonical input and requires equality.
    #[inline]
    pub fn claimed_statement_tail(&self) -> &[Fr] {
        &self.statement_tail
    }

    /// The detached companion proof, as tagged bytes.
    #[inline]
    pub fn companion_proof_bytes(&self) -> &[u8] {
        &self.companion_proof
    }

    /// The never-trusted locator, if the wrapper carried one.
    #[inline]
    pub fn locator(&self) -> Option<&UntrustedLocator> {
        self.locator.as_ref()
    }

    /// The exact serialized length this wrapper encodes to.
    pub fn encoded_len(&self) -> usize {
        let mut len = WRAPPER_HEADER_BYTES;
        for section_len in [
            self.memo.len(),
            32,
            2,
            STATEMENT_TAIL_BYTES,
            self.companion_proof.len(),
        ] {
            len += SECTION_HEADER_BYTES + section_len;
        }
        if let Some(locator) = &self.locator {
            len += SECTION_HEADER_BYTES + locator.0.len();
        }
        len
    }

    /// Encodes the wrapper. Sections are emitted in ascending tag order, so the
    /// encoding is canonical and `decode ∘ encode` and `encode ∘ decode` are
    /// both the identity.
    pub fn encode(&self) -> Vec<u8> {
        let mut section_count: u16 = REQUIRED_SECTIONS.len() as u16;
        if self.locator.is_some() {
            section_count += 1;
        }

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(WRAPPER_MAGIC);
        out.extend_from_slice(&WRAPPER_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&section_count.to_le_bytes());

        push_section(&mut out, SECTION_MEMO, self.memo.as_bytes());
        push_section(&mut out, SECTION_NULLIFIER, &self.nullifier.0.0);
        push_section(&mut out, SECTION_SEGMENT, &self.segment.to_le_bytes());

        let mut tail = Vec::with_capacity(STATEMENT_TAIL_BYTES);
        for row in &self.statement_tail {
            tail.extend_from_slice(&fr_le32(*row));
        }
        push_section(&mut out, SECTION_STATEMENT_TAIL, &tail);
        push_section(&mut out, SECTION_COMPANION_PROOF, &self.companion_proof);

        if let Some(locator) = &self.locator {
            push_section(&mut out, SECTION_LOCATOR, &locator.0);
        }
        out
    }

    /// Decodes untrusted bytes. Never panics; every failure is a typed refusal
    /// and nothing is allocated before the length that governs it is checked.
    pub fn decode(bytes: &[u8]) -> Result<Self, WrapperError> {
        // 1. The whole-artifact ceiling, first, so an oversized blob is refused
        //    without being walked.
        if bytes.len() > MAX_WRAPPER_BYTES {
            return Err(WrapperError::Oversized {
                len: bytes.len(),
                limit: MAX_WRAPPER_BYTES,
            });
        }
        if bytes.len() < WRAPPER_HEADER_BYTES {
            return Err(WrapperError::Truncated {
                context: "wrapper header",
                needed: WRAPPER_HEADER_BYTES,
                available: bytes.len(),
            });
        }
        if &bytes[..WRAPPER_MAGIC.len()] != WRAPPER_MAGIC {
            return Err(WrapperError::BadMagic);
        }
        let version =
            u16::from_le_bytes([bytes[WRAPPER_MAGIC.len()], bytes[WRAPPER_MAGIC.len() + 1]]);
        if version != WRAPPER_VERSION_V1 {
            return Err(WrapperError::UnsupportedVersion { found: version });
        }
        let section_count = u16::from_le_bytes([
            bytes[WRAPPER_MAGIC.len() + 2],
            bytes[WRAPPER_MAGIC.len() + 3],
        ]) as usize;
        if section_count > MAX_SECTIONS {
            return Err(WrapperError::TooManySections {
                declared: section_count,
                limit: MAX_SECTIONS,
            });
        }

        // 2. Index pass. Records (tag, span) only; copies nothing. The Vec is
        //    bounded by MAX_SECTIONS, which was checked above.
        let mut spans: Vec<(u16, &[u8])> = Vec::with_capacity(section_count);
        let mut rest = &bytes[WRAPPER_HEADER_BYTES..];
        for _ in 0..section_count {
            if rest.len() < SECTION_HEADER_BYTES {
                return Err(WrapperError::Truncated {
                    context: "section header",
                    needed: SECTION_HEADER_BYTES,
                    available: rest.len(),
                });
            }
            let tag = u16::from_le_bytes([rest[0], rest[1]]);
            let declared = u32::from_le_bytes([rest[2], rest[3], rest[4], rest[5]]) as u64;
            if declared > MAX_SECTION_BYTES as u64 {
                return Err(WrapperError::OversizedSection {
                    tag,
                    len: declared,
                    limit: MAX_SECTION_BYTES,
                });
            }
            let declared = declared as usize;
            rest = &rest[SECTION_HEADER_BYTES..];
            if rest.len() < declared {
                return Err(WrapperError::Truncated {
                    context: "section payload",
                    needed: declared,
                    available: rest.len(),
                });
            }
            spans.push((tag, &rest[..declared]));
            rest = &rest[declared..];
        }
        if !rest.is_empty() {
            return Err(WrapperError::TrailingBytes { extra: rest.len() });
        }

        // 3. Duplicates FIRST — duplicate fields are named explicitly, so a
        //    duplicate must be reported as one whatever order it arrived in.
        //    `spans` is bounded by MAX_SECTIONS, so the quadratic scan is 32x32
        //    at worst.
        for (i, (tag, _)) in spans.iter().enumerate() {
            if spans[i + 1..].iter().any(|(other, _)| other == tag) {
                return Err(WrapperError::DuplicateSection { tag: *tag });
            }
        }
        // ... then the ordering rule, which is what makes the encoding
        // canonical.
        for window in spans.windows(2) {
            let (previous, _) = window[0];
            let (found, _) = window[1];
            if found < previous {
                return Err(WrapperError::SectionsOutOfOrder { previous, found });
            }
        }

        // 4. Unknown tags. Mandatory range: refuse. Optional range: ignore.
        for (tag, _) in &spans {
            let known = REQUIRED_SECTIONS.contains(tag) || *tag == SECTION_LOCATOR;
            if !known && *tag <= MANDATORY_SECTION_MAX {
                return Err(WrapperError::UnknownMandatorySection { tag: *tag });
            }
        }

        // 5. Every mandatory section present.
        let find = |tag: u16| spans.iter().find(|(t, _)| *t == tag).map(|(_, s)| *s);
        for tag in REQUIRED_SECTIONS {
            if find(tag).is_none() {
                return Err(WrapperError::MissingMandatorySection { tag });
            }
        }

        // 6. Materialize. Each field checks its own rule on the BORROWED slice
        //    before any copy is made.
        let memo_bytes = find(SECTION_MEMO).expect("checked present");
        check_memo_len(memo_bytes.len())?;
        let memo = Memo::from_slice(memo_bytes)?;

        let nullifier_bytes = find(SECTION_NULLIFIER).expect("checked present");
        if nullifier_bytes.len() != 32 {
            return Err(WrapperError::BadSectionLength {
                tag: SECTION_NULLIFIER,
                found: nullifier_bytes.len(),
                expected: 32,
            });
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(nullifier_bytes);
        let nullifier = Nullifier(HashOutput(raw));

        let segment_bytes = find(SECTION_SEGMENT).expect("checked present");
        if segment_bytes.len() != 2 {
            return Err(WrapperError::BadSectionLength {
                tag: SECTION_SEGMENT,
                found: segment_bytes.len(),
                expected: 2,
            });
        }
        let segment = u16::from_le_bytes([segment_bytes[0], segment_bytes[1]]);

        let tail_bytes = find(SECTION_STATEMENT_TAIL).expect("checked present");
        if tail_bytes.len() != STATEMENT_TAIL_BYTES {
            return Err(WrapperError::BadSectionLength {
                tag: SECTION_STATEMENT_TAIL,
                found: tail_bytes.len(),
                expected: STATEMENT_TAIL_BYTES,
            });
        }
        let mut statement_tail = Vec::with_capacity(STATEMENT_TAIL_ROWS);
        for (i, chunk) in tail_bytes.chunks_exact(FR_BYTES).enumerate() {
            let row = Fr::from_le_bytes(chunk)
                .ok_or(WrapperError::NonCanonicalStatementRow { row: i + 1 })?;
            statement_tail.push(row);
        }

        let proof_bytes = find(SECTION_COMPANION_PROOF).expect("checked present");
        if proof_bytes.is_empty() {
            return Err(WrapperError::EmptyCompanionProof);
        }
        if proof_bytes.len() > MAX_COMPANION_PROOF_BYTES {
            return Err(WrapperError::OversizedSection {
                tag: SECTION_COMPANION_PROOF,
                len: proof_bytes.len() as u64,
                limit: MAX_COMPANION_PROOF_BYTES,
            });
        }

        let locator = match find(SECTION_LOCATOR) {
            Some(bytes) => Some(UntrustedLocator::from_slice(bytes)?),
            None => None,
        };

        Ok(MemoWrapperV1 {
            memo,
            nullifier,
            segment,
            statement_tail,
            companion_proof: proof_bytes.to_vec(),
            locator,
        })
    }
}

/// Never renders the memo bytes, the proof bytes, or the locator.
impl Debug for MemoWrapperV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoWrapperV1")
            .field("memo", &self.memo)
            .field("nullifier", &hex_lower(&self.nullifier.0.0))
            .field("segment", &self.segment)
            .field("statement_tail_rows", &self.statement_tail.len())
            .field("companion_proof_bytes", &self.companion_proof.len())
            .field("locator", &self.locator)
            .field("status", &"PARSED — NOT VERIFIED")
            .finish()
    }
}

fn push_section(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memo::MAX_MEMO_BYTES;

    fn test_nullifier(seed: u8) -> Nullifier {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(seed);
        }
        Nullifier(HashOutput(raw))
    }

    fn test_tail() -> Vec<Fr> {
        (0..STATEMENT_TAIL_ROWS)
            .map(|i| Fr::from(0x0100_0000_u64 + i as u64))
            .collect()
    }

    fn test_proof_bytes() -> Vec<u8> {
        (0..256u32).map(|i| (i % 251) as u8).collect()
    }

    fn sample(locator: Option<&[u8]>) -> MemoWrapperV1 {
        MemoWrapperV1::from_parts(
            Memo::from_slice(b"hello world").unwrap(),
            test_nullifier(7),
            3,
            test_tail(),
            test_proof_bytes(),
            locator.map(|l| UntrustedLocator::from_slice(l).unwrap()),
        )
        .unwrap()
    }

    /// Writes a raw container, so a malformed case is genuinely malformed
    /// rather than something the encoder would refuse to produce.
    fn raw_container(sections: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(WRAPPER_MAGIC);
        out.extend_from_slice(&WRAPPER_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        for (tag, payload) in sections {
            push_section(&mut out, *tag, payload);
        }
        out
    }

    fn valid_sections() -> Vec<(u16, Vec<u8>)> {
        let mut tail = Vec::new();
        for row in test_tail() {
            tail.extend_from_slice(&fr_le32(row));
        }
        vec![
            (SECTION_MEMO, b"hello world".to_vec()),
            (SECTION_NULLIFIER, test_nullifier(7).0.0.to_vec()),
            (SECTION_SEGMENT, 3u16.to_le_bytes().to_vec()),
            (SECTION_STATEMENT_TAIL, tail),
            (SECTION_COMPANION_PROOF, test_proof_bytes()),
        ]
    }

    #[test]
    fn round_trip_is_the_identity_both_ways() {
        for locator in [None, Some(&b"offer.bin"[..])] {
            let w = sample(locator);
            let bytes = w.encode();
            assert_eq!(bytes.len(), w.encoded_len());
            let back = MemoWrapperV1::decode(&bytes).unwrap();
            assert_eq!(back, w);
            assert_eq!(back.encode(), bytes);
        }
    }

    #[test]
    fn the_frozen_header_is_what_it_says_it_is() {
        assert_eq!(WRAPPER_MAGIC, b"midnight:zswap-memo-wrapper");
        assert_eq!(WRAPPER_MAGIC.len(), 27);
        assert_eq!(WRAPPER_HEADER_BYTES, 31);
        assert_eq!(SECTION_HEADER_BYTES, 6);
        assert_eq!(STATEMENT_TAIL_ROWS, 67);
        assert_eq!(STATEMENT_TAIL_BYTES, 2144);
        let bytes = sample(None).encode();
        assert!(bytes.starts_with(WRAPPER_MAGIC));
        assert_eq!(&bytes[27..29], &1u16.to_le_bytes());
        assert_eq!(&bytes[29..31], &5u16.to_le_bytes());
    }

    #[test]
    fn oversized_is_refused_before_the_container_is_walked() {
        let junk = vec![0u8; MAX_WRAPPER_BYTES + 1];
        assert_eq!(
            MemoWrapperV1::decode(&junk).unwrap_err(),
            WrapperError::Oversized {
                len: MAX_WRAPPER_BYTES + 1,
                limit: MAX_WRAPPER_BYTES
            }
        );
    }

    /// A declared `u32::MAX` must be a typed error, not a four-gigabyte
    /// allocation.
    #[test]
    fn a_declared_length_of_u32_max_is_a_typed_error_not_an_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(WRAPPER_MAGIC);
        bytes.extend_from_slice(&WRAPPER_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&SECTION_MEMO.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            MemoWrapperV1::decode(&bytes).unwrap_err(),
            WrapperError::OversizedSection {
                tag: SECTION_MEMO,
                len: u32::MAX as u64,
                limit: MAX_SECTION_BYTES
            }
        );
    }

    #[test]
    fn every_prefix_is_a_typed_reject_not_a_panic() {
        let bytes = sample(Some(b"tx:deadbeef")).encode();
        for cut in 0..bytes.len() {
            assert!(
                MemoWrapperV1::decode(&bytes[..cut]).is_err(),
                "prefix of length {cut} decoded"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_a_typed_reject() {
        for extra in [vec![0x00u8], vec![0x00u8; 8], vec![0xffu8; 3]] {
            let mut bytes = sample(None).encode();
            let n = extra.len();
            bytes.extend_from_slice(&extra);
            assert_eq!(
                MemoWrapperV1::decode(&bytes).unwrap_err(),
                WrapperError::TrailingBytes { extra: n }
            );
        }
    }

    #[test]
    fn bad_magic_is_a_typed_reject() {
        let base = sample(None).encode();
        let mut zeroed = base.clone();
        zeroed[..WRAPPER_MAGIC.len()].fill(0);
        assert_eq!(
            MemoWrapperV1::decode(&zeroed).unwrap_err(),
            WrapperError::BadMagic
        );
        for i in 0..WRAPPER_MAGIC.len() {
            for bit in 0..8 {
                let mut b = base.clone();
                b[i] ^= 1 << bit;
                assert_eq!(
                    MemoWrapperV1::decode(&b).unwrap_err(),
                    WrapperError::BadMagic
                );
            }
        }
    }

    #[test]
    fn unsupported_versions_are_typed_rejects() {
        for v in [0u16, 2, 3, 0x00ff, u16::MAX] {
            let mut bytes = sample(None).encode();
            bytes[27..29].copy_from_slice(&v.to_le_bytes());
            assert_eq!(
                MemoWrapperV1::decode(&bytes).unwrap_err(),
                WrapperError::UnsupportedVersion { found: v }
            );
        }
    }

    #[test]
    fn duplicate_sections_are_a_typed_reject() {
        let mut sections = valid_sections();
        sections.push((SECTION_MEMO, b"hello world".to_vec()));
        assert_eq!(
            MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
            WrapperError::DuplicateSection { tag: SECTION_MEMO }
        );
    }

    #[test]
    fn sections_out_of_order_are_a_typed_reject() {
        let mut sections = valid_sections();
        sections.swap(0, 1);
        assert!(matches!(
            MemoWrapperV1::decode(&raw_container(&sections)),
            Err(WrapperError::SectionsOutOfOrder { .. })
        ));
    }

    #[test]
    fn unknown_mandatory_sections_are_typed_rejects() {
        let mut sections = valid_sections();
        sections.push((0x0006, vec![0u8; 4]));
        assert_eq!(
            MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
            WrapperError::UnknownMandatorySection { tag: 0x0006 }
        );
    }

    /// Forward compatibility: a later version may add an optional section and a
    /// version 1 reader must still authenticate, with every parsed field
    /// identical to the baseline.
    #[test]
    fn unknown_optional_sections_are_ignored() {
        let baseline = MemoWrapperV1::decode(&raw_container(&valid_sections())).unwrap();
        let mut sections = valid_sections();
        sections.push((0x2000, b"something from the future".to_vec()));
        let with_future = MemoWrapperV1::decode(&raw_container(&sections)).unwrap();
        assert_eq!(with_future, baseline);
    }

    #[test]
    fn every_missing_mandatory_section_is_a_typed_reject() {
        for drop in 0..valid_sections().len() {
            let mut sections = valid_sections();
            let (tag, _) = sections.remove(drop);
            assert_eq!(
                MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
                WrapperError::MissingMandatorySection { tag }
            );
        }
    }

    #[test]
    fn too_many_sections_is_a_typed_reject() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(WRAPPER_MAGIC);
        bytes.extend_from_slice(&WRAPPER_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&((MAX_SECTIONS + 1) as u16).to_le_bytes());
        assert_eq!(
            MemoWrapperV1::decode(&bytes).unwrap_err(),
            WrapperError::TooManySections {
                declared: MAX_SECTIONS + 1,
                limit: MAX_SECTIONS
            }
        );
    }

    #[test]
    fn memo_length_zero_and_513_are_refused_inside_the_container() {
        for bad in [0usize, MAX_MEMO_BYTES + 1] {
            let mut sections = valid_sections();
            sections[0].1 = vec![0x41; bad];
            assert!(matches!(
                MemoWrapperV1::decode(&raw_container(&sections)),
                Err(WrapperError::Memo(_))
            ));
        }
        for good in [1usize, 31, 32, 511, 512] {
            let mut sections = valid_sections();
            sections[0].1 = vec![0x41; good];
            assert_eq!(
                MemoWrapperV1::decode(&raw_container(&sections))
                    .unwrap()
                    .unverified_memo()
                    .len(),
                good
            );
        }
    }

    #[test]
    fn fixed_width_sections_reject_every_other_width() {
        for (index, tag, expected) in [
            (1usize, SECTION_NULLIFIER, 32usize),
            (2, SECTION_SEGMENT, 2),
            (3, SECTION_STATEMENT_TAIL, STATEMENT_TAIL_BYTES),
        ] {
            for delta in [-1isize, 1] {
                let len = (expected as isize + delta) as usize;
                let mut sections = valid_sections();
                sections[index].1 = vec![0u8; len];
                assert_eq!(
                    MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
                    WrapperError::BadSectionLength {
                        tag,
                        found: len,
                        expected
                    }
                );
            }
        }
    }

    #[test]
    fn non_canonical_statement_rows_are_typed_rejects() {
        let mut sections = valid_sections();
        // An all-ones 32-byte value is above the field modulus.
        sections[3].1[FR_BYTES * 4..FR_BYTES * 5].fill(0xff);
        assert_eq!(
            MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
            WrapperError::NonCanonicalStatementRow { row: 5 }
        );
    }

    #[test]
    fn an_empty_companion_proof_is_a_typed_reject() {
        let mut sections = valid_sections();
        sections[4].1 = Vec::new();
        assert_eq!(
            MemoWrapperV1::decode(&raw_container(&sections)).unwrap_err(),
            WrapperError::EmptyCompanionProof
        );
        assert_eq!(
            MemoWrapperV1::from_parts(
                Memo::from_slice(b"x").unwrap(),
                test_nullifier(1),
                0,
                test_tail(),
                Vec::new(),
                None
            )
            .unwrap_err(),
            WrapperError::EmptyCompanionProof
        );
    }

    #[test]
    fn an_oversized_locator_is_a_typed_reject() {
        assert!(matches!(
            UntrustedLocator::from_slice(&vec![0x41; MAX_LOCATOR_BYTES + 1]),
            Err(WrapperError::OversizedSection { .. })
        ));
        assert!(UntrustedLocator::from_slice(&vec![0x41; MAX_LOCATOR_BYTES]).is_ok());
    }

    #[test]
    fn hostile_bytes_never_panic_and_never_forge_the_original() {
        let w = sample(Some(b"tx:deadbeef"));
        let bytes = w.encode();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut mutated = bytes.clone();
                mutated[i] ^= mask;
                if let Ok(other) = MemoWrapperV1::decode(&mutated) {
                    assert_ne!(other, w, "byte {i} mask {mask:#x} forged the original");
                }
            }
        }
    }

    #[test]
    fn junk_never_decodes_and_never_panics() {
        for junk in [
            vec![],
            vec![0u8; 1],
            vec![0u8; WRAPPER_HEADER_BYTES],
            vec![0xffu8; 1024],
            (0..2048u32).map(|i| (i % 256) as u8).collect(),
        ] {
            assert!(MemoWrapperV1::decode(&junk).is_err());
        }
    }

    #[test]
    fn debug_never_emits_the_payloads() {
        let w = MemoWrapperV1::from_parts(
            Memo::from_slice(b"\x1b[2Jerased\x00").unwrap(),
            test_nullifier(3),
            1,
            test_tail(),
            test_proof_bytes(),
            Some(UntrustedLocator::from_slice(b"\x1bhostile").unwrap()),
        )
        .unwrap();
        let rendered = format!("{w:?}");
        assert!(!rendered.contains('\x1b'));
        assert!(rendered.contains("PARSED — NOT VERIFIED"));
        assert!(rendered.contains("NEVER TRUSTED AS PROOF"));
    }
}
