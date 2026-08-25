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

//! `AnchorV1` — the on-chain **strip evidence** carried in an ordinary
//! zero-value output's `CoinCiphertext`.
//!
//! ```text
//! c       = EmbeddedGroupAffine::generator()
//! ciph[0] = Fr::from_le_bytes("midnight:zswap-anchor")   // marker
//! ciph[1] = Fr::from(1)                                  // version
//! ciph[2] = Fr::from_le_bytes(N_bytes[31..32])           // trailing byte FIRST
//! ciph[3] = Fr::from_le_bytes(N_bytes[0..31])            // leading 31 bytes
//! ciph[4] = h                                            // nonzero
//! ciph[5] = Fr::from(0)                                  // reserved
//! ```
//!
//! `N_bytes` is the RAW 32 bytes stored in the nullifier's `HashOutput` — not
//! display hex, not tagged serialization. The 1-then-31 split is this crate's
//! own `FieldRepr for [u8]` order (it walks the slice from the back, emitting
//! the `len % 31` stray bytes first), so an anchor's nullifier fields line up
//! with how the ledger already embeds a `HashOutput`.
//!
//! # On the wire the ciphertext is UNTAGGED
//!
//! `tagged_serialize` writes a tag header once per **top-level** artifact, so a
//! `CoinCiphertext` sitting inside a serialized `Transaction`/`Offer`/`Output`
//! carries no tag bytes of its own. An anchor scanner must look for
//! [`AnchorV1::encode_untagged_bytes`], never for `tagged_serialize` output.
//! Each `Fr` is additionally serialized through a SCALE-compact
//! **variable-length** integer, so the untagged encoding has **no fixed
//! width** — a scanner must not assume one. [`anchor_wire_prefix`] is what
//! makes scanning tractable anyway: `c`, `ciph[0]` and `ciph[1]` are constants
//! in version 1, so every anchor begins with the same fixed byte string.
//!
//! # Decoding is total and typed
//!
//! Decoding never panics and never returns a partially trusted result. It
//! requires ALL of: the exact marker, version exactly 1, the canonical
//! generator point, a **canonical nullifier split**, a nonzero `h`, and a zero
//! reserved field. Anything else — including an unknown version — is simply not
//! an anchor.
//!
//! The canonical-split rule is load-bearing rather than decorative. `ciph[2]`
//! encodes one byte and `ciph[3]` thirty-one; without range checks,
//! `ciph[2] = 256` would decode to the same nullifier byte as `ciph[2] = 0`, so
//! two different ciphertexts would decode to one `N` and anchor matching would
//! stop being exact. The rule is strictly narrowing: it rejects ciphertexts,
//! never accepts more, and changes no byte an honest constructor writes.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use base_crypto::hash::HashOutput;
use coin_structure::coin::Nullifier;
use serialize::{Deserializable, Serializable};
use transient_crypto::curve::{EmbeddedGroupAffine, Fr};

use crate::CoinCiphertext;
use crate::memo::{BindingElement, ReservedBindingElement, fr_le32, hex_lower};

/// Domain marker for version 1 anchors: 21 bytes.
///
/// Deliberately distinct from the memo domain separator: the two live in
/// different roles and must never be interchangeable.
pub const ANCHOR_MARKER: &[u8] = b"midnight:zswap-anchor";

/// The only anchor version this codec accepts.
pub const ANCHOR_VERSION_V1: u64 = 1;

/// The number of field elements in a `CoinCiphertext`.
pub const ANCHOR_FIELDS: usize = 6;

/// The marker as a field element.
pub fn anchor_marker_field() -> Fr {
    Fr::from_le_bytes(ANCHOR_MARKER).expect("the anchor marker is 21 bytes, hence in range")
}

/// The version field as a field element.
pub fn anchor_version_field() -> Fr {
    Fr::from(ANCHOR_VERSION_V1)
}

/// The reserved (currently always zero) field element.
pub fn anchor_reserved_field() -> Fr {
    Fr::from(0u64)
}

/// The canonical anchor curve point.
pub fn anchor_point() -> EmbeddedGroupAffine {
    EmbeddedGroupAffine::generator()
}

/// Why a `CoinCiphertext` is not a version 1 anchor.
///
/// Every variant means the same thing to a reader — *this is not an anchor* —
/// but they stay distinct so a diagnostic can say which rule failed without
/// logging the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorDecodeError {
    /// `c` is not the canonical generator point.
    NonCanonicalPoint {
        /// Whether the offending point was the identity specifically. The
        /// identity is additionally rejected by `CoinCiphertext::deserialize`,
        /// so it cannot arrive over the wire — but an in-memory value can hold
        /// it.
        identity: bool,
    },
    /// `ciph[0]` is not [`ANCHOR_MARKER`].
    BadMarker {
        /// The offending element, little-endian.
        found: [u8; 32],
    },
    /// `ciph[1]` is not `1`. Unknown versions are NOT anchors.
    UnsupportedVersion {
        /// The offending element, little-endian.
        found: [u8; 32],
    },
    /// `ciph[2]` or `ciph[3]` is wider than the byte window it encodes, so it
    /// is not the canonical split of any 32-byte nullifier.
    NonCanonicalNullifierSplit {
        /// Which `ciph` index was out of range (2 or 3).
        index: usize,
        /// The offending element, little-endian.
        found: [u8; 32],
    },
    /// `ciph[4]` is the reserved zero element.
    ReservedBindingElement,
    /// `ciph[5]` is not zero.
    NonZeroReservedField {
        /// The offending element, little-endian.
        found: [u8; 32],
    },
    /// The bytes could not be read as a `CoinCiphertext` at all.
    Malformed {
        /// The underlying message, verbatim.
        reason: String,
    },
    /// A `CoinCiphertext` was read, but bytes remained. An anchor's encoding is
    /// exactly consumed.
    TrailingBytes {
        /// How many bytes were left over.
        extra: usize,
    },
}

impl Display for AnchorDecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AnchorDecodeError::NonCanonicalPoint { identity } => {
                if *identity {
                    f.write_str("anchor point is the identity, not the canonical generator")
                } else {
                    f.write_str("anchor point is not the canonical generator")
                }
            }
            AnchorDecodeError::BadMarker { found } => write!(
                f,
                "ciph[0] is {} , not the AnchorV1 marker",
                hex_lower(found)
            ),
            AnchorDecodeError::UnsupportedVersion { found } => write!(
                f,
                "ciph[1] is {}, not version {ANCHOR_VERSION_V1}",
                hex_lower(found)
            ),
            AnchorDecodeError::NonCanonicalNullifierSplit { index, found } => write!(
                f,
                "ciph[{index}] is {}, wider than the nullifier byte window it encodes",
                hex_lower(found)
            ),
            AnchorDecodeError::ReservedBindingElement => {
                f.write_str("ciph[4] is the reserved zero binding element, which means \"no memo\"")
            }
            AnchorDecodeError::NonZeroReservedField { found } => write!(
                f,
                "ciph[5] is {}, but the reserved field must be zero",
                hex_lower(found)
            ),
            AnchorDecodeError::Malformed { reason } => {
                write!(f, "not a readable CoinCiphertext: {reason}")
            }
            AnchorDecodeError::TrailingBytes { extra } => {
                write!(f, "{extra} trailing byte(s) after the anchor ciphertext")
            }
        }
    }
}

impl Error for AnchorDecodeError {}

impl From<ReservedBindingElement> for AnchorDecodeError {
    fn from(_: ReservedBindingElement) -> Self {
        AnchorDecodeError::ReservedBindingElement
    }
}

/// A decoded, fully validated version 1 anchor.
///
/// Holding one means the marker, version, point, nullifier split and reserved
/// field were all exactly right and `binding` is nonzero. It does **not** mean
/// the memo is authenticated — that comes only from a verified companion spend
/// proof. It also says nothing about the carrier coin's value, token type,
/// nonce or recipient: those are honest-constructor invariants hidden behind
/// the output commitment, not facts a reader of a settled output can establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorV1 {
    /// The attributed input's nullifier.
    pub nullifier: Nullifier,
    /// The memo commitment `h`. Nonzero by construction.
    pub binding: BindingElement,
}

impl AnchorV1 {
    /// Builds an anchor for `nullifier` and the (already nonzero) `binding`.
    ///
    /// There is deliberately no constructor taking a bare `Fr`: the
    /// reserved-zero rule is enforced by [`BindingElement`], so a zero-`h`
    /// anchor cannot be constructed through this API at all.
    pub fn new(nullifier: Nullifier, binding: BindingElement) -> Self {
        AnchorV1 { nullifier, binding }
    }

    /// The raw 32 nullifier bytes.
    #[inline]
    pub fn nullifier_bytes(&self) -> [u8; 32] {
        self.nullifier.0.0
    }

    /// Encodes to the `CoinCiphertext` an ordinary zero-value output carries.
    pub fn encode(&self) -> CoinCiphertext {
        let n = self.nullifier_bytes();
        CoinCiphertext {
            c: anchor_point(),
            ciph: [
                anchor_marker_field(),
                anchor_version_field(),
                Fr::from_le_bytes(&n[31..32]).expect("1 byte is always in range"),
                Fr::from_le_bytes(&n[0..31]).expect("31 bytes are always in range"),
                self.binding.get(),
                anchor_reserved_field(),
            ],
        }
    }

    /// The exact bytes an anchor occupies **inside a serialized transaction**:
    /// the plain, UNTAGGED `Serializable` encoding.
    pub fn encode_untagged_bytes(&self) -> Vec<u8> {
        let ciph = self.encode();
        let mut out = Vec::with_capacity(Serializable::serialized_size(&ciph));
        Serializable::serialize(&ciph, &mut out)
            .expect("writing a CoinCiphertext into a Vec cannot fail");
        out
    }

    /// Decodes a `CoinCiphertext`, requiring **every** version 1 rule.
    ///
    /// Never panics. Every failure is a typed "this is not an anchor".
    pub fn decode(ciph: &CoinCiphertext) -> Result<Self, AnchorDecodeError> {
        if ciph.c != anchor_point() {
            return Err(AnchorDecodeError::NonCanonicalPoint {
                identity: ciph.c.is_identity(),
            });
        }
        if ciph.ciph[0] != anchor_marker_field() {
            return Err(AnchorDecodeError::BadMarker {
                found: fr_le32(ciph.ciph[0]),
            });
        }
        if ciph.ciph[1] != anchor_version_field() {
            return Err(AnchorDecodeError::UnsupportedVersion {
                found: fr_le32(ciph.ciph[1]),
            });
        }
        if ciph.ciph[5] != anchor_reserved_field() {
            return Err(AnchorDecodeError::NonZeroReservedField {
                found: fr_le32(ciph.ciph[5]),
            });
        }

        let trailing = fr_le32(ciph.ciph[2]);
        if trailing[1..].iter().any(|b| *b != 0) {
            return Err(AnchorDecodeError::NonCanonicalNullifierSplit {
                index: 2,
                found: trailing,
            });
        }
        let leading = fr_le32(ciph.ciph[3]);
        if leading[31] != 0 {
            return Err(AnchorDecodeError::NonCanonicalNullifierSplit {
                index: 3,
                found: leading,
            });
        }

        let binding = BindingElement::new(ciph.ciph[4])?;

        let mut n = [0u8; 32];
        n[0..31].copy_from_slice(&leading[0..31]);
        n[31] = trailing[0];

        Ok(AnchorV1 {
            nullifier: Nullifier(HashOutput(n)),
            binding,
        })
    }

    /// Decodes from the UNTAGGED wire bytes, requiring exact consumption.
    ///
    /// Truncated input, an invalid group encoding, an out-of-range field
    /// element and trailing bytes are all typed rejects; none of them panics.
    pub fn decode_untagged_bytes(bytes: &[u8]) -> Result<Self, AnchorDecodeError> {
        let (anchor, consumed) = Self::decode_untagged_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(AnchorDecodeError::TrailingBytes {
                extra: bytes.len() - consumed,
            });
        }
        Ok(anchor)
    }

    /// Decodes an anchor from the START of `bytes`, allowing bytes to remain,
    /// and reports how many were consumed.
    ///
    /// This is the entry point a scanner over a serialized transaction needs:
    /// [`AnchorV1::decode_untagged_bytes`] requires exact consumption, which is
    /// right for a standalone artifact and wrong for a ciphertext embedded in a
    /// larger stream.
    pub fn decode_untagged_prefix(bytes: &[u8]) -> Result<(Self, usize), AnchorDecodeError> {
        let mut cursor = bytes;
        let ciph =
            <CoinCiphertext as Deserializable>::deserialize(&mut cursor, 0).map_err(|e| {
                AnchorDecodeError::Malformed {
                    reason: e.to_string(),
                }
            })?;
        let consumed = bytes.len() - cursor.len();
        Self::decode(&ciph).map(|anchor| (anchor, consumed))
    }
}

/// A `CoinCiphertext` that is shaped like an anchor but carries the RESERVED
/// ZERO binding element.
///
/// **Test double.** It exists so that "a forced `MemoHashV1 = 0` double is
/// rejected by constructors, decoders and verifiers" can be exercised without
/// finding a real Poseidon preimage of zero. It hard-codes zero, so it cannot
/// be used to forge an anchor with an attacker-chosen `h`; the honest
/// construction path is [`AnchorV1::encode`], which takes a [`BindingElement`]
/// and therefore cannot produce this value.
pub fn reserved_zero_anchor_ciphertext(nullifier: &Nullifier) -> CoinCiphertext {
    let n = nullifier.0.0;
    CoinCiphertext {
        c: anchor_point(),
        ciph: [
            anchor_marker_field(),
            anchor_version_field(),
            Fr::from_le_bytes(&n[31..32]).expect("1 byte is always in range"),
            Fr::from_le_bytes(&n[0..31]).expect("31 bytes are always in range"),
            Fr::from(0u64),
            anchor_reserved_field(),
        ],
    }
}

/// The constant byte prefix every version 1 anchor has on the wire.
///
/// The untagged serialization of the canonical point, the marker field and the
/// version field — the three parts of an `AnchorV1` that never vary. Derived
/// rather than hard-coded.
pub fn anchor_wire_prefix() -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    Serializable::serialize(&anchor_point(), &mut out).expect("writing to a Vec cannot fail");
    Serializable::serialize(&anchor_marker_field(), &mut out)
        .expect("writing to a Vec cannot fail");
    Serializable::serialize(&anchor_version_field(), &mut out)
        .expect("writing to a Vec cannot fail");
    out
}

/// Whether `ciph` LOOKS like an anchor: canonical point and exact marker.
///
/// Deliberately weaker than [`AnchorV1::decode`], and used for exactly one
/// thing — reporting a ciphertext that is anchor-*shaped* but not a valid
/// anchor as an anomaly instead of silently ignoring it. It is never a reason
/// to trust anything.
pub fn is_anchor_shaped(ciph: &CoinCiphertext) -> bool {
    ciph.c == anchor_point() && ciph.ciph[0] == anchor_marker_field()
}

/// One anchor found while scanning raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorSighting {
    /// Byte offset where the anchor's untagged encoding begins.
    pub offset: usize,
    /// How many bytes it occupies. This VARIES between anchors.
    pub len: usize,
    /// The decoded anchor.
    pub anchor: AnchorV1,
}

/// Scans raw transaction/offer bytes for version 1 anchors.
///
/// Returns every sighting in offset order, **without** deduplicating and
/// without deciding which one "counts" — selecting an anchor by position or
/// insertion order is exactly what a reader must not do, so that decision is
/// left to the caller, who must make it by comparing decoded `(N, h)`.
///
/// A false-positive prefix hit inside unrelated data simply fails to decode and
/// is skipped, so the scan is total: no input panics and no input is rejected.
pub fn scan_untagged_anchors(bytes: &[u8]) -> Vec<AnchorSighting> {
    let prefix = anchor_wire_prefix();
    let mut out = Vec::new();
    if prefix.is_empty() || bytes.len() < prefix.len() {
        return out;
    }
    for offset in 0..=(bytes.len() - prefix.len()) {
        if &bytes[offset..offset + prefix.len()] != prefix.as_slice() {
            continue;
        }
        if let Ok((anchor, len)) = AnchorV1::decode_untagged_prefix(&bytes[offset..]) {
            out.push(AnchorSighting {
                offset,
                len,
                anchor,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memo::{Memo, memo_hash_v1};
    use serialize::{tagged_deserialize, tagged_serialize};

    fn nullifier(bytes: [u8; 32]) -> Nullifier {
        Nullifier(HashOutput(bytes))
    }

    fn binding(memo: &[u8]) -> BindingElement {
        BindingElement::for_memo(&Memo::from_slice(memo).unwrap()).unwrap()
    }

    fn sample() -> AnchorV1 {
        let mut n = [0u8; 32];
        for (i, b) in n.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        AnchorV1::new(nullifier(n), binding(b"hello world"))
    }

    #[test]
    fn field_layout_matches_the_protocol_literally() {
        let a = sample();
        let c = a.encode();
        assert_eq!(c.c, EmbeddedGroupAffine::generator());
        assert_eq!(c.ciph.len(), ANCHOR_FIELDS);
        assert_eq!(
            c.ciph[0],
            Fr::from_le_bytes(b"midnight:zswap-anchor").unwrap()
        );
        assert_eq!(c.ciph[1], Fr::from(1u64));
        let n = a.nullifier_bytes();
        assert_eq!(c.ciph[2], Fr::from_le_bytes(&n[31..32]).unwrap());
        assert_eq!(c.ciph[3], Fr::from_le_bytes(&n[0..31]).unwrap());
        assert_eq!(
            c.ciph[4],
            memo_hash_v1(&Memo::from_slice(b"hello world").unwrap())
        );
        assert_eq!(c.ciph[5], Fr::from(0u64));
    }

    #[test]
    fn decode_is_canonical() {
        for raw in [[0u8; 32], [0xff; 32], sample().nullifier_bytes()] {
            let a = AnchorV1::new(nullifier(raw), binding(b"midnight offer memo"));
            let encoded = a.encode();
            let decoded = AnchorV1::decode(&encoded).unwrap();
            assert_eq!(decoded, a);
            // decode ∘ encode is the identity on BYTES too.
            assert_eq!(decoded.encode_untagged_bytes(), a.encode_untagged_bytes());
        }
    }

    #[test]
    fn boundary_nullifiers_round_trip() {
        let mut trailing_only = [0u8; 32];
        trailing_only[31] = 0xff;
        let mut leading_only = [0u8; 32];
        leading_only[0] = 0xff;
        for raw in [[0u8; 32], [0xff; 32], trailing_only, leading_only] {
            let a = AnchorV1::new(nullifier(raw), binding(b"x"));
            assert_eq!(
                AnchorV1::decode(&a.encode()).unwrap().nullifier_bytes(),
                raw
            );
        }
    }

    #[test]
    fn zero_binding_element_is_not_an_anchor() {
        let n = nullifier([0x11; 32]);
        let ciph = reserved_zero_anchor_ciphertext(&n);
        assert_eq!(
            AnchorV1::decode(&ciph).unwrap_err(),
            AnchorDecodeError::ReservedBindingElement
        );
        // ...and on the wire too.
        let mut bytes = Vec::new();
        Serializable::serialize(&ciph, &mut bytes).unwrap();
        assert_eq!(
            AnchorV1::decode_untagged_bytes(&bytes).unwrap_err(),
            AnchorDecodeError::ReservedBindingElement
        );
    }

    #[test]
    fn bad_marker_is_not_an_anchor() {
        let a = sample();
        for bad in [
            Fr::from(0u64),
            Fr::from(1u64),
            memo_hash_v1(&Memo::from_slice(b"x").unwrap()),
        ] {
            let mut c = a.encode();
            c.ciph[0] = bad;
            assert!(matches!(
                AnchorV1::decode(&c),
                Err(AnchorDecodeError::BadMarker { .. })
            ));
        }
    }

    #[test]
    fn unknown_versions_are_not_anchors() {
        let a = sample();
        for bad in [0u64, 2, 3, u64::MAX] {
            let mut c = a.encode();
            c.ciph[1] = Fr::from(bad);
            assert!(matches!(
                AnchorV1::decode(&c),
                Err(AnchorDecodeError::UnsupportedVersion { .. })
            ));
        }
    }

    #[test]
    fn nonzero_reserved_field_is_not_an_anchor() {
        let a = sample();
        let mut c = a.encode();
        c.ciph[5] = Fr::from(1u64);
        assert!(matches!(
            AnchorV1::decode(&c),
            Err(AnchorDecodeError::NonZeroReservedField { .. })
        ));
    }

    #[test]
    fn noncanonical_and_identity_points_are_not_anchors() {
        let a = sample();
        let mut c = a.encode();
        c.c = EmbeddedGroupAffine::identity();
        assert_eq!(
            AnchorV1::decode(&c),
            Err(AnchorDecodeError::NonCanonicalPoint { identity: true })
        );
        let mut c = a.encode();
        c.c = EmbeddedGroupAffine::generator() + EmbeddedGroupAffine::generator();
        assert_eq!(
            AnchorV1::decode(&c),
            Err(AnchorDecodeError::NonCanonicalPoint { identity: false })
        );
    }

    /// The rule the protocol needs and a literal reading would miss: two
    /// different field pairs must never decode to the same nullifier.
    #[test]
    fn noncanonical_nullifier_split_is_not_an_anchor() {
        let a = sample();

        let mut c = a.encode();
        c.ciph[2] = Fr::from(256u64); // low byte 0x00, exactly like Fr::from(0)
        assert!(matches!(
            AnchorV1::decode(&c),
            Err(AnchorDecodeError::NonCanonicalNullifierSplit { index: 2, .. })
        ));

        let mut c = a.encode();
        let mut wide = [0u8; 32];
        wide[31] = 0x01; // 2^248: the same low 31 bytes as zero
        c.ciph[3] = Fr::from_le_bytes(&wide).unwrap();
        assert!(matches!(
            AnchorV1::decode(&c),
            Err(AnchorDecodeError::NonCanonicalNullifierSplit { index: 3, .. })
        ));
    }

    #[test]
    fn untagged_encoding_is_what_goes_on_the_wire() {
        let a = sample();
        let untagged = a.encode_untagged_bytes();
        let mut tagged = Vec::new();
        tagged_serialize(&a.encode(), &mut tagged).unwrap();
        assert!(
            tagged.len() > untagged.len(),
            "the tag header must be extra"
        );
        assert!(
            tagged.ends_with(&untagged),
            "the tagged form is the tag header followed by the untagged bytes"
        );
        let round: CoinCiphertext = tagged_deserialize(&mut tagged.as_slice()).unwrap();
        assert_eq!(AnchorV1::decode(&round).unwrap(), a);
    }

    /// Each `Fr` is a SCALE-compact variable-length integer, so anchors have no
    /// fixed width. A scanner that assumed one would be wrong.
    #[test]
    fn untagged_length_is_value_dependent() {
        let small = AnchorV1::new(nullifier([0u8; 32]), binding(b"hello world"));
        let large = AnchorV1::new(nullifier([0xff; 32]), binding(b"hello world"));
        assert_ne!(
            small.encode_untagged_bytes().len(),
            large.encode_untagged_bytes().len()
        );
    }

    #[test]
    fn truncated_bytes_are_a_typed_reject_not_a_panic() {
        let bytes = sample().encode_untagged_bytes();
        for cut in 0..bytes.len() {
            assert!(
                AnchorV1::decode_untagged_bytes(&bytes[..cut]).is_err(),
                "prefix of length {cut} decoded"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_a_typed_reject() {
        let mut bytes = sample().encode_untagged_bytes();
        bytes.push(0x00);
        assert_eq!(
            AnchorV1::decode_untagged_bytes(&bytes).unwrap_err(),
            AnchorDecodeError::TrailingBytes { extra: 1 }
        );
    }

    #[test]
    fn hostile_bytes_never_panic_and_never_forge_the_original() {
        let a = sample();
        let bytes = a.encode_untagged_bytes();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut mutated = bytes.clone();
                mutated[i] ^= mask;
                if let Ok(other) = AnchorV1::decode_untagged_bytes(&mutated) {
                    assert_ne!(other, a, "byte {i} mask {mask:#x} forged the original");
                }
            }
        }
        for junk in [vec![], vec![0u8; 1], vec![0xffu8; 256], vec![0x5au8; 91]] {
            let _ = AnchorV1::decode_untagged_bytes(&junk);
        }
    }

    #[test]
    fn wire_prefix_is_a_prefix_of_every_anchor() {
        let prefix = anchor_wire_prefix();
        assert!(!prefix.is_empty());
        for raw in [[0u8; 32], [0xff; 32], sample().nullifier_bytes()] {
            let bytes = AnchorV1::new(nullifier(raw), binding(b"x")).encode_untagged_bytes();
            assert!(bytes.starts_with(&prefix));
        }
    }

    #[test]
    fn is_anchor_shaped_is_weaker_than_decode() {
        let n = nullifier([0x22; 32]);
        let ciph = reserved_zero_anchor_ciphertext(&n);
        assert!(is_anchor_shaped(&ciph));
        assert!(AnchorV1::decode(&ciph).is_err());
    }

    #[test]
    fn scanning_finds_embedded_anchors_and_skips_noise() {
        let a = sample();
        let b = AnchorV1::new(nullifier([0xab; 32]), binding(b"midnight offer memo"));
        let mut haystack = vec![0x5au8; 37];
        haystack.extend_from_slice(&a.encode_untagged_bytes());
        haystack.extend_from_slice(&[0x00u8; 11]);
        haystack.extend_from_slice(&b.encode_untagged_bytes());
        haystack.extend_from_slice(&[0xffu8; 13]);

        let found = scan_untagged_anchors(&haystack);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].anchor, a);
        assert_eq!(found[1].anchor, b);
        assert!(found[0].offset < found[1].offset);
        assert_eq!(
            &haystack[found[0].offset..found[0].offset + found[0].len],
            a.encode_untagged_bytes().as_slice()
        );
    }

    #[test]
    fn scanning_never_panics_on_junk() {
        for junk in [vec![], vec![0u8; 1], vec![0u8; 4096], vec![0xffu8; 4096]] {
            assert!(scan_untagged_anchors(&junk).is_empty());
        }
        // A truncated anchor is a prefix hit that fails to decode.
        let bytes = sample().encode_untagged_bytes();
        assert!(scan_untagged_anchors(&bytes[..bytes.len() - 1]).is_empty());
    }
}
