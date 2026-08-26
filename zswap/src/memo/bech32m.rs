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

//! bech32m rendering of canonical raw bytes (BIP-350).
//!
//! **Raw bytes are canonical.** A wrapper *is* the byte string
//! [`super::wrapper::MemoWrapperV1::encode`] produces: that is what a digest is
//! taken over, what is published to a data-availability blob, and what a
//! verifier parses. This module adds the *display and transport* rendering —
//! a checksummed, human-copyable, case-insensitive string with a
//! human-readable prefix — following the same convention Midnight uses for
//! other user-visible byte strings.
//!
//! ```text
//! <hrp> "1" <data: 5-bit groups> <checksum: 6 characters>
//! ```
//!
//! # Two deliberate departures from BIP-173/350
//!
//! 1. **No 90-character ceiling.** BIP-173 caps a segwit address at 90
//!    characters so that the BCH code's guaranteed error-detection bound
//!    holds. The artifacts rendered here are kilobytes, so the cap cannot
//!    apply; the checksum keeps its value as an integrity check, not as a
//!    bounded-distance guarantee. This is the same choice every non-Bitcoin
//!    bech32 user (Cardano addresses, Nostr entities) makes.
//! 2. **The HRP is a parameter.** [`DEFAULT_MEMO_WRAPPER_HRP`] is a
//!    **proposal**, not a ratified constant — see the note on that item — so
//!    every entry point takes an explicit HRP and the default is only a
//!    default.
//!
//! Everything else is BIP-350 exactly: the same character set, the same
//!  generator, the same `0x2bc830a3` constant, the same HRP expansion, the
//! same mixed-case refusal, and the same "leftover bits must be fewer than
//! five and all zero" rule when converting back from 5-bit groups.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// The bech32 character set (BIP-173), indexed by 5-bit value.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// bech32**m**'s checksum constant (BIP-350). bech32's is `1`.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// The separator between the human-readable prefix and the data part.
const SEPARATOR: char = '1';

/// How many characters the checksum occupies.
const CHECKSUM_CHARS: usize = 6;

/// The **proposed** human-readable prefix for a memo companion wrapper.
///
/// **PROVISIONAL.** This value has not been ratified. Every function here
/// takes the prefix explicitly precisely so that a change is a caller-side
/// decision rather than a format break, and so that conformance vectors
/// generated against this default are labelled provisional until the prefix is
/// confirmed.
pub const DEFAULT_MEMO_WRAPPER_HRP: &str = "swapmsg";

/// Why a bech32m string could not be produced or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bech32Error {
    /// The human-readable prefix is empty, too long, or contains a character
    /// outside the printable US-ASCII range `33..=126`.
    InvalidHrp {
        /// What was wrong.
        reason: &'static str,
    },
    /// The string mixes upper and lower case. bech32 is case-insensitive but
    /// mixed case is explicitly invalid, because it breaks the checksum's
    /// case-folding.
    MixedCase,
    /// There is no `1` separator, or it leaves no room for a prefix.
    MissingSeparator,
    /// Fewer than six data characters follow the separator, so there is not
    /// even a checksum.
    TooShort {
        /// How many data characters were present.
        found: usize,
    },
    /// A character outside the bech32 alphabet appeared in the data part.
    InvalidCharacter {
        /// Byte offset of the offending character in the whole string.
        index: usize,
        /// The offending character.
        found: char,
    },
    /// The checksum did not verify.
    BadChecksum,
    /// The 5-bit groups did not unpack to whole bytes: either more than four
    /// bits were left over, or the padding bits were not zero.
    NonCanonicalPadding,
    /// The prefix was not the one the caller required.
    UnexpectedHrp {
        /// The prefix the caller required.
        expected: String,
        /// The prefix the string carried.
        found: String,
    },
}

impl Display for Bech32Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Bech32Error::InvalidHrp { reason } => {
                write!(f, "invalid human-readable prefix: {reason}")
            }
            Bech32Error::MixedCase => f.write_str("bech32m string mixes upper and lower case"),
            Bech32Error::MissingSeparator => {
                f.write_str("bech32m string has no '1' separator after a prefix")
            }
            Bech32Error::TooShort { found } => write!(
                f,
                "bech32m data part is {found} character(s); it must hold at least the \
                 {CHECKSUM_CHARS}-character checksum"
            ),
            Bech32Error::InvalidCharacter { index, found } => write!(
                f,
                "character {found:?} at offset {index} is not in the bech32 alphabet"
            ),
            Bech32Error::BadChecksum => f.write_str("bech32m checksum does not verify"),
            Bech32Error::NonCanonicalPadding => {
                f.write_str("bech32m data does not unpack to whole bytes")
            }
            Bech32Error::UnexpectedHrp { expected, found } => write!(
                f,
                "bech32m prefix is {found:?}, not the expected {expected:?}"
            ),
        }
    }
}

impl Error for Bech32Error {}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for b in bytes {
        out.push(b >> 5);
    }
    out.push(0);
    for b in bytes {
        out.push(b & 31);
    }
    out
}

fn check_hrp(hrp: &str) -> Result<(), Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::InvalidHrp {
            reason: "it is empty",
        });
    }
    if hrp.len() > 83 {
        return Err(Bech32Error::InvalidHrp {
            reason: "it is longer than 83 characters",
        });
    }
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Bech32Error::InvalidHrp {
            reason: "it contains a character outside printable US-ASCII 33..=126",
        });
    }
    if hrp.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Bech32Error::InvalidHrp {
            reason: "it contains uppercase; use the lowercase form and render the whole string \
                     uppercase if an uppercase rendering is wanted",
        });
    }
    Ok(())
}

/// Repacks `data` from `from` bits per element to `to` bits per element.
///
/// With `pad`, trailing bits are zero-extended to a whole output element (the
/// 8 → 5 direction). Without it, leftover bits must be fewer than `to` and all
/// zero (the 5 → 8 direction), which is what makes the encoding canonical.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::with_capacity((data.len() * from as usize).div_ceil(to as usize) + 1);
    for value in data {
        let v = *value as u32;
        if from < 8 && v >> from != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return None;
    }
    Some(out)
}

/// Encodes already-5-bit-grouped `five` under `hrp`.
///
/// The checksum layer on its own. Split out from [`encode_with_hrp`] because
/// BIP-350's reference vectors exercise exactly this layer: they are
/// checksum-valid strings whose data parts do not all unpack to whole bytes.
fn encode_5bit(hrp: &str, five: &[u8]) -> Result<String, Bech32Error> {
    check_hrp(hrp)?;
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(five);
    values.extend_from_slice(&[0u8; CHECKSUM_CHARS]);
    let poly = polymod(&values) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + five.len() + CHECKSUM_CHARS);
    out.push_str(hrp);
    out.push(SEPARATOR);
    for v in five {
        out.push(CHARSET[*v as usize] as char);
    }
    for i in 0..CHECKSUM_CHARS {
        let v = ((poly >> (5 * (CHECKSUM_CHARS - 1 - i))) & 31) as usize;
        out.push(CHARSET[v] as char);
    }
    Ok(out)
}

/// Encodes `data` under `hrp` as a lowercase bech32m string.
pub fn encode_with_hrp(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    check_hrp(hrp)?;
    let five = convert_bits(data, 8, 5, true).expect("8 -> 5 with padding never fails");
    encode_5bit(hrp, &five)
}

/// Encodes `data` under [`DEFAULT_MEMO_WRAPPER_HRP`].
///
/// The prefix is provisional; prefer [`encode_with_hrp`] where the caller
/// knows which prefix its deployment uses.
pub fn encode(data: &[u8]) -> Result<String, Bech32Error> {
    encode_with_hrp(DEFAULT_MEMO_WRAPPER_HRP, data)
}

/// Verifies the checksum and returns the (lowercased) prefix plus the payload
/// as **5-bit groups**, checksum characters removed.
///
/// The checksum layer on its own; see [`encode_5bit`].
fn decode_5bit(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = s.to_ascii_lowercase();

    let sep = lowered
        .rfind(SEPARATOR)
        .ok_or(Bech32Error::MissingSeparator)?;
    if sep == 0 {
        return Err(Bech32Error::MissingSeparator);
    }
    let hrp = &lowered[..sep];
    check_hrp(hrp)?;

    let data_part = &lowered[sep + 1..];
    if data_part.len() < CHECKSUM_CHARS {
        return Err(Bech32Error::TooShort {
            found: data_part.len(),
        });
    }

    let mut values = Vec::with_capacity(data_part.len());
    for (i, c) in data_part.chars().enumerate() {
        let v =
            CHARSET
                .iter()
                .position(|d| *d as char == c)
                .ok_or(Bech32Error::InvalidCharacter {
                    index: sep + 1 + i,
                    found: c,
                })?;
        values.push(v as u8);
    }

    let mut checked = hrp_expand(hrp);
    checked.extend_from_slice(&values);
    if polymod(&checked) != BECH32M_CONST {
        return Err(Bech32Error::BadChecksum);
    }

    values.truncate(values.len() - CHECKSUM_CHARS);
    Ok((hrp.to_string(), values))
}

/// Decodes a bech32m string, returning its (lowercased) prefix and payload.
pub fn decode_with_hrp(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    let (hrp, five) = decode_5bit(s)?;
    let bytes = convert_bits(&five, 5, 8, false).ok_or(Bech32Error::NonCanonicalPadding)?;
    Ok((hrp, bytes))
}

/// Decodes a bech32m string and requires a particular prefix.
///
/// This is the entry point a consumer should use: accepting any prefix would
/// let a string minted for a different artifact type be read as a wrapper.
pub fn decode_expecting(s: &str, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
    check_hrp(expected_hrp)?;
    let (hrp, bytes) = decode_with_hrp(s)?;
    if hrp != expected_hrp {
        return Err(Bech32Error::UnexpectedHrp {
            expected: expected_hrp.to_string(),
            found: hrp,
        });
    }
    Ok(bytes)
}

/// Decodes a bech32m string minted under [`DEFAULT_MEMO_WRAPPER_HRP`].
pub fn decode(s: &str) -> Result<Vec<u8>, Bech32Error> {
    decode_expecting(s, DEFAULT_MEMO_WRAPPER_HRP)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-350's own bech32m test vectors. These are the reason to trust the
    /// implementation at all: they were produced by the reference
    /// implementation, not by this one.
    ///
    /// They exercise the CHECKSUM layer: several of them have data parts whose
    /// bit count is not a multiple of eight, so they are checksum-valid
    /// strings that carry no byte payload. That is why they go through
    /// [`decode_5bit`]/[`encode_5bit`] rather than the byte-level API.
    #[test]
    fn bip350_valid_vectors_round_trip() {
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            let (hrp, five) = decode_5bit(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            let re = encode_5bit(&hrp, &five).unwrap();
            assert_eq!(re, s.to_ascii_lowercase(), "re-encoding {s} changed it");
        }
    }

    #[test]
    fn bip350_invalid_vectors_are_refused() {
        for s in [
            // wrong checksum constant (these are bech32, not bech32m)
            "A1G7SGD8",
            // invalid character in the data part
            "abc1rzg",
            // mixed case
            "aBc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            // empty HRP
            "1p2gdwpf",
            // no separator
            "qyrz8wqd2c9m",
            // too short a data part
            "a1qqq",
        ] {
            assert!(decode_5bit(s).is_err(), "{s} was accepted");
            assert!(decode_with_hrp(s).is_err(), "{s} was accepted");
        }
    }

    /// A checksum-valid string whose data part does not unpack to whole bytes
    /// must be refused by the BYTE-level API even though the checksum layer
    /// accepts it. Otherwise two different strings could decode to one payload.
    #[test]
    fn a_checksum_valid_string_with_leftover_bits_has_no_byte_payload() {
        let s = "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8";
        assert!(decode_5bit(s).is_ok());
        assert_eq!(
            decode_with_hrp(s).unwrap_err(),
            Bech32Error::NonCanonicalPadding
        );
    }

    #[test]
    fn round_trips_every_length_from_zero_to_a_few_hundred() {
        for len in 0..300usize {
            let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) % 251) as u8).collect();
            let s = encode(&data).unwrap();
            assert_eq!(decode(&s).unwrap(), data, "round trip failed at len {len}");
        }
    }

    /// A real wrapper is kilobytes, far past BIP-173's 90-character ceiling.
    /// That ceiling is deliberately not enforced here.
    #[test]
    fn a_wrapper_sized_payload_round_trips() {
        let data: Vec<u8> = (0..7_134u32).map(|i| (i % 256) as u8).collect();
        let s = encode(&data).unwrap();
        assert!(s.len() > 90);
        assert_eq!(decode(&s).unwrap(), data);
    }

    #[test]
    fn the_default_prefix_is_what_it_says_it_is() {
        assert_eq!(DEFAULT_MEMO_WRAPPER_HRP, "swapmsg");
        let s = encode(b"hello world").unwrap();
        assert!(s.starts_with("swapmsg1"));
        assert_eq!(decode(&s).unwrap(), b"hello world");
    }

    #[test]
    fn a_foreign_prefix_is_refused_rather_than_silently_accepted() {
        let s = encode_with_hrp("offer", b"hello world").unwrap();
        assert_eq!(
            decode(&s).unwrap_err(),
            Bech32Error::UnexpectedHrp {
                expected: "swapmsg".to_string(),
                found: "offer".to_string()
            }
        );
        assert_eq!(decode_expecting(&s, "offer").unwrap(), b"hello world");
    }

    #[test]
    fn uppercase_is_accepted_and_mixed_case_is_not() {
        let s = encode(b"midnight offer memo").unwrap();
        assert_eq!(
            decode(&s.to_ascii_uppercase()).unwrap(),
            b"midnight offer memo"
        );
        let mut mixed = s.clone();
        mixed = mixed
            .char_indices()
            .map(|(i, c)| {
                if i == mixed.len() - 1 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(decode(&mixed).unwrap_err(), Bech32Error::MixedCase);
    }

    /// Every single-character substitution must be caught by the checksum or
    /// by the alphabet — that is the whole point of the rendering.
    #[test]
    fn every_single_character_substitution_is_caught() {
        let data: Vec<u8> = (0..64u32).map(|i| (i * 7 % 256) as u8).collect();
        let s = encode(&data).unwrap();
        let original: Vec<char> = s.chars().collect();
        let hrp_len = DEFAULT_MEMO_WRAPPER_HRP.len();
        for i in (hrp_len + 1)..original.len() {
            for replacement in ['q', 'p', 'z', 'l', '0'] {
                if original[i] == replacement {
                    continue;
                }
                let mut mutated = original.clone();
                mutated[i] = replacement;
                let candidate: String = mutated.into_iter().collect();
                if let Ok(other) = decode(&candidate) {
                    panic!("substitution at {i} -> {replacement} decoded to {other:?}");
                }
            }
        }
    }

    #[test]
    fn truncation_and_extension_are_refused() {
        let s = encode(b"hello world").unwrap();
        for cut in 0..s.len() {
            assert!(decode(&s[..cut]).is_err(), "prefix of length {cut} decoded");
        }
        assert!(decode(&format!("{s}q")).is_err());
    }

    #[test]
    fn an_invalid_prefix_is_a_typed_error() {
        assert!(matches!(
            encode_with_hrp("", b"x"),
            Err(Bech32Error::InvalidHrp { .. })
        ));
        assert!(matches!(
            encode_with_hrp("SWAPMSG", b"x"),
            Err(Bech32Error::InvalidHrp { .. })
        ));
        assert!(matches!(
            encode_with_hrp("swap msg", b"x"),
            Err(Bech32Error::InvalidHrp { .. })
        ));
        assert!(matches!(
            encode_with_hrp(&"a".repeat(84), b"x"),
            Err(Bech32Error::InvalidHrp { .. })
        ));
    }

    #[test]
    fn junk_never_panics() {
        for junk in [
            "",
            "1",
            "11",
            "swapmsg1",
            "swapmsg1\u{202e}qqqqqq",
            "\u{1f600}1qqqqqq",
            "swapmsg1",
            &"q".repeat(1000),
        ] {
            let _ = decode(junk);
            let _ = decode_with_hrp(junk);
        }
    }
}
