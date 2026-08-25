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

//! JavaScript bindings for **spend-proof memo binding**.
//!
//! Everything here delegates to `zswap::memo`. There is deliberately **no
//! second implementation of any byte mapping in JavaScript** — a JS memo hash
//! or a JS wrapper encoder would be a second source of truth for a
//! security-critical derivation, which is exactly what the frozen conformance
//! vectors exist to prevent. The WASM module is the same Rust code a Rust
//! verifier runs, compiled for a different target.
//!
//! # What a JS consumer can do
//!
//! | Binding | What it is for |
//! | --- | --- |
//! | [`memo_hash_v1`] | `h = MemoHashV1(memo)` |
//! | [`memo_anchor_encode`] / [`memo_anchor_decode`] | the on-chain strip-evidence ciphertext |
//! | [`memo_anchor_scan`] | find anchors in raw transaction bytes |
//! | [`create_memo_anchor_output`] | build the zero-value carrying output |
//! | [`memo_spend_statement_tail`] | the statement rows a wrapper carries |
//! | [`memo_wrapper_build`] / [`memo_wrapper_parse`] | the off-chain container |
//! | [`memo_wrapper_verify`] | verify a companion against a settled offer |
//! | [`memo_wrapper_to_bech32m`] / [`memo_wrapper_from_bech32m`] | the display rendering |
//! | [`create_memo_companion_proving_payload`] | ask a proof server for the companion |
//!
//! # Bytes in, bytes out
//!
//! Field elements cross the boundary as **32 little-endian bytes**, nullifiers
//! as their raw 32 bytes, and every artifact as its canonical byte string —
//! never as a decimal `BigInt` and never as a hex string with an implied
//! endianness. Those are the two ways a JS/Rust boundary usually loses a byte
//! order, and both are avoided by construction here.
//!
//! # Errors
//!
//! Every refusal is a thrown `Error` carrying the Rust error's own message, so
//! a JS caller sees *which rule failed* rather than a bare boolean.

use js_sys::{Object, Reflect, Uint8Array};
use serialize::{tagged_deserialize, tagged_serialize};
use storage::Storable;
use storage::db::{DB, InMemoryDB};
use transient_crypto::curve::Fr;
use transient_crypto::proofs::Proof;
use wasm_bindgen::prelude::*;

use base_crypto::hash::HashOutput;
use coin_structure::coin::{Info as CoinInfo, Nullifier};
use rand::rngs::OsRng;
use zswap::memo::anchor::AnchorV1;
use zswap::memo::wrapper::{MemoWrapperV1, STATEMENT_TAIL_ROWS, UntrustedLocator};
use zswap::memo::{
    BindingElement, Memo, bech32m, fr_le32, memo_hash_v1 as memo_hash_v1_inner,
    reserved_absence_element,
};

use crate::conversions::{from_hex_ser, value_to_shielded_coininfo};
use crate::zswap_wasm::{ZswapInput, ZswapInputTypes, ZswapOutput, ZswapOutputTypes};

// ---------------------------------------------------------------------------
// Small conversions, kept in one place so no binding invents its own.
// ---------------------------------------------------------------------------

fn bytes32(value: &Uint8Array, what: &str) -> Result<[u8; 32], JsError> {
    let v = value.to_vec();
    if v.len() != 32 {
        return Err(JsError::new(&format!(
            "{what} must be exactly 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn field_from(value: &Uint8Array, what: &str) -> Result<Fr, JsError> {
    let raw = bytes32(value, what)?;
    Fr::from_le_bytes(&raw).ok_or_else(|| {
        JsError::new(&format!(
            "{what} is not a canonical little-endian field element"
        ))
    })
}

fn binding_from(value: &Uint8Array) -> Result<BindingElement, JsError> {
    let h = field_from(value, "h")?;
    BindingElement::new(h).map_err(|e| JsError::new(&e.to_string()))
}

fn nullifier_from(value: &Uint8Array) -> Result<Nullifier, JsError> {
    Ok(Nullifier(HashOutput(bytes32(value, "nullifier")?)))
}

fn memo_from(value: &Uint8Array) -> Result<Memo, JsError> {
    Memo::new(value.to_vec()).map_err(|e| JsError::new(&e.to_string()))
}

fn set(obj: &Object, key: &str, value: impl Into<JsValue>) -> Result<(), JsError> {
    Reflect::set(obj, &JsValue::from_str(key), &value.into())
        .map_err(|_| JsError::new("failed to build the result object"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The derivation.
// ---------------------------------------------------------------------------

/// `h = MemoHashV1(memo)`, returned as 32 little-endian bytes.
///
/// Throws if the memo is empty or longer than 512 bytes — absence is
/// represented by having no memo at all, never by a zero-length one.
#[wasm_bindgen(js_name = "memoHashV1")]
pub fn memo_hash_v1(memo: Uint8Array) -> Result<Uint8Array, JsError> {
    let memo = memo_from(&memo)?;
    Ok(Uint8Array::from(&fr_le32(memo_hash_v1_inner(&memo))[..]))
}

// ---------------------------------------------------------------------------
// The anchor.
// ---------------------------------------------------------------------------

/// The version 1 anchor ciphertext for `(nullifier, h)`, in the **untagged**
/// form that appears inside a serialized transaction.
#[wasm_bindgen(js_name = "memoAnchorEncode")]
pub fn memo_anchor_encode(nullifier: Uint8Array, h: Uint8Array) -> Result<Uint8Array, JsError> {
    let anchor = AnchorV1::new(nullifier_from(&nullifier)?, binding_from(&h)?);
    Ok(Uint8Array::from(&anchor.encode_untagged_bytes()[..]))
}

/// Decode untagged anchor bytes to `{ nullifier, h }`.
///
/// Throws — with the specific rule that failed — for anything that is not a
/// version 1 anchor: a wrong marker, an unknown version, a non-canonical point
/// or nullifier split, a zero `h`, a non-zero reserved field, truncation, or
/// trailing bytes.
#[wasm_bindgen(js_name = "memoAnchorDecode")]
pub fn memo_anchor_decode(bytes: Uint8Array) -> Result<Object, JsError> {
    let anchor = AnchorV1::decode_untagged_bytes(&bytes.to_vec())
        .map_err(|e| JsError::new(&e.to_string()))?;
    let out = Object::new();
    set(
        &out,
        "nullifier",
        Uint8Array::from(&anchor.nullifier_bytes()[..]),
    )?;
    set(
        &out,
        "h",
        Uint8Array::from(&fr_le32(anchor.binding.get())[..]),
    )?;
    Ok(out)
}

/// Every version 1 anchor inside raw transaction or offer bytes, in offset
/// order, as `{ offset, length, nullifier, h }`.
///
/// Returns **all** sightings without deduplicating: an anchor must be selected
/// by its decoded `(nullifier, h)`, never by position, because output order is
/// assigned by the ledger's own sorting rather than by the constructor.
#[wasm_bindgen(js_name = "memoAnchorScan")]
pub fn memo_anchor_scan(bytes: Uint8Array) -> Result<js_sys::Array, JsError> {
    let out = js_sys::Array::new();
    for sighting in zswap::memo::anchor::scan_untagged_anchors(&bytes.to_vec()) {
        let entry = Object::new();
        set(&entry, "offset", sighting.offset as f64)?;
        set(&entry, "length", sighting.len as f64)?;
        set(
            &entry,
            "nullifier",
            Uint8Array::from(&sighting.anchor.nullifier_bytes()[..]),
        )?;
        set(
            &entry,
            "h",
            Uint8Array::from(&fr_le32(sighting.anchor.binding.get())[..]),
        )?;
        out.push(&entry);
    }
    Ok(out)
}

/// Build the ordinary **zero-value** output that carries an anchor.
///
/// A typed memo-anchor constructor rather than an "arbitrary ciphertext"
/// escape hatch: the value is zero, the token type is the attributed input's,
/// the nonce is fresh, and the recipient key pair is generated and dropped
/// inside, so the anchor coin is unspendable by anyone — its creator included.
///
/// `tokenType` is the hex-serialized `ShieldedTokenType` the rest of this API
/// already uses. Add the result to the offer **before** balancing and proving:
/// the output proof binds the ciphertext, so an anchor cannot be grafted onto
/// an already-proved transaction.
#[wasm_bindgen(js_name = "createMemoAnchorOutput")]
pub fn create_memo_anchor_output(
    segment: Option<u16>,
    token_type: &str,
    nullifier: Uint8Array,
    h: Uint8Array,
) -> Result<ZswapOutput, JsError> {
    let token_type = from_hex_ser(token_type)?;
    let output = zswap::Output::<_, InMemoryDB>::new_memo_anchor(
        &mut OsRng,
        segment,
        token_type,
        nullifier_from(&nullifier)?,
        &binding_from(&h)?,
    )?;
    Ok(ZswapOutput(ZswapOutputTypes::UnprovenOutput(output)))
}

// ---------------------------------------------------------------------------
// The spend statement tail.
//
// The missing piece a JavaScript consumer needed in order to assemble a wrapper
// at all: `memo_wrapper_build` demands the statement rows, `memo_wrapper_verify`
// rebuilds them privately, and until this binding existed nothing in between
// could produce them. See project 00005's Q-W7.
// ---------------------------------------------------------------------------

/// Rows `1..INPUT_PIS` of the public spend statement, flattened to
/// little-endian bytes.
///
/// The derivation is [`zswap::verify::spend_statement`] — the one certified
/// producer, the same call `Input::prove_memo_companion` makes when it builds a
/// companion and the same one `verify::verify_memo_companion` makes when it
/// rebuilds the rows to check them. This layer performs **no row arithmetic**:
/// it drops row 0 and flattens, and nothing else.
fn statement_tail_le_bytes<P: Storable<D>, D: DB>(
    input: &zswap::Input<P, D>,
    segment: u16,
) -> Result<Vec<u8>, String> {
    // Fail here rather than three steps later. `verify_memo_companion` refuses a
    // contract-owned carrier outright, so a wrapper built over such an input
    // could never verify — a caller who got this far has already gone wrong.
    if input.contract_address.is_some() {
        return Err(
            "this input is contract-owned: a contract input has no controlling secret to \
             authenticate a memo with, so memoWrapperVerify refuses it and a wrapper built \
             over it could never verify"
                .to_string(),
        );
    }

    // Row 0 is the ONLY row this argument reaches: every later row comes from
    // the input's public fields and the segment. The row is discarded below, so
    // the reserved zero is passed and a caller never supplies `h` here — which
    // also means the tail of a canonical statement and the tail of a companion
    // statement are the same 67 rows.
    let statement = zswap::verify::spend_statement(input, segment, reserved_absence_element());

    // A version 1 wrapper carries exactly `INPUT_PIS - 1` rows. If the statement
    // length ever moved, silently handing over a differently-sized tail would be
    // the worst outcome, so it is checked rather than assumed.
    if statement.len() != STATEMENT_TAIL_ROWS + 1 {
        return Err(format!(
            "the spend statement has {} rows, but a version 1 memo wrapper carries {} tail rows",
            statement.len(),
            STATEMENT_TAIL_ROWS
        ));
    }

    let mut out = Vec::with_capacity(STATEMENT_TAIL_ROWS * 32);
    for row in &statement[1..] {
        out.extend_from_slice(&fr_le32(*row));
    }
    Ok(out)
}

/// The `statementTail` argument [`memo_wrapper_build`] asks for: spend
/// statement rows `1..INPUT_PIS`, each 32 little-endian bytes, concatenated.
///
/// ```text
/// const tail = memoSpendStatementTail(input, segment);
/// const wrapper = memoWrapperBuild(memo, input.nullifier bytes, segment,
///                                  tail, companionProof);
/// ```
///
/// **Row 0 is deliberately absent.** Row 0 is the binding input — the reserved
/// zero for a canonical spend, `h = MemoHashV1(memo)` for a companion — and a
/// wrapper never carries it, because a verifier derives `h` from the memo bytes
/// it is checking rather than reading it from the artifact under test. Carrying
/// row 0 would create exactly the second source of truth the format exists to
/// avoid. Everything after row 0 is independent of it, which is why this
/// binding needs no memo and no `h`.
///
/// The tail is public, and it is a **cross-check, not evidence**:
/// [`memo_wrapper_verify`] rebuilds these rows from the settled offer's own
/// input and refuses any wrapper that disagrees, so a wrong tail is caught
/// there rather than trusted here.
///
/// `input` may be unproven, proven, or proof-erased — the rows read only public
/// fields, so a caller may take the tail from the input it just constructed and
/// the bytes still match the input that later settles. `segment` must be the
/// segment the offer settles at; a mismatch is refused by
/// [`memo_wrapper_verify`].
///
/// Throws if the input is contract-owned (no such wrapper can ever verify), or
/// if the statement length is not the one a version 1 wrapper carries.
#[wasm_bindgen(js_name = "memoSpendStatementTail")]
pub fn memo_spend_statement_tail(input: &ZswapInput, segment: u16) -> Result<Uint8Array, JsError> {
    let tail = match &input.0 {
        ZswapInputTypes::UnprovenInput(i) => statement_tail_le_bytes(i, segment),
        ZswapInputTypes::ProvenInput(i) => statement_tail_le_bytes(i, segment),
        ZswapInputTypes::ProofErasedInput(i) => statement_tail_le_bytes(i, segment),
    }
    .map_err(|e| JsError::new(&e))?;
    Ok(Uint8Array::from(&tail[..]))
}

// ---------------------------------------------------------------------------
// The off-chain wrapper.
// ---------------------------------------------------------------------------

/// Assemble a wrapper from its parts and return its canonical bytes.
///
/// `statementTail` is the concatenation of statement rows `1..INPUT_PIS`, each
/// 32 little-endian bytes; `companionProof` is the tagged detached proof.
/// `locator` is optional and is **never trusted as proof** by any verifier.
#[wasm_bindgen(js_name = "memoWrapperBuild")]
pub fn memo_wrapper_build(
    memo: Uint8Array,
    nullifier: Uint8Array,
    segment: u16,
    statement_tail: Uint8Array,
    companion_proof: Uint8Array,
    locator: Option<Uint8Array>,
) -> Result<Uint8Array, JsError> {
    let tail_bytes = statement_tail.to_vec();
    if !tail_bytes.len().is_multiple_of(32) {
        return Err(JsError::new(
            "statementTail must be a whole number of 32-byte field elements",
        ));
    }
    let mut rows = Vec::with_capacity(tail_bytes.len() / 32);
    for (i, chunk) in tail_bytes.chunks_exact(32).enumerate() {
        rows.push(Fr::from_le_bytes(chunk).ok_or_else(|| {
            JsError::new(&format!(
                "statement row {} is not a canonical little-endian field element",
                i + 1
            ))
        })?);
    }
    let locator = match locator {
        Some(l) => {
            Some(UntrustedLocator::new(l.to_vec()).map_err(|e| JsError::new(&e.to_string()))?)
        }
        None => None,
    };
    let wrapper = MemoWrapperV1::from_parts(
        memo_from(&memo)?,
        nullifier_from(&nullifier)?,
        segment,
        rows,
        companion_proof.to_vec(),
        locator,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(Uint8Array::from(&wrapper.encode()[..]))
}

/// Parse wrapper bytes into their fields.
///
/// **Parsing is not verifying.** The returned `memo` is the memo *as parsed*;
/// it must not be shown as authenticated until [`memo_wrapper_verify`]
/// succeeds. The key is named `unverifiedMemo` so that a caller cannot reach
/// for it by accident.
#[wasm_bindgen(js_name = "memoWrapperParse")]
pub fn memo_wrapper_parse(bytes: Uint8Array) -> Result<Object, JsError> {
    let wrapper =
        MemoWrapperV1::decode(&bytes.to_vec()).map_err(|e| JsError::new(&e.to_string()))?;
    let out = Object::new();
    set(
        &out,
        "unverifiedMemo",
        Uint8Array::from(wrapper.unverified_memo().as_bytes()),
    )?;
    set(
        &out,
        "nullifier",
        Uint8Array::from(&wrapper.nullifier().0.0[..]),
    )?;
    set(&out, "segment", wrapper.segment() as f64)?;
    let mut tail = Vec::new();
    for row in wrapper.claimed_statement_tail() {
        tail.extend_from_slice(&fr_le32(*row));
    }
    set(&out, "claimedStatementTail", Uint8Array::from(&tail[..]))?;
    set(
        &out,
        "companionProof",
        Uint8Array::from(wrapper.companion_proof_bytes()),
    )?;
    match wrapper.locator() {
        Some(l) => set(
            &out,
            "untrustedLocator",
            Uint8Array::from(l.as_untrusted_bytes()),
        )?,
        None => set(&out, "untrustedLocator", JsValue::NULL)?,
    }
    Ok(out)
}

/// Verify a companion wrapper against a **settled, proven** Zswap offer.
///
/// `offer` is the tagged serialization of a proven `Offer`. `segment` is the
/// segment the offer settled at.
///
/// On success the returned object carries the now-authenticated memo, the
/// input it is attributed to, and the settled anchors whose decoded
/// `(nullifier, h)` match. An **empty** `matchingAnchors` is not a failure: it
/// means the companion authenticated the memo but no matching anchor was found
/// in the offer that was checked, which is a weaker state a reader must
/// present as such. `duplicateAnchors` is an anomaly worth surfacing and is
/// **not** a reason to downgrade authentication.
///
/// Throws — with the specific rule that failed — for a nullifier that is not
/// in the offer, a contract-owned carrier, a segment mismatch, a statement row
/// that disagrees with the verifier's own rebuild, unreadable proof bytes, or
/// a proof that does not bind the memo.
#[wasm_bindgen(js_name = "memoWrapperVerify")]
pub fn memo_wrapper_verify(
    wrapper: Uint8Array,
    offer: Uint8Array,
    segment: u16,
) -> Result<Object, JsError> {
    let wrapper =
        MemoWrapperV1::decode(&wrapper.to_vec()).map_err(|e| JsError::new(&e.to_string()))?;
    let offer: zswap::Offer<Proof, InMemoryDB> = tagged_deserialize(&mut &offer.to_vec()[..])
        .map_err(|e| JsError::new(&format!("offer is not a readable proven Offer: {e}")))?;

    let record = zswap::verify::verify_memo_companion(&wrapper, &offer, segment)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let out = Object::new();
    set(
        &out,
        "memo",
        Uint8Array::from(record.authenticated_memo().as_bytes()),
    )?;
    set(
        &out,
        "nullifier",
        Uint8Array::from(&record.nullifier().0.0[..]),
    )?;
    set(&out, "segment", record.segment() as f64)?;
    set(
        &out,
        "h",
        Uint8Array::from(&fr_le32(record.binding().get())[..]),
    )?;
    let anchors = js_sys::Array::new();
    for a in record.matching_anchors() {
        let entry = Object::new();
        set(&entry, "outputIndex", a.output_index as f64)?;
        let mut com = Vec::new();
        tagged_serialize(&a.coin_com, &mut com)?;
        set(&entry, "coinCommitment", Uint8Array::from(&com[..]))?;
        anchors.push(&entry);
    }
    set(&out, "matchingAnchors", anchors)?;
    set(&out, "duplicateAnchors", record.has_duplicate_anchors())?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// The bech32m rendering.
// ---------------------------------------------------------------------------

/// Render canonical wrapper bytes as bech32m.
///
/// Raw bytes stay canonical — this is the display and transport form. `hrp`
/// defaults to `swapmsg`, which is a **proposal** rather than a ratified
/// prefix, which is why it is a parameter.
#[wasm_bindgen(js_name = "memoWrapperToBech32m")]
pub fn memo_wrapper_to_bech32m(bytes: Uint8Array, hrp: Option<String>) -> Result<String, JsError> {
    let hrp = hrp.unwrap_or_else(|| bech32m::DEFAULT_MEMO_WRAPPER_HRP.to_string());
    bech32m::encode_with_hrp(&hrp, &bytes.to_vec()).map_err(|e| JsError::new(&e.to_string()))
}

/// Read a bech32m rendering back to canonical bytes, requiring the prefix.
///
/// Accepting any prefix would let a string minted for a different artifact
/// type be read as a wrapper, so the expected prefix is always checked.
#[wasm_bindgen(js_name = "memoWrapperFromBech32m")]
pub fn memo_wrapper_from_bech32m(text: &str, hrp: Option<String>) -> Result<Uint8Array, JsError> {
    let hrp = hrp.unwrap_or_else(|| bech32m::DEFAULT_MEMO_WRAPPER_HRP.to_string());
    let bytes = bech32m::decode_expecting(text, &hrp).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(Uint8Array::from(&bytes[..]))
}

/// The bech32m prefix these bindings default to. **Provisional.**
#[wasm_bindgen(js_name = "memoWrapperDefaultHrp")]
pub fn memo_wrapper_default_hrp() -> String {
    bech32m::DEFAULT_MEMO_WRAPPER_HRP.to_string()
}

// ---------------------------------------------------------------------------
// Asking a proof server for the companion.
// ---------------------------------------------------------------------------

/// Build the proof-server `/prove` payload that asks for the **companion**
/// proof of `memo` over `serializedPreimage`.
///
/// This is `createProvingPayload` with the binding input derived from the memo
/// bytes rather than supplied by the caller, so a JS consumer cannot ask for a
/// companion over the wrong `h` — the one mistake that would produce a proof
/// which verifies against nothing.
///
/// **Accepting the override is not evidence that a backend honoured it.** A
/// backend that takes the parameter and then proves the original row-0-zero
/// preimage returns a proof that verifies at row 0 = 0 and fails at row 0 =
/// `h`. Before trusting a backend, check the returned proof against the
/// companion statement **and** confirm it does *not* verify at row 0 = 0.
#[wasm_bindgen(js_name = "createMemoCompanionProvingPayload")]
pub fn create_memo_companion_proving_payload(
    serialized_preimage: Uint8Array,
    memo: Uint8Array,
    key_material: JsValue,
) -> Result<Uint8Array, JsError> {
    let memo = memo_from(&memo)?;
    let h = memo_hash_v1_inner(&memo);
    // Refuse the reserved zero here too, so an impossible request never
    // reaches a prover.
    BindingElement::new(h).map_err(|e| JsError::new(&e.to_string()))?;
    let bigint = crate::conversions::fr_to_bigint(h);
    crate::create_proving_payload(serialized_preimage, Some(bigint), key_material)
}

/// The shielded token type of a coin, hex-serialized, for
/// [`create_memo_anchor_output`].
///
/// A convenience so a caller does not have to reach into a coin object and
/// re-serialize a field by hand — getting that wrong would produce an anchor
/// carrier of the wrong token type, which nothing else would catch.
#[wasm_bindgen(js_name = "memoAnchorTokenTypeOf")]
pub fn memo_anchor_token_type_of(coin: JsValue) -> Result<String, JsError> {
    let coin: CoinInfo = value_to_shielded_coininfo(coin)?;
    let mut out = Vec::new();
    tagged_serialize(&coin.type_, &mut out)?;
    Ok(hex::encode(out))
}

// ---------------------------------------------------------------------------
// Tests.
//
// These run NATIVELY (`cargo test -p midnight-ledger-wasm-v9`), which is why
// they exercise `statement_tail_le_bytes` and the two token-type helpers rather
// than the `#[wasm_bindgen]` functions wrapping them: `js_sys::Uint8Array` has
// no meaning outside a JavaScript host. What the wrappers add is a `match` over
// the three proof flavours and a `Uint8Array::from`; every byte mapping under
// test is in the helpers, and the JS surface itself is covered end to end by
// the Node smoke test, which builds a real wrapper from a real tail and
// verifies it against a real proven offer.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use coin_structure::coin::ShieldedTokenType;
    use coin_structure::contract::ContractAddress;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use storage::arena::Sp;
    use transient_crypto::proofs::ProofPreimage;
    use zswap::Input;
    use zswap::keys::{SecretKeys, Seed};
    use zswap::local;
    use zswap::verify::spend_statement;

    /// The frozen wrapper vectors, produced by an implementation other than
    /// this one. Read for the two numbers that pin the tail's shape.
    const WRAPPER_VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../zswap/tests/memo-vectors/wrapper.txt"
    );

    const MEMO: &[u8] = b"hello world";

    /// One real, user-owned spend, built through `zswap`'s own public API —
    /// exactly the construction `ZswapLocalState.spend` performs for a JS
    /// caller, so the input under test is the input a JS caller holds.
    fn user_owned_input(seed: u8, segment: u16) -> Input<ProofPreimage, InMemoryDB> {
        let mut rng = StdRng::from_seed([seed; 32]);
        let secret_keys: SecretKeys = Seed::random(&mut rng).into();
        let coin = CoinInfo {
            nonce: rng.r#gen(),
            type_: ShieldedTokenType(rng.r#gen()),
            value: 4_242,
        };
        let state: local::State<InMemoryDB> = local::State::new()
            .insert_coin(&secret_keys, coin)
            .expect("inserting the carrier coin");
        let (_after, input) = state
            .spend(&mut rng, &secret_keys, &coin.qualify(0), Some(segment))
            .expect("spending the carrier coin");
        input
    }

    /// The reference the binding must equal, assembled the long way round in
    /// the test: the certified producer, sliced and flattened HERE rather than
    /// by the code under test.
    fn reference_tail(input: &Input<ProofPreimage, InMemoryDB>, segment: u16, row0: Fr) -> Vec<u8> {
        spend_statement(input, segment, row0)[1..]
            .iter()
            .flat_map(|row| fr_le32(*row))
            .collect()
    }

    fn h_for_memo() -> Fr {
        memo_hash_v1_inner(&Memo::from_slice(MEMO).expect("the test memo is in range"))
    }

    /// `key: value` out of the `vector: wrapper/constants` record.
    fn frozen_constant(key: &str) -> usize {
        let text = std::fs::read_to_string(WRAPPER_VECTORS)
            .unwrap_or_else(|e| panic!("reading {WRAPPER_VECTORS}: {e}"));
        let mut in_constants = false;
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("vector: ") {
                in_constants = name.trim() == "wrapper/constants";
                continue;
            }
            if !in_constants {
                continue;
            }
            if let Some(value) = line.strip_prefix(&format!("{key}: ")) {
                return value.trim().parse().expect("a numeric frozen constant");
            }
        }
        panic!("no `{key}` in the frozen wrapper/constants record");
    }

    // -----------------------------------------------------------------------
    // Q-W7: the statement tail.
    // -----------------------------------------------------------------------

    /// SINGLE INPUT: the bytes are `spend_statement`'s rows `1..`, exactly.
    #[test]
    fn tail_is_spend_statement_rows_one_onwards() {
        let segment = 3u16;
        let input = user_owned_input(0x11, segment);

        let tail = statement_tail_le_bytes(&input, segment).expect("a user-owned input");

        assert_eq!(
            tail,
            reference_tail(&input, segment, reserved_absence_element()),
            "the tail must be byte-identical to zswap::verify::spend_statement's rows 1..",
        );
        assert_eq!(tail.len(), STATEMENT_TAIL_ROWS * 32);
        // Row 0 is excluded, not merely different: the first 32 bytes of the
        // tail are row 1, so the full statement's first row appears nowhere.
        assert_eq!(
            &tail[..32],
            &fr_le32(spend_statement(&input, segment, reserved_absence_element())[1])[..],
        );
    }

    /// The tail does not depend on row 0, so the canonical statement and the
    /// companion statement share it — which is why the binding takes no memo
    /// and no `h`, and why a caller cannot get either wrong.
    #[test]
    fn tail_is_independent_of_row_zero() {
        let segment = 7u16;
        let input = user_owned_input(0x22, segment);
        let tail = statement_tail_le_bytes(&input, segment).expect("a user-owned input");

        for row0 in [
            reserved_absence_element(),
            h_for_memo(),
            Fr::from(1u64),
            Fr::from(u64::MAX),
        ] {
            assert_eq!(
                tail,
                reference_tail(&input, segment, row0),
                "the tail changed with row 0, which it must never do",
            );
        }
    }

    /// MULTI-INPUT, DISTINCT SEGMENTS: every combination matches its own
    /// input's rows, and no two combinations collide — so the binding cannot be
    /// returning something constant that happens to match once.
    #[test]
    fn tail_matches_per_input_and_per_segment() {
        let segments = [0u16, 3, 1_024, u16::MAX];
        let mut seen: Vec<Vec<u8>> = Vec::new();

        for seed in [0x31u8, 0x32, 0x33] {
            for segment in segments {
                let input = user_owned_input(seed, segment);
                let tail = statement_tail_le_bytes(&input, segment).expect("a user-owned input");

                assert_eq!(
                    tail,
                    reference_tail(&input, segment, reserved_absence_element()),
                    "seed {seed:#x} segment {segment}",
                );
                assert_eq!(tail.len(), STATEMENT_TAIL_ROWS * 32);
                assert!(
                    !seen.contains(&tail),
                    "seed {seed:#x} segment {segment} produced a tail already seen",
                );
                seen.push(tail);
            }
        }
        assert_eq!(seen.len(), 12);

        // And the same input read at two different segments really does differ,
        // stated directly rather than inferred from the collision check above.
        let input = user_owned_input(0x44, 5);
        assert_ne!(
            statement_tail_le_bytes(&input, 5).unwrap(),
            statement_tail_le_bytes(&input, 6).unwrap(),
        );
    }

    /// FROZEN-VECTOR-DERIVED: the tail's shape is pinned by numbers a DIFFERENT
    /// implementation froze, not by a constant recomputed here.
    #[test]
    fn tail_shape_matches_the_frozen_vectors() {
        let rows = frozen_constant("statement_tail_rows");
        let bytes = frozen_constant("statement_tail_bytes");
        assert_eq!(rows, 67, "the frozen record moved");
        assert_eq!(bytes, 2_144, "the frozen record moved");

        let segment = 3u16;
        let input = user_owned_input(0x55, segment);
        let tail = statement_tail_le_bytes(&input, segment).expect("a user-owned input");

        assert_eq!(tail.len(), bytes);
        assert_eq!(tail.len() / 32, rows);
        assert_eq!(rows, STATEMENT_TAIL_ROWS);
    }

    /// The tail is shaped exactly as `memoWrapperBuild` expects: it is accepted
    /// by the wrapper's own constructor, survives the container round trip, and
    /// comes back as the rows a verifier rebuilds for the COMPANION statement.
    #[test]
    fn tail_is_what_a_wrapper_carries() {
        let segment = 3u16;
        let input = user_owned_input(0x66, segment);
        let tail = statement_tail_le_bytes(&input, segment).expect("a user-owned input");

        // Exactly the path `memo_wrapper_build` takes with this argument.
        let rows: Vec<Fr> = tail
            .chunks_exact(32)
            .map(|c| Fr::from_le_bytes(c).expect("a canonical field element"))
            .collect();

        let mut stand_in_proof = Vec::new();
        tagged_serialize(&Proof(vec![0u8; 64]), &mut stand_in_proof)
            .expect("serializing a stand-in proof");

        let wrapper = MemoWrapperV1::from_parts(
            Memo::from_slice(MEMO).expect("the test memo is in range"),
            input.nullifier,
            segment,
            rows,
            stand_in_proof,
            None,
        )
        .expect("the derived tail must satisfy the wrapper's own row-count rule");

        let decoded = MemoWrapperV1::decode(&wrapper.encode()).expect("a wrapper we just encoded");

        let companion_rows = spend_statement(&input, segment, h_for_memo());
        assert_eq!(
            decoded.claimed_statement_tail(),
            &companion_rows[1..],
            "a wrapper built from this tail must carry the COMPANION statement's rows 1..",
        );
    }

    /// A contract-owned input is refused here rather than three steps later:
    /// `verify_memo_companion` rejects a contract-owned carrier outright, so no
    /// wrapper over one could ever verify.
    #[test]
    fn contract_owned_inputs_are_refused() {
        let segment = 3u16;
        let mut input = user_owned_input(0x77, segment);
        assert!(statement_tail_le_bytes(&input, segment).is_ok());

        input.contract_address = Some(Sp::new(ContractAddress(HashOutput([0x11u8; 32]))));
        let message = statement_tail_le_bytes(&input, segment)
            .expect_err("a contract-owned input must be refused");
        assert!(
            message.contains("contract-owned") && message.contains("memoWrapperVerify"),
            "the refusal must say why: {message}",
        );
    }
}
