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

#[cfg(feature = "proof-verifying")]
use crate::ciphertext_to_field;
use crate::error::MalformedOffer;
#[cfg(any(feature = "proof-verifying", test))]
use crate::filter_invalid;
use crate::structure::*;
#[cfg(feature = "proof-verifying")]
use base_crypto::fab::AlignedValue;
#[cfg(test)]
use coin_structure::contract::ContractAddress;
#[cfg(feature = "proof-verifying")]
use serialize::Deserializable;
#[cfg(feature = "proof-verifying")]
use serialize::tagged_deserialize;
use storage::db::DB;
use storage::db::InMemoryDB;
use storage::{Storable, arena::Sp};
use transient_crypto::commitment::Pedersen;
use transient_crypto::curve::{EmbeddedFr, EmbeddedGroupAffine};
// Needed by the ADDITIVE memo-binding helpers at the bottom of this file. The
// existing `(Fr, Fr)` tokens above are macro arguments that `Cell_write!` never
// expands into a type position, so `Fr` was not previously in scope here.
use transient_crypto::curve::Fr;
#[cfg(feature = "proof-verifying")]
use transient_crypto::hash::transient_commit;
use transient_crypto::proofs::PARAMS_VERIFIER;
#[cfg(feature = "proof-verifying")]
use transient_crypto::proofs::{ParamsVerifier, VerifierKey};
use transient_crypto::proofs::{Proof, ProofPreimage};
#[cfg(any(feature = "proof-verifying", test))]
use transient_crypto::repr::FieldRepr;
// On nightly this becomes a noop
#[allow(unused_imports)]
use is_sorted::IsSorted;
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::ops::{Key, Op};
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::program_fragments::*;
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::result_mode::{ResultModeGather, ResultModeVerify};
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::state::StateValue;
use std::ops::Add;
use std::ops::Deref;
#[cfg(any(feature = "proof-verifying", test))]
use std::sync::Arc;

#[cfg(feature = "proof-verifying")]
const OUTPUT_VK_RAW: &[u8] = include_bytes!("../static/output.verifier");
#[cfg(feature = "proof-verifying")]
const SPEND_VK_RAW: &[u8] = include_bytes!("../static/spend.verifier");
#[cfg(feature = "proof-verifying")]
const SIGN_VK_RAW: &[u8] = include_bytes!("../static/sign.verifier");

#[cfg(feature = "proof-verifying")]
lazy_static! {
    pub static ref OUTPUT_VK: transient_crypto_old::proofs::VerifierKey =
        serialize::tagged_deserialize(&mut OUTPUT_VK_RAW.to_vec().as_slice())
            .expect("Zswap Output VK should be valid");
    pub static ref SPEND_VK: transient_crypto_old::proofs::VerifierKey =
        serialize::tagged_deserialize(&mut SPEND_VK_RAW.to_vec().as_slice())
            .expect("Zswap Spend VK should be valid");
    pub static ref SIGN_VK: transient_crypto_old::proofs::VerifierKey =
        serialize::tagged_deserialize(&mut SIGN_VK_RAW.to_vec().as_slice())
            .expect("Zswap Sign VK should be valid");
}

#[cfg(feature = "proof-verifying")]
pub fn with_outputs<
    'a,
    A: Iterator<Item = Op<ResultModeGather, D>> + 'a,
    B: Iterator<Item = AlignedValue> + 'a,
    D: DB,
>(
    prog: A,
    mut values: B,
) -> impl Iterator<Item = Op<ResultModeVerify, D>> + 'a {
    filter_invalid(prog).map(move |op| {
        op.translate(|()| {
            values
                .next()
                .expect("must have sufficient values to annotate operations")
        })
    })
}

#[cfg(any(test, feature = "proof-verifying"))]
const CADDR_OP_LEN: u32 = 12;

#[cfg(test)]
#[test]
fn test_caddr_op() {
    let mut repr = Vec::new();
    for op in filter_invalid::<
        ResultModeVerify,
        std::array::IntoIter<Op<ResultModeVerify, InMemoryDB>, 5>,
        InMemoryDB,
    >(
        Cell_write!(
            [Key::Value(3u8.into())],
            false,
            ContractAddress,
            ContractAddress::default()
        )
        .into_iter(),
    ) {
        op.field_repr(&mut repr);
    }
    assert_eq!(repr.len(), CADDR_OP_LEN as usize);
}

impl AuthorizedClaim<Proof> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self) -> Result<(), MalformedOffer> {
        Ok(())
    }

    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self) -> Result<(), MalformedOffer> {
        use storage::db::InMemoryDB;

        let prog: [Op<ResultModeVerify, InMemoryDB>; 5] = Cell_write!(
            [Key::Value(4u8.into())],
            false,
            CoinPublicKey,
            self.recipient
        );
        let mut statement = vec![transient_commit(&self.coin, 0u8.into())];
        for op in filter_invalid(prog.iter().cloned()) {
            op.field_repr(&mut statement);
        }
        SIGN_VK
            .verify(
                &transient_crypto_old::proofs::PARAMS_VERIFIER,
                &transient_crypto_old::proofs::Proof(self.proof.0.clone()),
                statement.into_iter().map(|f|
                    transient_crypto_old::curve::Fr::from_le_bytes(&f.as_le_bytes())
                        .expect("Fr round-trip")
                ),
            )
            .map_err(|e| MalformedOffer::InvalidProof(anyhow::anyhow!("{e}")))
    }
}

impl<D: DB> Input<Proof, D> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        Ok(())
    }

    #[instrument]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        let mut prog = Vec::new();
        prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.merkle_tree_root
        ));
        prog.extend(Set_insert!(
            [Key::Value(1u8.into())],
            false,
            [u8; 32],
            self.nullifier
        ));
        match &self.contract_address {
            Some(addr) => prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                *addr.deref()
            )),
            None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
        }
        prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
        prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            self.value_commitment.0
        ));
        let mut statement = vec![0.into()];
        for op in with_outputs(prog.into_iter(), [true.into(), segment.into()].into_iter()) {
            op.field_repr(&mut statement);
        }
        SPEND_VK
            .verify(
                &transient_crypto_old::proofs::PARAMS_VERIFIER,
                &transient_crypto_old::proofs::Proof(self.proof.0.clone()),
                statement.into_iter().map(|f|
                    transient_crypto_old::curve::Fr::from_le_bytes(&f.as_le_bytes())
                        .expect("Fr round-trip")
                ),
            )
            .map_err(|e| MalformedOffer::InvalidProof(anyhow::anyhow!("{e}")))
    }
}

impl<D: DB> Input<(), D> {
    #[instrument]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        Ok(())
    }
}

impl<D: DB> Output<Proof, D> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        Ok(())
    }

    #[instrument]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        let mut prog = Vec::new();
        prog.extend::<[Op<_, InMemoryDB>; 17]>(HistoricMerkleTree_insert_hash!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.coin_com
        ));
        match &self.contract_address {
            Some(addr) => prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                addr.deref()
            )),
            None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
        }
        prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
        prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            self.value_commitment.0
        ));
        let msg = match &self.ciphertext {
            Some(ciph) => ciphertext_to_field(ciph),
            None => 0.into(),
        };
        let mut statement = vec![msg];
        for op in with_outputs(prog.into_iter(), [segment.into()].into_iter()) {
            op.field_repr(&mut statement);
        }
        OUTPUT_VK
            .verify(
                &transient_crypto_old::proofs::PARAMS_VERIFIER,
                &transient_crypto_old::proofs::Proof(self.proof.0.clone()),
                statement.into_iter().map(|f|
                    transient_crypto_old::curve::Fr::from_le_bytes(&f.as_le_bytes())
                        .expect("Fr round-trip")
                ),
            )
            .map_err(|e| MalformedOffer::InvalidProof(anyhow::anyhow!("{e}")))
    }
}

impl<D: DB> Output<(), D> {
    #[instrument]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        Ok(())
    }
}

impl<D: DB> Transient<Proof, D> {
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.as_input().well_formed(segment)?;
        self.as_output().well_formed(segment)?;
        Ok(())
    }
}

impl<D: DB> Transient<(), D> {
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.as_input().well_formed(segment)?;
        self.as_output().well_formed(segment)?;
        Ok(())
    }
}

#[allow(unstable_name_collisions)] // is_sorted method by the same name works the same.
fn offer_well_formed_common<P: Ord + Storable<D>, D: DB>(
    offer: &Offer<P, D>,
    segment: u16,
) -> Result<Pedersen, MalformedOffer> {
    if !offer.inputs.iter().is_sorted()
        || !offer.outputs.iter().is_sorted()
        || !offer.transient.iter().is_sorted()
        || !Vec::from(&offer.deltas)
            .windows(2)
            .all(|slice| slice[0].token_type < slice[1].token_type)
        || !offer.deltas.iter().all(|d| d.value != 0)
    {
        warn!("Zswap offer not in normal form");
        return Err(MalformedOffer::NotNormalized);
    }
    let com_unit: Pedersen = Pedersen(EmbeddedGroupAffine::identity());
    let io_com = offer
        .inputs
        .iter()
        .map(|inp| inp.value_commitment)
        .chain(offer.outputs.iter().map(|inp| -inp.value_commitment))
        .chain(
            offer
                .transient
                .iter()
                .map(|io| io.value_commitment_input - io.value_commitment_output),
        )
        .fold(com_unit, Add::add);
    let deltas_com = offer
        .deltas
        .iter()
        .map(|delta| {
            Pedersen::commit(
                &(delta.token_type, segment),
                &<EmbeddedFr as From<i128>>::from(delta.value),
                &0u64.into(),
            )
        })
        .fold(com_unit, Add::add);
    Ok(io_com - deltas_com)
}

impl<D: DB> Offer<Proof, D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        self.inputs
            .iter()
            .try_for_each(|i| i.well_formed(segment))?;
        self.outputs
            .iter()
            .try_for_each(|o| o.well_formed(segment))?;
        self.transient
            .iter()
            .try_for_each(|t| t.well_formed(segment))?;
        offer_well_formed_common(self, segment)
    }
}

impl<D: DB> Offer<(), D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        offer_well_formed_common(self, segment)
    }
}

impl<D: DB> Offer<ProofPreimage, D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        offer_well_formed_common(self, segment)
    }
}

// ---------------------------------------------------------------------------
// Spend-proof memo binding — ADDITIVE detached verification.
//
// Nothing below is reachable from `Offer::well_formed`, `Input::well_formed` or
// any other consensus entry point, and nothing above was changed. In
// particular `Input::<Proof>::well_formed` still builds
//
//     let mut statement = vec![0.into()];
//
// by hand, still never inspects an output's ciphertext for an anchor, and still
// has no way to accept a nonzero row 0. A companion proof placed in
// `Input.proof` is therefore rejected by the shipped `SPEND_VK` — which is
// exactly the property that lets the canonical transaction stay acceptable to
// unmodified nodes.
//
// `spend_statement` below deliberately RESTATES `well_formed`'s assembly rather
// than refactoring `well_formed` to call it. Sharing would be tidier; leaving
// the consensus function untouched byte for byte is worth more, because it lets
// an auditor confirm at a glance that no validity surface moved. The
// duplication is not left to a code reading:
//
//   * `memo_statement_matches_well_formed` (below) rebuilds the statement a
//     third time, inline, and requires all three to agree; and
//   * `memo_statement_agrees_with_the_shipped_verifier` (integration test)
//     requires a REAL canonical proof to verify against
//     `spend_statement(input, segment, 0)` and a REAL companion proof to verify
//     against `spend_statement(input, segment, h)` and NOT against row 0 = 0.
//     A statement that differed from `well_formed`'s by a single row would fail
//     that test, because the proof would not verify.
// ---------------------------------------------------------------------------

/// Rebuild the public spend statement for `input` at `segment`, with `row0` in
/// statement position 0.
///
/// `row0 = Fr::from(0)` reproduces exactly what every unmodified verifier
/// derives. `row0 = h` is the detached companion statement.
///
/// This reads only public fields of the input, so it is generic over the proof
/// type: the same call works on an unproven `Input<ProofPreimage, _>` and on a
/// settled `Input<Proof, _>`.
#[cfg(feature = "proof-verifying")]
pub fn spend_statement<P: Storable<D>, D: DB>(
    input: &Input<P, D>,
    segment: u16,
    row0: Fr,
) -> Vec<Fr> {
    let mut prog = Vec::new();
    prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
        [Key::Value(0u8.into())],
        false,
        32,
        [u8; 32],
        input.merkle_tree_root
    ));
    prog.extend(Set_insert!(
        [Key::Value(1u8.into())],
        false,
        [u8; 32],
        input.nullifier
    ));
    match &input.contract_address {
        Some(addr) => prog.extend(Cell_write!(
            [Key::Value(3u8.into())],
            false,
            ContractAddress,
            *addr.deref()
        )),
        None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
    }
    prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
    prog.extend(Cell_write!(
        [Key::Value(2u8.into())],
        false,
        (Fr, Fr),
        input.value_commitment.0
    ));

    let mut statement = vec![row0];
    for op in with_outputs(prog.into_iter(), [true.into(), segment.into()].into_iter()) {
        op.field_repr(&mut statement);
    }
    statement
}

/// The statement every unmodified verifier derives: row 0 pinned to zero.
#[cfg(feature = "proof-verifying")]
pub fn canonical_spend_statement<P: Storable<D>, D: DB>(
    input: &Input<P, D>,
    segment: u16,
) -> Vec<Fr> {
    spend_statement(input, segment, crate::memo::reserved_absence_element())
}

/// The **row-0 admission check**: the reserved-zero rule at the verification
/// boundary.
///
/// A verifier reading `h` out of an untrusted wrapper or a decoded anchor calls
/// this before any statement or proof work. Reaching the rejection needs no
/// hash preimage, no `Input` and no key material.
pub fn admit_companion_row0(
    row0: Fr,
) -> Result<crate::memo::BindingElement, crate::memo::ReservedBindingElement> {
    crate::memo::BindingElement::new(row0)
}

/// Verify a shipped-format spend proof against `statement` under the shipped
/// `SPEND_VK`.
///
/// **Detached and non-consensus.** This is the same verifier call
/// `Input::<Proof>::well_formed` makes, with the statement supplied by the
/// caller instead of derived with a zero row 0.
#[cfg(feature = "proof-verifying")]
pub fn verify_detached_spend_proof(
    proof: &Proof,
    statement: &[Fr],
) -> Result<(), MalformedOffer> {
    SPEND_VK
        .verify(
            &transient_crypto_old::proofs::PARAMS_VERIFIER,
            &transient_crypto_old::proofs::Proof(proof.0.clone()),
            statement.iter().map(|f| {
                transient_crypto_old::curve::Fr::from_le_bytes(&f.as_le_bytes())
                    .expect("Fr round-trip")
            }),
        )
        .map_err(|e| MalformedOffer::InvalidProof(anyhow::anyhow!("{e}")))
}

/// Verify an off-chain companion wrapper against a settled offer.
///
/// The whole check, in order, so that a refusal costs as little as possible and
/// says as much as possible:
///
/// 1. locate the attributed input **in the offer** by nullifier;
/// 2. refuse a contract-owned carrier;
/// 3. require the wrapper's claimed segment to be the settled one;
/// 4. derive `h` from the memo bytes — it is **never read out of the
///    wrapper** — and refuse the reserved zero;
/// 5. rebuild statement rows `1..` from the canonical settled input and require
///    the wrapper's carried copy to equal them, row by row;
/// 6. only then deserialize the companion proof and verify it under the shipped
///    `SPEND_VK` with row 0 = `h`;
/// 7. finally, collect the settled anchors whose decoded `(N, h)` match.
///
/// Step 4 is what makes memo tampering fail twice over: `h` is derived, so an
/// altered memo breaks proof verification *and* anchor matching at once, with
/// no separate check to forget. Step 5 is what makes the carried statement a
/// cross-check rather than an input — a wrapper cannot talk the verifier into
/// checking a statement of its own choosing.
///
/// A missing or non-matching anchor is **not** a failure: it produces a
/// [`MemoVerification`] with no matching anchors, which a reader must present
/// as a weaker state than an anchored one.
#[cfg(feature = "proof-verifying")]
pub fn verify_memo_companion<P: Storable<D> + Ord, D: DB>(
    wrapper: &crate::memo::wrapper::MemoWrapperV1,
    offer: &Offer<P, D>,
    settled_segment: u16,
) -> Result<MemoVerification, crate::memo::MemoVerifyError> {
    use crate::memo::MemoVerifyError;

    let nullifier = wrapper.nullifier();
    let input = offer
        .inputs
        .iter_deref()
        .find(|i| i.nullifier == nullifier)
        .cloned()
        .ok_or(MemoVerifyError::AttributedInputNotFound { nullifier })?;

    if input.contract_address.is_some() {
        return Err(MemoVerifyError::ContractOwnedCarrier { nullifier });
    }

    if wrapper.segment() != settled_segment {
        return Err(MemoVerifyError::SegmentMismatch {
            claimed: wrapper.segment(),
            settled: settled_segment,
        });
    }

    // `h` is DERIVED from the memo bytes. It is never carried, so there is no
    // second source of truth a tampered wrapper could exploit.
    let binding = admit_companion_row0(crate::memo::memo_hash_v1(wrapper.unverified_memo()))?;

    let statement = spend_statement(&input, settled_segment, binding.get());
    let claimed = wrapper.claimed_statement_tail();
    if claimed.len() != statement.len() - 1 {
        return Err(MemoVerifyError::StatementRowCount {
            found: claimed.len(),
            expected: statement.len() - 1,
        });
    }
    for (i, (rebuilt, carried)) in statement[1..].iter().zip(claimed.iter()).enumerate() {
        if rebuilt != carried {
            return Err(MemoVerifyError::StatementRowMismatch { row: i + 1 });
        }
    }

    let mut proof_bytes = wrapper.companion_proof_bytes();
    let proof: Proof = tagged_deserialize(&mut proof_bytes).map_err(|e| {
        MemoVerifyError::MalformedCompanionProof {
            reason: e.to_string(),
        }
    })?;
    if !proof_bytes.is_empty() {
        return Err(MemoVerifyError::MalformedCompanionProof {
            reason: format!(
                "{} trailing byte(s) after the companion proof",
                proof_bytes.len()
            ),
        });
    }

    verify_detached_spend_proof(&proof, &statement).map_err(|e| {
        MemoVerifyError::CompanionProofRejected {
            reason: e.to_string(),
        }
    })?;

    // Anchors are matched by DECODED `(N, h)`, never by output position:
    // `Offer::new` sorts its outputs, so position is not caller-controlled.
    let anchors = offer
        .memo_anchors()
        .into_iter()
        .filter(|a| a.anchor.nullifier == nullifier && a.anchor.binding == binding)
        .collect();

    Ok(MemoVerification::new(
        wrapper.unverified_memo().clone(),
        nullifier,
        settled_segment,
        binding,
        anchors,
    ))
}

#[cfg(all(test, feature = "proof-verifying"))]
mod memo_statement_tests {
    use super::*;
    use crate::memo::{BindingElement, Memo};
    use base_crypto::hash::HashOutput;
    use coin_structure::coin::Nullifier;
    use transient_crypto::commitment::Pedersen;
    use transient_crypto::merkle_tree::MerkleTreeDigest;

    /// Builds an `Input` with no proof at all — the statement rebuild reads
    /// only public fields, which is exactly the point.
    fn bare_input(nullifier_seed: u8, contract: bool) -> Input<(), InMemoryDB> {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(nullifier_seed);
        }
        Input {
            nullifier: Nullifier(HashOutput(raw)),
            value_commitment: Pedersen(EmbeddedGroupAffine::generator()),
            contract_address: if contract {
                Some(Sp::new(ContractAddress::default()))
            } else {
                None
            },
            merkle_tree_root: MerkleTreeDigest::default(),
            proof: Arc::new(()),
        }
    }

    /// A THIRD, inline rebuild, transcribed from `Input::<Proof>::well_formed`
    /// above. If either copy drifts, this fails.
    fn inline_rebuild(input: &Input<(), InMemoryDB>, segment: u16, row0: Fr) -> Vec<Fr> {
        let mut prog = Vec::new();
        prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            input.merkle_tree_root
        ));
        prog.extend(Set_insert!(
            [Key::Value(1u8.into())],
            false,
            [u8; 32],
            input.nullifier
        ));
        match &input.contract_address {
            Some(addr) => prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                *addr.deref()
            )),
            None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
        }
        prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
        prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            input.value_commitment.0
        ));
        let mut statement = vec![row0];
        for op in with_outputs(prog.into_iter(), [true.into(), segment.into()].into_iter()) {
            op.field_repr(&mut statement);
        }
        statement
    }

    #[test]
    fn memo_statement_matches_well_formed() {
        for contract in [false, true] {
            for segment in [0u16, 1, 3, u16::MAX] {
                let input = bare_input(5, contract);
                let mine = spend_statement(&input, segment, Fr::from(0u64));
                let theirs = inline_rebuild(&input, segment, Fr::from(0u64));
                assert_eq!(mine, theirs, "contract={contract} segment={segment}");
                assert_eq!(mine.len(), INPUT_PIS);
            }
        }
    }

    #[test]
    fn only_row_zero_differs_between_canonical_and_companion() {
        let input = bare_input(9, false);
        let h = BindingElement::for_memo(&Memo::from_slice(b"hello world").unwrap()).unwrap();
        let canonical = canonical_spend_statement(&input, 3);
        let companion = spend_statement(&input, 3, h.get());
        assert_eq!(canonical.len(), companion.len());
        assert_eq!(canonical.len(), INPUT_PIS);
        assert_eq!(canonical[0], Fr::from(0u64));
        assert_eq!(companion[0], h.get());
        assert_eq!(canonical[1..], companion[1..]);
    }

    #[test]
    fn the_statement_binds_the_nullifier_the_root_and_the_segment() {
        let base = spend_statement(&bare_input(1, false), 3, Fr::from(0u64));
        assert_ne!(base, spend_statement(&bare_input(2, false), 3, Fr::from(0u64)));
        assert_ne!(base, spend_statement(&bare_input(1, false), 4, Fr::from(0u64)));
        assert_ne!(base, spend_statement(&bare_input(1, true), 3, Fr::from(0u64)));
    }

    /// The reserved-zero rule, boundary 3 of 3: no hash preimage, no input and
    /// no key material are needed to reach the rejection.
    #[test]
    fn forced_zero_is_rejected_at_the_verification_boundary() {
        assert!(admit_companion_row0(Fr::from(0u64)).is_err());
        assert!(admit_companion_row0(crate::memo::reserved_absence_element()).is_err());
        for h in [Fr::from(1u64), Fr::from(u64::MAX)] {
            assert_eq!(admit_companion_row0(h).unwrap().get(), h);
        }
    }
}
