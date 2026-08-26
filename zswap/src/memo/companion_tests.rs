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

//! The memo-binding claims that can only be made with **real proofs**, against
//! the shipped `SPEND_VK` and `OUTPUT_VK`.
//!
//! Like `prove::tests::test_proof_sizes`, these need the Zswap key material the
//! data provider resolves, so they are slower than the rest of the suite and
//! they exercise the real prover rather than a stand-in.
//!
//! Two of them carry more weight than the others:
//!
//! * [`the_restated_statement_agrees_with_the_shipped_verifier`] is what makes
//!   it safe for `verify::spend_statement` to restate `well_formed`'s assembly
//!   instead of refactoring the consensus function to share it. A statement
//!   that differed by a single row would not verify a real canonical proof.
//! * [`the_companion_proves_h_and_not_zero`] is what makes "the override was
//!   honoured" a measurement rather than an assumption. A backend that accepted
//!   `Some(h)` and then proved the original row-0-zero preimage would produce a
//!   proof that verifies at row 0 = 0 and fails at row 0 = `h` — the exact
//!   opposite of what is asserted here.

use std::sync::Arc;

use base_crypto::data_provider::{self, MidnightDataProvider};
use base_crypto::rng::SplittableRng;
use coin_structure::coin::{Info as CoinInfo, Nullifier, ShieldedTokenType};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serialize::{tagged_deserialize, tagged_serialize};
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{Proof, ProofPreimage, ProvingProvider};
use zkir_v2::LocalProvingProvider;

use crate::keys::{SecretKeys, Seed};
use crate::local;
use crate::memo::anchor::AnchorV1;
use crate::memo::wrapper::{MemoWrapperV1, UntrustedLocator};
use crate::memo::{BindingElement, Memo, MemoVerifyError, memo_hash_v1};
use crate::prove::ZswapResolver;
use crate::structure::{
    INPUT_PROOF_SIZE, Input, MemoCompanion, OUTPUT_PROOF_SIZE, Offer, Output, ZSWAP_EXPECTED_FILES,
};
use crate::verify::{
    Confirmation, canonical_spend_statement, spend_statement, verify_detached_spend_proof,
    verify_memo_companion,
};

const SEGMENT: u16 = 3;
const MEMO: &[u8] = b"hello world";

/// A settlement attestation for a LOCALLY PROVEN offer (00006 finding F3).
///
/// These tests prove and verify inside one process: there is no chain and no
/// settled transaction, so the honest thing to attest to is the offer's own
/// canonical bytes — and this helper's name says so. The evidence boundary is
/// still exercised for real: `Confirmation::settled` recomputes the hash, and
/// `verify_memo_companion` still requires the attested bytes to spend the
/// attributed input and publish the wrapper's `(N, h)`.
fn stand_in_attestation(offer: &Offer<Proof, InMemoryDB>) -> Confirmation {
    let mut bytes = Vec::new();
    serialize::tagged_serialize(offer, &mut bytes).expect("serializing an offer cannot fail");
    Confirmation::settled(&bytes, base_crypto::hash::persistent_hash(&bytes))
        .expect("a self-consistent attestation")
}

fn resolver() -> ZswapResolver {
    ZswapResolver(
        MidnightDataProvider::new(
            data_provider::FetchMode::Synchronous,
            data_provider::OutputMode::Log,
            ZSWAP_EXPECTED_FILES.to_owned(),
        )
        .expect("the Zswap key material must be resolvable"),
    )
}

/// One real, user-owned spend, built through the crate's own public API.
struct Fixture {
    input: Input<ProofPreimage, InMemoryDB>,
    coin: CoinInfo,
    binding: BindingElement,
}

fn fixture(rng: &mut StdRng) -> Fixture {
    let secret_keys: SecretKeys = Seed::random(rng).into();
    let coin = CoinInfo {
        nonce: rng.r#gen(),
        type_: ShieldedTokenType(rng.r#gen()),
        value: 4_242,
    };
    let state: local::State<InMemoryDB> = local::State::new()
        .insert_coin(&secret_keys, coin)
        .expect("inserting the carrier coin");
    let (_after, input) = state
        .spend(rng, &secret_keys, &coin.qualify(0), Some(SEGMENT))
        .expect("spending the carrier coin");

    let memo = Memo::from_slice(MEMO).expect("the test memo is in range");
    let binding = BindingElement::for_memo(&memo).expect("a real memo hash is nonzero");

    Fixture {
        input,
        coin,
        binding,
    }
}

/// The whole construction: the canonical proof, the detached companion, and the
/// anchor output, all from one finalized preimage.
struct Built {
    input: Input<ProofPreimage, InMemoryDB>,
    binding: BindingElement,
    companion: MemoCompanion,
    proven: Offer<Proof, InMemoryDB>,
}

async fn build(rng: &mut StdRng) -> Built {
    let f = fixture(rng);
    let resolver = resolver();
    let mut provider = LocalProvingProvider {
        rng: rng.split(),
        params: &resolver,
        resolver: &resolver,
    };

    // The companion first, from the SAME preimage the canonical proof will be
    // made from. Each call gets its own split provider, so the two proofs use
    // independent prover randomness.
    let companion = f
        .input
        .prove_memo_companion(provider.split(), &f.binding, SEGMENT)
        .await
        .expect("the companion must prove");

    let anchor_output: Output<ProofPreimage, InMemoryDB> = Output::new_memo_anchor(
        rng,
        Some(SEGMENT),
        f.coin.type_,
        f.input.nullifier,
        &f.binding,
    )
    .expect("the anchor output must build");

    let offer = Offer::new(vec![f.input.clone()], vec![anchor_output], Vec::new())
        .expect("a non-empty offer");
    let (_, proven) = offer
        .prove(provider.split(), SEGMENT)
        .await
        .expect("the canonical offer must prove");

    Built {
        input: f.input,
        binding: f.binding,
        companion,
        proven,
    }
}

fn settled_input(built: &Built) -> Input<Proof, InMemoryDB> {
    built
        .proven
        .inputs
        .iter_deref()
        .find(|i| i.nullifier == built.input.nullifier)
        .cloned()
        .expect("the carrier survived proving")
}

fn companion_proof(built: &Built) -> Proof {
    let bytes = built
        .companion
        .detached_proof_bytes()
        .expect("the companion serializes");
    let mut cursor = &bytes[..];
    let proof: Proof = tagged_deserialize(&mut cursor).expect("detached bytes round-trip");
    assert!(cursor.is_empty());
    proof
}

fn wrapper(built: &Built) -> MemoWrapperV1 {
    MemoWrapperV1::build(
        Memo::from_slice(MEMO).unwrap(),
        &built.companion,
        Some(UntrustedLocator::from_slice(b"offer.bin").unwrap()),
    )
    .expect("the wrapper must build")
}

// ---------------------------------------------------------------------------
// The load-bearing pair.
// ---------------------------------------------------------------------------

/// `verify::spend_statement` restates `Input::<Proof>::well_formed`'s assembly
/// rather than refactoring the consensus function. This is what makes that
/// safe: a REAL canonical proof verifies against the restated statement, and
/// the shipped verifier accepts the same input through `well_formed`.
#[tokio::test]
async fn the_restated_statement_agrees_with_the_shipped_verifier() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1101);
    let built = build(&mut rng).await;
    let settled = settled_input(&built);

    // The consensus entry point accepts it...
    settled
        .well_formed(SEGMENT)
        .expect("the canonical input must be well formed");

    // ...and so does the restated statement, with row 0 = 0.
    let canonical = canonical_spend_statement(&settled, SEGMENT);
    assert_eq!(canonical[0], Fr::from(0u64));
    verify_detached_spend_proof(&settled.proof, &canonical)
        .expect("the canonical proof must verify against the restated statement");

    // The mirror control: the canonical proof must NOT verify at row 0 = h, or
    // the statement would not be binding row 0 at all.
    let companion_statement = spend_statement(&settled, SEGMENT, built.binding.get());
    assert!(
        verify_detached_spend_proof(&settled.proof, &companion_statement).is_err(),
        "the canonical proof must not verify with a nonzero row 0"
    );
}

/// The override reached the prover: the companion verifies at row 0 = `h` and
/// does NOT verify at row 0 = 0.
#[tokio::test]
async fn the_companion_proves_h_and_not_zero() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1102);
    let built = build(&mut rng).await;
    let settled = settled_input(&built);
    let proof = companion_proof(&built);

    assert_eq!(built.companion.proof_len(), INPUT_PROOF_SIZE);
    assert_eq!(built.companion.nullifier(), built.input.nullifier);
    assert_eq!(built.companion.segment(), SEGMENT);
    assert_eq!(built.companion.binding(), built.binding);
    assert_eq!(built.companion.statement()[0], built.binding.get());

    // The statement the companion reports must be the one rebuilt from the
    // settled input — that is the whole attribution claim.
    assert_eq!(
        built.companion.statement(),
        spend_statement(&settled, SEGMENT, built.binding.get())
    );

    verify_detached_spend_proof(&proof, built.companion.statement())
        .expect("the companion must verify at row 0 = h");
    assert!(
        verify_detached_spend_proof(&proof, &canonical_spend_statement(&settled, SEGMENT)).is_err(),
        "the companion must NOT verify at row 0 = 0 — a silent row-0-zero prover would"
    );
}

// ---------------------------------------------------------------------------
// The old-node boundary.
// ---------------------------------------------------------------------------

/// The property the whole design rests on: a companion proof substituted into
/// `Input.proof` is refused by the shipped consensus entry point, because that
/// entry point re-derives row 0 as zero and never reads it from the proof.
#[tokio::test]
async fn a_companion_substituted_into_input_proof_is_refused() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1103);
    let built = build(&mut rng).await;
    let settled = settled_input(&built);

    let tampered = Input {
        proof: Arc::new(companion_proof(&built)),
        ..settled.clone()
    };
    assert!(
        tampered.well_formed(SEGMENT).is_err(),
        "well_formed must refuse a companion proof in Input.proof"
    );
    // ...while the untouched input is still fine, so the refusal is about the
    // proof and not about the input.
    settled.well_formed(SEGMENT).expect("control");
}

/// The two proofs are distinct artifacts over the same preimage.
#[tokio::test]
async fn the_two_proofs_are_byte_distinct() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1104);
    let built = build(&mut rng).await;
    let settled = settled_input(&built);
    assert_ne!(settled.proof.0, companion_proof(&built).0);
    assert_eq!(settled.proof.0.len(), INPUT_PROOF_SIZE);
}

// ---------------------------------------------------------------------------
// The anchor output.
// ---------------------------------------------------------------------------

/// The anchor is an ORDINARY output: proved and verified by the unchanged
/// output path, under the shipped `OUTPUT_VK`.
#[tokio::test]
async fn the_anchor_output_is_an_ordinary_output_the_shipped_path_accepts() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1105);
    let built = build(&mut rng).await;

    let anchors = built.proven.memo_anchors();
    assert_eq!(anchors.len(), 1, "exactly one anchor");
    let found = anchors[0];
    assert_eq!(found.anchor.nullifier, built.input.nullifier);
    assert_eq!(found.anchor.binding, built.binding);

    let output = built
        .proven
        .outputs
        .iter_deref()
        .find(|o| o.coin_com == found.coin_com)
        .cloned()
        .expect("the carrying output is in the proven offer");

    output
        .well_formed(SEGMENT)
        .expect("the anchor output must pass the unchanged output verifier");
    assert_eq!(output.proof.0.len(), OUTPUT_PROOF_SIZE);
    assert!(
        output.contract_address.is_none(),
        "the anchor carrier is an ordinary USER output"
    );

    // The ciphertext that survived proving is exactly the anchor.
    let ciph = output.ciphertext.as_ref().expect("the anchor ciphertext");
    let decoded = AnchorV1::decode(ciph).expect("it decodes as an anchor");
    assert_eq!(decoded.nullifier, built.input.nullifier);
    assert_eq!(decoded.binding, built.binding);

    // ...and it is the same bytes an on-wire scan would find.
    let mut offer_bytes = Vec::new();
    tagged_serialize(&built.proven, &mut offer_bytes).unwrap();
    let sightings = crate::memo::anchor::scan_untagged_anchors(&offer_bytes);
    assert_eq!(sightings.len(), 1);
    assert_eq!(sightings[0].anchor, decoded);
}

/// Two anchors for the same `(N, h)` are independent coins, so an anchor
/// cannot be recognised by its commitment.
#[tokio::test]
async fn two_anchors_for_one_pair_have_distinct_commitments() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1106);
    let f = fixture(&mut rng);
    let a: Output<ProofPreimage, InMemoryDB> = Output::new_memo_anchor(
        &mut rng,
        Some(SEGMENT),
        f.coin.type_,
        f.input.nullifier,
        &f.binding,
    )
    .unwrap();
    let b: Output<ProofPreimage, InMemoryDB> = Output::new_memo_anchor(
        &mut rng,
        Some(SEGMENT),
        f.coin.type_,
        f.input.nullifier,
        &f.binding,
    )
    .unwrap();
    assert_ne!(a.coin_com, b.coin_com);
    // ...but they carry the same anchor.
    assert_eq!(
        AnchorV1::decode(a.ciphertext.as_ref().unwrap()).unwrap(),
        AnchorV1::decode(b.ciphertext.as_ref().unwrap()).unwrap()
    );
}

// ---------------------------------------------------------------------------
// End to end, through the wrapper.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_real_wrapper_authenticates_against_the_proven_offer() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1107);
    let built = build(&mut rng).await;
    let w = wrapper(&built);

    // Through the bytes, exactly as a consumer would receive it.
    let encoded = w.encode();
    let parsed = MemoWrapperV1::decode(&encoded).expect("the wrapper round-trips");
    assert_eq!(parsed.encode(), encoded);

    let record = verify_memo_companion(
        &parsed,
        &built.proven,
        SEGMENT,
        &stand_in_attestation(&built.proven),
    )
    .expect("a real wrapper must authenticate");
    assert_eq!(record.authenticated_memo().as_bytes(), MEMO);
    assert_eq!(record.nullifier(), built.input.nullifier);
    assert_eq!(record.segment(), SEGMENT);
    assert_eq!(record.binding(), built.binding);
    assert!(record.has_matching_anchor());
    assert!(
        record.is_settled_anchored(),
        "the attestation covers this memo"
    );
    assert!(record.attested_transaction().is_some());
    assert!(!record.has_duplicate_anchors());

    // The SAME wrapper with no settlement asserted authenticates just as well
    // and claims no settlement at all (00006 finding F3, spec FR-103).
    let unattested =
        verify_memo_companion(&parsed, &built.proven, SEGMENT, &Confirmation::Unconfirmed)
            .expect("authentication does not depend on settlement evidence");
    assert!(unattested.has_matching_anchor());
    assert!(!unattested.is_settled_anchored());
    assert_eq!(unattested.attested_transaction(), None);
    assert_eq!(record.matching_anchors().len(), 1);

    // The bech32m rendering is a rendering: it round-trips to the same bytes.
    let rendered = crate::memo::bech32m::encode(&encoded).expect("bech32m encodes");
    assert!(rendered.starts_with("swapmsg1"));
    assert_eq!(crate::memo::bech32m::decode(&rendered).unwrap(), encoded);
}

/// The tamper matrix, against a real proof and a real proven offer. Every case
/// must fail closed with its own diagnosis.
#[tokio::test]
async fn the_tamper_matrix_fails_closed() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1108);
    let built = build(&mut rng).await;
    let good = wrapper(&built);
    let tail = good.claimed_statement_tail().to_vec();
    let proof_bytes = good.companion_proof_bytes().to_vec();

    let rebuild = |memo: &[u8], nullifier: Nullifier, segment: u16, tail: Vec<Fr>| {
        MemoWrapperV1::from_parts(
            Memo::from_slice(memo).unwrap(),
            nullifier,
            segment,
            tail,
            proof_bytes.clone(),
            None,
        )
        .unwrap()
    };

    // 1. memo altered / truncated / extended / trailing-zero-extended. `h` is
    //    DERIVED, so each of these breaks the proof rather than some separate
    //    check.
    for memo in [
        &b"hello worlds"[..],
        b"hello worl",
        b"Hello world",
        b"hello world\0",
    ] {
        let w = rebuild(memo, built.input.nullifier, SEGMENT, tail.clone());
        assert!(
            matches!(
                verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed),
                Err(MemoVerifyError::CompanionProofRejected { .. })
            ),
            "a tampered memo authenticated: {memo:02x?}"
        );
    }

    // 2. re-attributed to a nullifier that is not in the offer.
    let w = rebuild(
        MEMO,
        Nullifier(base_crypto::hash::HashOutput([0x11; 32])),
        SEGMENT,
        tail.clone(),
    );
    assert!(matches!(
        verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed),
        Err(MemoVerifyError::AttributedInputNotFound { .. })
    ));

    // 3. a segment that is not the settled one.
    let w = rebuild(MEMO, built.input.nullifier, SEGMENT + 1, tail.clone());
    assert!(matches!(
        verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed),
        Err(MemoVerifyError::SegmentMismatch { .. })
    ));

    // 4. a perturbed statement row — caught BEFORE any proof work, because the
    //    verifier rebuilds the rows and requires equality.
    let mut bad_tail = tail.clone();
    bad_tail[12] = bad_tail[12] + Fr::from(1u64);
    let w = rebuild(MEMO, built.input.nullifier, SEGMENT, bad_tail);
    match verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed) {
        Err(MemoVerifyError::StatementRowMismatch { row }) => assert_eq!(row, 13),
        other => panic!("a perturbed statement row was not caught: {other:?}"),
    }

    // 5. a grafted proof: the CANONICAL proof offered as a companion.
    let settled = settled_input(&built);
    let mut canonical_bytes = Vec::new();
    tagged_serialize(&*settled.proof, &mut canonical_bytes).unwrap();
    let w = MemoWrapperV1::from_parts(
        Memo::from_slice(MEMO).unwrap(),
        built.input.nullifier,
        SEGMENT,
        tail.clone(),
        canonical_bytes,
        None,
    )
    .unwrap();
    assert!(matches!(
        verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed),
        Err(MemoVerifyError::CompanionProofRejected { .. })
    ));

    // 6. unreadable proof bytes.
    let w = MemoWrapperV1::from_parts(
        Memo::from_slice(MEMO).unwrap(),
        built.input.nullifier,
        SEGMENT,
        tail.clone(),
        vec![0xff; 64],
        None,
    )
    .unwrap();
    assert!(matches!(
        verify_memo_companion(&w, &built.proven, SEGMENT, &Confirmation::Unconfirmed),
        Err(MemoVerifyError::MalformedCompanionProof { .. })
    ));

    // ...and the untouched wrapper still authenticates, so none of the above
    // passed for an unrelated reason.
    verify_memo_companion(
        &good,
        &built.proven,
        SEGMENT,
        &stand_in_attestation(&built.proven),
    )
    .expect("control");
}

/// An authenticated memo without a matching anchor is a WEAKER state, not a
/// failure — and it is reported as such.
#[tokio::test]
async fn a_companion_without_a_matching_anchor_is_unanchored_not_rejected() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1109);
    let f = fixture(&mut rng);
    let resolver = resolver();
    let mut provider = LocalProvingProvider {
        rng: rng.split(),
        params: &resolver,
        resolver: &resolver,
    };
    let companion = f
        .input
        .prove_memo_companion(provider.split(), &f.binding, SEGMENT)
        .await
        .expect("the companion must prove");

    // An offer with the carrier but NO anchor output.
    let recipient: SecretKeys = Seed::random(&mut rng).into();
    let plain_coin = CoinInfo {
        nonce: rng.r#gen(),
        type_: f.coin.type_,
        value: 1,
    };
    let plain: Output<ProofPreimage, InMemoryDB> = Output::new(
        &mut rng,
        &plain_coin,
        Some(SEGMENT),
        &recipient.coin_public_key(),
        None,
    )
    .unwrap();
    let offer = Offer::new(vec![f.input.clone()], vec![plain], Vec::new()).unwrap();
    let (_, proven) = offer.prove(provider.split(), SEGMENT).await.unwrap();

    assert!(proven.memo_anchors().is_empty());
    let w = MemoWrapperV1::build(Memo::from_slice(MEMO).unwrap(), &companion, None).unwrap();
    let record = verify_memo_companion(&w, &proven, SEGMENT, &stand_in_attestation(&proven))
        .expect("the companion still authenticates the memo");
    assert!(!record.has_matching_anchor());
    assert!(
        !record.is_settled_anchored(),
        "no anchor, so nothing to settle"
    );
    assert_eq!(record.authenticated_memo().as_bytes(), MEMO);
}

/// The carrier is resolved BY VALUE, and a duplicated nullifier is REFUSED
/// rather than silently disambiguated by position (00006 finding F3: this
/// lookup used to be a `.find()`).
#[tokio::test]
async fn a_duplicated_attributed_input_is_refused_rather_than_picked() {
    let mut rng = StdRng::seed_from_u64(0x0000_03C0_1F03);
    let built = build(&mut rng).await;
    let w = wrapper(&built);

    let mut inputs: Vec<Input<Proof, InMemoryDB>> =
        built.proven.inputs.iter_deref().cloned().collect();
    let carrier = inputs
        .iter()
        .find(|i| i.nullifier == w.nullifier())
        .cloned()
        .expect("the carrier is in the proven offer");
    inputs.push(carrier);
    let doubled = Offer {
        inputs: inputs.into(),
        outputs: built.proven.outputs.clone(),
        transient: built.proven.transient.clone(),
        deltas: built.proven.deltas.clone(),
    };

    match verify_memo_companion(&w, &doubled, SEGMENT, &Confirmation::Unconfirmed) {
        Err(MemoVerifyError::DuplicateAttributedInput { nullifier, count }) => {
            assert_eq!(nullifier, w.nullifier());
            assert_eq!(count, 2);
        }
        other => panic!("expected a duplicate-carrier refusal, got {other:?}"),
    }
}

/// The construction gate: a contract-owned carrier never reaches the prover.
#[tokio::test]
async fn a_contract_owned_carrier_is_refused_before_proving() {
    use crate::memo::MemoCompanionError;
    use coin_structure::contract::ContractAddress;
    use coin_structure::transfer::Recipient;
    use transient_crypto::merkle_tree::MerkleTree;

    let mut rng = StdRng::seed_from_u64(0x0000_03C0_110A);
    let address = ContractAddress(rng.r#gen());
    let coin = CoinInfo {
        nonce: rng.r#gen(),
        type_: ShieldedTokenType(rng.r#gen()),
        value: 10,
    };
    let tree = MerkleTree::<(), InMemoryDB>::blank(crate::ZSWAP_TREE_HEIGHT)
        .try_update_hash(0, coin.commitment(&Recipient::Contract(address)).0, ())
        .unwrap()
        .rehash();
    let input =
        Input::new_contract_owned(&mut rng, &coin.qualify(0), Some(SEGMENT), address, &tree)
            .unwrap();

    let memo = Memo::from_slice(MEMO).unwrap();
    let binding = BindingElement::for_memo(&memo).unwrap();
    let resolver = resolver();
    let provider = LocalProvingProvider {
        rng: rng.split(),
        params: &resolver,
        resolver: &resolver,
    };
    assert!(matches!(
        input
            .prove_memo_companion(provider, &binding, SEGMENT)
            .await,
        Err(MemoCompanionError::ContractOwnedCarrier { .. })
    ));
}

/// The FR-004 gate: a preimage that already stores a nonzero row 0 is refused
/// before the prover is called, because `prove(P, None)` would otherwise keep
/// that value and poison the canonical proof too.
#[tokio::test]
async fn a_stored_nonzero_row_zero_is_refused_before_proving() {
    use crate::memo::MemoCompanionError;

    let mut rng = StdRng::seed_from_u64(0x0000_03C0_110B);
    let f = fixture(&mut rng);

    let mut preimage = (*f.input.proof).clone();
    preimage.binding_input = Fr::from(7u64);
    let poisoned = Input {
        proof: Arc::new(preimage),
        ..f.input.clone()
    };

    let resolver = resolver();
    let provider = LocalProvingProvider {
        rng: rng.split(),
        params: &resolver,
        resolver: &resolver,
    };
    assert!(matches!(
        poisoned
            .prove_memo_companion(provider, &f.binding, SEGMENT)
            .await,
        Err(MemoCompanionError::StoredBindingInputNotZero { .. })
    ));
}

/// The memo hash is stable across everything above: the same memo bytes give
/// the field element the frozen conformance vectors record.
#[test]
fn the_memo_hash_is_the_frozen_value() {
    let memo = Memo::from_slice(MEMO).unwrap();
    assert_eq!(
        crate::memo::fr_le32(memo_hash_v1(&memo)),
        [
            0x65, 0xd3, 0xc3, 0x3a, 0x0f, 0xb1, 0x4d, 0x48, 0xa0, 0x42, 0x62, 0x0c, 0x37, 0x5b,
            0xb1, 0x9f, 0xba, 0x0f, 0x9d, 0x8f, 0xbf, 0xc6, 0xbb, 0xe3, 0xf2, 0x19, 0x59, 0xf7,
            0x3c, 0x2a, 0x54, 0x55,
        ]
    );
}
