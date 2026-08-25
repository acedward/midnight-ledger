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

//! PROJECT 00006 — the fork half of the RED demonstrator suite.
//!
//! Companion file to the toolkit's `tests/red_00006.rs`. Every test here
//! demonstrates a defect of the **additive memo helpers this branch adds** —
//! never of anything that exists at the pinned baseline. Each test asserts the
//! DESIRED post-remediation behaviour, so each one FAILS on this branch today;
//! the failure message names the finding and states what the code did instead.
//!
//! All of them are `#[ignore]`d so that `cargo test -p midnight-zswap` stays
//! green for everyone else while the remediation workstreams are in flight:
//!
//! ```text
//! MIDNIGHT_PP=$HOME/.cache/midnight/zk-params \
//!   cargo test -p midnight-zswap --test red_00006 -- --ignored --test-threads=1
//! ```
//!
//! The tests marked `[real prover]` need the shipped Zswap key material, like
//! `memo::companion_tests`. The rest need none: where the defect is "the
//! correlated fields are never compared at all", a stand-in prover is enough to
//! reach the emission point.

use base_crypto::data_provider::{self, MidnightDataProvider};
use base_crypto::rng::SplittableRng;
use coin_structure::coin::Info as CoinInfo;
use coin_structure::coin::ShieldedTokenType;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serialize::tagged_deserialize;
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider, Resolver,
};
use zkir_v2::LocalProvingProvider;

use midnight_zswap::keys::{SecretKeys, Seed};
use midnight_zswap::local;
use midnight_zswap::memo::wrapper::MemoWrapperV1;
use midnight_zswap::memo::{BindingElement, Memo};
use midnight_zswap::prove::ZswapResolver;
use midnight_zswap::verify::verify_memo_companion;
use midnight_zswap::{INPUT_PROOF_SIZE, Input, Offer, Output, ZSWAP_EXPECTED_FILES};

const SEGMENT: u16 = 3;
const OTHER_SEGMENT: u16 = 9;
const MEMO_A: &[u8] = b"hello world";
const MEMO_B: &[u8] = b"a completely different memo";

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

/// A real, user-owned spend built through the crate's own public API.
struct Fixture {
    input: Input<ProofPreimage, InMemoryDB>,
    coin: CoinInfo,
    binding: BindingElement,
}

fn fixture(rng: &mut StdRng, segment: u16, memo: &[u8]) -> Fixture {
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
        .spend(rng, &secret_keys, &coin.qualify(0), Some(segment))
        .expect("spending the carrier coin");

    let memo = Memo::from_slice(memo).expect("the test memo is in range");
    let binding = BindingElement::for_memo(&memo).expect("a real memo hash is nonzero");

    Fixture {
        input,
        coin,
        binding,
    }
}

// ---------------------------------------------------------------------------
// Test doubles.
// ---------------------------------------------------------------------------

/// **The SC-011 double, fork side.** Accepts `Some(h)` and proves the ORIGINAL
/// row-0-zero preimage — exactly what the pinned `zkir-wasm` `verifier-key[v6]`
/// arm did before the Phase 4 correction. Mirrors the toolkit's
/// `conformance::adversarial::SilentRowZeroProver`.
struct SilentRowZeroProver<P> {
    inner: P,
}

impl<P: ProvingProvider> ProvingProvider for SilentRowZeroProver<P> {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        self.inner.check(preimage).await
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        _overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        // The defect, reproduced exactly: the parameter is accepted and then
        // dropped, and the caller sees an ordinary success.
        self.inner.prove(preimage, None).await
    }

    fn split(&mut self) -> Self {
        SilentRowZeroProver {
            inner: self.inner.split(),
        }
    }

    fn resolver(&self) -> &impl Resolver {
        self.inner.resolver()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NullResolver;

impl Resolver for NullResolver {
    async fn resolve_key(&self, _key: KeyLocation) -> std::io::Result<Option<ProvingKeyMaterial>> {
        Ok(None)
    }
}

/// A stand-in `ProvingProvider`. It is NOT a proving backend and produces
/// nothing verifiable — which is precisely why reaching an `Ok` through it
/// proves the construction path performed no consistency check.
#[derive(Clone, Default)]
struct StandInProver {
    tag: u64,
    resolver: NullResolver,
}

impl ProvingProvider for StandInProver {
    async fn check(&self, _preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        Ok(Vec::new())
    }

    async fn prove(
        self,
        _preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let mut out = vec![0xa5u8; INPUT_PROOF_SIZE];
        out[0] = self.tag as u8;
        if let Some(h) = overwrite_binding_input {
            out[1..33].copy_from_slice(&h.as_le_bytes());
        }
        Ok(Proof(out))
    }

    fn split(&mut self) -> Self {
        self.tag += 1;
        StandInProver {
            tag: self.tag,
            resolver: NullResolver,
        }
    }

    fn resolver(&self) -> &impl Resolver {
        &self.resolver
    }
}

// ===========================================================================
// F1 — `Input::prove_memo_companion` never checks the proof it returns.
//
// Research file, F1 table, row 5: the fork producer carries a doc warning
// (`prove.rs:171-181`) telling the CALLER to check, and performs no check
// itself, even though `verify::verify_detached_spend_proof` is available under
// the very same `proof-verifying` feature gate.
//
// Desired (spec FR-101): a typed `MemoCompanionError`. Today: `Ok`.
// ===========================================================================

#[tokio::test]
#[ignore = "RED until 00006 Phase 1 (F1) — [real prover]"]
async fn f1_fork_prove_memo_companion_returns_a_silent_row_zero_companion() {
    let mut rng = StdRng::seed_from_u64(0x0000_06F0_0F01);
    let f = fixture(&mut rng, SEGMENT, MEMO_A);
    let resolver = resolver();
    let mut silent = SilentRowZeroProver {
        inner: LocalProvingProvider {
            rng: rng.split(),
            params: &resolver,
            resolver: &resolver,
        },
    };

    let result = f
        .input
        .prove_memo_companion(silent.split(), &f.binding, SEGMENT)
        .await;

    match result {
        Err(_) => { /* the post-remediation behaviour */ }
        Ok(companion) => {
            // Show WHY this is the defect, with the crate's own verifier: the
            // returned companion verifies with row 0 = 0 and fails at row 0 = h.
            let bytes = companion
                .detached_proof_bytes()
                .expect("the companion serializes");
            let proof: Proof =
                tagged_deserialize(&mut &bytes[..]).expect("the detached bytes round-trip");
            let canonical = midnight_zswap::verify::canonical_spend_statement(&f.input, SEGMENT);
            let at_zero =
                midnight_zswap::verify::verify_detached_spend_proof(&proof, &canonical).is_ok();
            let at_h =
                midnight_zswap::verify::verify_detached_spend_proof(&proof, companion.statement())
                    .is_ok();
            panic!(
                "F1 RED: `Input::prove_memo_companion` returned Ok for a backend that \
                 silently dropped the row-0 override. The returned companion verifies at \
                 row 0 = 0: {at_zero}; it binds the memo (row 0 = h): {at_h}. Spec FR-101 \
                 requires a typed MemoCompanionError instead."
            );
        }
    }
}

// ===========================================================================
// F2 — inconsistent construction requests return Ok (fork half).
//
// Research file F2, sub-claims 3 and 4:
//
//   * `prove_memo_companion` (prove.rs:186-224) never checks
//     `self.segment() == Some(segment)`, although `Input::segment()` exists
//     (structure.rs:287) and the toolkit enforces exactly this gate via
//     `require_carrier_segment`;
//   * `MemoWrapperV1::build` (memo/wrapper.rs:405-423) never checks
//     `memo_hash_v1(&memo) == companion.binding().get()`.
//
// Desired (spec FR-102): typed errors at construction time. Today: `Ok`.
// ===========================================================================

#[tokio::test]
#[ignore = "RED until 00006 Phase 2 (F2.4) — fork segment gate"]
async fn f2_fork_prove_memo_companion_accepts_a_wrong_segment() {
    let mut rng = StdRng::seed_from_u64(0x0000_06F0_0201);
    let f = fixture(&mut rng, SEGMENT, MEMO_A);
    assert_eq!(
        f.input.segment(),
        Some(SEGMENT),
        "the carrier really is encoded at SEGMENT"
    );

    let mut prover = StandInProver::default();
    let result = f
        .input
        .prove_memo_companion(prover.split(), &f.binding, OTHER_SEGMENT)
        .await;

    assert!(
        result.is_err(),
        "F2 RED: `Input::prove_memo_companion` produced a companion for segment \
         {OTHER_SEGMENT} from a carrier whose own encoded segment is {:?}. The statement \
         it returns can never be rebuilt from that input, so the companion can never \
         verify. Spec FR-102 requires a typed SegmentMismatch, matching the toolkit's \
         `require_carrier_segment` gate.",
        f.input.segment()
    );
}

#[tokio::test]
#[ignore = "RED until 00006 Phase 2 (F2.3) — fork wrapper memo<->binding check"]
async fn f2_fork_wrapper_build_accepts_a_memo_that_does_not_hash_to_the_binding() {
    let mut rng = StdRng::seed_from_u64(0x0000_06F0_0202);
    let f = fixture(&mut rng, SEGMENT, MEMO_A);

    let mut prover = StandInProver::default();
    let companion = f
        .input
        .prove_memo_companion(prover.split(), &f.binding, SEGMENT)
        .await
        .expect("the stand-in prover produces a companion");

    // Memo B beside memo A's companion: `memo_hash_v1(MEMO_B)` is not
    // `companion.binding()`, so the wrapper can never verify anywhere.
    let unrelated = Memo::from_slice(MEMO_B).expect("valid memo");
    let built = MemoWrapperV1::build(unrelated, &companion, None);

    assert!(
        built.is_err(),
        "F2 RED: `MemoWrapperV1::build` accepted a memo whose MemoHashV1 is not the \
         companion's binding element. Spec FR-102 requires a typed mismatch error on \
         both sides."
    );
}

// ===========================================================================
// F3 — the fork verification API describes unestablished settlement.
//
// Research file F3, last bullet: `verify_memo_companion`
// (`zswap/src/verify.rs:520-626`) is the WEAKER of the two verifiers — it takes
// no confirmation parameter at all, and its result type is worded as settled
// fact (`structure.rs:753`, `:807-881`: "settled anchors", "one valid AnchorV1
// found on a settled output").
//
// Desired (spec FR-103): the same evidence boundary the toolkit gets. Today:
// a purely local offer, assembled in this process seconds ago, yields
// `is_anchored() == true` and accessors that call its anchors settled.
// ===========================================================================

#[tokio::test]
#[ignore = "RED until 00006 Phase 3 (F3) — [real prover]"]
async fn f3_fork_verify_memo_companion_calls_a_never_on_chain_anchor_settled() {
    let mut rng = StdRng::seed_from_u64(0x0000_06F0_0301);
    let f = fixture(&mut rng, SEGMENT, MEMO_A);
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
        .expect("a real companion");

    let anchor_output: Output<ProofPreimage, InMemoryDB> = Output::new_memo_anchor(
        &mut rng,
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

    let wrapper = MemoWrapperV1::build(
        Memo::from_slice(MEMO_A).expect("valid memo"),
        &companion,
        None,
    )
    .expect("the wrapper must build");

    // NOTHING here has been near a chain: `proven` was assembled and proved in
    // this process moments ago, and `verify_memo_companion` has no parameter
    // through which a caller could even claim otherwise.
    let verification =
        verify_memo_companion(&wrapper, &proven, SEGMENT).expect("verification succeeds today");

    assert!(
        !verification.is_anchored(),
        "F3 RED: `verify_memo_companion` reported {} matching anchor(s) as SETTLED strip \
         evidence for an offer that was never broadcast, and its signature has no place \
         to supply settlement evidence at all. Spec FR-103 requires the same typed, \
         transaction-bound evidence boundary the toolkit gets.",
        verification.matching_anchors().len()
    );
}
