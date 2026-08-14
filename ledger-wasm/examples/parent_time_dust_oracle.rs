// Generates the T1 parent-time fixture consumed by UmbraDB.
//
// The transaction's guaranteed contract transcript reads QueryContext[7] (`last_block_time`) and
// asserts the real parent timestamp. The same intent carries a signed dust registration. Applying
// it with node semantics succeeds and changes dust state; applying it with the reference indexer's
// restart sentinel (current block time substituted for a zero cursor) fails before registration.
// Expected hashes are computed here in native Rust, never through the WASM replay under test.

use base_crypto::cost_model::{FixedPoint, SyntheticCost};
use base_crypto::fab::AlignedValue;
use base_crypto::hash::persistent_hash;
use base_crypto::rng::SplittableRng;
use base_crypto::signatures::{Signature, SigningKey};
use base_crypto::time::Timestamp;
use ledger::construct::{ContractCallPrototype, PreTranscript, partition_transcripts};
use ledger::dust::{DustActions, DustPublicKey, DustRegistration, DustSecretKey};
use ledger::semantics::{TransactionContext, TransactionResult};
use ledger::structure::{
    ContractDeploy, Intent, LedgerState, ProofMarker, ProofPreimageMarker, Transaction,
};
use ledger::verify::WellFormedStrictness;
use onchain_runtime::context::{BlockContext, QueryContext};
use onchain_runtime::ops::{Key, Op, key, op};
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::{ContractOperation, ContractState, EntryPointBuf, StateValue};
use onchain_runtime::transcript::Transcript;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serialize::tagged_serialize;
use std::borrow::Cow;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use storage::storage::HashMap;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use transient_crypto::proofs::{KeyLocation, Proof, ProofPreimage, ProvingProvider};

const NETWORK: &str = "parent-time-dust-oracle";
const PARENT_TIME: u64 = 1_700_000_000;
const BLOCK_TIME: u64 = 1_700_000_010;

#[derive(Clone)]
struct StructuralProof;

impl ProvingProvider for StructuralProof {
    async fn check(&self, _preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        // The fixture has exactly three public transcript operations and no conditional skips.
        Ok(vec![None, None, None])
    }

    async fn prove(
        self,
        _preimage: &ProofPreimage,
        _overwrite_binding_input: Option<transient_crypto::curve::Fr>,
    ) -> Result<Proof, anyhow::Error> {
        // ledger-wasm is compiled without proof verification, while the authoritative node fold
        // consumes a VerifiedTransaction after admission. This structurally valid marker isolates
        // that post-validation fold without introducing a proving server into the state oracle.
        Ok(Proof(Vec::new()))
    }

    fn split(&mut self) -> Self {
        Self
    }
}

type Proven = Transaction<Signature, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

fn serialized<T: serialize::Tagged + serialize::Serializable>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    tagged_serialize(value, &mut bytes).expect("oracle value must serialize");
    bytes
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(persistent_hash(bytes).0)
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn close_exact(
    state: &LedgerState<InMemoryDB>,
    tblock: Timestamp,
    cost: SyntheticCost,
) -> LedgerState<InMemoryDB> {
    let limits = state.parameters.limits.block_limits;
    let normalized = SyntheticCost {
        read_time: cost.read_time.min(limits.read_time),
        compute_time: cost.compute_time.min(limits.compute_time),
        block_usage: cost.block_usage.min(limits.block_usage),
        bytes_written: cost.bytes_written.min(limits.bytes_written),
        bytes_churned: cost.bytes_churned.min(limits.bytes_churned),
    }
    .normalize(limits)
    .expect("clamped cost must normalize");
    let overall = FixedPoint::max(
        FixedPoint::max(
            FixedPoint::max(normalized.read_time, normalized.compute_time),
            normalized.block_usage,
        ),
        FixedPoint::max(normalized.bytes_written, normalized.bytes_churned),
    );
    state
        .post_block_update(tblock, normalized, overall)
        .expect("fixture must close")
}

fn apply(
    prestate: &LedgerState<InMemoryDB>,
    tx: &Proven,
    parent_time: u64,
) -> (LedgerState<InMemoryDB>, &'static str, String, String) {
    let tblock = Timestamp::from_secs(BLOCK_TIME);
    let mut strictness = WellFormedStrictness::default();
    strictness.enforce_balancing = false;
    let verified = tx
        .clone()
        .well_formed(prestate, strictness, tblock)
        .expect("fixture transaction must be structurally well formed");
    let context = TransactionContext {
        ref_state: prestate.clone(),
        block_context: BlockContext {
            tblock,
            tblock_err: 30,
            parent_block_hash: persistent_hash(b"parent-time-dust-oracle-parent"),
            last_block_time: Timestamp::from_secs(parent_time),
        },
        whitelist: None,
    };
    let (applied, result) = prestate.apply(&verified, &context);
    let (label, cost) = match result {
        TransactionResult::Success(_) => (
            "success",
            tx.cost(&prestate.parameters, false)
                .expect("fixture transaction must have a cost"),
        ),
        TransactionResult::PartialSuccess(_, _) => panic!("fixture must not partially succeed"),
        TransactionResult::Failure(_) => ("failure", SyntheticCost::ZERO),
    };
    let closed = close_exact(&applied, tblock, cost);
    let dust_hash = sha256(&serialized(&*closed.dust));
    let state_hash = sha256(&serialized(&closed));
    (closed, label, dust_hash, state_hash)
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x5031_4455_5354);

    let operation = ContractOperation::new(None);
    let contract = ContractState::new(
        StateValue::Null,
        HashMap::new().insert(
            EntryPointBuf(b"require-parent-time".to_vec()),
            operation.clone(),
        ),
        Default::default(),
    );
    let deploy = ContractDeploy::new(&mut rng, contract.clone());
    let address = deploy.address();
    let mut prestate = LedgerState::new(NETWORK);
    prestate.contract = prestate.contract.insert(address, contract.clone());

    let mut query_context = QueryContext::new(contract.data.clone(), address);
    query_context.call_context.last_block_time = Timestamp::from_secs(PARENT_TIME);
    let program: Vec<Op<ResultModeVerify, InMemoryDB>> = vec![
        op!(dup 2),
        op!(idx[7u8]),
        op!(popeq AlignedValue::from(PARENT_TIME)),
    ];
    let (guaranteed, fallible): (Option<Transcript<_>>, Option<Transcript<_>>) =
        partition_transcripts(
            &[PreTranscript {
                context: query_context,
                program,
                comm_comm: None,
            }],
            &prestate.parameters,
        )
        .expect("parent-time program must partition")[0]
            .clone();
    assert!(
        guaranteed.is_some(),
        "parent-time assertion must be guaranteed"
    );
    assert!(
        fallible.is_none(),
        "parent-time assertion must not become fallible"
    );

    let call = ContractCallPrototype {
        address,
        entry_point: EntryPointBuf(b"require-parent-time".to_vec()),
        op: operation,
        guaranteed_public_transcript: guaranteed,
        fallible_public_transcript: fallible,
        private_transcript_outputs: Vec::new(),
        input: ().into(),
        output: ().into(),
        communication_commitment_rand: rng.r#gen(),
        key_location: KeyLocation(Cow::Borrowed("parent-time-dust-oracle")),
    };

    let night_key = SigningKey::sample(&mut rng);
    let dust_key = DustSecretKey::sample(&mut rng);
    let dust_actions = DustActions {
        spends: Vec::new().into(),
        registrations: vec![DustRegistration {
            allow_fee_payment: 0,
            dust_address: Some(Sp::new(DustPublicKey::from(dust_key))),
            night_key: night_key.verifying_key(),
            signature: None,
        }]
        .into(),
        ctime: Timestamp::from_secs(BLOCK_TIME),
    };
    let intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>::new(
        &mut rng,
        None,
        None,
        vec![call],
        Vec::new(),
        Vec::new(),
        Some(dust_actions),
        Timestamp::from_secs(BLOCK_TIME + 600),
    )
    .sign(&mut rng, 1, &[], &[], &[night_key])
    .expect("dust registration must sign");
    let unproven = Transaction::from_intents(NETWORK, HashMap::new().insert(1, intent));
    let tx: Proven = block_on(unproven.prove(
        StructuralProof,
        &onchain_runtime::cost_model::INITIAL_COST_MODEL,
    ))
    .expect("structural proof assembly must succeed")
    .seal(rng.split());

    let (_, node_outcome, node_dust_hash, node_state_hash) = apply(&prestate, &tx, PARENT_TIME);
    // The indexer initializes its in-process cursor to zero and substitutes the CURRENT block time
    // on the first block after restart. That is the counterweight, not literal time zero.
    let (_, sentinel_outcome, sentinel_dust_hash, sentinel_state_hash) =
        apply(&prestate, &tx, BLOCK_TIME);

    assert_eq!(node_outcome, "success");
    assert_eq!(sentinel_outcome, "failure");
    assert_ne!(node_dust_hash, sentinel_dust_hash);
    assert_ne!(node_state_hash, sentinel_state_hash);

    println!("prestate_hex={}", hex::encode(serialized(&prestate)));
    println!("transaction_hex={}", hex::encode(serialized(&tx)));
    println!(
        "parent_hash={}",
        hex::encode(persistent_hash(b"parent-time-dust-oracle-parent").0)
    );
    println!("block_timestamp_ms={}", BLOCK_TIME * 1000);
    println!("node_parent_timestamp_ms={}", PARENT_TIME * 1000);
    println!("sentinel_parent_timestamp_ms={}", BLOCK_TIME * 1000);
    println!("node_outcome={node_outcome}");
    println!("sentinel_outcome={sentinel_outcome}");
    println!("node_dust_hash={node_dust_hash}");
    println!("sentinel_dust_hash={sentinel_dust_hash}");
    println!("node_state_hash={node_state_hash}");
    println!("sentinel_state_hash={sentinel_state_hash}");
}
