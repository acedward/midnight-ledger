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

use crate::conversions::*;
use crate::dust::{DustState, UtxoMeta};
use crate::events::Event;
use crate::onchain_runtime::{ContractState, value_to_token_type};
use crate::tx::{SystemTransaction, TransactionContext, TransactionResult, VerifiedTransaction};
use crate::zswap_state::*;
use crate::zswap_wasm::*;
use base_crypto::cost_model::{FixedPoint, NormalizedCost, SyntheticCost};
use base_crypto::time::Timestamp;
use coin_structure::coin::UserAddress;
use js_sys::{Array, BigInt, Date, Function, Map, Set, Uint8Array};
use ledger::structure::{ClaimKind, OutputInstructionUnshielded};
use onchain_runtime_wasm::from_value_ser;
use onchain_runtime_wasm::state::ChargedState;
use rand::Rng;
use rand::rngs::OsRng;
use serialize::tagged_serialize;
use storage::arena::Sp;
use storage::db::InMemoryDB;
use storage::storage::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct LedgerState(pub(crate) ledger::structure::LedgerState<InMemoryDB>);

fn clamp_and_normalize_block_cost(cost: SyntheticCost, limits: SyntheticCost) -> NormalizedCost {
    SyntheticCost {
        read_time: cost.read_time.min(limits.read_time),
        compute_time: cost.compute_time.min(limits.compute_time),
        block_usage: cost.block_usage.min(limits.block_usage),
        bytes_written: cost.bytes_written.min(limits.bytes_written),
        bytes_churned: cost.bytes_churned.min(limits.bytes_churned),
    }
    .normalize(limits)
    .expect("a cost clamped to valid ledger block limits must normalize")
}

fn overall_block_fullness(normalized: &NormalizedCost) -> FixedPoint {
    FixedPoint::max(
        FixedPoint::max(
            FixedPoint::max(normalized.read_time, normalized.compute_time),
            normalized.block_usage,
        ),
        FixedPoint::max(normalized.bytes_written, normalized.bytes_churned),
    )
}

fn close_block_exact(
    state: &ledger::structure::LedgerState<InMemoryDB>,
    tblock: Timestamp,
    accumulated_cost: SyntheticCost,
) -> Result<ledger::structure::LedgerState<InMemoryDB>, ledger::error::BlockLimitExceeded> {
    let normalized =
        clamp_and_normalize_block_cost(accumulated_cost, state.parameters.limits.block_limits);
    state.post_block_update(tblock, normalized, overall_block_fullness(&normalized))
}

#[wasm_bindgen]
impl LedgerState {
    #[wasm_bindgen(constructor)]
    pub fn new(network_id: String, zswap: &ZswapChainState) -> LedgerState {
        let mut res = Self::blank(network_id);
        res.0.zswap = Sp::new(zswap.clone().into());
        res
    }

    pub fn blank(network_id: String) -> LedgerState {
        LedgerState(ledger::structure::LedgerState::new(network_id))
    }

    #[wasm_bindgen(getter)]
    pub fn parameters(&self) -> LedgerParameters {
        (*self.0.parameters).clone().into()
    }

    #[wasm_bindgen(setter = parameters)]
    pub fn set_parameters(&mut self, params: &LedgerParameters) {
        self.0.parameters = Sp::new(params.clone().into());
    }

    #[wasm_bindgen(js_name = "postBlockUpdate")]
    pub fn post_block_update(
        &self,
        tblock: &Date,
        detailed_fullness: JsValue,
        overall_fullness: JsValue,
    ) -> Result<LedgerState, JsError> {
        let detailed_fullness = if detailed_fullness.is_null() || detailed_fullness.is_undefined() {
            NormalizedCost::ZERO
        } else {
            from_value(detailed_fullness)?
        };
        let overall_fullness = if overall_fullness.is_null() || overall_fullness.is_undefined() {
            FixedPoint::from_u64_div(1, 2)
        } else if let Some(f) = overall_fullness.as_f64() {
            FixedPoint::from(f)
        } else {
            return Err(JsError::new(
                "expected number or undefined for overall fullness",
            ));
        };
        Ok(LedgerState(self.0.post_block_update(
            Timestamp::from_secs(js_date_to_seconds(tblock)),
            detailed_fullness,
            overall_fullness,
        )?))
    }

    /// Closes a block from its accumulated raw synthetic cost without exposing normalized Q64
    /// fixed-point values to JavaScript.
    ///
    /// The active block limits come from this state, after all transactions in the block have
    /// applied. Clamping, normalization, max-of-five selection, and `post_block_update` all run in
    /// Rust so no fullness value crosses the lossy JavaScript `f64` boundary.
    #[wasm_bindgen(js_name = "closeBlock")]
    pub fn close_block(
        &self,
        tblock: &Date,
        accumulated_cost: JsValue,
    ) -> Result<LedgerState, JsError> {
        let accumulated_cost: SyntheticCost = from_value(accumulated_cost)?;
        Ok(LedgerState(close_block_exact(
            &self.0,
            Timestamp::from_secs(js_date_to_seconds(tblock)),
            accumulated_cost,
        )?))
    }

    #[wasm_bindgen(js_name = treasuryBalance)]
    pub fn treasury_balance(&self, token_type: JsValue) -> Result<BigInt, JsError> {
        let token_type = value_to_token_type(token_type)?;
        Ok(self
            .0
            .treasury
            .get(&token_type)
            .copied()
            .unwrap_or(0)
            .into())
    }

    #[wasm_bindgen(js_name = bridgeReceiving)]
    pub fn bridge_receiving(&self, recipient: &str) -> Result<BigInt, JsError> {
        let recipient: UserAddress = from_hex_ser(recipient)?;
        Ok(self
            .0
            .bridge_receiving
            .get(&recipient)
            .copied()
            .unwrap_or(0)
            .into())
    }

    #[wasm_bindgen(getter = lockedPool)]
    pub fn locked_pool(&self) -> BigInt {
        self.0.locked_pool.into()
    }

    #[wasm_bindgen(getter = reservePool)]
    pub fn reserve_pool(&self) -> BigInt {
        self.0.reserve_pool.into()
    }

    #[wasm_bindgen(js_name = unclaimedBlockRewards)]
    pub fn unclaimed_block_rewards(&self, recipient: &str) -> Result<BigInt, JsError> {
        let recipient: UserAddress = from_hex_ser(recipient)?;
        Ok(self
            .0
            .unclaimed_block_rewards
            .get(&recipient)
            .copied()
            .unwrap_or(0)
            .into())
    }

    #[wasm_bindgen(getter = blockRewardPool)]
    pub fn block_reward_pool(&self) -> BigInt {
        self.0.block_reward_pool.into()
    }

    #[wasm_bindgen(getter)]
    pub fn zswap(&self) -> ZswapChainState {
        (*self.0.zswap).clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn utxo(&self) -> UtxoState {
        (*self.0.utxo).clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn dust(&self) -> DustState {
        DustState((*self.0.dust).clone())
    }

    pub fn apply(
        &self,
        transaction: &VerifiedTransaction,
        context: &TransactionContext,
    ) -> JsValue {
        let (next_state, result) = self.0.apply(&transaction.0, &context.0);
        let res = Array::new();
        res.push(&JsValue::from(LedgerState(next_state)));
        res.push(&JsValue::from(TransactionResult(result)));
        res.into()
    }

    #[wasm_bindgen(js_name = "applySystemTx")]
    pub fn apply_system_tx(&self, tx: &SystemTransaction, tblock: &Date) -> Result<Array, JsError> {
        let (state, events) = self.0.apply_system_tx(
            tx.as_ref(),
            Timestamp::from_secs(js_date_to_seconds(tblock)),
        )?;
        let events: Vec<_> = events.into_iter().map(Event::from).collect();

        let tuple = Array::new();
        tuple.push(&JsValue::from(LedgerState(state)));
        tuple.push(&JsValue::from(events));

        Ok(tuple)
    }

    pub fn index(&self, address: &str) -> Result<Option<ContractState>, JsError> {
        Ok(self.0.index(from_hex_ser(address)?).map(Into::into))
    }

    #[wasm_bindgen(js_name = "updateIndex")]
    pub fn update_index(
        &self,
        address: &str,
        state: &ChargedState,
        balances_map: Map,
    ) -> Result<LedgerState, JsError> {
        let mut balances = HashMap::new();
        for key in balances_map.keys() {
            let key = key.unwrap();
            let value = balances_map.get(&key);
            let token_type = value_to_token_type(key)?;
            balances = balances.insert(token_type, from_value(value)?);
        }
        let mut new_state = self.0.clone();
        new_state = new_state.update_index(from_hex_ser(address)?, state.clone().into(), balances);
        Ok(LedgerState(new_state))
    }

    pub fn serialize(&self) -> Result<Uint8Array, JsError> {
        let mut res = Vec::new();
        tagged_serialize(&self.0, &mut res)?;
        Ok(Uint8Array::from(&res[..]))
    }

    pub fn deserialize(raw: Uint8Array) -> Result<LedgerState, JsError> {
        Ok(LedgerState(from_value_ser(raw, "LedgerState")?))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self, compact: Option<bool>) -> String {
        if compact.unwrap_or(false) {
            format!("{:?}", &self.0)
        } else {
            format!("{:#?}", &self.0)
        }
    }

    #[wasm_bindgen(js_name = "testingDistributeNight")]
    pub fn distribute_night(
        &self,
        user_address: &str,
        amount: BigInt,
        tblock: &Date,
    ) -> Result<LedgerState, JsError> {
        let address: UserAddress = from_hex_ser(user_address)?;
        let amount = u128::try_from(amount).map_err(|_| JsError::new("amount is out of range"))?;
        let sys_tx_distribute = ledger::structure::SystemTransaction::DistributeReserve(amount);
        let time = Timestamp::from_secs(js_date_to_seconds(tblock));
        let (ledger, _) = self.0.apply_system_tx(&sys_tx_distribute, time)?;

        let sys_tx_rewards = ledger::structure::SystemTransaction::DistributeNight(
            ClaimKind::Reward,
            vec![OutputInstructionUnshielded {
                amount,
                target_address: address,
                nonce: OsRng.r#gen(),
            }],
        );
        let (ledger, _) = ledger.apply_system_tx(&sys_tx_rewards, time)?;

        Ok(LedgerState(ledger))
    }
}

#[cfg(test)]
mod exact_close_tests {
    use super::{close_block_exact, overall_block_fullness};
    use base_crypto::cost_model::{CostDuration, FixedPoint, NormalizedCost, SyntheticCost};
    use base_crypto::hash::persistent_hash;
    use base_crypto::time::Timestamp;
    use ledger::structure::{LedgerState, SystemTransaction};
    use serialize::{tagged_deserialize, tagged_serialize};
    use storage::db::InMemoryDB;

    const NATIVE_ORACLES: &str = include_str!("../verification/native-close-block-oracles.txt");

    fn expected_hash(label: &str, kind: &str) -> &'static str {
        NATIVE_ORACLES
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                if fields.next()? == label {
                    let native = fields.next()?;
                    let rounded = fields.next()?;
                    Some(match kind {
                        "native" => native,
                        "rounded" => rounded,
                        _ => panic!("unknown oracle kind: {kind}"),
                    })
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("missing close-block oracle fixture: {label}"))
    }

    fn serialized(state: &LedgerState<InMemoryDB>) -> Vec<u8> {
        let mut bytes = Vec::new();
        tagged_serialize(state, &mut bytes).expect("test state must serialize");
        bytes
    }

    fn state_hash(state: &LedgerState<InMemoryDB>) -> String {
        format!("{:?}", persistent_hash(&serialized(state)))
    }

    fn fixture_system_transactions() -> Vec<SystemTransaction> {
        include_str!("../verification/indexer-ground-truth.txt")
            .lines()
            .map(|line| {
                let raw_hex = line
                    .split_whitespace()
                    .nth(3)
                    .expect("each oracle row must contain raw transaction bytes");
                let raw = hex::decode(raw_hex).expect("oracle transaction hex must decode");
                tagged_deserialize(raw.as_slice())
                    .expect("oracle transaction bytes must deserialize natively")
            })
            .collect()
    }

    fn genesis_pre_close_state() -> (LedgerState<InMemoryDB>, SyntheticCost) {
        let tblock = Timestamp::from_secs(0);
        let mut state = LedgerState::<InMemoryDB>::new("undeployed");
        let mut accumulated = SyntheticCost::ZERO;

        for tx in fixture_system_transactions() {
            accumulated = accumulated + tx.cost(&state.parameters);
            let (next_state, _) = state
                .apply_system_tx(&tx, tblock)
                .expect("the native genesis system transaction must apply");
            state = next_state;
        }

        (state, accumulated)
    }

    fn through_f64(value: FixedPoint) -> FixedPoint {
        FixedPoint::from(f64::from(value))
    }

    #[derive(Clone, Copy, Debug)]
    enum CostDimension {
        ReadTime,
        ComputeTime,
        BlockUsage,
        BytesWritten,
        BytesChurned,
    }

    impl CostDimension {
        fn index(self) -> usize {
            match self {
                Self::ReadTime => 0,
                Self::ComputeTime => 1,
                Self::BlockUsage => 2,
                Self::BytesWritten => 3,
                Self::BytesChurned => 4,
            }
        }
    }

    fn synthetic_dimension_cost(limits: SyntheticCost, dominant: CostDimension) -> SyntheticCost {
        let mut accumulated = SyntheticCost {
            read_time: limits.read_time / 5,
            compute_time: limits.compute_time / 5,
            block_usage: limits.block_usage / 5,
            bytes_written: limits.bytes_written / 5,
            bytes_churned: limits.bytes_churned / 5,
        };
        match dominant {
            CostDimension::ReadTime => {
                accumulated.read_time = limits.read_time + CostDuration::from_picoseconds(1)
            }
            CostDimension::ComputeTime => {
                accumulated.compute_time = limits.compute_time + CostDuration::from_picoseconds(1)
            }
            CostDimension::BlockUsage => accumulated.block_usage = limits.block_usage + 1,
            CostDimension::BytesWritten => accumulated.bytes_written = limits.bytes_written + 1,
            CostDimension::BytesChurned => accumulated.bytes_churned = limits.bytes_churned + 1,
        }
        accumulated
    }

    fn assert_dimension_vector(label: &str, dominant: CostDimension) {
        let state = LedgerState::<InMemoryDB>::new("local-test");
        let limits = state.parameters.limits.block_limits;
        let accumulated = synthetic_dimension_cost(limits, dominant);
        let tblock = Timestamp::from_secs(1_700_000_100);

        let over_limit = [
            accumulated.read_time > limits.read_time,
            accumulated.compute_time > limits.compute_time,
            accumulated.block_usage > limits.block_usage,
            accumulated.bytes_written > limits.bytes_written,
            accumulated.bytes_churned > limits.bytes_churned,
        ];
        assert_eq!(over_limit.into_iter().filter(|is_over| *is_over).count(), 1);
        assert!(over_limit[dominant.index()]);
        assert!(accumulated.normalize(limits).is_none());

        // Assemble the oracle without either production helper. Every field is clamped here,
        // normalization is invoked directly, and the five-way maximum is taken independently.
        let clamped = SyntheticCost {
            read_time: accumulated.read_time.min(limits.read_time),
            compute_time: accumulated.compute_time.min(limits.compute_time),
            block_usage: accumulated.block_usage.min(limits.block_usage),
            bytes_written: accumulated.bytes_written.min(limits.bytes_written),
            bytes_churned: accumulated.bytes_churned.min(limits.bytes_churned),
        };
        let normalized = clamped
            .normalize(limits)
            .expect("the independently clamped dimension vector must normalize");
        let normalized_values = [
            normalized.read_time,
            normalized.compute_time,
            normalized.block_usage,
            normalized.bytes_written,
            normalized.bytes_churned,
        ];
        let oracle_overall = normalized_values
            .into_iter()
            .max()
            .expect("the five cost dimensions are non-empty");
        assert_eq!(normalized_values[dominant.index()], FixedPoint::ONE);
        for (index, value) in normalized_values.into_iter().enumerate() {
            if index != dominant.index() {
                assert!(
                    value < normalized_values[dominant.index()],
                    "{dominant:?} must be strictly dominant over dimension {index}"
                );
            }
        }

        let oracle = state
            .post_block_update(tblock, normalized, oracle_overall)
            .expect("the independent native dimension oracle close must succeed");
        let exact = close_block_exact(&state, tblock, accumulated)
            .expect("the atomic dimension-vector close must succeed");
        assert_eq!(serialized(&exact), serialized(&oracle));

        let rounded = NormalizedCost {
            read_time: through_f64(normalized.read_time),
            compute_time: through_f64(normalized.compute_time),
            block_usage: through_f64(normalized.block_usage),
            bytes_written: through_f64(normalized.bytes_written),
            bytes_churned: through_f64(normalized.bytes_churned),
        };
        assert_ne!(
            rounded, normalized,
            "the dimension vector must expose Q64 precision loss"
        );
        let rounded_overall = [
            rounded.read_time,
            rounded.compute_time,
            rounded.block_usage,
            rounded.bytes_written,
            rounded.bytes_churned,
        ]
        .into_iter()
        .max()
        .expect("the five rounded dimensions are non-empty");
        let rounded_state = state
            .post_block_update(tblock, rounded, rounded_overall)
            .expect("the rounded dimension counterweight must remain valid");
        assert_ne!(serialized(&exact), serialized(&rounded_state));

        let native_hash = state_hash(&oracle);
        let rounded_hash = state_hash(&rounded_state);
        println!("{label} {native_hash} {rounded_hash}");
        assert_eq!(native_hash, expected_hash(label, "native"));
        assert_eq!(rounded_hash, expected_hash(label, "rounded"));
    }

    #[test]
    fn close_block_matches_the_native_oracle_without_a_float_round_trip() {
        let tblock = Timestamp::from_secs(0);
        let (state, accumulated) = genesis_pre_close_state();
        let limits = state.parameters.limits.block_limits;

        // Assemble the node's oracle independently from the exported helper. In particular, the
        // clamp and max expressions are repeated here so a shared helper cannot make both sides
        // agree on the same wrong implementation.
        let clamped = SyntheticCost {
            read_time: accumulated.read_time.min(limits.read_time),
            compute_time: accumulated.compute_time.min(limits.compute_time),
            block_usage: accumulated.block_usage.min(limits.block_usage),
            bytes_written: accumulated.bytes_written.min(limits.bytes_written),
            bytes_churned: accumulated.bytes_churned.min(limits.bytes_churned),
        };
        let normalized = clamped
            .normalize(limits)
            .expect("the independently clamped oracle vector must normalize");
        let oracle_overall = [
            normalized.read_time,
            normalized.compute_time,
            normalized.block_usage,
            normalized.bytes_written,
            normalized.bytes_churned,
        ]
        .into_iter()
        .max()
        .expect("the five cost dimensions are non-empty");
        let oracle = state
            .post_block_update(tblock, normalized, oracle_overall)
            .expect("the native oracle close must succeed");
        let exact = close_block_exact(&state, tblock, accumulated)
            .expect("the exact binding close must succeed");

        assert_eq!(serialized(&exact), serialized(&oracle));

        let rounded = NormalizedCost {
            read_time: through_f64(normalized.read_time),
            compute_time: through_f64(normalized.compute_time),
            block_usage: through_f64(normalized.block_usage),
            bytes_written: through_f64(normalized.bytes_written),
            bytes_churned: through_f64(normalized.bytes_churned),
        };
        assert_ne!(
            rounded, normalized,
            "the oracle vector must expose Q64 precision loss"
        );
        let rounded_state = state
            .post_block_update(tblock, rounded, overall_block_fullness(&rounded))
            .expect("the rounded comparison close must remain valid");
        assert_ne!(serialized(&exact), serialized(&rounded_state));

        assert_eq!(
            state_hash(&oracle),
            expected_hash("genesis-system-transactions", "native"),
            "the expected state must stay pinned to the independently assembled native fold"
        );
        assert_eq!(
            state_hash(&rounded_state),
            expected_hash("genesis-system-transactions", "rounded"),
            "the counterweight must keep proving that this vector exposes the f64 path"
        );

        // A WASM expectation built through `clampAndNormalizeFullness` and `postBlockUpdate`
        // would repeat the lossy path on both sides. The independent native fold plus the required
        // rounded-state inequality closes that committed-oracle trap.
    }

    #[test]
    fn close_block_clamps_overlimit_cost_inside_the_atomic_operation() {
        let state = LedgerState::<InMemoryDB>::new("local-test");
        let limits = state.parameters.limits.block_limits;
        let accumulated = SyntheticCost {
            read_time: limits.read_time + CostDuration::from_picoseconds(1),
            compute_time: limits.compute_time / 5,
            block_usage: limits.block_usage / 3,
            bytes_written: limits.bytes_written / 11,
            bytes_churned: limits.bytes_churned / 13,
        };
        let tblock = Timestamp::from_secs(1_700_000_000);

        // This is deliberately independent of `clamp_and_normalize_block_cost`: omitting the
        // clamp from the export must either fail or produce bytes different from this oracle.
        let clamped = SyntheticCost {
            read_time: accumulated.read_time.min(limits.read_time),
            compute_time: accumulated.compute_time.min(limits.compute_time),
            block_usage: accumulated.block_usage.min(limits.block_usage),
            bytes_written: accumulated.bytes_written.min(limits.bytes_written),
            bytes_churned: accumulated.bytes_churned.min(limits.bytes_churned),
        };
        assert!(accumulated.normalize(limits).is_none());
        let normalized = clamped
            .normalize(limits)
            .expect("the independently clamped oracle must normalize");
        let oracle_overall = [
            normalized.read_time,
            normalized.compute_time,
            normalized.block_usage,
            normalized.bytes_written,
            normalized.bytes_churned,
        ]
        .into_iter()
        .max()
        .expect("the five cost dimensions are non-empty");
        let oracle = state
            .post_block_update(tblock, normalized, oracle_overall)
            .expect("the native overlimit oracle close must succeed");
        let exact = close_block_exact(&state, tblock, accumulated)
            .expect("the atomic close must clamp rather than reject overlimit cost");

        let rounded = NormalizedCost {
            read_time: through_f64(normalized.read_time),
            compute_time: through_f64(normalized.compute_time),
            block_usage: through_f64(normalized.block_usage),
            bytes_written: through_f64(normalized.bytes_written),
            bytes_churned: through_f64(normalized.bytes_churned),
        };
        let rounded_state = state
            .post_block_update(tblock, rounded, overall_block_fullness(&rounded))
            .expect("the rounded overlimit comparison must remain valid");

        assert_eq!(serialized(&exact), serialized(&oracle));
        assert_ne!(serialized(&exact), serialized(&rounded_state));
        assert_eq!(
            state_hash(&oracle),
            expected_hash("synthetic-overlimit-q64", "native")
        );
        assert_eq!(
            state_hash(&rounded_state),
            expected_hash("synthetic-overlimit-q64", "rounded")
        );
    }

    #[test]
    fn close_block_covers_read_time_as_the_only_overlimit_dominant_dimension() {
        assert_dimension_vector("synthetic-dominant-read-time", CostDimension::ReadTime);
    }

    #[test]
    fn close_block_covers_compute_time_as_the_only_overlimit_dominant_dimension() {
        assert_dimension_vector(
            "synthetic-dominant-compute-time",
            CostDimension::ComputeTime,
        );
    }

    #[test]
    fn close_block_covers_block_usage_as_the_only_overlimit_dominant_dimension() {
        assert_dimension_vector("synthetic-dominant-block-usage", CostDimension::BlockUsage);
    }

    #[test]
    fn close_block_covers_bytes_written_as_the_only_overlimit_dominant_dimension() {
        assert_dimension_vector(
            "synthetic-dominant-bytes-written",
            CostDimension::BytesWritten,
        );
    }

    #[test]
    fn close_block_covers_bytes_churned_as_the_only_overlimit_dominant_dimension() {
        assert_dimension_vector(
            "synthetic-dominant-bytes-churned",
            CostDimension::BytesChurned,
        );
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct UtxoState(pub(crate) ledger::structure::UtxoState<InMemoryDB>);

impl From<ledger::structure::UtxoState<InMemoryDB>> for UtxoState {
    fn from(state: ledger::structure::UtxoState<InMemoryDB>) -> UtxoState {
        UtxoState(state)
    }
}

impl From<UtxoState> for ledger::structure::UtxoState<InMemoryDB> {
    fn from(state: UtxoState) -> ledger::structure::UtxoState<InMemoryDB> {
        state.0
    }
}

#[wasm_bindgen]
impl UtxoState {
    // Map<Utxo, UtxoMeta>
    pub fn new(utxo_map: Map) -> Result<Self, JsError> {
        let mut storage_utxos = HashMap::new();
        for key in utxo_map.keys() {
            let key = key.unwrap();
            let value = utxo_map.get(&key);
            let utxo = value_to_utxo(key).map_err(|_| JsError::new("unable to decode UTXO"))?;
            let meta = value_to_utxo_meta(value)
                .map_err(|_| JsError::new("unable to decode UTXO Meta"))?;

            storage_utxos = storage_utxos.insert(utxo, meta);
        }
        Ok(UtxoState(ledger::structure::UtxoState::<InMemoryDB> {
            utxos: storage_utxos,
        }))
    }

    #[wasm_bindgen(js_name = "lookupMeta")]
    pub fn lookup_meta(&self, utxo: JsValue) -> Result<Option<UtxoMeta>, JsError> {
        let utxo = value_to_utxo(utxo)?;
        let meta = self
            .0
            .utxos
            .get(&utxo)
            .map(|utxo| UtxoMeta((*utxo).clone()));
        Ok(meta)
    }

    #[wasm_bindgen(getter)]
    // Set<Utxo>
    pub fn utxos(&self) -> Result<Set, JsError> {
        let res = Set::new(&JsValue::NULL);
        for utxo in self.0.utxos.iter() {
            let utxo = &*utxo.0;
            res.add(&utxo_to_value(utxo)?);
        }
        Ok(res)
    }

    // Set<Utxo>
    pub fn filter(&self, user_address: &str) -> Result<Set, JsError> {
        let address: UserAddress = from_hex_ser(user_address)?;
        let res = Set::new(&JsValue::NULL);
        for utxo in self.0.utxos.iter() {
            let utxo = &*utxo.0;
            if utxo.owner == address {
                res.add(&utxo_to_value(utxo)?);
            }
        }
        Ok(res)
    }

    // delta(prior: UtxoState<D>, filterBy?: (utxo: Utxo) => boolean): [Set<Utxo>, Set<Utxo>]
    pub fn delta(&self, prior: &Self, filter_by: Option<Function>) -> Result<Array, JsError> {
        let this_minus_prior = Set::new(&JsValue::NULL);
        let prior_minus_this = Set::new(&JsValue::NULL);

        for utxo in self.0.utxos.iter() {
            let utxo = &*utxo.0;
            let is_member = prior.0.utxos.contains_key(utxo);
            if !is_member {
                let js_value = utxo_to_value(utxo)?;
                let mut accepted = true;

                if let Some(filter_by) = filter_by.clone() {
                    let resp = filter_by
                        .call1(&JsValue::NULL, &js_value)
                        .map_err(|_| JsError::new("callback error"))?;

                    let r = resp
                        .as_bool()
                        .ok_or(JsError::new("non boolean received from the callback"))?;
                    accepted = r;
                }

                if accepted {
                    this_minus_prior.add(&js_value);
                }
            }
        }
        for utxo in prior.0.utxos.iter() {
            let utxo = &*utxo.0;
            let is_member = self.0.utxos.contains_key(utxo);
            if !is_member {
                let js_value = utxo_to_value(utxo)?;
                let mut accepted = true;

                if let Some(filter_by) = filter_by.clone() {
                    let resp = filter_by
                        .call1(&JsValue::NULL, &js_value)
                        .map_err(|_| JsError::new("callback error"))?;

                    let r = resp
                        .as_bool()
                        .ok_or(JsError::new("non boolean received from the callback"))?;
                    accepted = r;
                }

                if accepted {
                    prior_minus_this.add(&utxo_to_value(utxo)?);
                }
            }
        }

        let tuple = Array::new();
        tuple.push(&this_minus_prior);
        tuple.push(&prior_minus_this);
        Ok(tuple)
    }
}
