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

use crate::ZSWAP_TREE_HEIGHT;
use crate::error::MalformedOffer;
use coin_structure::coin::{
    Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey, ShieldedTokenType,
    TokenType, UnshieldedTokenType,
};
use coin_structure::contract::ContractAddress;
use derive_where::derive_where;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::Serialize;
use serialize::{Deserializable, Serializable, Tagged, tag_enforcement_test};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::ops::{Add, Sub};
use std::sync::Arc;
use storage::Storable;
use storage::arena::Sp;
use storage::arena::{ArenaHash, ArenaKey};
use storage::db::DB;
#[cfg(test)]
use storage::db::InMemoryDB;
use storage::storable::Loader;
use storage::storage::Array;
use transient_crypto::commitment::{Pedersen, PedersenRandomness};
use transient_crypto::curve::{EmbeddedGroupAffine, Fr};
use transient_crypto::encryption;
use transient_crypto::merkle_tree::{MerkleTree, MerkleTreeDigest};
use transient_crypto::proofs::ProofPreimage;
use transient_crypto::repr::{FieldRepr, FromFieldRepr};

macro_rules! exptfile {
    ($name:literal, $desc:literal) => {
        (
            concat!("zswap/", midnight_ledger_static::version!(), "/", $name),
            base_crypto::data_provider::hexhash(
                &include_bytes!(concat!("../static/", $name, ".sha256"))
                    .split_at(64)
                    .0,
            ),
            $desc,
        )
    };
}

/// Files provided by Midnight's data provider for Zswap.
pub const ZSWAP_EXPECTED_FILES: &[(&str, [u8; 32], &str)] = &[
    exptfile!(
        "spend.prover",
        "zero-knowledge proving key for Zswap inputs"
    ),
    exptfile!(
        "spend.verifier",
        "zero-knowledge verifying key for Zswap inputs"
    ),
    exptfile!("spend.bzkir", "ZKIR source for Zswap inputs"),
    exptfile!(
        "output.prover",
        "zero-knowledge proving key for Zswap outputs"
    ),
    exptfile!(
        "output.verifier",
        "zero-knowledge verifying key for Zswap outputs"
    ),
    exptfile!("output.bzkir", "ZKIR source for Zswap outputs"),
    exptfile!(
        "sign.prover",
        "zero-knowledge proving key for Zswap signing operations"
    ),
    exptfile!(
        "sign.verifier",
        "zero-knowledge verifying key for Zswap signing operations"
    ),
    exptfile!("sign.bzkir", "ZKIR source for Zswap signing operations"),
];

pub(crate) const COIN_CIPHERTEXT_LEN: usize = 6;
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Storable)]
#[storable(base)]
pub struct CoinCiphertext {
    pub c: EmbeddedGroupAffine,
    pub ciph: [Fr; COIN_CIPHERTEXT_LEN],
}

impl Tagged for CoinCiphertext {
    fn tag() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("zswap-coin-ciphertext[v1]")
    }
    fn tag_unique_factor() -> String {
        format!("(embedded-group-affine[v1],array(fr-bls,{COIN_CIPHERTEXT_LEN}))")
    }
}
tag_enforcement_test!(CoinCiphertext);

impl Serializable for CoinCiphertext {
    fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        <EmbeddedGroupAffine as Serializable>::serialize(&self.c, writer)?;
        // Because this is unversioned we need not send COIN_CIPHERTEXT_LEN
        for elem in self.ciph {
            <Fr as Serializable>::serialize(&elem, writer)?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        EmbeddedGroupAffine::serialized_size(&self.c)
            + self
                .ciph
                .iter()
                .map(Serializable::serialized_size)
                .sum::<usize>()
    }
}

impl Deserializable for CoinCiphertext {
    fn deserialize(
        reader: &mut impl std::io::Read,
        recursive_depth: u32,
    ) -> Result<Self, std::io::Error> {
        let c = EmbeddedGroupAffine::deserialize(reader, recursive_depth)?;
        // See note in `transient_crypto::encryption::SecretKey::decrypt` for why the identity
        // element is excluded.
        if c.is_identity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ciphertext challenge may not be the point at infinity",
            ));
        };
        let ciph = {
            let mut res = [Fr::default(); COIN_CIPHERTEXT_LEN];
            for byte in res.iter_mut() {
                *byte = Fr::deserialize(reader, recursive_depth)?;
            }
            res
        };
        Ok(Self { c, ciph })
    }
}

impl CoinCiphertext {
    pub fn new<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
        coin: &CoinInfo,
        pk: encryption::PublicKey,
    ) -> CoinCiphertext {
        pk.encrypt(rng, coin)
            .try_into()
            .expect("ciphertext should have ciphertext length")
    }
}

impl TryFrom<encryption::Ciphertext> for CoinCiphertext {
    type Error = ();

    fn try_from(ciph: encryption::Ciphertext) -> Result<Self, ()> {
        if ciph.ciph.len() != COIN_CIPHERTEXT_LEN {
            return Err(());
        }
        let mut arr = [0.into(); COIN_CIPHERTEXT_LEN];
        arr.copy_from_slice(&ciph.ciph);
        Ok(CoinCiphertext {
            c: ciph.c,
            ciph: arr,
        })
    }
}

impl From<CoinCiphertext> for encryption::Ciphertext {
    fn from(ciph: CoinCiphertext) -> encryption::Ciphertext {
        encryption::Ciphertext {
            c: ciph.c,
            ciph: ciph.ciph.to_vec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize)]
#[tag = "zswap-authorized-claim[v3]"]
/// A claim to a specific public key, authorized by the user's private key.
pub struct AuthorizedClaim<P> {
    pub coin: CoinInfo,
    pub recipient: CoinPublicKey,
    pub proof: Arc<P>,
}
tag_enforcement_test!(AuthorizedClaim<()>);

impl<P> AuthorizedClaim<P> {
    pub fn erase_proof(&self) -> AuthorizedClaim<()> {
        AuthorizedClaim {
            coin: self.coin,
            recipient: self.recipient,
            proof: Arc::new(()),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-input[v2]"]
#[storable(db = D)]
pub struct Input<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub merkle_tree_root: MerkleTreeDigest,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Input<(), InMemoryDB>);

impl<P> Debug for AuthorizedClaim<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "<claim of {} of token {:?} for recipient {:?}>",
            self.coin.value, self.coin.type_, self.recipient
        )
    }
}

impl<P: Storable<D>, D: DB> Input<P, D> {
    pub fn erase_proof(&self) -> Input<(), D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: self.merkle_tree_root,
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs
        // Input before last is CoinInfo
        let inputs = &self.proof.inputs;
        let coin = CoinInfo::from_field_repr(
            &inputs[inputs.len() - 1 - CoinInfo::FIELD_SIZE..inputs.len() - 1],
        )
        .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs
        // rc is the last input, and should be a single Fr element.
        (*self
            .proof
            .inputs
            .last()
            .expect("must have witness to extract from"))
        .try_into()
        .expect("extracted binding randomness is invalid")
    }
}

impl<P: Storable<D>, D: DB> Debug for Input<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded input {:?} for: {:?}>",
                self.nullifier, addr
            ),
            None => write!(formatter, "<shielded input {:?}>", self.nullifier),
        }
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-output[v2]"]
#[storable(db = D)]
pub struct Output<P: Storable<D>, D: DB> {
    pub coin_com: Commitment,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Output<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Output<P, D> {
    pub fn erase_proof(&self) -> Output<(), D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Output<ProofPreimage, D> {
    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs.
        // Input before last is CoinInfo
        let inputs = &self.proof.inputs;
        let coin = CoinInfo::from_field_repr(
            &inputs[inputs.len() - 1 - CoinInfo::FIELD_SIZE..inputs.len() - 1],
        )
        .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX).saturating_neg(),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs.
        // rc is the last input, and should be a single Fr element.
        // NOTE: rc negated because output commitments are subtracted
        -PedersenRandomness::try_from(
            *self
                .proof
                .inputs
                .last()
                .expect("must have witness to extract from"),
        )
        .expect("extracted binding randomness is invalid")
    }
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

impl<P: Storable<D>, D: DB> Debug for Output<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded output {:?} for: {:?}>",
                self.coin_com, addr
            ),
            None => write!(formatter, "<shielded output {:?}>", self.coin_com),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialOrd, Ord, PartialEq, Eq, Clone; P)]
#[tag = "zswap-transient[v2]"]
#[storable(db = D)]
pub struct Transient<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub coin_com: Commitment,
    pub value_commitment_input: Pedersen,
    pub value_commitment_output: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof_input: Arc<P>,
    pub proof_output: Arc<P>,
}
tag_enforcement_test!(Transient<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Transient<P, D> {
    pub fn erase_proof(&self) -> Transient<(), D> {
        Transient {
            nullifier: self.nullifier,
            coin_com: self.coin_com,
            value_commitment_input: self.value_commitment_input,
            value_commitment_output: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof_input: Arc::new(()),
            proof_output: Arc::new(()),
        }
    }
}

impl<D: DB> Transient<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.as_input().binding_randomness() + self.as_output().binding_randomness()
    }
    pub fn segment(&self) -> Option<u16> {
        self.as_input().segment()
    }
}

impl<P: Clone + Storable<D>, D: DB> Transient<P, D> {
    pub fn as_input(&self) -> Input<P, D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment_input,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: MerkleTree::<_>::blank(ZSWAP_TREE_HEIGHT)
                .try_update_hash(0, self.coin_com.0, ())
                .expect("updating hash on non-collapsed tree should always succeed")
                .rehash()
                .root()
                .expect("rehashed tree must have root"),
            proof: self.proof_input.clone(),
        }
    }

    pub fn as_output(&self) -> Output<P, D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: self.proof_output.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Transient<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self.contract_address.clone() {
            Some(addr) => {
                write!(
                    formatter,
                    "<shielded transient coin {:?} {:?} for: {:?}>",
                    self.coin_com, self.nullifier, addr
                )
            }
            None => write!(
                formatter,
                "<shielded transient coin {:?} {:?}>",
                self.coin_com, self.nullifier
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize, Storable)]
#[storable(base)]
#[tag = "zswap-delta"]
pub struct Delta {
    pub token_type: ShieldedTokenType,
    pub value: i128,
}
tag_enforcement_test!(Delta);

#[derive(Storable)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Clone; P)]
#[tag = "zswap-offer[v5]"]
#[storable(db = D)]
/// A Zswap offer consists of a potentially unbalanced set of Zswap
/// inputs/outputs.
///
/// All vectors must be sorted to be valid, and `deltas` must be key-unique
/// (i.e. not contain tuples sharing their first element `(a, b)` and `(a, c)`).
/// This is to have a canonical representation while operating on sets and maps.
pub struct Offer<P: Storable<D>, D: DB> {
    /// A set of Inputs
    pub inputs: Array<Input<P, D>, D>,
    /// A set of Outputs
    pub outputs: Array<Output<P, D>, D>,
    /// A set of "transient" Zswap coins: Coins that are created and spent in
    /// the same transaction
    pub transient: Array<Transient<P, D>, D>,
    /// A map from types (coin colors) to the offer value in this type.
    /// A positive value means more coins have been spent, a negative value
    /// means more coins were created.
    pub deltas: Array<Delta, D>,
}
tag_enforcement_test!(Offer<(), InMemoryDB>);

impl<D: DB> Offer<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.inputs
            .iter()
            .map(|i| i.binding_randomness())
            .chain(self.outputs.iter().map(|o| o.binding_randomness()))
            .chain(self.transient.iter().map(|t| t.binding_randomness()))
            .fold(0.into(), |a, b| a + b)
    }
}

impl<P: Storable<D>, D: DB> Offer<P, D> {
    pub fn erase_proofs(&self) -> Offer<(), D> {
        Offer {
            inputs: self.inputs.iter_deref().map(Input::erase_proof).collect(),
            outputs: self.outputs.iter_deref().map(Output::erase_proof).collect(),
            transient: self
                .transient
                .iter_deref()
                .map(Transient::erase_proof)
                .collect(),
            deltas: self.deltas.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Offer<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_map()
            .entry(&Symbol("inputs"), &self.inputs)
            .entry(&Symbol("outputs"), &self.outputs)
            .entry(&Symbol("transient"), &self.transient)
            .entry(
                &Symbol("deltas"),
                &self
                    .deltas
                    .iter_deref()
                    .cloned()
                    .map(DebugDelta)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

struct DebugDelta(Delta);

impl Debug for DebugDelta {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?} -> {:?}", self.0.token_type, self.0.value)
    }
}

pub fn normalize_deltas<T: Ord, I: Iterator<Item = (T, i128)>>(deltas: I) -> Vec<(T, i128)> {
    let mut new_deltas: Vec<_> = deltas
        .fold(BTreeMap::new(), |mut map, (k, v)| {
            *map.entry(k).or_insert(0) += v;
            map
        })
        .into_iter()
        .collect();
    new_deltas.retain(|(_, v)| *v != 0);
    new_deltas.sort();
    new_deltas
}

impl<P: Clone + Ord + Storable<D>, D: DB> Offer<P, D> {
    pub fn normalize(&mut self) {
        self.inputs = self.inputs.iter_deref().sorted().cloned().collect();
        self.outputs = self.outputs.iter_deref().sorted().cloned().collect();
        self.transient = self.transient.iter_deref().sorted().cloned().collect();
        self.deltas = normalize_deltas(
            self.deltas
                .iter_deref()
                .map(|delta| (delta.token_type, delta.value)),
        )
        .into_iter()
        .map(|(token_type, value)| Delta { token_type, value })
        .collect();
    }

    #[instrument(skip(self, other))]
    pub fn merge(&self, other: &Self) -> Result<Self, MalformedOffer> {
        #[allow(clippy::mutable_key_type)]
        let inputs1: BTreeSet<_> = self.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let inputs2: BTreeSet<_> = other.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs1: BTreeSet<_> = self.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs2: BTreeSet<_> = other.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient1: BTreeSet<_> = self.transient.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient2: BTreeSet<_> = other.transient.iter_deref().cloned().collect();
        if inputs1.is_disjoint(&inputs2)
            && outputs1.is_disjoint(&outputs2)
            && transient1.is_disjoint(&transient2)
        {
            let mut res = Offer {
                inputs: inputs1.into_iter().chain(inputs2.into_iter()).collect(),
                outputs: outputs1.into_iter().chain(outputs2.into_iter()).collect(),
                transient: transient1
                    .iter()
                    .chain(transient2.iter())
                    .cloned()
                    .collect(),
                deltas: self
                    .deltas
                    .iter_deref()
                    .chain(other.deltas.iter_deref())
                    .cloned()
                    .collect(),
            };
            res.normalize();
            Ok(res)
        } else {
            warn!("overlap in coins attempted to merge");
            Err(MalformedOffer::NonDisjointCoinMerge)
        }
    }
}

struct Symbol(&'static str);

impl Debug for Symbol {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

pub const INPUT_PIS: usize = 68;
pub const INPUT_PROOF_SIZE: usize = 4_832;
pub const OUTPUT_PIS: usize = 77;
pub const OUTPUT_PROOF_SIZE: usize = 4_832;
pub const AUTHORIZED_CLAIM_PIS: usize = 13;

// ---------------------------------------------------------------------------
// Spend-proof memo binding — non-serialized helper and report types.
//
// ADDITIVE ONLY. Nothing below is `Serializable`, `Tagged`, or a field of
// `Input`, `Output`, `Offer` or `Transaction`: these are in-memory results a
// caller holds, never anything that reaches the wire, a ledger state, or a
// consensus check. See `crate::memo` for what they are for.
// ---------------------------------------------------------------------------

/// A **detached** companion spend proof: the same finalized spend statement as
/// the canonical proof, but with statement row 0 set to the memo commitment
/// `h` instead of the reserved zero.
///
/// # This is not a spend proof
///
/// The inner proof is private and has **no accessor**, no `Deref`, no `AsRef`
/// and no `Into`, so it cannot be placed in `Input.proof` through this API. The
/// only way it leaves the type is [`MemoCompanion::detached_proof_bytes`],
/// which hands back opaque *tagged bytes* under a name that says what they are.
///
/// That is a convenience, not the security boundary. The real boundary is that
/// an unmodified verifier derives row 0 as the constant zero
/// (`Input::<Proof>::well_formed`), so a companion substituted into
/// `Input.proof` is rejected — by the shipped verifier key and by every node
/// running it.
pub struct MemoCompanion {
    proof: transient_crypto::proofs::Proof,
    nullifier: Nullifier,
    segment: u16,
    binding: crate::memo::BindingElement,
    statement: Vec<Fr>,
}

impl MemoCompanion {
    pub(crate) fn new(
        proof: transient_crypto::proofs::Proof,
        nullifier: Nullifier,
        segment: u16,
        binding: crate::memo::BindingElement,
        statement: Vec<Fr>,
    ) -> Self {
        MemoCompanion {
            proof,
            nullifier,
            segment,
            binding,
            statement,
        }
    }

    /// The nullifier of the input this companion is attributed to.
    #[inline]
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// The final segment the companion's statement was built at.
    #[inline]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// The memo commitment in statement row 0. Always nonzero.
    #[inline]
    pub fn binding(&self) -> crate::memo::BindingElement {
        self.binding
    }

    /// The full public statement the companion proves: `INPUT_PIS` rows, with
    /// row 0 equal to [`MemoCompanion::binding`].
    #[inline]
    pub fn statement(&self) -> &[Fr] {
        &self.statement
    }

    /// Statement rows `1..INPUT_PIS` — everything after row 0.
    ///
    /// This is what an off-chain wrapper carries, as a cross-check that a
    /// verifier compares against its own independent rebuild.
    #[inline]
    pub fn statement_tail(&self) -> &[Fr] {
        &self.statement[1..]
    }

    /// The detached proof's size in bytes.
    #[inline]
    pub fn proof_len(&self) -> usize {
        self.proof.0.len()
    }

    /// The proof as **tagged** bytes, for an off-chain wrapper.
    ///
    /// Deliberately the only way the proof leaves this type, and it leaves as
    /// opaque bytes under a name that says what they are.
    pub fn detached_proof_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(self.proof.0.len() + 32);
        serialize::tagged_serialize(&self.proof, &mut buf)?;
        Ok(buf)
    }
}

/// Never renders the proof bytes.
impl Debug for MemoCompanion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoCompanion")
            .field("nullifier", &crate::memo::hex_lower(&self.nullifier.0.0))
            .field("segment", &self.segment)
            .field(
                "binding",
                &crate::memo::hex_lower(&crate::memo::fr_le32(self.binding.get())),
            )
            .field("statement_rows", &self.statement.len())
            .field("proof_len", &self.proof.0.len())
            .field("status", &Symbol("DETACHED — never consensus-submittable"))
            .finish()
    }
}

/// One valid `AnchorV1` found on an output of the offer that was scanned.
///
/// A reference, not a judgement: an anchor is **strip evidence** that a memo
/// commitment was published in the offer it was found in. It authenticates
/// nothing on its own, and its presence says nothing about whether the
/// transaction carrying it settled — that is a separate, caller-attested
/// question ([`crate::verify::SettledAttestation`], 00006 finding F3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoAnchorRef {
    /// Where the carrying output sits in the offer's (sorted) output array.
    ///
    /// Reported for diagnostics only. `Offer::new` sorts its outputs, so
    /// position is not caller-controlled and must never be used to select an
    /// anchor — match by decoded `(N, h)` instead.
    pub output_index: usize,
    /// The carrying output's coin commitment.
    pub coin_com: Commitment,
    /// The decoded anchor.
    pub anchor: crate::memo::anchor::AnchorV1,
}

impl<P: Storable<D>, D: DB> Offer<P, D> {
    /// Every output of this offer whose ciphertext decodes as a valid
    /// `AnchorV1`, in output order.
    ///
    /// Ordinary encrypted outputs, absent ciphertexts and anchor-*shaped* but
    /// invalid ciphertexts are all simply not anchors and are skipped; the scan
    /// never fails and never panics. Deduplication and matching are the
    /// caller's job, and must be done by comparing decoded `(N, h)`.
    pub fn memo_anchors(&self) -> Vec<MemoAnchorRef> {
        self.outputs
            .iter_deref()
            .enumerate()
            .filter_map(|(output_index, output)| {
                let ciph = output.ciphertext.as_ref()?;
                let anchor = crate::memo::anchor::AnchorV1::decode(ciph).ok()?;
                Some(MemoAnchorRef {
                    output_index,
                    coin_com: output.coin_com,
                    anchor,
                })
            })
            .collect()
    }
}

/// The result of a **successful** detached companion verification.
///
/// The constructor is crate-private and is only ever called after the
/// companion proof has verified under the shipped `SPEND_VK` against a
/// statement rebuilt from the canonical input, so holding one of these means
/// the memo bytes really were authorized by whoever could spend that input.
///
/// It still does not mean the memo is *true*, that it was delivered, that a
/// missing wrapper was deliberately withheld, or that anything settled: the
/// settlement column is whatever the caller attested
/// ([`crate::verify::Confirmation`]) and nothing more.
#[derive(Debug, Clone)]
pub struct MemoVerification {
    memo: crate::memo::Memo,
    nullifier: Nullifier,
    segment: u16,
    binding: crate::memo::BindingElement,
    anchors: Vec<MemoAnchorRef>,
    attested_tx_hash: Option<base_crypto::hash::HashOutput>,
}

impl MemoVerification {
    pub(crate) fn new(
        memo: crate::memo::Memo,
        nullifier: Nullifier,
        segment: u16,
        binding: crate::memo::BindingElement,
        anchors: Vec<MemoAnchorRef>,
        attested_tx_hash: Option<base_crypto::hash::HashOutput>,
    ) -> Self {
        MemoVerification {
            memo,
            nullifier,
            segment,
            binding,
            anchors,
            attested_tx_hash,
        }
    }

    /// The memo bytes, now safe to attribute to the input's controller.
    #[inline]
    pub fn authenticated_memo(&self) -> &crate::memo::Memo {
        &self.memo
    }

    /// The input the memo is attributed to.
    #[inline]
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// The canonical segment the statement was rebuilt at.
    #[inline]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// The memo commitment `h` the companion proved in row 0.
    #[inline]
    pub fn binding(&self) -> crate::memo::BindingElement {
        self.binding
    }

    /// Anchors of the offer that was checked whose decoded `(N, h)` match this
    /// record exactly.
    ///
    /// Empty means the companion authenticated the memo but no matching anchor
    /// was found in the offer that was checked — which is a weaker state, not a
    /// failure. A non-empty list means the commitment was published in that
    /// offer; whether the transaction carrying it settled is
    /// [`MemoVerification::attested_transaction`]'s question, not this one.
    #[inline]
    pub fn matching_anchors(&self) -> &[MemoAnchorRef] {
        &self.anchors
    }

    /// Whether at least one matching anchor is present in the offer that was
    /// checked. **Publication, not settlement** (00006 finding F3).
    #[inline]
    pub fn has_matching_anchor(&self) -> bool {
        !self.anchors.is_empty()
    }

    /// The transaction the caller attested settled, when that attestation
    /// really does spend this input and publish this `(N, h)`.
    ///
    /// `None` whenever settlement was not asserted, or was asserted for some
    /// other transaction. It is a caller assertion either way — this crate
    /// never observes a chain.
    #[inline]
    pub fn attested_transaction(&self) -> Option<base_crypto::hash::HashOutput> {
        self.attested_tx_hash
    }

    /// Whether a matching anchor is present **and** the caller attested that
    /// the transaction carrying it settled.
    ///
    /// This is the strongest state this API reports, and it is exactly as
    /// strong as the caller's attestation — see
    /// [`crate::verify::SettledAttestation`].
    #[inline]
    pub fn is_settled_anchored(&self) -> bool {
        self.attested_tx_hash.is_some() && !self.anchors.is_empty()
    }

    /// Whether more than one matching anchor was present.
    ///
    /// An anomaly worth surfacing — an honest constructor emits exactly one —
    /// but **not** a reason to downgrade authentication: the companion proof
    /// is what authenticates, and duplicates cannot forge it.
    #[inline]
    pub fn has_duplicate_anchors(&self) -> bool {
        self.anchors.len() > 1
    }
}
