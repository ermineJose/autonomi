// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Register Secret Key
pub use bls::SecretKey as RegisterSecretKey;
use sn_evm::Amount;
use sn_evm::AttoTokens;
use sn_evm::EvmWalletError;
use sn_evm::ProofOfPayment;
use sn_networking::VerificationKind;
use sn_protocol::storage::RetryStrategy;
pub use sn_registers::{Permissions as RegisterPermissions, RegisterAddress};

use crate::client::data::PayError;
use crate::client::Client;
use crate::client::ClientEvent;
use crate::client::UploadSummary;
use bytes::Bytes;
use libp2p::kad::{Quorum, Record};
use sn_evm::EvmWallet;
use sn_networking::{GetRecordCfg, GetRecordError, NetworkError, PutRecordCfg};
use sn_protocol::storage::try_deserialize_record;
use sn_protocol::storage::try_serialize_record;
use sn_protocol::storage::RecordKind;
use sn_protocol::NetworkAddress;
use sn_registers::Register as BaseRegister;
use sn_registers::{Permissions, RegisterCrdt, RegisterOp, SignedRegister};
use std::collections::BTreeSet;
use xor_name::XorName;

use super::data::CostError;

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("Cost error: {0}")]
    Cost(#[from] CostError),
    #[error("Network error")]
    Network(#[from] NetworkError),
    #[error("Serialization error")]
    Serialization,
    #[error("Register could not be verified (corrupt)")]
    FailedVerification,
    #[error("Payment failure occurred during register creation.")]
    Pay(#[from] PayError),
    #[error("Failed to retrieve wallet payment")]
    Wallet(#[from] EvmWalletError),
    #[error("Failed to write to low-level register")]
    Write(#[source] sn_registers::Error),
    #[error("Failed to sign register")]
    CouldNotSign(#[source] sn_registers::Error),
    #[error("Received invalid quote from node, this node is possibly malfunctioning, try another node by trying another register name")]
    InvalidQuote,
}

#[derive(Clone, Debug)]
pub struct Register {
    signed_reg: SignedRegister,
    crdt_reg: RegisterCrdt,
}

impl Register {
    pub fn address(&self) -> &RegisterAddress {
        self.signed_reg.address()
    }

    /// Retrieve the current values of the register. There can be multiple values
    /// in case a register was updated concurrently. This is because of the nature
    /// of registers, which allows for network concurrency.
    pub fn values(&self) -> Vec<Bytes> {
        self.crdt_reg
            .read()
            .into_iter()
            .map(|(_hash, value)| value.into())
            .collect()
    }

    fn new(
        initial_value: Option<Bytes>,
        name: XorName,
        owner: RegisterSecretKey,
        permissions: RegisterPermissions,
    ) -> Result<Register, RegisterError> {
        let pk = owner.public_key();

        let base_register = BaseRegister::new(pk, name, permissions);

        let signature = owner.sign(base_register.bytes().map_err(RegisterError::Write)?);
        let signed_reg = SignedRegister::new(base_register, signature, BTreeSet::new());

        let crdt_reg = RegisterCrdt::new(*signed_reg.address());

        let mut register = Register {
            signed_reg,
            crdt_reg,
        };

        if let Some(value) = initial_value {
            register.write_atop(&value, &owner)?;
        }

        Ok(register)
    }

    fn write_atop(&mut self, entry: &[u8], owner: &RegisterSecretKey) -> Result<(), RegisterError> {
        let children: BTreeSet<_> = self.crdt_reg.read().iter().map(|(hash, _)| *hash).collect();

        let (_hash, address, crdt_op) = self
            .crdt_reg
            .write(entry.to_vec(), &children)
            .map_err(RegisterError::Write)?;

        let op = RegisterOp::new(address, crdt_op, owner);

        let _ = self.signed_reg.add_op(op);

        Ok(())
    }

    /// Merge two registers together.
    pub(crate) fn merge(&mut self, other: &Self) -> Result<(), RegisterError> {
        debug!("Merging Register of: {:?}", self.address());

        other.signed_reg.verify().map_err(|_| {
            error!(
                "Failed to verify register at address: {:?}",
                other.address()
            );
            RegisterError::FailedVerification
        })?;

        self.signed_reg.merge(&other.signed_reg).map_err(|err| {
            error!("Failed to merge registers {}: {err}", self.address());
            RegisterError::Write(err)
        })?;

        for op in other.signed_reg.ops() {
            if let Err(err) = self.crdt_reg.apply_op(op.clone()) {
                error!(
                    "Failed to apply {op:?} to Register {}: {err}",
                    self.address()
                );
                return Err(RegisterError::Write(err));
            }
        }

        Ok(())
    }
}

impl Client {
    /// Generate a new register key
    pub fn register_generate_key() -> RegisterSecretKey {
        RegisterSecretKey::random()
    }

    /// Fetches a Register from the network.
    pub async fn register_get(&self, address: RegisterAddress) -> Result<Register, RegisterError> {
        info!("Fetching register at addr: {address}");
        let network_address = NetworkAddress::from_register_address(address);
        let key = network_address.to_record_key();

        let get_cfg = GetRecordCfg {
            get_quorum: Quorum::Majority,
            retry_strategy: None,
            target_record: None,
            expected_holders: Default::default(),
            is_register: true,
        };

        let signed_reg = match self.network.get_record_from_network(key, &get_cfg).await {
            Ok(record) => {
                let signed_reg: SignedRegister =
                    try_deserialize_record(&record).map_err(|_| RegisterError::Serialization)?;
                signed_reg
            }
            Err(NetworkError::GetRecordError(GetRecordError::SplitRecord { result_map })) => {
                error!("Got split record error for register at address: {address}. This should've been handled at the network layer");
                Err(RegisterError::Network(NetworkError::GetRecordError(
                    GetRecordError::SplitRecord { result_map },
                )))?
            }
            Err(e) => {
                error!("Failed to get register {address:?} from network: {e}");
                Err(e)?
            }
        };

        // Make sure the fetched record contains valid CRDT operations
        signed_reg.verify().map_err(|_| {
            error!("Failed to verify register at address: {address}");
            RegisterError::FailedVerification
        })?;

        let mut crdt_reg = RegisterCrdt::new(*signed_reg.address());
        for op in signed_reg.ops() {
            if let Err(err) = crdt_reg.apply_op(op.clone()) {
                error!(
                    "Failed to apply {op:?} to Register {address}: {err}",
                    address = signed_reg.address()
                );
                return Err(RegisterError::Write(err));
            }
        }

        Ok(Register {
            signed_reg,
            crdt_reg,
        })
    }

    /// Updates a Register on the network with a new value. This will overwrite existing value(s).
    pub async fn register_update(
        &self,
        mut register: Register,
        new_value: Bytes,
        owner: RegisterSecretKey,
    ) -> Result<(), RegisterError> {
        register.write_atop(&new_value, &owner)?;

        let get_cfg = GetRecordCfg {
            get_quorum: Quorum::Majority,
            retry_strategy: Some(RetryStrategy::default()),
            target_record: None,
            expected_holders: Default::default(),
            is_register: true,
        };
        let put_cfg = PutRecordCfg {
            put_quorum: Quorum::All,
            retry_strategy: None,
            use_put_record_to: None,
            verification: Some((VerificationKind::Network, get_cfg)),
        };

        self.register_upload(&register, None, &put_cfg).await?;

        Ok(())
    }

    /// Get the cost to create a register
    pub async fn register_cost(
        &self,
        name: String,
        owner: RegisterSecretKey,
    ) -> Result<AttoTokens, RegisterError> {
        info!("Getting cost for register with name: {name}");
        // get register address
        let pk = owner.public_key();
        let name = XorName::from_content_parts(&[name.as_bytes()]);
        let permissions = Permissions::new_with([pk]);
        let register = Register::new(None, name, owner, permissions)?;
        let reg_xor = register.address().xorname();

        // get cost to store register
        // NB TODO: register should be priced differently from other data
        let cost_map = self.get_store_quotes(std::iter::once(reg_xor)).await?;
        let total_cost = AttoTokens::from_atto(
            cost_map
                .values()
                .map(|quote| quote.2.cost.as_atto())
                .sum::<Amount>(),
        );

        Ok(total_cost)
    }

    /// Get the address of a register from its name and owner
    pub fn register_address(name: &str, owner: &RegisterSecretKey) -> RegisterAddress {
        let pk = owner.public_key();
        let name = XorName::from_content_parts(&[name.as_bytes()]);
        RegisterAddress::new(name, pk)
    }

    /// Creates a new Register with a name and an initial value and uploads it to the network.
    ///
    /// The Register is created with the owner as the only writer.
    pub async fn register_create(
        &self,
        value: Bytes,
        name: &str,
        owner: RegisterSecretKey,
        wallet: &EvmWallet,
    ) -> Result<Register, RegisterError> {
        let pk = owner.public_key();
        let permissions = Permissions::new_with([pk]);

        self.register_create_with_permissions(value, name, owner, permissions, wallet)
            .await
    }

    /// Creates a new Register with a name and an initial value and uploads it to the network.
    ///
    /// Unlike `register_create`, this function allows you to specify the permissions for the register.
    pub async fn register_create_with_permissions(
        &self,
        value: Bytes,
        name: &str,
        owner: RegisterSecretKey,
        permissions: RegisterPermissions,
        wallet: &EvmWallet,
    ) -> Result<Register, RegisterError> {
        info!("Creating register with name: {name}");
        let name = XorName::from_content_parts(&[name.as_bytes()]);

        // Owner can write to the register.
        let register = Register::new(Some(value), name, owner, permissions)?;
        let address = register.address();

        let reg_xor = address.xorname();
        debug!("Paying for register at address: {address}");
        let (payment_proofs, _skipped) = self
            .pay(std::iter::once(reg_xor), wallet)
            .await
            .inspect_err(|err| {
                error!("Failed to pay for register at address: {address} : {err}")
            })?;
        let proof = payment_proofs.get(&reg_xor).ok_or_else(|| {
            // register was skipped, meaning it was already paid for
            error!("Register at address: {address} was already paid for");
            RegisterError::Network(NetworkError::RegisterAlreadyExists)
        })?;

        let payee = proof
            .to_peer_id_payee()
            .ok_or(RegisterError::InvalidQuote)
            .inspect_err(|err| error!("Failed to get payee from payment proof: {err}"))?;

        let get_cfg = GetRecordCfg {
            get_quorum: Quorum::Majority,
            retry_strategy: Some(RetryStrategy::default()),
            target_record: None,
            expected_holders: Default::default(),
            is_register: true,
        };
        let put_cfg = PutRecordCfg {
            put_quorum: Quorum::All,
            retry_strategy: None,
            use_put_record_to: Some(vec![payee]),
            verification: Some((VerificationKind::Network, get_cfg)),
        };

        self.register_upload(&register, Some(proof), &put_cfg)
            .await?;

        if let Some(channel) = self.client_event_sender.as_ref() {
            let summary = UploadSummary {
                record_count: 1,
                tokens_spent: proof.quote.cost.as_atto(),
            };
            if let Err(err) = channel.send(ClientEvent::UploadComplete(summary)).await {
                error!("Failed to send client event: {err}");
            }
        }

        Ok(register)
    }

    pub(crate) async fn register_upload(
        &self,
        register: &Register,
        payment: Option<&ProofOfPayment>,
        put_cfg: &PutRecordCfg,
    ) -> Result<(), RegisterError> {
        let signed_register = &register.signed_reg;
        let record = if let Some(proof) = payment {
            Record {
                key: NetworkAddress::from_register_address(*register.address()).to_record_key(),
                value: try_serialize_record(
                    &(proof, signed_register),
                    RecordKind::RegisterWithPayment,
                )
                .map_err(|_| RegisterError::Serialization)?
                .to_vec(),
                publisher: None,
                expires: None,
            }
        } else {
            Record {
                key: NetworkAddress::from_register_address(*register.address()).to_record_key(),
                value: try_serialize_record(signed_register, RecordKind::Register)
                    .map_err(|_| RegisterError::Serialization)?
                    .to_vec(),
                publisher: None,
                expires: None,
            }
        };

        self.network
            .put_record(record, put_cfg)
            .await
            .inspect_err(|err| {
                error!(
                    "Failed to put record - register {:?} to the network: {err}",
                    register.address()
                )
            })?;

        Ok(())
    }
}
