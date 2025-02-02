// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Client SDK for Rust
#![deny(missing_docs)]

mod cached_tx_data;
mod client;
mod client_builder;
mod error;

pub use crate::{
    client::Client,
    client_builder::ClientBuilder,
    error::{Error, Result, TxOutMatchingError},
};
pub use mc_account_keys::{AccountKey, PublicAddress};
pub use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
pub use mc_transaction_core::{
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{Tx, TxOutMembershipProof},
    BlockIndex,
};

/// A status that a submitted transaction can have
pub enum TransactionStatus {
    /// The transaction has appeared at a particular block index
    Appeared(BlockIndex),
    /// The transaction has expired (tombstone block passed)
    Expired,
    /// It isn't known if the transaction appeared or expired yet
    Unknown,
}
