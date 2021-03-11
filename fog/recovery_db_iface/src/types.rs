// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database API types
//! These are not user-facing, the user facing versions are in fog-types crate.

use core::{fmt, ops::Deref};
use mc_attest_core::VerificationReport;
use mc_crypto_keys::CompressedRistrettoPublic;
use serde::{Deserialize, Serialize};

/// Status in the database connected to this ingress public key
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IngressPublicKeyStatus {
    /// The first block that fog promises to scan with this key after publishing it.
    /// This should be the latest block that existed before we published it (or, a block close to but before that)
    pub start_block: u64,
    /// The largest pubkey expiry value that we have ever published for this key.
    /// If less than start_block, it means we have never published this key.
    pub pubkey_expiry: u64,
    /// Whether this key is retiring / retired.
    /// When a key is retired, we stop publishing reports about it.
    pub retired: bool,
}

impl IngressPublicKeyStatus {
    /// Whether a block index lies between start_block and pubkey_expiry for this key.
    /// If the key is not retired yet, we assume that pubkey_expiry may be increasing,
    /// so we only check if self.start_block <= block_index in that case.
    ///
    /// If it does, then the block index potentially contains TxOut's which had
    /// fog hints encrypted using this ingress public key, and fog needs to scan
    /// this block with this ingress key, or declare it a missed block.
    pub fn covers_block_index(&self, block_index: u64) -> bool {
        self.start_block <= block_index && (!self.retired || block_index < self.pubkey_expiry)
    }
}

/// Information returned after attempting to add block data to the database.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddBlockDataStatus {
    /// Indicates that the block we tried to add has already been scanned using this ingress key,
    /// and didn't need to be scanned again.
    ///
    /// If this value is true, then no data was added to the database.
    pub block_already_scanned_with_this_key: bool,
}

/// IngressPublicKeyRecord
///
/// This is returned by get_ingress_public_key_records, and augments the PublicKeyStatus so that
/// the last_block_scanned is also returned, as well as the public key bytes themselves.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IngressPublicKeyRecord {
    /// The ingress public key this data refers to
    pub key: CompressedRistrettoPublic,
    /// The status of the key
    pub status: IngressPublicKeyStatus,
    /// The last block scanned by this key.
    /// This is inherently racy since other partcipants may be writing concurrently with us, but this
    /// number is a lower bound.
    pub last_scanned_block: Option<u64>,
}

impl IngressPublicKeyRecord {
    /// The next block index that needs to be scanned with this key.
    ///
    /// This is one of:
    /// - last_scanned_block + 1
    /// - start_block if last_scanned_block is None
    /// - None, we're not actually on the hook for that block, per self.covers_block_index
    pub fn next_needed_block_index(&self) -> Option<u64> {
        let candidate = self
            .last_scanned_block
            .map(|x| x + 1)
            .unwrap_or(self.status.start_block);
        if self.status.covers_block_index(candidate) {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Possible user events to be returned to end users.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum FogUserEvent {
    /// A new RNG record the user should begin searching for.
    NewRngRecord(fog_types::view::RngRecord),

    /// Ingest invocation decommissioned event
    DecommissionIngestInvocation(fog_types::view::DecommissionedIngestInvocation),

    /// A missed block range
    MissingBlocks(fog_types::common::BlockRange),
}

/// An ingest invocation begins consuming the blockchain at some particular block index, and eventually stops.
/// The IngestableRange tracks the start block, what the last scanned block is,
/// and whether it has stopped.
/// Clients use this information, for example, to avoid making unnecessary fog-view queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestableRange {
    /// The ingest invocation id this range is tied to.
    pub id: IngestInvocationId,

    /// The first block index that will be ingested by this invocation.
    pub start_block: u64,

    /// Whether this ingest invocation has been decommissioned or is still active.
    pub decommissioned: bool,

    /// The last block ingested by this invocation, if any.
    pub last_ingested_block: Option<u64>,
}

impl IngestableRange {
    /// Is, or will this IngestableRange be able to provide data for a given block index.
    pub fn can_provide_block(&self, block: u64) -> bool {
        // If this ingestable range starts after the desired block, it is not going to provide it.
        if block < self.start_block {
            false
        } else {
            // If this ingestable range is decomissioned, it will only provide blocks up until the
            // last ingested block
            if self.decommissioned {
                if let Some(last_ingested_block) = self.last_ingested_block {
                    last_ingested_block >= block
                } else {
                    false
                }
            } else {
                // Ingest invocation is still active so it is expected to provide this block
                true
            }
        }
    }
}

/// A globally unique identifier for ingest invocations. This ID should be unique for each instance
/// of an ingest enclave, and allows identifying that enclave during its lifetime.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct IngestInvocationId(i64);
impl fmt::Display for IngestInvocationId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl AsRef<i64> for IngestInvocationId {
    fn as_ref(&self) -> &i64 {
        &self.0
    }
}
impl Deref for IngestInvocationId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<i64> for IngestInvocationId {
    fn from(id: i64) -> Self {
        Self(id)
    }
}
impl From<IngestInvocationId> for i64 {
    fn from(src: IngestInvocationId) -> i64 {
        src.0
    }
}

/// Fog report data (the data associated with each report).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportData {
    /// The ingest invocation id that wrote this report.
    pub ingest_invocation_id: Option<IngestInvocationId>,

    /// The Intel Attestation Service report, which include the pubkey
    pub report: VerificationReport,

    /// The pubkey_expiry (a block height)
    pub pubkey_expiry: u64,
}
