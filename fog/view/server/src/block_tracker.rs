// Copyright (c) 2018-2021 The MobileCoin Foundation

use fog_recovery_db_iface::IngressPublicKeyRecord;
use fog_types::common::BlockRange;
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use std::collections::HashMap;

/// A utility object that keeps track of which block number was processed for every known ingest
/// invocation. This provides utilities such as:
/// - Finding out what is the next block that needs processing for any of the ingress keys.
/// - Finding out what is the highest block index we have encountered so far.
/// - Finding out for which block index have we processed data for all ingress keys, while
///   taking into account missed blocks.
pub struct BlockTracker {
    processed_block_per_ingress_key: HashMap<CompressedRistrettoPublic, u64>,
    last_highest_processed_block_count: u64,
    logger: Logger,
}

impl BlockTracker {
    pub fn new(logger: Logger) -> Self {
        Self {
            processed_block_per_ingress_key: HashMap::default(),
            last_highest_processed_block_count: 0,
            logger,
        }
    }

    // Given a list of ingress keys and the current state, calculate which block
    // index needs to be processed next for each ingress key
    pub fn next_blocks(
        &self,
        ingress_key_records: &[IngressPublicKeyRecord],
    ) -> HashMap<CompressedRistrettoPublic, u64> {
        let mut next_blocks = HashMap::default();

        for rec in ingress_key_records {
            if let Some(last_processed_block) = self.processed_block_per_ingress_key.get(&rec.key) {
                // A block has previously been processed for this ingress key. See if the
                // next one can be provided by it, and if so add it to the list of next blocks we
                // would like to process.
                let next_block = last_processed_block + 1;
                if rec.status.covers_block_index(next_block) {
                    next_blocks.insert(rec.key, next_block);
                }
            } else {
                // No block has been processed for this ingress key, so the next block is the
                // first one, assuming it can actually be provided by the ingress key.
                // (It will not be able to provide the start block if it got decommissioned
                // immediately after starting before scanning any blocks)
                if rec.status.covers_block_index(rec.status.start_block) {
                    next_blocks.insert(rec.key, rec.status.start_block);
                }
            }
        }

        next_blocks
    }

    /// Notify the tracker that a block has been processed (loaded into enclave and is now available)
    pub fn block_processed(&mut self, ingress_key: CompressedRistrettoPublic, block_index: u64) {
        if let Some(previous_block_index) = self
            .processed_block_per_ingress_key
            .insert(ingress_key, block_index)
        {
            // Sanity check that we are only moving forward and not skipping any blocks.
            assert!(block_index == previous_block_index + 1);
        }
    }

    /// Given a list of ingress keys, missing blocks and current state, calculate the highest
    /// processed block count number. The highest processed block count number is the block count
    /// for which we know we have loaded all required data, so the users can potentially compute
    /// their balance up to this block without missing any transactions.
    ///
    /// Arguments:
    /// * highest_known_block_index:
    ///   The highest block index known to have appeared in the blockchain.
    ///   If there are no ingress keys at all right now, then this is also the highest
    ///   fully-processed block. It is assumed in the algorithm that any new keys will
    ///   appear with start block after this number.
    /// * ingress_keys:
    ///   IngressPublicKeyRecord's that exist in the database right now.
    ///   This indicates their start block, their last-scanned block, their expiry block,
    ///   and whether they are retired.
    /// * missing_block_ranges:
    ///   Any manually entered missing block ranges.
    ///
    /// Returns:
    /// * The highest fully processed block count, which may be 0 if nothing is processed
    /// * Optionally, an IngressPublicKeyRecord which is the *reason* that the previous number
    ///   is less than highest_known_block_index -- the next thing we are waiting on for data.
    pub fn highest_fully_processed_block_count(
        &mut self,
        highest_known_block_index: u64,
        ingress_keys: &[IngressPublicKeyRecord],
        missing_block_ranges: &[BlockRange],
    ) -> (u64, Option<IngressPublicKeyRecord>) {
        let initial_last_highest_processed_block_count = self.last_highest_processed_block_count;
        let mut reason_we_stopped: Option<IngressPublicKeyRecord> = None;

        // Each pass through the loop attempts to increase self.last_highest_processed_block_count
        // or break the loop and indicate the reason we can't increase it
        'outer: loop {
            let next_block_index = self.last_highest_processed_block_count;
            let next_block_count = self.last_highest_processed_block_count + 1;

            log::trace!(
                self.logger,
                "checking if highest_processed_block_count can be advanced to {}",
                next_block_count,
            );

            // If the next block index we are checking doesn't exist yet, then we definitely
            // can't advance the highest processed block count.
            // This breaks the loop if both ingress_keys and missing_block_ranges are empty.
            if highest_known_block_index < next_block_index {
                log::trace!(
                    self.logger,
                    "We processed everything up to highest known block index"
                );
                break 'outer;
            }

            // If the block has been reported as missing, we can advance since we don't need to do
            // any processing for it.
            if Self::is_missing_block(missing_block_ranges, next_block_index) {
                log::trace!(
                    self.logger,
                    "block {} reported missing, advancing block count to {}",
                    next_block_index,
                    next_block_count
                );
                self.last_highest_processed_block_count = next_block_count;
                continue;
            }

            // Go over all known ingestable ranges and check if
            // any of them need to provide this block and have not provided it
            for rec in ingress_keys {
                if !rec.status.covers_block_index(next_block_index) {
                    continue;
                }

                if let Some(last_processed_block) =
                    self.processed_block_per_ingress_key.get(&rec.key)
                {
                    if next_block_index > *last_processed_block {
                        // This ingress key needs to provide this block, but we haven't got it yet
                        log::trace!(self.logger, "cannot advance highest_processed_block_count to {}, because ingress_key {:?} only processed block {}", next_block_count, rec.key, last_processed_block);
                        reason_we_stopped = Some(rec.clone());
                        break 'outer;
                    }
                } else {
                    // No blocks have been processed yet by this ingress key.
                    // If next_block_index < start_block then "covers_block_index" is false.
                    // So if we got here, next_block_index >= start_block, so we are blocked.
                    log::trace!(self.logger, "cannot advance highest_processed_block_count to {}, because ingress_key {:?} hasn't processed anything yet", next_block_count, rec.key);
                    reason_we_stopped = Some(rec.clone());
                    break 'outer;
                }
            }

            // If we got here it means there was no reason we cannot advance the highest processed block count
            // 1) next_block_index did not exceed highest_known_block_index
            // 2) next_block_index was not both covered, and not yet provided for, for any ingress public key
            //
            // If next_block_index is missing, we already did
            // self.last_highest_processed_block_count = next_block_count;
            // and re-entered the loop early.
            self.last_highest_processed_block_count = next_block_count;
        }

        if self.last_highest_processed_block_count != initial_last_highest_processed_block_count {
            log::info!(
                self.logger,
                "advancing last_highest_processed_block_count from {} to {}",
                initial_last_highest_processed_block_count,
                self.last_highest_processed_block_count,
            );
        }

        (self.last_highest_processed_block_count, reason_we_stopped)
    }

    /// Get the highest block count we have encountered.
    pub fn highest_known_block_count(&self) -> u64 {
        self.processed_block_per_ingress_key
            .iter()
            .map(|(_key, block_index)| *block_index + 1)
            .max()
            .unwrap_or(0)
    }

    /// Check if a block has been reported as missing.
    // TODO this can be much more efficient
    pub fn is_missing_block(missing_block_ranges: &[BlockRange], block: u64) -> bool {
        for range in missing_block_ranges.iter() {
            if range.contains(block) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fog_recovery_db_iface::IngressPublicKeyStatus;
    use mc_common::logger::test_with_logger;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{cmp::min, iter::FromIterator};

    #[test_with_logger]
    fn next_blocks_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger.clone());
        assert_eq!(block_tracker.next_blocks(&[]).len(), 0);
    }

    // Single key (hasn't scanned any blocks yet)
    #[test_with_logger]
    fn next_blocks_single_key_hasnt_scanned(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
            },
            last_scanned_block: None,
        };

        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single ingestable range (commissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_commissioned_scanned_some(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
            },
            last_scanned_block: Some(126),
        };
        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single key (retired, hasn't scanned anything)
    #[test_with_logger]
    fn next_blocks_single_key_retired_hasnt_scanned(logger: Logger) {
        // TODO currently failing since even if retired=true next_blocks returns blocks that are
        // less than the pubkey expiry.

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: true,
            },
            last_scanned_block: None,
        };

        let expected_state = HashMap::from_iter(vec![]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should return the same result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single ingestable range (decommissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_retired_scanned_some(logger: Logger) {
        // TODO currently failing since last_scanned_block does not play into next_blocks

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let last_ingested_block = 126;
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: true,
            },
            last_scanned_block: Some(last_ingested_block),
        };

        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // Capped at the last block that was scanned.
            let expected_state = if rec.status.start_block + i + 1 <= last_ingested_block {
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)])
            } else {
                HashMap::default()
            };

            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Two ingestable ranges should advance independently of eachother
    #[test_with_logger]
    fn next_blocks_multiple_keys(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 200,
                retired: false,
            },
            last_scanned_block: None,
        };
        let rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 3000,
                pubkey_expiry: 200,
                retired: false,
            },
            last_scanned_block: None,
        };

        let expected_state = HashMap::from_iter(vec![(rec1.key, rec1.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        // Try again with the second ingestable range.
        let expected_state = HashMap::from_iter(vec![(rec2.key, rec2.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec2.clone()]), expected_state);

        // Advancing the first one should not affect the second.
        block_tracker.block_processed(rec1.key, rec1.status.start_block);

        let expected_state = HashMap::from_iter(vec![(rec1.key, rec1.status.start_block + 1)]);

        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        let expected_state = HashMap::from_iter(vec![(rec2.key, rec2.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec2.clone()]), expected_state);

        // Try with both.
        let expected_state = HashMap::from_iter(vec![
            (rec1.key, rec1.status.start_block + 1),
            (rec2.key, rec2.status.start_block),
        ]);

        assert_eq!(
            block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
            expected_state
        );
    }

    // highest_fully_processed_block_count behaves as expected
    #[test_with_logger]
    fn highest_fully_processed_block_count_all_empty(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        // higehst_known_block_index shouldn't affect these tests so we try a bunch of options
        for highest_known_block_index in 0..20 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    highest_known_block_index,
                    &[],
                    &[]
                ),
                (0, None)
            );
        }
        todo!()
    }

    // A missing range that doesn't start at block 0 should not affect the count.
    #[test_with_logger]
    fn highest_fully_processed_block_count_some_missing_blocks(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        // higehst_known_block_index shouldn't affect these tests so we try a bunch of options
        for highest_known_block_index in 0..20 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    highest_known_block_index,
                    &[],
                    &[BlockRange::new(1, 10)]
                ),
                (0, None)
            );
        }
        todo!()
    }

    // A missing range that does start at block 0 should advance the count to the end of the
    // range.
    #[test_with_logger]
    fn highest_fully_processed_block_count_starts_with_missing_blocks(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        // higehst_known_block_index shouldn't affect these tests so we try a bunch of options
        for highest_known_block_index in 0..20 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    highest_known_block_index,
                    &[],
                    &[BlockRange::new(0, 10)]
                ),
                (10, None)
            );
        }
        todo!()
    }

    // Multiple missing ranges are handled appropriately
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_missing1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        // higehst_known_block_index shouldn't affect these tests so we try a bunch of options
        for highest_known_block_index in 0..20 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    highest_known_block_index,
                    &[],
                    &[BlockRange::new(0, 10), BlockRange::new(20, 30)]
                ),
                (10, None)
            );
        }
        todo!()
    }

    // Multiple missing ranges are handled appropriately
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_missing2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                100,
                &[],
                &[
                    BlockRange::new(0, 10),
                    BlockRange::new(20, 30),
                    BlockRange::new(10, 20)
                ]
            ),
            (30, None),
        );

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                25, // This should cap us
                &[],
                &[
                    BlockRange::new(0, 10),
                    BlockRange::new(20, 30),
                    BlockRange::new(10, 20)
                ]
            ),
            (25, None),
        );
        todo!()
    }

    // Check with a key that hasn't yet processed anything.
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_nothing_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 12,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        // higehst_known_block_index shouldn't affect these tests so we try a bunch of options
        for highest_known_block_index in 0..20 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    highest_known_block_index,
                    &[rec.clone()],
                    &[]
                ),
                (0, None),
            );
        }
        todo!()
    }

    // Check with a key that hasn't yet processed anything but has missing blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_nothing_processed2(
        logger: Logger,
    ) {
        let mut block_tracker = BlockTracker::new(logger.clone());
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 12,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                0, // TODO try different values
                &[rec],
                &[BlockRange::new(0, 10)]
            ),
            (10, None),
        );
        todo!()
    }

    // A block tracker with a single ingestable range tracks it properly as blocks are
    // processed when the start block is 0.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &[]),
                (rec.status.start_block + i, None)
            );

            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &[]),
                (rec.status.start_block + i + 1, None)
            );
        }
        todo!()
    }

    // A block tracker with a single ingestable range ignores it if the start block is higher than
    // 0.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &[]),
                (0, None)
            );

            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &[]),
                (0, None)
            );
        }
        todo!()
    }

    // A block tracker with a single ingestable range respects missing ranges before the processed
    // blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_with_missing_blocks_before(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        let missing_ranges = vec![BlockRange::new(0, rec.status.start_block)];

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec.clone()],
                    &missing_ranges
                ),
                (rec.status.start_block + i, None)
            );

            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec.clone()],
                    &missing_ranges
                ),
                (rec.status.start_block + i + 1, None)
            );
        }
        todo!()
    }

    // A block tracker with a single ingestable range respects missing ranges after the processed
    // blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_with_missing_blocks_after(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        let missing_ranges = vec![
            BlockRange::new(10, 20),
            BlockRange::new(20, 30),
            BlockRange::new(32, 40), // This range skips blocks 31 and 32 so we will not advance automatically to them.
        ];

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec.clone()],
                    &missing_ranges
                ),
                (rec.status.start_block + i, None)
            );

            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // The last iteration moves ahead due to the missed block ranges.
            if i == 9 {
                assert_eq!(
                    block_tracker.highest_fully_processed_block_count(
                        0,
                        &[rec.clone()],
                        &missing_ranges
                    ),
                    (30, None)
                );
            } else {
                assert_eq!(
                    block_tracker.highest_fully_processed_block_count(
                        0,
                        &[rec.clone()],
                        &missing_ranges
                    ),
                    (rec.status.start_block + i + 1, None)
                );
            }
        }

        // Proccess blocks 10-29, this should not change anything since they were reported as
        // missing.
        for i in 10..30 {
            block_tracker.block_processed(rec.key, i);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec.clone()],
                    &missing_ranges
                ),
                (30, None)
            );
        }

        // Process block #30, this should get us to #31
        block_tracker.block_processed(rec.key, 30);
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &missing_ranges),
            (31, None)
        );

        // Process block 31, this should get us to 40 (due to missed range)
        block_tracker.block_processed(rec.key, 31);
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(0, &[rec.clone()], &missing_ranges),
            (40, None)
        );
        todo!()
    }

    // A block tracker with a multiple ingestable ranges waits for both of them.
    // blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_multiple_recs(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };
        let rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
            },
            last_scanned_block: None,
        };

        // Initially, we're at 0.
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                0,
                &[rec1.clone(), rec2.clone()],
                &[]
            ),
            (0, None)
        );

        // Advancing the first ingestable range would only get us up to 10 since at that point we
        // also need the 2nd range to advance.
        for i in 0..20 {
            block_tracker.block_processed(rec1.key, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec1.clone(), rec2.clone()],
                    &[]
                ),
                (min(rec2.status.start_block, i + 1), None)
            );
        }

        // Advancing the second range would get us all the way to the first one and stop there.
        for i in 0..40 {
            block_tracker.block_processed(rec2.key, rec2.status.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    0,
                    &[rec1.clone(), rec2.clone()],
                    &[]
                ),
                (
                    min(
                        rec1.status.start_block + 20, // We advanced the first range 20 times in the previous loop
                        rec2.status.start_block + i + 1
                    ),
                    None
                )
            );
        }

        todo!()
    }

    // Higehst known block count is 0 when there are no inputs.
    #[test_with_logger]
    fn highest_known_block_count_when_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger);

        assert_eq!(block_tracker.highest_known_block_count(), 0);
    }

    // Highest known block count is set to the highest block count that was processed.
    #[test_with_logger]
    fn highest_known_block_count_tracks_processed(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 100);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 80);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 101);
        assert_eq!(block_tracker.highest_known_block_count(), 102);
    }
}
