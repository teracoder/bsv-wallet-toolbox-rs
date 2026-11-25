//! `ingest_merkle_proofs`: many proofs, each stored exactly as
//! `ingest_merkle_proof` stores it, with one gate read, one tracker
//! question per (root, height) and one write per `INGEST_PROOFS_PER_WRITE`
//! proofs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bsv_rs::transaction::{
    ChainTracker, ChainTrackerError, MerklePath, MerklePathLeaf, MockChainTracker,
};
use chrono::Utc;

use super::reorg_tests::{insert_proven, insert_req, open_gate, single_leaf_bump, storage};
use super::{ProofToIngest, StorageSqlx, INGEST_PROOFS_PER_WRITE};
use crate::storage::ProofIngestOutcome;

/// A tracker that knows the given `(height, root)` pairs and counts the
/// questions it is asked.
struct CountingTracker {
    inner: MockChainTracker,
    asked: AtomicUsize,
}

impl CountingTracker {
    fn new(roots: &[(u32, &str)]) -> Self {
        let mut inner = MockChainTracker::new(1000);
        for (h, r) in roots {
            inner.add_root(*h, r.to_string());
        }
        Self {
            inner,
            asked: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ChainTracker for CountingTracker {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> std::result::Result<bool, ChainTrackerError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.is_valid_root_for_height(root, height).await
    }

    async fn current_height(&self) -> std::result::Result<u32, ChainTrackerError> {
        self.inner.current_height().await
    }
}

/// A BUMP proving `a` and `b` as the two leaves of one block: both compute
/// the same root.
fn two_leaf_bump(height: u32, a: &str, b: &str) -> Vec<u8> {
    MerklePath {
        block_height: height,
        path: vec![vec![
            MerklePathLeaf::new_txid(0, a.to_string()),
            MerklePathLeaf::new_txid(1, b.to_string()),
        ]],
    }
    .to_binary()
}

fn root_of(bump: &[u8], txid: &str) -> String {
    MerklePath::from_binary(bump)
        .unwrap()
        .compute_root(Some(txid))
        .unwrap()
}

fn txid(n: u8) -> String {
    format!("{:02x}", n).repeat(32)
}

async fn insert_seen(s: &StorageSqlx, txid: &str, status: &str) {
    sqlx::query(
        "INSERT INTO broadcast_seen (txid, provider, status, seen_at) VALUES (?, 'chain', ?, '2020-01-01 00:00:00')",
    )
    .bind(txid)
    .bind(status)
    .execute(s.writer())
    .await
    .unwrap();
}

/// Every row a proof store or its record completion writes, timestamps
/// left out (and `broadcast_seen.seen_at` kept only as "refreshed or not").
async fn dump(s: &StorageSqlx) -> Vec<String> {
    let queries = [
        "SELECT 'proven|' || txid || '|' || height || '|' || idx || '|' || block_hash || '|' || merkle_root || '|' || hex(merkle_path) || '|' || hex(raw_tx) || '|' || proven_tx_id FROM proven_txs ORDER BY txid",
        "SELECT 'req|' || txid || '|' || status || '|' || attempts || '|' || IFNULL(proven_tx_id, '-') FROM proven_tx_reqs ORDER BY txid",
        "SELECT 'tx|' || IFNULL(txid, '-') || '|' || status || '|' || IFNULL(proven_tx_id, '-') FROM transactions ORDER BY txid",
        "SELECT 'root|' || txid || '|' || height || '|' || merkle_root FROM proof_root_checks ORDER BY txid",
        "SELECT 'seen|' || txid || '|' || provider || '|' || status || '|' || (seen_at = '2020-01-01 00:00:00') FROM broadcast_seen ORDER BY txid, provider",
    ];
    let mut rows = Vec::new();
    for q in queries {
        let mut part: Vec<String> = sqlx::query_scalar(q).fetch_all(s.pool()).await.unwrap();
        rows.append(&mut part);
    }
    rows
}

/// The proofs of the differential test and the store they meet.
struct Case {
    proofs: Vec<(String, Vec<u8>, u32, String)>,
    tracker_roots: Vec<(u32, String)>,
}

/// One store seeded for every outcome a proof can have:
/// - `a`, `b`: new, two leaves of one block (one root);
///
/// (`MockChainTracker` holds one root a height, so each root has its own.)
/// - `a` again in the same call: its row now exists, unchanged;
/// - `c`: new, but no raw bytes anywhere (nothing written);
/// - `e`: above the gate (deferred);
/// - `x`: bytes that are no BUMP;
/// - `f`: a root the tracker does not know;
/// - `g`: stored before with the same anchor and no block hash (backfilled);
/// - `h`: stored before in another block (re-anchored).
///
/// `a` was seen (`seen`), `b` already `mined`, so the mined memory is a
/// `Set` for one and a `Keep` for the other.
async fn seeded() -> (StorageSqlx, Case) {
    let s = storage().await;
    open_gate(&s, 200).await;
    let (a, b, c, e, x, f, g, h) = (
        txid(0xa1),
        txid(0xb2),
        txid(0xc3),
        txid(0xe5),
        txid(0x77),
        txid(0xf6),
        txid(0x07),
        txid(0x08),
    );
    for (n, t) in [&a, &b, &e, &f, &g, &h].iter().enumerate() {
        insert_req(&s, t, &[n as u8 + 1; 12], "unmined", 0, None, Utc::now()).await;
    }
    insert_proven(&s, &g, 100, "", &[9; 12], &single_leaf_bump(100, &g)).await;
    insert_proven(
        &s,
        &h,
        90,
        &"d".repeat(64),
        &[10; 12],
        &single_leaf_bump(90, &h),
    )
    .await;
    insert_seen(&s, &a, "seen").await;
    insert_seen(&s, &b, "mined").await;

    let ab = two_leaf_bump(103, &a, &b);
    let root_ab = root_of(&ab, &a);
    let proofs = vec![
        (a.clone(), ab.clone(), 103, "a".repeat(64)),
        (b.clone(), ab.clone(), 103, "a".repeat(64)),
        (c.clone(), single_leaf_bump(104, &c), 104, "a".repeat(64)),
        (a.clone(), ab, 103, "a".repeat(64)),
        (e.clone(), single_leaf_bump(300, &e), 300, "b".repeat(64)),
        (x, vec![1, 2, 3], 100, "a".repeat(64)),
        (f.clone(), single_leaf_bump(105, &f), 105, "a".repeat(64)),
        (g.clone(), single_leaf_bump(100, &g), 100, "c".repeat(64)),
        (h.clone(), single_leaf_bump(110, &h), 110, "e".repeat(64)),
    ];
    let tracker_roots = vec![(103, root_ab), (104, c), (100, g), (110, h)];
    (
        s,
        Case {
            proofs,
            tracker_roots,
        },
    )
}

fn as_args(case: &Case) -> Vec<ProofToIngest<'_>> {
    case.proofs
        .iter()
        .map(|(t, bump, height, hash)| ProofToIngest {
            txid: t,
            merkle_path: bump,
            block_height: *height,
            block_hash: hash,
            header_merkle_root: None,
        })
        .collect()
}

async fn wire(s: &StorageSqlx, case: &Case) -> Arc<CountingTracker> {
    let roots: Vec<(u32, &str)> = case
        .tracker_roots
        .iter()
        .map(|(h, r)| (*h, r.as_str()))
        .collect();
    let tracker = Arc::new(CountingTracker::new(&roots));
    s.set_chain_tracker(tracker.clone()).await;
    tracker
}

/// The batch writes what the same proofs write one call at a time, and
/// answers each proof as its own call does, for every outcome.
#[tokio::test]
async fn a_batch_writes_what_one_proof_at_a_time_writes() {
    let (one_by_one, case) = seeded().await;
    wire(&one_by_one, &case).await;
    let mut singles = Vec::new();
    for p in as_args(&case) {
        singles.push(
            one_by_one
                .ingest_merkle_proof(
                    p.txid,
                    p.merkle_path,
                    p.block_height,
                    p.block_hash,
                    p.header_merkle_root,
                )
                .await
                .unwrap(),
        );
    }

    let (batched, case_b) = seeded().await;
    wire(&batched, &case_b).await;
    let outcomes = batched
        .ingest_merkle_proofs(&as_args(&case_b))
        .await
        .unwrap();

    let names = |v: &[ProofIngestOutcome]| v.iter().map(|o| format!("{o:?}")).collect::<Vec<_>>();
    assert_eq!(
        names(&outcomes),
        names(&singles),
        "the same answer per proof"
    );
    let kinds: Vec<&str> = outcomes
        .iter()
        .map(|o| match o {
            ProofIngestOutcome::Ingested(_) => "ingested",
            ProofIngestOutcome::InvalidProof(_) => "invalid",
            ProofIngestOutcome::DeferredAboveProcessedHeight { .. } => "deferred",
            ProofIngestOutcome::InvalidMerkleRoot { .. } => "bad-root",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "ingested", "ingested", "invalid", "ingested", "deferred", "invalid", "bad-root",
            "ingested", "ingested"
        ],
        "precondition: the case reaches every outcome"
    );
    assert_eq!(
        dump(&batched).await,
        dump(&one_by_one).await,
        "the same rows"
    );
}

/// The proofs of one block share their root: the tracker is asked once for
/// them however many there are, and once more for each other (root, height).
#[tokio::test]
async fn a_blocks_proofs_ask_the_tracker_once() {
    let (s, case) = seeded().await;
    let tracker = wire(&s, &case).await;
    let block: Vec<ProofToIngest<'_>> = as_args(&case).into_iter().take(4).collect();
    let outcomes = s.ingest_merkle_proofs(&block).await.unwrap();
    assert_eq!(outcomes.len(), 4);
    // a, b and a again share one root; c is its own.
    assert_eq!(tracker.asked.load(Ordering::SeqCst), 2);
}

/// More proofs than one write holds: every one is stored and completed.
#[tokio::test]
async fn proofs_past_one_write_are_all_stored() {
    let s = storage().await;
    open_gate(&s, 1000).await;
    let n = INGEST_PROOFS_PER_WRITE + 3;
    let txids: Vec<String> = (0..n).map(|i| format!("{:064x}", i + 1)).collect();
    let heights: Vec<u32> = (0..n).map(|i| 100 + i as u32).collect();
    let bumps: Vec<Vec<u8>> = txids
        .iter()
        .zip(&heights)
        .map(|(t, h)| single_leaf_bump(*h, t))
        .collect();
    for t in &txids {
        insert_req(&s, t, &[1; 12], "unmined", 0, None, Utc::now()).await;
    }
    let roots: Vec<(u32, &str)> = heights
        .iter()
        .zip(&txids)
        .map(|(h, t)| (*h, t.as_str()))
        .collect();
    s.set_chain_tracker(Arc::new(CountingTracker::new(&roots)))
        .await;
    let hash = "a".repeat(64);
    let args: Vec<ProofToIngest<'_>> = txids
        .iter()
        .zip(bumps.iter().zip(&heights))
        .map(|(t, (b, h))| ProofToIngest {
            txid: t,
            merkle_path: b,
            block_height: *h,
            block_hash: &hash,
            header_merkle_root: None,
        })
        .collect();

    let outcomes = s.ingest_merkle_proofs(&args).await.unwrap();

    assert!(outcomes
        .iter()
        .all(|o| matches!(o, ProofIngestOutcome::Ingested(_))));
    let completed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proven_tx_reqs WHERE status = 'completed' AND proven_tx_id IS NOT NULL",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(completed as usize, n);
}

/// No tracker, no proof: every proof of the batch is refused and nothing is
/// written.
#[tokio::test]
async fn a_trackerless_batch_stores_nothing() {
    let (s, case) = seeded().await;
    let before = dump(&s).await;
    let outcomes = s.ingest_merkle_proofs(&as_args(&case)).await.unwrap();
    assert!(outcomes.iter().all(|o| matches!(
        o,
        ProofIngestOutcome::TrackerUnavailable
            | ProofIngestOutcome::InvalidProof(_)
            | ProofIngestOutcome::DeferredAboveProcessedHeight { .. }
    )));
    assert!(outcomes
        .iter()
        .any(|o| matches!(o, ProofIngestOutcome::TrackerUnavailable)));
    assert_eq!(dump(&s).await, before);
}

/// An empty batch answers nothing and touches nothing.
#[tokio::test]
async fn an_empty_batch_answers_nothing() {
    let s = storage().await;
    assert!(s.ingest_merkle_proofs(&[]).await.unwrap().is_empty());
}
