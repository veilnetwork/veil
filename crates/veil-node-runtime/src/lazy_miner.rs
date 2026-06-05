//! Background identity nonce miner —.
//!
//! Mines a better identity nonce during idle periods, upgrading the node's
//! trust level (leading-zero-bit difficulty) without manual intervention.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::sync::watch;

use veil_cfg as cfg;
use veil_crypto::pow::score::{CachedSigningKey, PowScratch, pow_score_raw_into, u32_to_nonce};
use veil_observability::{NodeLogger, NodeMetrics};

const BATCH_SIZE: u32 = 1024;
const YIELD_MS: u64 = 50;
/// Pause mining when active sessions exceed this fraction of max_concurrent.
const SESSION_LOAD_THRESHOLD: f64 = 0.8;
/// How long to sleep when load is detected before re-checking.
const LOAD_PAUSE_MS: u64 = 5_000;

pub(crate) async fn spawn_lazy_miner(
    config_path: std::path::PathBuf,
    identity: cfg::IdentityConfig,
    metrics: Option<Arc<NodeMetrics>>,
    max_concurrent: usize,
    mut shutdown_rx: watch::Receiver<bool>,
    logger: Arc<NodeLogger>,
) {
    if !identity.lazy_mining {
        return;
    }
    let max_difficulty = identity.max_lazy_difficulty;
    let algo = identity.algo;

    let current_difficulty = match cfg::identity::DomainIdentity::from_config(&identity) {
        Ok(di) => match di.pow_score() {
            Ok(score) => score.zero_bits as u8,
            Err(e) => {
                logger.warn("lazy_miner.init_err", format!("pow_score failed: {e}"));
                return;
            }
        },
        Err(e) => {
            logger.warn(
                "lazy_miner.init_err",
                format!("identity config invalid: {e}"),
            );
            return;
        }
    };

    if current_difficulty >= max_difficulty {
        logger.info(
            "lazy_miner.skip",
            format!("identity difficulty {current_difficulty} already >= cap {max_difficulty}"),
        );
        return;
    }

    logger.info(
        "lazy_miner.start",
        format!("current difficulty={current_difficulty} target={max_difficulty}"),
    );

    let pk_bytes: Arc<Vec<u8>> = {
        let decoded = match veil_crypto::signature::decode_public_key(algo, &identity.public_key) {
            Ok(b) => b,
            Err(e) => {
                logger.warn("lazy_miner.init_err", format!("decode public_key: {e}"));
                return;
            }
        };
        Arc::new(decoded)
    };
    let sk_bytes: Arc<Vec<u8>> = {
        let decoded = match veil_crypto::signature::decode_private_key(algo, &identity.private_key)
        {
            Ok(b) => (*b).clone(),
            Err(e) => {
                logger.warn("lazy_miner.init_err", format!("decode private_key: {e}"));
                return;
            }
        };
        Arc::new(decoded)
    };

    let start_nonce = {
        let bytes = STANDARD.decode(&identity.nonce).unwrap_or_default();
        if bytes.len() >= 4 {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).wrapping_add(1)
        } else {
            0
        }
    };

    let mut best_difficulty = current_difficulty;
    let mut candidate = start_nonce;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        // Load detection: pause when session load is high.
        if let Some(ref m) = metrics {
            let active = m.snapshot().active_sessions;
            let threshold = (max_concurrent as f64 * SESSION_LOAD_THRESHOLD) as u64;
            if max_concurrent > 0 && active >= threshold {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(LOAD_PAUSE_MS)) => {}
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                }
                continue;
            }
        }

        let batch_result = tokio::task::spawn_blocking({
            let pk = Arc::clone(&pk_bytes);
            let sk = Arc::clone(&sk_bytes);
            let from = candidate;
            move || {
                let signing_key = match CachedSigningKey::from_private_key(algo, &sk) {
                    Ok(k) => k,
                    Err(_) => return (0u8, from),
                };
                let mut local_best_diff = 0u8;
                let mut local_best_nonce = from;
                // Reuse scratch across the whole batch — zero per-nonce allocation.
                let mut scratch = PowScratch::default();
                for i in 0..BATCH_SIZE {
                    let n = from.wrapping_add(i);
                    let nonce_bytes = u32_to_nonce(n);
                    if let Ok(score) =
                        pow_score_raw_into(&pk, &signing_key, &nonce_bytes, &mut scratch)
                    {
                        let d = score.zero_bits as u8;
                        if d > local_best_diff {
                            local_best_diff = d;
                            local_best_nonce = n;
                        }
                    }
                }
                (local_best_diff, local_best_nonce)
            }
        })
        .await;

        let (batch_diff, batch_nonce) = match batch_result {
            Ok(r) => r,
            Err(_) => break,
        };

        if batch_diff > best_difficulty {
            best_difficulty = batch_diff;

            let nonce_b64 = STANDARD.encode(u32_to_nonce(batch_nonce));

            logger.info(
                "lazy_miner.upgraded",
                format!("difficulty={best_difficulty} nonce={nonce_b64}"),
            );

            upgrade_nonce_in_config(&config_path, &nonce_b64, &logger);

            if best_difficulty >= max_difficulty {
                logger.info("lazy_miner.done", format!("reached cap {max_difficulty}"));
                break;
            }
        }

        candidate = candidate.wrapping_add(BATCH_SIZE);

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(YIELD_MS)) => {}
            Ok(_) = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

fn upgrade_nonce_in_config(
    config_path: &std::path::Path,
    new_nonce_b64: &str,
    logger: &NodeLogger,
) {
    let result = (|| -> Result<(), String> {
        let mut config = cfg::load_config(config_path).map_err(|e| e.to_string())?;
        let identity = config.identity.as_mut().ok_or("no identity section")?;
        identity.nonce = new_nonce_b64.to_owned();
        identity.node_id = cfg::NodeId::from_public_key(identity.algo, &identity.public_key).ok();
        cfg::save_config(config_path, &config).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(e) = result {
        logger.warn("lazy_miner.config_write_err", format!("err={e}"));
    }
}
