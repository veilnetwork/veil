//! Vivaldi network coordinate subsystem.
//!
//! Vivaldi NC computes a synthetic coordinate in a 2D+height space such that
//! the Euclidean distance between two coordinates approximates their real RTT.
//!
//! # Usage
//!
//! The coordinate is a **pure optimization hint** — it must never be used as:
//! * a `node_id` or address
//! * a DHT placement key
//! * an ownership or trust anchor
//!
//! It is used only for neighbor ranking and replica ordering.
//!
//! # Algorithm
//!
//! Based on Dabek et al., "Vivaldi: A Decentralized Network Coordinate System"
//! (SIGCOMM 2004). Simplified 2D+height variant.

/// A Vivaldi network coordinate.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VivaldiCoord {
    pub x: f64,
    pub y: f64,
    pub height: f64,
    /// Estimate of local error.
    pub error: f64,
}

impl Default for VivaldiCoord {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            height: 0.1,
            error: 1.0,
        }
    }
}

/// physical-plausibility bounds для peer-reported
/// coordinate fields. Real-world RTT ≤ ~300 ms (geosynchronous), so any
/// 2D coord beyond ±1000 ms-equivalent is не plausible. An attacker
/// publishing `{x:0,y:0,h:0,error:0}` would otherwise appear "near
/// everyone" в distance_estimate и win latency-aware circuit-builder
/// selection — guard-position bias. These bounds are wide enough к
/// fit ANY honest network topology (even satellite hops) и tight
/// enough to prevent the deanonymization-vector exploit.
const VIVALDI_COORD_MAX: f64 = 100_000.0; // ±100 s-equivalent (10× geosync RTT)
const VIVALDI_HEIGHT_MAX: f64 = 100_000.0; // same scale
const VIVALDI_ERROR_FLOOR: f64 = 1e-3; // floor — zero would let attacker
// claim infinite confidence
const VIVALDI_ERROR_CEIL: f64 = 1.0; // saturated uncertainty

impl VivaldiCoord {
    pub fn new() -> Self {
        Self::default()
    }

    /// clamp peer-reported coord fields к physically-
    /// plausible bounds. Calls this BEFORE consuming а peer's coordinate
    /// — `distance_estimate`, `update`, persistence layer. NaN / Infinity
    /// are mapped к conservative-uncertainty defaults (cap-bounded values
    /// + max error) so а malformed peer claim cannot poison routing math.
    pub fn sanitize(&self) -> Self {
        let clamp = |v: f64, cap: f64| {
            if v.is_finite() {
                v.clamp(-cap, cap)
            } else {
                0.0
            }
        };
        let clamp_pos = |v: f64, floor: f64, ceil: f64| {
            if v.is_finite() {
                v.clamp(floor, ceil)
            } else {
                ceil
            }
        };
        Self {
            x: clamp(self.x, VIVALDI_COORD_MAX),
            y: clamp(self.y, VIVALDI_COORD_MAX),
            height: clamp_pos(self.height, 0.0, VIVALDI_HEIGHT_MAX),
            error: clamp_pos(self.error, VIVALDI_ERROR_FLOOR, VIVALDI_ERROR_CEIL),
        }
    }

    /// Estimated RTT (in ms) to a node at `remote`.
    pub fn distance_estimate(&self, remote: &VivaldiCoord) -> f64 {
        // Sanitize peer-reported `remote` before consumption (AT9).
        let remote = remote.sanitize();
        let dx = self.x - remote.x;
        let dy = self.y - remote.y;
        (dx * dx + dy * dy).sqrt() + self.height + remote.height
    }

    /// Update this coordinate given a real RTT sample toward `remote`.
    ///
    /// `rtt_ms` — measured round-trip time in milliseconds.
    /// `remote` — the remote node's published coordinate.
    ///
    /// Uses the standard Vivaldi update rule with adaptive step size.
    pub fn update(&mut self, rtt_ms: f64, remote: &VivaldiCoord) {
        // sanitize peer-reported coord BEFORE update math.
        let remote = remote.sanitize();
        let remote = &remote;
        const CC: f64 = 0.25; // confidence correction
        const CE: f64 = 0.5; // error evolution
        const MAX_STEP: f64 = 0.1;
        // defensive clamp on peer-influenceable input.
        // `probe.rs::record` already clamps RttTable storage, but
        // `update` is called directly from non-probe paths (gossip
        // sim harness, future replication). A peer-reported NaN /
        // Infinity here propagates through `sample_error` and the
        // step computation, poisoning `self.x`/`self.y`/`self.height`
        // permanently. Static-clamp before any math touches the value.
        const RTT_FLOOR_MS: f64 = 1.0;
        const RTT_CEIL_MS: f64 = 60_000.0;
        let rtt_ms = if rtt_ms.is_finite() {
            rtt_ms.clamp(RTT_FLOOR_MS, RTT_CEIL_MS)
        } else {
            // NaN or Infinity from a hostile peer — drop the sample
            // entirely rather than fold a bogus value into the model.
            return;
        };

        let estimated = self.distance_estimate(remote).max(1e-9);
        let sample_error = (rtt_ms - estimated).abs() / rtt_ms.max(1.0);
        let weight = self.error / (self.error + remote.error).max(1e-9);
        self.error =
            (CE * weight * sample_error + self.error * (1.0 - CE * weight)).clamp(0.0, 1.0);

        let step = (CC * weight).min(MAX_STEP);
        let delta = rtt_ms - estimated;
        let force = delta * step;

        // Direction vector from remote to self
        let dx = self.x - remote.x;
        let dy = self.y - remote.y;
        let len = (dx * dx + dy * dy).sqrt().max(1e-9);

        self.x += (dx / len) * force;
        self.y += (dy / len) * force;
        self.height = (self.height + force * 0.1).max(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_to_self_is_just_heights() {
        let c = VivaldiCoord {
            x: 1.0,
            y: 2.0,
            height: 0.05,
            error: 0.5,
        };
        let d = c.distance_estimate(&c);
        // distance = 0 (Euclidean) + 2 * height
        let expected = 2.0 * c.height;
        assert!((d - expected).abs() < 1e-9);
    }

    #[test]
    fn distance_symmetric() {
        let a = VivaldiCoord {
            x: 0.0,
            y: 0.0,
            height: 0.1,
            error: 0.5,
        };
        let b = VivaldiCoord {
            x: 10.0,
            y: 0.0,
            height: 0.2,
            error: 0.5,
        };
        assert!((a.distance_estimate(&b) - b.distance_estimate(&a)).abs() < 1e-9);
    }

    #[test]
    fn update_converges_toward_rtt() {
        let remote = VivaldiCoord::default();
        let mut local = VivaldiCoord::default();
        let target_rtt = 100.0_f64;

        for _ in 0..500 {
            local.update(target_rtt, &remote);
        }

        let estimated = local.distance_estimate(&remote);
        // Should converge to within 30% of target
        assert!(
            (estimated - target_rtt).abs() < target_rtt * 0.3,
            "estimated={estimated:.2} target={target_rtt}"
        );
    }

    #[test]
    fn update_does_not_panic_on_zero_rtt() {
        let mut c = VivaldiCoord::default();
        c.update(0.0, &VivaldiCoord::default());
    }

    #[test]
    fn height_stays_non_negative() {
        let mut c = VivaldiCoord {
            x: 0.0,
            y: 0.0,
            height: 0.001,
            error: 0.5,
        };
        for _ in 0..50 {
            c.update(1.0, &VivaldiCoord::default());
        }
        assert!(c.height >= 0.0);
    }

    /// — VivaldiCoord JSON persistence roundtrip.
    #[test]
    fn json_roundtrip_preserves_all_fields() {
        let original = VivaldiCoord {
            x: 1.23,
            y: -4.56,
            height: 0.07,
            error: 0.42,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: VivaldiCoord = serde_json::from_str(&json).expect("deserialize");
        assert!((decoded.x - original.x).abs() < 1e-12);
        assert!((decoded.y - original.y).abs() < 1e-12);
        assert!((decoded.height - original.height).abs() < 1e-12);
        assert!((decoded.error - original.error).abs() < 1e-12);
    }

    /// — Default coordinate restores correctly from JSON.
    #[test]
    fn default_coord_roundtrips() {
        let c = VivaldiCoord::default();
        let json = serde_json::to_string(&c).unwrap();
        let d: VivaldiCoord = serde_json::from_str(&json).unwrap();
        assert_eq!(c, d);
    }
}
