//! WHEN a node offers itself at the public meeting points.
//!
//! Announcing is what puts this node's address in front of strangers, and a
//! node that announces around the clock is a node whose address can be
//! collected once and blocked forever. The seeds are the case that matters:
//! the production seed list ships EMPTY — `veil_bootstrap::builtin_seeds()`
//! returns nothing and the app's `assets/prod/seeds.json` holds nothing — so a
//! client learns a seed at a meeting point or not at all. That is what makes
//! this worth having: an address that is not announced right now is not merely
//! quieter, it is unobtainable, because there is no second copy anywhere for
//! an observer to fall back on.
//!
//! Four seeds on eight-hour shifts therefore show an index-watcher one or two
//! addresses at a time instead of four, and the set it sees this morning is not
//! the set it sees tonight.
//!
//! WHAT THIS DOES NOT DO. It does not hide anything from someone who already
//! holds an address: a seed that has stopped announcing still accepts, still
//! relays, still serves every node that knows it. `global.bootstrap` governs
//! the ANNOUNCE and nothing else — which is also why rotating it costs the
//! network nothing but discoverability, and why a client that remembers its
//! peers across restarts (`global.remembered_peers`) barely notices.
//!
//! Times are UTC and the granularity is a minute. A schedule expressed in
//! local time would move with a machine's timezone database, and four hosts
//! disagreeing about when their shift starts is the one failure this cannot
//! detect from the inside.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const MINUTES_PER_DAY: u32 = 24 * 60;

/// When a node announces itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AnnounceSchedule {
    /// Around the clock. The behaviour every node had before this existed, and
    /// the right answer for a node whose address is already public.
    #[default]
    Always,

    /// One daily UTC window, e.g. `01:00-09:00`. Wraps midnight when the end
    /// is before the start (`22:00-06:00` is eight hours, not sixteen).
    ///
    /// The mode that GUARANTEES coverage: four seeds given overlapping windows
    /// leave no minute of the day unserved, and the operator can see that from
    /// the four config files without running anything.
    Window { start_min: u32, end_min: u32 },

    /// A short appearance every so often, e.g. `every 2h for 20m`.
    ///
    /// Aligned to the UTC day rather than to process start, so a restart does
    /// not shift the pattern and two nodes given the same period do not drift
    /// apart. The offset that keeps them from appearing in lockstep is the
    /// node's own, applied below.
    Every { period_min: u32, for_min: u32 },

    /// A window of `hours` whose START is drawn from this node's identity and
    /// today's date.
    ///
    /// No coordination and no two nodes configured alike: each picks its own
    /// slot, and every node moves to a different slot tomorrow. What it trades
    /// away is the guarantee — four nodes CAN land in the same eight hours by
    /// chance, leaving the rest of the day unserved. Use it where coverage is
    /// a preference; use [`Self::Window`] where it is a promise.
    Derived { hours: u32 },
}

impl AnnounceSchedule {
    /// Whether this node should be announcing at `unix_secs`.
    ///
    /// `node_id` gives every node its own offset, so nodes sharing a schedule
    /// do not flip together — a synchronised flip across several hosts is
    /// itself a signature, and the thing it signs is "these belong together".
    pub fn announcing_at(self, unix_secs: u64, node_id: &[u8; 32]) -> bool {
        let minute_of_day =
            u32::try_from((unix_secs / 60) % u64::from(MINUTES_PER_DAY)).unwrap_or(0);
        match self {
            Self::Always => true,
            Self::Window { start_min, end_min } => {
                in_window(minute_of_day, start_min, window_len(start_min, end_min))
            }
            Self::Every {
                period_min,
                for_min,
            } => {
                if period_min == 0 {
                    return true;
                }
                // The offset is the node's, so two nodes on `every 2h` appear
                // at different minutes of each two-hour cycle rather than
                // together on the hour.
                let offset = u32::from(node_id[0]) % period_min.max(1);
                let phase = (minute_of_day + period_min - offset % period_min) % period_min;
                phase < for_min.min(period_min)
            }
            Self::Derived { hours } => {
                let day = unix_secs / (u64::from(MINUTES_PER_DAY) * 60);
                let start = derived_start(node_id, day);
                in_window(minute_of_day, start, (hours * 60).min(MINUTES_PER_DAY))
            }
        }
    }
}

fn window_len(start_min: u32, end_min: u32) -> u32 {
    if end_min >= start_min {
        end_min - start_min
    } else {
        // Wraps midnight.
        MINUTES_PER_DAY - start_min + end_min
    }
}

fn in_window(minute_of_day: u32, start: u32, len: u32) -> bool {
    if len == 0 {
        return false;
    }
    if len >= MINUTES_PER_DAY {
        return true;
    }
    let from_start = (minute_of_day + MINUTES_PER_DAY - start % MINUTES_PER_DAY) % MINUTES_PER_DAY;
    from_start < len
}

/// The minute of the day this node starts on `day`, from its identity.
///
/// BLAKE3 over the id and the day number: public inputs and a public function,
/// so an observer holding the id can compute tomorrow's slot. That is not the
/// property this mode sells — what it removes is the need to configure four
/// hosts consistently, and what it costs is the guarantee of coverage. The
/// unpredictability it does buy is against an observer who has NOT seen the
/// node id, which at a meeting point is everyone who has not met it.
fn derived_start(node_id: &[u8; 32], day: u64) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(&day.to_be_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    raw % MINUTES_PER_DAY
}

/// The shortest appearance that can actually be observed.
///
/// Both announcers check this schedule once per rendezvous pass
/// (`RENDEZVOUS_INTERVAL`, 15 minutes), so anything shorter can fall entirely
/// between two checks. Kept here rather than imported from the runtime: this
/// crate is what refuses the config, and a number that lives in two places
/// drifts.
pub const MIN_WINDOW_MINUTES: u32 = 15;

fn parse_hhmm(text: &str) -> Option<u32> {
    let (h, m) = text.split_once(':')?;
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// `90m`, `2h`, `8h` → minutes.
///
/// Split on the CHARACTER, not on the byte before the end: `split_at` panics
/// when the index is not a char boundary, and a config file is text somebody
/// typed. `2ч` — a Cyrillic unit two bytes wide — took the parser's own
/// process down with it (report27 V04). A bad unit is a configuration mistake
/// and must read as one.
fn parse_duration(text: &str) -> Option<u32> {
    let text = text.trim();
    let unit = text.chars().next_back()?;
    let digits = &text[..text.len() - unit.len_utf8()];
    let n: u32 = digits.parse().ok()?;
    match unit {
        'm' => Some(n),
        'h' => n.checked_mul(60),
        _ => None,
    }
}

impl FromStr for AnnounceSchedule {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("always") || value.is_empty() {
            return Ok(Self::Always);
        }
        if let Some(rest) = value.strip_prefix("derived") {
            let hours = match rest.trim().strip_prefix(':') {
                Some(d) => {
                    parse_duration(d.trim()).ok_or_else(|| format!("bad derived window: {rest}"))?
                        / 60
                }
                None => 8,
            };
            if hours == 0 || hours > 24 {
                return Err(format!("derived window out of range: {hours}h"));
            }
            return Ok(Self::Derived { hours });
        }
        if let Some(rest) = value.strip_prefix("every") {
            // `every 2h for 20m`
            let (period, tail) = rest
                .trim()
                .split_once(' ')
                .ok_or_else(|| format!("expected `every <period> for <length>`: {value}"))?;
            let for_part = tail
                .trim()
                .strip_prefix("for")
                .ok_or_else(|| format!("expected `for <length>`: {value}"))?;
            let period_min =
                parse_duration(period).ok_or_else(|| format!("bad period: {period}"))?;
            let for_min =
                parse_duration(for_part.trim()).ok_or_else(|| format!("bad length: {for_part}"))?;
            if period_min == 0 {
                return Err("period must be longer than nothing".to_owned());
            }
            if for_min == 0 || for_min > period_min {
                return Err(format!(
                    "appearance ({for_min}m) must fit inside the period ({period_min}m)"
                ));
            }
            if for_min < MIN_WINDOW_MINUTES {
                // A WINDOW NOBODY WILL BE LOOKING AT IS NOT A WINDOW.
                //
                // The announcers consult this schedule on the rendezvous
                // cadence — once every 15 minutes — so a two-minute window can
                // open and close entirely between two checks, and a config
                // that reads as correct then announces nothing at all
                // (report27 V20). Refused at the point it is written rather
                // than discovered as silence on a seed.
                return Err(format!(
                    "an appearance of {for_min}m is shorter than the \
                     {MIN_WINDOW_MINUTES}m the announcers check on, so it can \
                     pass unseen: make it {MIN_WINDOW_MINUTES}m or longer"
                ));
            }
            return Ok(Self::Every {
                period_min,
                for_min,
            });
        }
        if let Some((start, end)) = value.split_once('-') {
            let start_min =
                parse_hhmm(start.trim()).ok_or_else(|| format!("bad start time: {start}"))?;
            let end_min = parse_hhmm(end.trim()).ok_or_else(|| format!("bad end time: {end}"))?;
            if start_min == end_min {
                return Err("a window that starts when it ends is never open".to_owned());
            }
            return Ok(Self::Window { start_min, end_min });
        }
        Err(format!(
            "expected `always`, `HH:MM-HH:MM`, `every <period> for <length>` \
             or `derived[:<hours>h]`, got: {value}"
        ))
    }
}

impl fmt::Display for AnnounceSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => f.write_str("always"),
            Self::Window { start_min, end_min } => write!(
                f,
                "{:02}:{:02}-{:02}:{:02}",
                start_min / 60,
                start_min % 60,
                end_min / 60,
                end_min % 60
            ),
            Self::Every {
                period_min,
                for_min,
            } => write!(f, "every {period_min}m for {for_min}m"),
            Self::Derived { hours } => write!(f, "derived:{hours}h"),
        }
    }
}

impl Serialize for AnnounceSchedule {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AnnounceSchedule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 32] = [0x11; 32];
    const DAY: u64 = 20_000 * 24 * 60 * 60;

    fn at(hh: u32, mm: u32) -> u64 {
        DAY + u64::from(hh) * 3600 + u64::from(mm) * 60
    }

    #[test]
    fn always_is_the_default_and_never_closes() {
        assert_eq!(AnnounceSchedule::default(), AnnounceSchedule::Always);
        for hour in 0..24 {
            assert!(AnnounceSchedule::Always.announcing_at(at(hour, 0), &ID));
        }
    }

    #[test]
    fn a_window_is_open_inside_and_shut_outside() {
        let s: AnnounceSchedule = "01:00-09:00".parse().expect("parses");
        assert!(!s.announcing_at(at(0, 59), &ID));
        assert!(s.announcing_at(at(1, 0), &ID));
        assert!(s.announcing_at(at(8, 59), &ID));
        assert!(!s.announcing_at(at(9, 0), &ID), "the end is exclusive");
        assert!(!s.announcing_at(at(23, 0), &ID));
    }

    #[test]
    fn a_window_may_wrap_midnight() {
        // Eight hours, not sixteen: the shift a night operator would write.
        let s: AnnounceSchedule = "22:00-06:00".parse().expect("parses");
        assert!(s.announcing_at(at(23, 30), &ID));
        assert!(s.announcing_at(at(0, 0), &ID));
        assert!(s.announcing_at(at(5, 59), &ID));
        assert!(!s.announcing_at(at(6, 0), &ID));
        assert!(!s.announcing_at(at(12, 0), &ID));
    }

    #[test]
    fn four_seeds_on_eight_hour_shifts_leave_no_minute_unserved() {
        // THE ARRANGEMENT THIS EXISTS FOR, checked minute by minute rather
        // than reasoned about: four windows of eight hours starting every six,
        // which overlap by two and cover the day twice over.
        let shifts: Vec<AnnounceSchedule> =
            ["00:00-08:00", "06:00-14:00", "12:00-20:00", "18:00-02:00"]
                .iter()
                .map(|s| s.parse().expect("parses"))
                .collect();
        for minute in 0..MINUTES_PER_DAY {
            let now = DAY + u64::from(minute) * 60;
            let live = shifts.iter().filter(|s| s.announcing_at(now, &ID)).count();
            assert!(
                live >= 1,
                "minute {minute} of the day has no seed announcing"
            );
            assert!(
                live <= 2,
                "minute {minute} has {live} seeds up — the overlap is meant to be one neighbour"
            );
        }
    }

    #[test]
    fn every_two_hours_appears_and_goes_away() {
        let s: AnnounceSchedule = "every 2h for 20m".parse().expect("parses");
        let mut seen_up = 0;
        let mut seen_down = 0;
        for minute in 0..MINUTES_PER_DAY {
            if s.announcing_at(DAY + u64::from(minute) * 60, &ID) {
                seen_up += 1;
            } else {
                seen_down += 1;
            }
        }
        // Twelve appearances of twenty minutes in a day.
        assert_eq!(seen_up, 12 * 20);
        assert_eq!(seen_down, MINUTES_PER_DAY - 12 * 20);
    }

    #[test]
    fn two_nodes_on_one_period_do_not_flip_together() {
        // A synchronised flip across several hosts is itself a signature, and
        // what it signs is "these belong together".
        let s: AnnounceSchedule = "every 2h for 20m".parse().expect("parses");
        let a = [0x00u8; 32];
        let b = [0x37u8; 32];
        let differ = (0..MINUTES_PER_DAY).any(|minute| {
            let now = DAY + u64::from(minute) * 60;
            s.announcing_at(now, &a) != s.announcing_at(now, &b)
        });
        assert!(differ, "two nodes announced in lockstep");
    }

    #[test]
    fn a_derived_window_moves_with_the_day_and_with_the_node() {
        let s: AnnounceSchedule = "derived:8h".parse().expect("parses");
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(
            derived_start(&a, 20_000),
            derived_start(&b, 20_000),
            "two nodes drew the same slot"
        );
        assert_ne!(
            derived_start(&a, 20_000),
            derived_start(&a, 20_001),
            "the slot did not move overnight"
        );
        // And it is a real window: up for a third of the day, down for the rest.
        let up = (0..MINUTES_PER_DAY)
            .filter(|m| s.announcing_at(DAY + u64::from(*m) * 60, &a))
            .count();
        assert_eq!(up, 8 * 60);
    }

    #[test]
    fn what_will_not_parse_is_refused_rather_than_guessed() {
        // A schedule nobody can read is a node that announces at the wrong
        // time, and the wrong time here is "never".
        for bad in [
            "09:00-09:00",
            "25:00-01:00",
            "01:00",
            "every 2h",
            "every 0h for 5m",
            // Shorter than the cadence the announcers check on: it would read
            // as a correct config and announce nothing (report27 V20).
            "every 2h for 5m",
            "every 2h for 1m",
            "every 10m for 20m",
            "derived:0h",
            "derived:48h",
            "sometimes",
            // A config file is text somebody typed, and a unit outside ASCII
            // is a mistake — not a reason to take the process down. Splitting
            // one byte before the end panicked on every multi-byte unit
            // (report27 V04); these are the cheapest ones to write by
            // accident on a Russian keyboard.
            "2ч",
            "90м",
            "every 2ч for 20m",
            "derived:8ч",
            "2h⏰",
        ] {
            assert!(
                bad.parse::<AnnounceSchedule>().is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn every_schedule_survives_a_round_trip_through_its_text() {
        for text in ["always", "01:00-09:00", "22:00-06:00", "derived:8h"] {
            let parsed: AnnounceSchedule = text.parse().expect("parses");
            assert_eq!(parsed.to_string(), text);
            assert_eq!(parsed.to_string().parse::<AnnounceSchedule>(), Ok(parsed));
        }
        // `every` normalises its units, so it round-trips through the value
        // rather than through the spelling.
        let every: AnnounceSchedule = "every 2h for 20m".parse().expect("parses");
        assert_eq!(every.to_string().parse::<AnnounceSchedule>(), Ok(every));
    }
}
