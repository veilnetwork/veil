//! Talking to a relay: publish one event, ask for others.
//!
//! Over the SAME public-PKI TLS path the HTTPS bootstrap layer uses — Mozilla
//! roots, this build's ECH-GREASE setting, and its TLS fingerprint. A second
//! TLS stack here would give veil nodes a handshake that looks like nothing
//! else veil does, which is the opposite of the point.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use veil_transport::TransportContext;

#[cfg(not(feature = "tls-boring"))]
use veil_transport::tls::connect_pki_verified_https_stream;
#[cfg(feature = "tls-boring")]
use veil_transport::tls_boring::connect_pki_verified_https_stream;

use crate::event::{Event, verify};

/// Relays this build asks when the operator names none.
///
/// Public, free, run by unrelated people. The list is plural because any one
/// of them may be down -- and measured, they are: on one pass two answered and
/// three did not, on another four answered. The ones behind a CDN fail as a
/// connection reset or a 503 when their origin is unwell, which reads like a
/// fault on this side and is not one. `relay.nostr.band` was dropped after
/// timing out on every attempt for a day, from this client and from `curl`
/// alike: a relay that never answers spends the pass's budget and returns
/// nothing.
///
/// Any one of them may also be lying. Every event they hand back is verified
/// before a word of it is believed, so a hostile relay costs a wasted query
/// and nothing else. That is why the list can be long without being a trust
/// decision, rate-limiting, or gone for good — and losing one is
/// supposed to cost nothing.
pub const PUBLIC_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
    "wss://relay.primal.net",
    "wss://nostr.oxtr.dev",
    "wss://offchain.pub",
    "wss://relay.snort.social",
];

/// Longest a single relay exchange may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most events read from one relay in one query. A relay that answers with
/// thousands is answering a question nobody asked.
pub const MAX_EVENTS: usize = 64;

/// Largest frame accepted. Relay messages are a few hundred bytes; this is
/// room to spare and a bound on what a stranger can make this node allocate.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

/// Why an exchange failed.
#[derive(Debug)]
pub enum RelayError {
    /// The URL is not a `wss://` relay address.
    BadUrl(String),
    /// TLS, TCP, or the WebSocket handshake.
    Connect(String),
    /// The socket closed, or the exchange ran past its deadline.
    Timeout,
    /// The relay said no. Its own words, which are usually worth reading:
    /// "rate-limited", "blocked", "invalid event".
    Refused(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(u) => write!(f, "not a relay URL: {u}"),
            Self::Connect(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("no answer in time"),
            Self::Refused(m) => write!(f, "relay refused: {m}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// `wss://host[:port][/path]` split into what a connection needs.
pub fn parse_relay_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("wss://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        // Only when what follows the colon is a port. `[::1]` has colons too.
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_owned(), p.parse().ok()?)
        }
        _ => (authority.to_owned(), 443u16),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_owned()))
}

type Socket = tokio_tungstenite::WebSocketStream<veil_transport::traits::BoxIoStream>;

async fn open(ctx: &TransportContext, url: &str) -> Result<Socket, RelayError> {
    let (host, port, path) =
        parse_relay_url(url).ok_or_else(|| RelayError::BadUrl(url.to_owned()))?;
    let stream = connect_pki_verified_https_stream(&host, port, None, &[b"http/1.1".to_vec()], ctx)
        .await
        .map_err(|e| RelayError::Connect(format!("{e}")))?;
    let request = format!("wss://{host}:{port}{path}");
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..Default::default()
    };
    let (socket, _response) =
        tokio_tungstenite::client_async_with_config(request, stream, Some(config))
            .await
            .map_err(|e| RelayError::Connect(format!("{e}")))?;
    Ok(socket)
}

/// Post one event and wait for the relay's verdict.
pub async fn publish(
    ctx: &TransportContext,
    url: &str,
    event: &Event,
    timeout: Duration,
) -> Result<(), RelayError> {
    let work = async {
        let mut socket = open(ctx, url).await?;
        let frame = serde_json::json!(["EVENT", event]).to_string();
        socket
            .send(Message::Text(frame))
            .await
            .map_err(|e| RelayError::Connect(format!("{e}")))?;

        // `["OK", <id>, <accepted>, <message>]`. Anything else is another
        // subscription's traffic on the same socket and not this answer.
        while let Some(msg) = socket.next().await {
            let Ok(Message::Text(text)) = msg else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            if value.get(0).and_then(|v| v.as_str()) != Some("OK") {
                continue;
            }
            if value.get(1).and_then(|v| v.as_str()) != Some(event.id.as_str()) {
                continue;
            }
            let accepted = value.get(2).and_then(serde_json::Value::as_bool) == Some(true);
            let reason = value
                .get(3)
                .and_then(|v| v.as_str())
                .unwrap_or("no reason given")
                .to_owned();
            let _ = socket.close(None).await;
            return if accepted {
                Ok(())
            } else {
                Err(RelayError::Refused(reason))
            };
        }
        Err(RelayError::Timeout)
    };
    tokio::time::timeout(timeout, work)
        .await
        .unwrap_or(Err(RelayError::Timeout))
}

/// Ask one relay who else is at `label`.
///
/// Every event is verified before it is returned. A relay is a stranger's
/// server: it can hand back anything, and an unverified event is a claim
/// somebody else signed for.
/// Whether an event a relay handed back is an answer to the query that was
/// asked: the kind and the `d` tag the filter named.
///
/// A signature proves who wrote an event, not that it answers this question.
/// The filter goes to the relay and the relay is a stranger's server — it is
/// free to send a different kind, or somebody else's label, and only the asker
/// can tell (report20 V20-M8).
pub fn event_answers_query(event: &Event, kind: u16, label: &str) -> bool {
    event.kind == kind
        && event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "d" && t[1] == label)
}

pub async fn query(
    ctx: &TransportContext,
    url: &str,
    kind: u16,
    label: &str,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<Event>, RelayError> {
    let work = async {
        let mut socket = open(ctx, url).await?;
        let sub = "veil";
        let filter = serde_json::json!({
            "kinds": [kind],
            "#d": [label],
            "limit": limit.min(MAX_EVENTS),
        });
        socket
            .send(Message::Text(
                serde_json::json!(["REQ", sub, filter]).to_string(),
            ))
            .await
            .map_err(|e| RelayError::Connect(format!("{e}")))?;

        // What the CALLER asked for, not what the relay is willing to send.
        // The filter carried this number and the reader did not: a relay that
        // ignores the filter — and a relay is a stranger's server — could hand
        // back four times as many events as were asked for, and every one of
        // them became a bootstrap dial attempt (report20 V20-M8).
        let cap = limit.min(MAX_EVENTS);
        let mut out = Vec::new();
        while let Some(msg) = socket.next().await {
            let Ok(Message::Text(text)) = msg else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            match value.get(0).and_then(|v| v.as_str()) {
                // End of stored events: everything after this is live traffic
                // nobody asked for.
                Some("EOSE") => break,
                Some("EVENT") => {
                    if value.get(1).and_then(|v| v.as_str()) != Some(sub) {
                        continue;
                    }
                    let Some(raw) = value.get(2) else { continue };
                    let Ok(event) = serde_json::from_value::<Event>(raw.clone()) else {
                        continue;
                    };
                    if verify(&event).is_err() {
                        log::debug!("nostr: {url} sent an event that does not verify");
                        continue;
                    }
                    // A signature proves who wrote it, not that it answers
                    // THIS question. The filter named a kind and a `d` tag;
                    // the relay is free to send something else, and only the
                    // asker can tell. Checked locally so a relay cannot widen
                    // its own answer.
                    if !event_answers_query(&event, kind, label) {
                        log::debug!(
                            "nostr: {url} sent kind {} for a {kind}/{label} query",
                            event.kind
                        );
                        continue;
                    }
                    out.push(event);
                    if out.len() >= cap {
                        break;
                    }
                }
                Some("CLOSED") | Some("NOTICE") => {
                    let reason = value
                        .get(2)
                        .or_else(|| value.get(1))
                        .and_then(|v| v.as_str())
                        .unwrap_or("closed")
                        .to_owned();
                    let _ = socket.close(None).await;
                    return Err(RelayError::Refused(reason));
                }
                _ => continue,
            }
        }
        let _ = socket
            .send(Message::Text(serde_json::json!(["CLOSE", sub]).to_string()))
            .await;
        let _ = socket.close(None).await;
        Ok(out)
    };
    tokio::time::timeout(timeout, work)
        .await
        .unwrap_or(Err(RelayError::Timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u16, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
        }
    }

    fn d(label: &str) -> Vec<Vec<String>> {
        vec![vec!["d".to_owned(), label.to_owned()]]
    }

    /// report20 V20-M8: a relay may answer a different question, and only the
    /// asker can tell.
    ///
    /// The filter names a kind and a `d` tag, and both go to the relay — a
    /// stranger's server, free to send whatever it likes. The signature it
    /// carries proves who wrote the event, not that it answers this query, and
    /// nothing local checked. Every event that came back became a bootstrap
    /// dial attempt.
    #[test]
    fn an_event_that_answers_a_different_question_is_not_an_answer() {
        assert!(
            event_answers_query(&ev(30078, d("veil:abc")), 30078, "veil:abc"),
            "vacuity: the genuine answer must pass, or every case below is \
             passing on a function that refuses everything"
        );
        assert!(
            !event_answers_query(&ev(1, d("veil:abc")), 30078, "veil:abc"),
            "a relay substituted another kind of event"
        );
        assert!(
            !event_answers_query(&ev(30078, d("veil:someone-else")), 30078, "veil:abc"),
            "a relay answered with somebody else's label"
        );
        assert!(
            !event_answers_query(&ev(30078, Vec::new()), 30078, "veil:abc"),
            "an event with no d tag was taken as tagged"
        );
        assert!(
            !event_answers_query(
                &ev(30078, vec![vec!["e".to_owned(), "veil:abc".to_owned()]]),
                30078,
                "veil:abc"
            ),
            "the label was matched under the wrong tag name"
        );
        assert!(
            !event_answers_query(&ev(30078, vec![vec!["d".to_owned()]]), 30078, "veil:abc"),
            "a bare d tag with no value was taken as a match"
        );
        // The right tag among several still answers.
        assert!(event_answers_query(
            &ev(
                30078,
                vec![
                    vec!["e".to_owned(), "x".to_owned()],
                    vec!["d".to_owned(), "veil:abc".to_owned()],
                ]
            ),
            30078,
            "veil:abc"
        ));
    }

    /// And the reader stops at the number the CALLER asked for.
    ///
    /// The filter carried the caller's limit and the loop counted to the
    /// relay's ceiling instead, so a relay that ignores its filter could hand
    /// back four times as many events as were wanted.
    #[test]
    fn the_reader_stops_at_the_limit_that_was_asked_for() {
        let src = include_str!("client.rs");
        let body = src
            .split("pub async fn query(")
            .nth(1)
            .and_then(|t| t.split("\n#[cfg(test)]").next())
            .expect("the query body");
        assert!(
            body.contains("let cap = limit.min(MAX_EVENTS);"),
            "the caller's limit is no longer computed"
        );
        assert!(
            body.contains("out.len() >= cap"),
            "the reader counts to something other than the caller's limit"
        );
        assert!(
            !body.contains("out.len() >= MAX_EVENTS"),
            "the reader counts to the relay ceiling again, so a relay that \
             ignores its filter decides how many events this node acts on"
        );
    }

    #[test]
    fn a_relay_url_is_split_the_way_a_connection_needs_it() {
        assert_eq!(
            parse_relay_url("wss://relay.damus.io"),
            Some(("relay.damus.io".to_owned(), 443, "/".to_owned())),
            "the default port for wss is 443"
        );
        assert_eq!(
            parse_relay_url("wss://relay.example:7447/nostr"),
            Some(("relay.example".to_owned(), 7447, "/nostr".to_owned()))
        );
        assert_eq!(
            parse_relay_url("wss://relay.example/"),
            Some(("relay.example".to_owned(), 443, "/".to_owned()))
        );
        // A host with colons in it and no port: an IPv6 literal must not have
        // its last group read as a port number.
        assert_eq!(
            parse_relay_url("wss://[2001:db8::1]"),
            Some(("[2001:db8::1]".to_owned(), 443, "/".to_owned()))
        );
    }

    #[test]
    fn anything_that_is_not_a_tls_relay_is_refused() {
        // `ws://` deliberately included: this meeting point exists because it
        // survives a network that drops UDP, and a plaintext WebSocket on 80
        // is not the same thing at all — it would hand the rendezvous to
        // whoever is between.
        for bad in [
            "ws://relay.example",
            "https://relay.example",
            "relay.example",
            "wss://",
            "wss:///path",
            "",
        ] {
            assert_eq!(parse_relay_url(bad), None, "`{bad}` was accepted");
        }
    }

    #[test]
    fn there_is_more_than_one_relay_and_none_is_ours() {
        // Plural on purpose: any one may be down, rate-limiting, or gone for
        // good, and losing one is supposed to cost nothing.
        assert!(
            PUBLIC_RELAYS.len() >= 3,
            "one relay is a single point of failure"
        );
        for url in PUBLIC_RELAYS {
            assert!(
                parse_relay_url(url).is_some(),
                "{url} is not a usable relay URL"
            );
            assert!(
                !url.contains("veil"),
                "{url} looks like ours; the point is that they are not"
            );
        }
    }

    /// A context for the live tests: public PKI, system resolver, nothing
    /// veil-specific. The same shape `debug_transport_context` builds.
    #[cfg(test)]
    fn public_context() -> TransportContext {
        TransportContext::new(
            std::sync::Arc::new(veil_transport::SystemDnsResolver),
            veil_transport::TlsContext::for_debug().expect("debug tls context"),
            veil_transport::TcpTransportSettings::default(),
            veil_transport::QuicTransportSettings::default(),
        )
    }

    #[tokio::test]
    #[ignore = "posts to a real Nostr relay; run with --ignored"]
    async fn a_real_relay_stores_what_this_publishes_and_gives_it_back() {
        // The only test here that proves this against somebody else's server.
        // Everything above pairs our writer with our reader, and a relay does
        // not: it recomputes the id and verifies the signature before storing
        // anything, so this is where "nearly right" shows up.
        //
        // The label is RANDOM, not veil's rendezvous. The mechanism is
        // identical either way, and posting on the real point would put this
        // machine's address on a public index labelled as a veil node --
        // a decision for whoever owns the machine, not for a test.
        use crate::event::{KIND_APP_DATA, sign};
        use crate::rendezvous::identity_from_seed;

        let mut seed = [0u8; 32];
        {
            use rand_core::RngCore as _;
            rand_core::OsRng.fill_bytes(&mut seed);
        }
        let key = identity_from_seed(&seed, 0);
        let label = format!("veil-selftest-{}", hex16(&seed));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let event = sign(
            &key,
            now,
            KIND_APP_DATA,
            vec![vec!["d".to_owned(), label.clone()]],
            "tcp://198.51.100.4:5556",
        );

        let ctx = public_context();
        let mut posted = Vec::new();
        for relay in PUBLIC_RELAYS {
            match publish(&ctx, relay, &event, DEFAULT_TIMEOUT).await {
                Ok(()) => {
                    eprintln!("{relay}: accepted");
                    posted.push(*relay);
                }
                Err(e) => eprintln!("{relay}: {e}"),
            }
        }
        assert!(
            !posted.is_empty(),
            "not one public relay accepted the event — either this machine has \
             no TLS out, or what we send is not what a relay reads"
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut found = 0usize;
        for relay in &posted {
            match query(&ctx, relay, KIND_APP_DATA, &label, 8, DEFAULT_TIMEOUT).await {
                Ok(events) => {
                    eprintln!("{relay}: gave back {} event(s)", events.len());
                    if events.iter().any(|e| e.id == event.id) {
                        found += 1;
                    }
                }
                Err(e) => eprintln!("{relay}: query failed: {e}"),
            }
        }
        eprintln!("{found}/{} relay(s) gave the event back", posted.len());
        assert!(
            found > 0,
            "no relay that accepted the event would return it"
        );

        // A rendezvous is not one node posting. Two must be visible under the
        // one label, or this is a place where nobody meets anybody.
        let mut other_seed = [0u8; 32];
        {
            use rand_core::RngCore as _;
            rand_core::OsRng.fill_bytes(&mut other_seed);
        }
        let other = sign(
            &identity_from_seed(&other_seed, 0),
            now,
            KIND_APP_DATA,
            vec![vec!["d".to_owned(), label.clone()]],
            "tcp://198.51.100.9:5556",
        );
        // And the FIRST node moves. Kind 30078 is addressable, so a relay is
        // supposed to REPLACE per (author, kind, d) rather than keep both --
        // and the announce loop re-posts every fifteen minutes, so a relay
        // that appends instead would grow one node's stale addresses forever
        // and hand them to everybody arriving.
        let moved = sign(
            &key,
            now + 1,
            KIND_APP_DATA,
            vec![vec!["d".to_owned(), label.clone()]],
            "tcp://198.51.100.77:5556",
        );

        let mut checked = 0usize;
        for relay in &posted {
            if publish(&ctx, relay, &other, DEFAULT_TIMEOUT).await.is_err() {
                continue;
            }
            if publish(&ctx, relay, &moved, DEFAULT_TIMEOUT).await.is_err() {
                continue;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            let Ok(events) = query(&ctx, relay, KIND_APP_DATA, &label, 16, DEFAULT_TIMEOUT).await
            else {
                continue;
            };
            let addresses: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
            eprintln!("{relay}: at the rendezvous -> {addresses:?}");

            let mine: Vec<&&str> = addresses
                .iter()
                .filter(|a| a.contains("198.51.100.4:") || a.contains("198.51.100.77:"))
                .collect();
            assert_eq!(
                mine.len(),
                1,
                "{relay} kept {} records for one author under one label; \
                 re-announcing accumulates instead of replacing",
                mine.len()
            );
            assert!(
                addresses.contains(&"tcp://198.51.100.77:5556"),
                "{relay} still serves the address this node moved away from"
            );
            assert!(
                addresses.contains(&"tcp://198.51.100.9:5556"),
                "{relay} does not show the second node; nobody meets anybody here"
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no relay could be checked for replacement — the result above says \
             the point works for one node, and nothing about two"
        );
    }

    fn hex16(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::new();
        for b in bytes.iter().take(8) {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }
}
