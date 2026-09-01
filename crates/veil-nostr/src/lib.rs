//! A meeting point on Nostr relays.
//!
//! # Why this one exists
//!
//! The other two meeting points are UDP. BitTorrent's DHT is UDP, and local
//! discovery is UDP multicast — so a network that drops UDP wholesale leaves a
//! veil node with no way in at all, and that is an ordinary shape for a
//! corporate or hotel network, never mind a hostile one.
//!
//! Nostr relays speak WebSocket over TLS on 443. A node that can load a web
//! page can reach one.
//!
//! # Why Nostr rather than a server of our own
//!
//! Same reason as the DHT: the relays are not ours. There are hundreds, run by
//! unrelated people for unrelated purposes, and a veil node is one more client
//! posting a small signed record among millions. Losing any one of them costs
//! nothing; nobody can be served notice about a veil developer to take the set
//! down.
//!
//! # What it does NOT buy
//!
//! The record is public and the relay sees the address it was posted from.
//! That is the same trade the DHT makes and it is stated the same way: this is
//! a PUBLIC ENTRY POINT, not private discovery, and publishing is opt-in
//! (`global.bootstrap`) for exactly that reason.

pub mod event;
pub mod rendezvous;
