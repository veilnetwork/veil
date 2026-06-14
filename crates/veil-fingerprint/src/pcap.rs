//! PCAP-format ingest for `NGramModel`.
//!
//! Wraps the `pcap-parser` crate (pure-Rust, no libpcap C dep) to extract
//! application-layer bytes from .pcap / .pcapng captures and feed them into
//! the n-gram analyzer.  Strips Ethernet/Linux-cooked + IPv4/IPv6 + TCP/UDP
//! overhead so the model only counts the actual encrypted payload bytes
//! (matching what a DPI middlebox would profile).
//!
//! ## Operator workflow
//!
//! ```bash
//! # Capture a sample.
//! sudo tcpdump -i any -w veil-sample.pcap "port 5556 or port 8443" -G 600 -W 1
//!
//! # Pipe into a Rust analyzer using this module.
//! cargo run --features pcap --example fp-compare -- \
//!   veil-sample.pcap chrome-reference.pcap
//! ```
//!
//! ## Limitations (deliberately scoped)
//!
//! * Supports linktypes **Ethernet** (1) and **Linux cooked v1** (113).
//!   Other linktypes silently skip the frame.  Most operator captures use
//!   one of these two.
//! * IPv4 + IPv6 supported; IPv6 extension headers NOT decoded (rare in
//!   practice for DPI-relevant flows; would silently skip).
//! * TCP + UDP supported; SCTP/QUIC-over-UDP encoded payload counted as
//!   "payload bytes" without further peeling (correct for n-gram purposes
//!   since QUIC ciphertext is what a DPI sees).
//! * Port filter is applied to **either** source-or-destination port —
//!   so capturing a bidirectional flow needs no separate flag.

use std::io::Read;

use pcap_parser::{PcapBlockOwned, PcapError, pcapng::Block};

use crate::NGramModel;

/// PCAP-ingest errors returned by [`observe_pcap`].
#[derive(Debug, thiserror::Error)]
pub enum PcapIngestError {
    #[error("pcap I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap parse error: {0}")]
    Parse(String),
    #[error("pcap-reader buffer exhausted")]
    BufferExhausted,
}

impl<E: std::fmt::Debug> From<PcapError<E>> for PcapIngestError {
    fn from(e: PcapError<E>) -> Self {
        PcapIngestError::Parse(format!("{e:?}"))
    }
}

/// Observe application-layer bytes from a pcap (.pcap or .pcapng) reader.
///
/// `port_filter` keeps frames where either src or dst port matches.
/// `None` ingests every TCP/UDP frame.
///
/// Returns the total byte count fed into the model.
pub fn observe_pcap<R: Read + Send + 'static>(
    model: &mut NGramModel,
    reader: R,
    port_filter: Option<u16>,
) -> Result<usize, PcapIngestError> {
    let mut pcap_reader = pcap_parser::create_reader(65536, reader)
        .map_err(|e| PcapIngestError::Parse(format!("create_reader: {e:?}")))?;
    let mut bytes_observed = 0usize;
    let mut linktype: Option<i32> = None;

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                process_block(
                    &block,
                    &mut linktype,
                    port_filter,
                    model,
                    &mut bytes_observed,
                );
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader
                    .refill()
                    .map_err(|e| PcapIngestError::Parse(format!("refill: {e:?}")))?;
            }
            Err(e) => return Err(PcapIngestError::Parse(format!("{e:?}"))),
        }
    }

    Ok(bytes_observed)
}

fn process_block(
    block: &PcapBlockOwned<'_>,
    linktype: &mut Option<i32>,
    port_filter: Option<u16>,
    model: &mut NGramModel,
    bytes_observed: &mut usize,
) {
    let (frame_bytes, frame_linktype) = match block {
        PcapBlockOwned::LegacyHeader(hdr) => {
            // Legacy PCAP file header carries the linktype for all
            // following frames in the file.
            *linktype = Some(hdr.network.0 as i32);
            return;
        }
        PcapBlockOwned::Legacy(blk) => (blk.data, linktype.unwrap_or(LINKTYPE_ETHERNET)),
        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
            *linktype = Some(idb.linktype.0 as i32);
            return;
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
            (epb.data, linktype.unwrap_or(LINKTYPE_ETHERNET))
        }
        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
            (spb.data, linktype.unwrap_or(LINKTYPE_ETHERNET))
        }
        _ => return, // Non-frame block (statistics, etc.) — ignore.
    };

    if let Some(payload) = strip_link_ip_transport(frame_bytes, frame_linktype, port_filter) {
        model.observe(payload);
        *bytes_observed = bytes_observed.saturating_add(payload.len());
    }
}

const LINKTYPE_ETHERNET: i32 = 1;
const LINKTYPE_LINUX_SLL: i32 = 113;

/// Strip Ethernet/Linux-cooked + IPv4/v6 + TCP/UDP headers, returning
/// the application-layer payload or None if the frame couldn't be
/// fully decoded (truncated, unsupported transport, filter mismatch).
fn strip_link_ip_transport<'a>(
    frame: &'a [u8],
    linktype: i32,
    port_filter: Option<u16>,
) -> Option<&'a [u8]> {
    let (after_link, ethertype) = strip_link_layer(frame, linktype)?;

    // EtherType: 0x0800 = IPv4, 0x86dd = IPv6.  Drop anything else
    // (ARP, VLAN tag without IP inside, etc.).
    let (after_ip, ip_protocol) = match ethertype {
        0x0800 => strip_ipv4(after_link)?,
        0x86dd => strip_ipv6(after_link)?,
        _ => return None,
    };

    // IP protocol numbers: 6 = TCP, 17 = UDP.
    match ip_protocol {
        6 => strip_tcp(after_ip, port_filter),
        17 => strip_udp(after_ip, port_filter),
        _ => None,
    }
}

fn strip_link_layer(frame: &[u8], linktype: i32) -> Option<(&[u8], u16)> {
    match linktype {
        LINKTYPE_ETHERNET => {
            if frame.len() < 14 {
                return None;
            }
            // Skip dst (6) + src (6) MAC; read ethertype (2 BE).
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            // Handle 802.1Q VLAN tag (ethertype 0x8100): 4 more bytes
            // before the real ethertype.
            if ethertype == 0x8100 && frame.len() >= 18 {
                let real = u16::from_be_bytes([frame[16], frame[17]]);
                return Some((&frame[18..], real));
            }
            Some((&frame[14..], ethertype))
        }
        LINKTYPE_LINUX_SLL => {
            // Linux cooked-mode v1: 16-byte header.  Ethertype at offset 14.
            if frame.len() < 16 {
                return None;
            }
            let ethertype = u16::from_be_bytes([frame[14], frame[15]]);
            Some((&frame[16..], ethertype))
        }
        _ => None,
    }
}

fn strip_ipv4(packet: &[u8]) -> Option<(&[u8], u8)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4; // header length in bytes
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let protocol = packet[9];
    Some((&packet[ihl..], protocol))
}

fn strip_ipv6(packet: &[u8]) -> Option<(&[u8], u8)> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 6 {
        return None;
    }
    // Next-header at offset 6; payload starts at offset 40.  Note: this
    // does NOT decode IPv6 extension headers (Hop-by-Hop, Routing,
    // Fragment, etc.) — rare in DPI-relevant flows; truncated frames
    // silently skip.
    let next_header = packet[6];
    Some((&packet[40..], next_header))
}

fn strip_tcp<'a>(packet: &'a [u8], port_filter: Option<u16>) -> Option<&'a [u8]> {
    if packet.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    if let Some(want) = port_filter
        && src_port != want
        && dst_port != want
    {
        return None;
    }
    // Data-offset in the upper 4 bits of byte 12, in units of 32-bit words.
    let data_offset = ((packet[12] >> 4) as usize) * 4;
    if data_offset < 20 || packet.len() < data_offset {
        return None;
    }
    Some(&packet[data_offset..])
}

fn strip_udp<'a>(packet: &'a [u8], port_filter: Option<u16>) -> Option<&'a [u8]> {
    if packet.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    if let Some(want) = port_filter
        && src_port != want
        && dst_port != want
    {
        return None;
    }
    Some(&packet[8..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic Ethernet + IPv4 + TCP frame with the given
    /// payload and ports.  Used to verify the strip logic without needing a
    /// real pcap fixture.
    fn build_ethernet_ipv4_tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet: dst MAC + src MAC + ethertype 0x0800 (IPv4)
        frame.extend_from_slice(&[0x11; 6]); // dst MAC
        frame.extend_from_slice(&[0x22; 6]); // src MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4: version=4, IHL=5 (20 bytes), no options
        let mut ipv4 = Vec::new();
        ipv4.push(0x45); // version 4 + IHL 5
        ipv4.push(0); // DSCP/ECN
        ipv4.extend_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes()); // total length
        ipv4.extend_from_slice(&[0; 4]); // id, flags, frag offset
        ipv4.push(64); // TTL
        ipv4.push(6); // protocol = TCP
        ipv4.extend_from_slice(&[0; 2]); // checksum (unused in tests)
        ipv4.extend_from_slice(&[10, 0, 0, 1]); // src IP
        ipv4.extend_from_slice(&[10, 0, 0, 2]); // dst IP
        frame.extend_from_slice(&ipv4);
        // TCP: 20-byte header
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&[0; 4]); // seq
        tcp.extend_from_slice(&[0; 4]); // ack
        tcp.push(0x50); // data offset 5 << 4 (= 20 bytes)
        tcp.push(0x18); // flags PSH+ACK
        tcp.extend_from_slice(&[0; 2]); // window
        tcp.extend_from_slice(&[0; 2]); // checksum
        tcp.extend_from_slice(&[0; 2]); // urgent ptr
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn strip_ethernet_ipv4_tcp_extracts_payload() {
        let payload = b"hello world this is application bytes";
        let frame = build_ethernet_ipv4_tcp_frame(12345, 80, payload);
        let extracted = strip_link_ip_transport(&frame, LINKTYPE_ETHERNET, None);
        assert_eq!(extracted, Some(payload.as_slice()));
    }

    #[test]
    fn port_filter_matches_dst() {
        let payload = b"abc";
        let frame = build_ethernet_ipv4_tcp_frame(12345, 5556, payload);
        let extracted = strip_link_ip_transport(&frame, LINKTYPE_ETHERNET, Some(5556));
        assert_eq!(extracted, Some(payload.as_slice()));
    }

    #[test]
    fn port_filter_matches_src() {
        let payload = b"abc";
        let frame = build_ethernet_ipv4_tcp_frame(5556, 12345, payload);
        let extracted = strip_link_ip_transport(&frame, LINKTYPE_ETHERNET, Some(5556));
        assert_eq!(extracted, Some(payload.as_slice()));
    }

    #[test]
    fn port_filter_rejects_mismatch() {
        let payload = b"abc";
        let frame = build_ethernet_ipv4_tcp_frame(80, 443, payload);
        let extracted = strip_link_ip_transport(&frame, LINKTYPE_ETHERNET, Some(5556));
        assert_eq!(extracted, None);
    }

    #[test]
    fn truncated_ethernet_skipped() {
        let extracted = strip_link_ip_transport(&[0x11; 10], LINKTYPE_ETHERNET, None);
        assert_eq!(extracted, None);
    }

    #[test]
    fn non_ip_ethertype_skipped() {
        // ARP ethertype 0x0806 — not IP, skipped.
        let mut frame = vec![0x11; 12];
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0; 28]); // ARP body
        let extracted = strip_link_ip_transport(&frame, LINKTYPE_ETHERNET, None);
        assert_eq!(extracted, None);
    }
}
