//! TFTP (Trivial File Transfer Protocol, RFC 1350) fetch.
//! Implements a minimal RRQ (Read Request) client over UDP.
//!
//! TFTP is not available in OpenDAL — it is a UDP-based, stop-and-wait protocol
//! used primarily for network boot (PXE), firmware updates, and router config
//! backups. Block size is fixed at 512 bytes per RFC 1350.

use std::net::UdpSocket;
use std::time::Duration;

use anyhow::{anyhow, Result};

// TFTP opcodes (RFC 1350 §5)
const OP_RRQ: u16 = 1;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

/// Default TFTP port (RFC 1350).
pub const DEFAULT_TFTP_PORT: u16 = 69;
/// Maximum TFTP data payload per block (RFC 1350).
const TFTP_BLOCK_SIZE: usize = 512;
/// Wire buffer: 4 bytes header + 512 bytes data.
const TFTP_BUF_LEN: usize = TFTP_BLOCK_SIZE + 4;
/// Per-datagram read timeout.
const READ_TIMEOUT_SECS: u64 = 5;

/// Parsed components of a `tftp://` URI.
#[derive(Debug, PartialEq)]
pub struct TftpUri {
    /// Remote hostname or IP.
    pub host: String,
    /// UDP port (default 69).
    pub port: u16,
    /// File path on the TFTP server (without leading slash).
    pub path: String,
}

/// Parse a `tftp://` URI into its components.
///
/// # Supported forms
/// - `tftp://host/file`
/// - `tftp://host:port/path/to/file`
pub fn parse_tftp_uri(uri: &str) -> Result<TftpUri> {
    let rest = uri
        .strip_prefix("tftp://")
        .ok_or_else(|| anyhow!("expected tftp:// URI, got: {uri}"))?;

    if rest.is_empty() {
        return Err(anyhow!("TFTP URI has no host: {uri}"));
    }

    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, p.to_string()))
        .unwrap_or((rest, String::new()));

    if authority.is_empty() {
        return Err(anyhow!("TFTP URI has empty host: {uri}"));
    }

    if path.is_empty() {
        return Err(anyhow!(
            "TFTP URI has no file path (expected tftp://host/filename): {uri}"
        ));
    }

    let (host, port) = if let Some((h, p)) = authority.split_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| anyhow!("invalid port in TFTP URI: {uri}"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), DEFAULT_TFTP_PORT)
    };

    if host.is_empty() {
        return Err(anyhow!("TFTP URI has empty host: {uri}"));
    }

    Ok(TftpUri { host, port, path })
}

/// Build a TFTP RRQ packet for `filename` in octet mode (RFC 1350 §5).
pub(crate) fn build_rrq(filename: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + filename.len() + 6);
    pkt.extend_from_slice(&OP_RRQ.to_be_bytes());
    pkt.extend_from_slice(filename.as_bytes());
    pkt.push(0); // null-terminate filename
    pkt.extend_from_slice(b"octet");
    pkt.push(0); // null-terminate mode
    pkt
}

/// Build a TFTP ACK packet for `block` (RFC 1350 §5).
pub(crate) fn build_ack(block: u16) -> [u8; 4] {
    let b = block.to_be_bytes();
    [0, OP_ACK as u8, b[0], b[1]]
}

/// Fetch the raw bytes of a file from a TFTP server.
///
/// Implements RFC 1350 RRQ in octet mode:
/// 1. Sends RRQ to `host:port`.
/// 2. Receives DATA blocks from the server's ephemeral transfer port (TID).
/// 3. Sends ACK for each block.
/// 4. Terminates when a DATA block carries fewer than 512 bytes.
pub fn fetch_tftp_bytes(uri: &str) -> Result<Vec<u8>> {
    let tftp_uri = parse_tftp_uri(uri)?;
    fetch_tftp_inner(&tftp_uri)
}

fn fetch_tftp_inner(uri: &TftpUri) -> Result<Vec<u8>> {
    let server_addr = format!("{}:{}", uri.host, uri.port);

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| anyhow!("UDP bind failed: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| anyhow!("set_read_timeout failed: {e}"))?;

    let rrq = build_rrq(&uri.path);
    socket
        .send_to(&rrq, &server_addr)
        .map_err(|e| anyhow!("TFTP RRQ send to {server_addr} failed: {e}"))?;

    let mut data: Vec<u8> = Vec::new();
    let mut expected_block: u16 = 1;
    let mut transfer_addr: Option<std::net::SocketAddr> = None;

    loop {
        let mut buf = [0u8; TFTP_BUF_LEN];
        let (n, from_addr) = socket
            .recv_from(&mut buf)
            .map_err(|e| anyhow!("TFTP recv failed: {e}"))?;

        if transfer_addr.is_none() {
            transfer_addr = Some(from_addr);
        } else if Some(from_addr) != transfer_addr {
            // Ignore packets from unexpected sources (RFC 1350 §4).
            continue;
        }

        if n < 4 {
            return Err(anyhow!("TFTP: received undersized packet"));
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let block = u16::from_be_bytes([buf[2], buf[3]]);

        match opcode {
            OP_DATA => {
                if block != expected_block {
                    // Duplicate block — re-send ACK for the last accepted block.
                    let ack = build_ack(block.wrapping_sub(1));
                    let _ = socket.send_to(&ack, from_addr);
                    continue;
                }

                data.extend_from_slice(&buf[4..n]);

                let ack = build_ack(block);
                socket
                    .send_to(&ack, from_addr)
                    .map_err(|e| anyhow!("TFTP ACK send failed: {e}"))?;

                if n - 4 < TFTP_BLOCK_SIZE {
                    break; // last block
                }

                expected_block = expected_block.wrapping_add(1);
            }

            OP_ERROR => {
                let err_code = u16::from_be_bytes([buf[2], buf[3]]);
                let msg_end = buf[4..n]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| i + 4)
                    .unwrap_or(n);
                let msg = String::from_utf8_lossy(&buf[4..msg_end]);
                return Err(anyhow!("TFTP error {err_code}: {msg}"));
            }

            other => {
                return Err(anyhow!("TFTP: unexpected opcode {other}"));
            }
        }
    }

    Ok(data)
}
