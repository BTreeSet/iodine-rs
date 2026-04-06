//! Downstream framing notes from upstream (`iodined.c`, `client.c`, `dns.c`):
//! - DNS NULL answers are binary payload passthrough from `dns_decode()` and are not text-decoded.
//! - DNS TXT/CNAME/MX/SRV answers carry text/name-encoded payload and must be decoded with
//!   `dns_namedec()` (codec marker + encoded stream) before packet interpretation.
//! - A valid downstream tunnel packet starts with a 2-byte tunnel header:
//!   - byte0: bit7=compress flag, bits6..4=upstream ack seq, bits3..0=upstream ack frag
//!   - byte1: bits7..5=downstream seq, bits4..1=downstream frag, bit0=last-fragment flag
//! - Bytes after the 2-byte header are compressed payload fragment bytes for reassembly.
//! - Reassembly is keyed by downstream seq/frag; once last-fragment is seen, payload is zlib-inflated
//!   and written to TUN.
use clap::Args;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use crate::dns::{
    DnsHeader, DnsQuestion, DnsRdata, DnsResourceRecord, DNS_CLASS_IN, DNS_TYPE_NULL,
};

#[derive(Debug, Clone, Args)]
pub struct ClientArgs {
    #[arg(long)]
    pub topdomain: Option<String>,
    #[arg(long)]
    pub nameserver: Option<String>,
    #[arg(long, default_value = "10.0.0.2")]
    pub tun_ip: String,
    #[arg(long, default_value = "255.255.255.0")]
    pub tun_netmask: String,
}

pub async fn run(args: ClientArgs) {
    let topdomain = args.topdomain.unwrap_or_else(|| "t1.example".to_string());
    let nameserver: SocketAddr = args
        .nameserver
        .as_deref()
        .unwrap_or("127.0.0.1:53")
        .parse()
        .expect("nameserver must be a valid socket address");
    let tun_ip: Ipv4Addr = args
        .tun_ip
        .parse()
        .expect("tun_ip must be a valid IPv4 address");
    let tun_netmask: Ipv4Addr = args
        .tun_netmask
        .parse()
        .expect("tun_netmask must be a valid IPv4 address");

    let mut tun_device = crate::tun::create_tun_device("iodine0", tun_ip, tun_netmask, 1500)
        .expect("failed to create tun device");
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("failed to bind client UDP socket");
    let password = std::env::var("IODINE_PASSWORD").unwrap_or_else(|_| "testpass".to_string());

    let mut dns_id: u16 = 1;
    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 2048];
    let mut downstream = DownstreamState::default();
    let mut session = ClientSession::default();
    let mut ping_tick = tokio::time::interval(Duration::from_millis(300));

    if let Err(err) = perform_handshake(
        &socket,
        nameserver,
        &topdomain,
        &password,
        &mut dns_id,
        &mut udp_buf,
        &mut session,
    )
    .await
    {
        warn!(error = %err, "client handshake failed; continuing in degraded mode");
    }

    loop {
        tokio::select! {
            tun_read = tun_device.read(&mut tun_buf) => {
                let len = match tun_read {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = %err, "tun read failed");
                        continue;
                    }
                };
                if !session.authenticated {
                    continue;
                }
                let packet = if session.mode == ClientMode::CCompat {
                    with_tun_header(&tun_buf[..len])
                } else {
                    tun_buf[..len].to_vec()
                };
                let compressed = match compress_zlib(&packet) {
                    Some(v) => v,
                    None => {
                        warn!("failed to compress upstream packet");
                        continue;
                    }
                };
                let mut offset = 0usize;
                let seq = session.next_up_seq;
                session.next_up_seq = (session.next_up_seq + 1) & 0x07;
                let mut frag = 0u8;
                while offset < compressed.len() {
                    let end = (offset + 96).min(compressed.len());
                    let chunk = &compressed[offset..end];
                    let is_last = end == compressed.len();
                    let header = build_upstream_header(
                        session.userid_char,
                        seq,
                        frag,
                        session.down_ack_seq,
                        session.down_ack_frag,
                        is_last,
                        session.next_cmc,
                    );
                    session.next_cmc = (session.next_cmc + 1) % 36;
                    let encoded_chunk = crate::encoding::base32::encode(chunk);
                    let qname = format!("{header}{}.{topdomain}", crate::encoding::inline_dotify(&encoded_chunk));
                    if send_query(
                        &socket,
                        nameserver,
                        &qname,
                        DNS_TYPE_NULL,
                        &mut dns_id,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                    frag = frag.wrapping_add(1) & 0x0f;
                    offset = end;
                }
            }
            recv = socket.recv_from(&mut udp_buf) => {
                let (len, _peer) = match recv {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = %err, "udp recv_from failed");
                        continue;
                    }
                };
                let packet = &udp_buf[..len];
                let mut cur = Cursor::new(packet);
                let header = match DnsHeader::parse(&mut cur) {
                    Ok(h) => h,
                    Err(err) => {
                        warn!(error = %err, "invalid dns header");
                        continue;
                    }
                };
                let _question = match DnsQuestion::parse(&mut cur) {
                    Ok(q) => q,
                    Err(err) => {
                        warn!(error = %err, "invalid dns question");
                        continue;
                    }
                };
                if header.ancount == 0 {
                    continue;
                }
                let rr = match DnsResourceRecord::parse(&mut cur) {
                    Ok(rr) => rr,
                    Err(err) => {
                        warn!(error = %err, "invalid dns answer");
                        continue;
                    }
                };
                let payload = match rr.rdata {
                    DnsRdata::Null(data) => {
                        debug!(rr_type = "NULL", raw_payload_len = data.len(), "downstream rr payload");
                        data.to_vec()
                    }
                    DnsRdata::Txt(data) => {
                        let txt = flatten_txt_rdata(data);
                        debug!(rr_type = "TXT", raw_payload_len = txt.len(), "downstream rr payload");
                        match decode_downstream_txt_payload(&txt) {
                            Some(v) => v,
                            None => {
                                warn!("invalid TXT answer payload encoding");
                                continue;
                            }
                        }
                    }
                    _ => continue,
                };
                debug!(decoded_payload_len = payload.len(), "downstream rr decoded");
                if payload.len() < 2 {
                    continue;
                }

                let up_ack_seq = (payload[0] >> 4) & 0x07;
                let up_ack_frag = payload[0] & 0x0f;
                let down_seq = (payload[1] >> 5) & 0x07;
                let down_frag = (payload[1] >> 1) & 0x0f;
                let last_frag = (payload[1] & 0x01) != 0;
                session.down_ack_seq = down_seq;
                session.down_ack_frag = down_frag;
                let fragment = &payload[2..];
                debug!(
                    up_ack_seq,
                    up_ack_frag,
                    down_seq,
                    down_frag,
                    last_frag,
                    frag_len = fragment.len(),
                    "downstream fragment header"
                );

                if let Some(packet) = downstream.push_fragment(down_seq, down_frag, fragment, last_frag) {
                    let ip_packet = if session.mode == ClientMode::CCompat {
                        strip_tun_header(&packet)
                    } else {
                        &packet
                    };
                    debug!(inflated_payload_len = ip_packet.len(), "downstream packet reassembled");
                    if let Err(err) = tun_device.write_all(ip_packet).await {
                        warn!(error = %err, "tun write_all failed");
                        continue;
                    }
                }
            }
            _ = ping_tick.tick() => {
                if !session.authenticated {
                    continue;
                }
                if session.mode == ClientMode::CCompat || session.mode == ClientMode::RawC {
                    let _ = send_c_ping(
                        &socket,
                        nameserver,
                        &topdomain,
                        &mut dns_id,
                        PingState {
                            userid: session.userid,
                            down_ack_seq: session.down_ack_seq,
                            down_ack_frag: session.down_ack_frag,
                        },
                        &mut session.rand_seed,
                    )
                    .await;
                }
            }
        }
    }
}

fn build_qname_wire(first_label: &str, topdomain: &str) -> Option<Vec<u8>> {
    if first_label.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(first_label.len() + topdomain.len() + 4);
    for part in first_label.split('.') {
        if part.is_empty() || part.len() > 63 {
            return None;
        }
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    let td = topdomain.trim_matches('.');
    if !td.is_empty() {
        for part in td.split('.') {
            if part.is_empty() || part.len() > 63 {
                return None;
            }
            out.push(part.len() as u8);
            out.extend_from_slice(part.as_bytes());
        }
    }
    out.push(0);
    Some(out)
}

fn flatten_txt_rdata(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0usize;
    while pos < data.len() {
        let chunk_len = data[pos] as usize;
        pos += 1;
        if pos + chunk_len > data.len() {
            break;
        }
        out.extend_from_slice(&data[pos..pos + chunk_len]);
        pos += chunk_len;
    }
    out
}

fn decode_base64_payload(encoded: &[u8]) -> Option<Vec<u8>> {
    if encoded.is_empty() {
        return Some(Vec::new());
    }
    let decoded = crate::encoding::base64::decode_bytes(encoded);
    decoded.ok()
}

fn decode_downstream_txt_payload(txt: &[u8]) -> Option<Vec<u8>> {
    let (&marker, data) = txt.split_first()?;
    match marker {
        b't' | b'T' => crate::encoding::base32::decode_bytes(data).ok(),
        b's' | b'S' => crate::encoding::base64::decode_bytes(data).ok(),
        b'u' | b'U' => crate::encoding::base64u::decode_bytes(data).ok(),
        b'v' | b'V' => Some(crate::encoding::base128::decode(data)),
        b'r' | b'R' => Some(data.to_vec()),
        // Compatibility fallback for simplified Rust server responses.
        _ if !data.is_empty() || marker.is_ascii_alphanumeric() => decode_base64_payload(txt),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct DownstreamState {
    seq: u8,
    frag: u8,
    buf: Vec<u8>,
    initialized: bool,
}

impl DownstreamState {
    fn push_fragment(&mut self, seq: u8, frag: u8, data: &[u8], last: bool) -> Option<Vec<u8>> {
        if !self.initialized {
            self.seq = seq;
            self.frag = frag;
            self.buf.clear();
            self.initialized = true;
        } else if seq != self.seq {
            if recent_seqno(self.seq, seq) {
                return None;
            }
            self.seq = seq;
            self.frag = frag;
            self.buf.clear();
        } else if (frag <= self.frag && !(self.frag == 0 && frag == 0 && self.buf.is_empty()))
            || frag > self.frag + 1
        {
            return None;
        } else {
            self.frag = frag;
        }

        self.buf.extend_from_slice(data);
        if !last {
            return None;
        }

        let mut decoder = ZlibDecoder::new(&self.buf[..]);
        let mut out = Vec::new();
        let decoded = decoder.read_to_end(&mut out).ok()?;
        if decoded == 0 {
            self.buf.clear();
            return None;
        }
        self.buf.clear();
        Some(out)
    }
}

fn recent_seqno(current: u8, candidate: u8) -> bool {
    let mut seq = current as i8;
    for _ in 0..4 {
        if candidate as i8 == seq {
            return true;
        }
        seq -= 1;
        if seq < 0 {
            seq = 7;
        }
    }
    false
}

#[derive(Debug, Default)]
struct ClientSession {
    userid: u8,
    userid_char: u8,
    down_ack_seq: u8,
    down_ack_frag: u8,
    next_up_seq: u8,
    next_cmc: usize,
    rand_seed: u16,
    mode: ClientMode,
    authenticated: bool,
}

#[derive(Debug, Clone, Copy)]
struct PingState {
    userid: u8,
    down_ack_seq: u8,
    down_ack_frag: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ClientMode {
    #[default]
    RustCompat,
    CCompat,
    RawC,
}

#[derive(thiserror::Error, Debug)]
enum ClientError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

async fn perform_handshake(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    topdomain: &str,
    password: &str,
    dns_id: &mut u16,
    udp_buf: &mut [u8; 2048],
    session: &mut ClientSession,
) -> Result<(), ClientError> {
    if let Ok((userid, _seed)) =
        try_rust_server_handshake(socket, nameserver, topdomain, password, dns_id, udp_buf).await
    {
        session.userid = userid;
        session.userid_char = b"0123456789abcdef"[(userid & 0x0f) as usize];
        session.mode = ClientMode::RustCompat;
        session.authenticated = true;
        return Ok(());
    }

    let userid =
        try_c_server_handshake(socket, nameserver, topdomain, password, dns_id, udp_buf).await?;
    session.userid = userid;
    session.userid_char = b"0123456789abcdef"[(userid & 0x0f) as usize];
    session.mode = ClientMode::CCompat;
    session.rand_seed = 1;
    session.next_up_seq = 1;
    session.authenticated = true;
    if try_raw_udp_login(socket, nameserver, password, userid, dns_id, udp_buf).await? {
        session.mode = ClientMode::RawC;
    }
    Ok(())
}

async fn try_rust_server_handshake(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    topdomain: &str,
    password: &str,
    dns_id: &mut u16,
    udp_buf: &mut [u8; 2048],
) -> Result<(u8, u32), ClientError> {
    let mut version_payload = [0u8; 6];
    version_payload[..4].copy_from_slice(&0x0000_0502u32.to_be_bytes());
    let vname = build_handshake_name('v', &version_payload, topdomain)?;
    let version_answer =
        send_and_read_first_answer(socket, nameserver, dns_id, udp_buf, &vname, DNS_TYPE_NULL)
            .await?;
    if version_answer.len() < 9 || &version_answer[..4] != b"VACK" {
        return Err(ClientError::Protocol("missing VACK".to_string()));
    }
    let seed = u32::from_be_bytes([
        version_answer[4],
        version_answer[5],
        version_answer[6],
        version_answer[7],
    ]);
    let userid = version_answer[8];

    let login_hash = login_hash(password, seed);
    let mut login_payload = [0u8; 19];
    login_payload[0] = userid;
    login_payload[1..17].copy_from_slice(&login_hash);
    let lname = build_handshake_name('l', &login_payload, topdomain)?;
    let login_answer =
        send_and_read_first_answer(socket, nameserver, dns_id, udp_buf, &lname, DNS_TYPE_NULL)
            .await?;
    if login_answer.starts_with(b"LNAK") {
        return Err(ClientError::Protocol("LNAK".to_string()));
    }
    Ok((userid, seed))
}

async fn try_c_server_handshake(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    topdomain: &str,
    password: &str,
    dns_id: &mut u16,
    udp_buf: &mut [u8; 2048],
) -> Result<u8, ClientError> {
    let mut version_payload = [0u8; 6];
    version_payload[..4].copy_from_slice(&0x0000_0502u32.to_be_bytes());
    let vname = build_handshake_name('v', &version_payload, topdomain)?;
    let version_answer =
        send_and_read_first_answer(socket, nameserver, dns_id, udp_buf, &vname, DNS_TYPE_NULL)
            .await?;
    if version_answer.len() < 9 || &version_answer[..4] != b"VACK" {
        return Err(ClientError::Protocol("missing VACK(c)".to_string()));
    }
    let seed = u32::from_be_bytes([
        version_answer[4],
        version_answer[5],
        version_answer[6],
        version_answer[7],
    ]);
    let userid = version_answer[8];
    let login_hash = login_hash(password, seed);
    let mut login_payload = [0u8; 19];
    login_payload[0] = userid;
    login_payload[1..17].copy_from_slice(&login_hash);
    let lname = build_handshake_name('l', &login_payload, topdomain)?;
    let login_answer =
        send_and_read_first_answer(socket, nameserver, dns_id, udp_buf, &lname, DNS_TYPE_NULL)
            .await?;
    if login_answer.starts_with(b"LNAK") || login_answer.is_empty() {
        return Err(ClientError::Protocol("login failed(c)".to_string()));
    }
    Ok(userid)
}

async fn try_raw_udp_login(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    password: &str,
    userid: u8,
    _dns_id: &mut u16,
    udp_buf: &mut [u8; 2048],
) -> Result<bool, ClientError> {
    let probe_hash = login_hash(password, 1);
    let mut payload = Vec::with_capacity(4 + 16);
    payload.extend_from_slice(&[0x10, 0xd1, 0x9e]);
    payload.push(0x10 | (userid & 0x0f));
    payload.extend_from_slice(&probe_hash);
    socket
        .send_to(&payload, nameserver)
        .await
        .map_err(|e| ClientError::Io(format!("raw login send failed: {e}")))?;
    let recv = timeout(Duration::from_millis(700), socket.recv_from(udp_buf)).await;
    let Ok(Ok((len, _))) = recv else {
        return Ok(false);
    };
    if len < 4 {
        return Ok(false);
    }
    Ok(udp_buf[0] == 0x10 && udp_buf[1] == 0xd1 && udp_buf[2] == 0x9e)
}

fn build_handshake_name(prefix: char, data: &[u8], topdomain: &str) -> Result<String, ClientError> {
    let encoded = crate::encoding::base32::encode(data);
    let encoded = crate::encoding::inline_dotify(&encoded);
    Ok(format!("{prefix}{encoded}.{topdomain}"))
}

async fn send_query(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    qname: &str,
    qtype: u16,
    dns_id: &mut u16,
) -> Result<(), ClientError> {
    let qname_wire = build_qname_wire(qname, "")
        .ok_or_else(|| ClientError::Protocol("invalid qname".to_string()))?;
    let mut query = BytesMut::with_capacity(2048);
    DnsHeader {
        id: *dns_id,
        flags: 0x0100,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    }
    .write_to(&mut query);
    DnsQuestion {
        qname_wire: &qname_wire,
        qtype,
        qclass: DNS_CLASS_IN,
    }
    .write_to(&mut query);
    *dns_id = dns_id.wrapping_add(1);
    socket
        .send_to(&query, nameserver)
        .await
        .map_err(|e| ClientError::Io(format!("udp send failed: {e}")))?;
    Ok(())
}

async fn send_and_read_first_answer(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    dns_id: &mut u16,
    udp_buf: &mut [u8; 2048],
    qname: &str,
    qtype: u16,
) -> Result<Vec<u8>, ClientError> {
    send_query(socket, nameserver, qname, qtype, dns_id).await?;
    let recv = timeout(Duration::from_secs(2), socket.recv_from(udp_buf))
        .await
        .map_err(|_| ClientError::Protocol("handshake timeout".to_string()))?
        .map_err(|e| ClientError::Io(format!("udp recv failed: {e}")))?;
    let (len, _) = recv;
    let mut cur = Cursor::new(&udp_buf[..len]);
    let header = DnsHeader::parse(&mut cur)
        .map_err(|e| ClientError::Protocol(format!("dns header: {e}")))?;
    let _question = DnsQuestion::parse(&mut cur)
        .map_err(|e| ClientError::Protocol(format!("dns question: {e}")))?;
    if header.ancount == 0 {
        return Err(ClientError::Protocol("ancount=0".to_string()));
    }
    let rr = DnsResourceRecord::parse(&mut cur)
        .map_err(|e| ClientError::Protocol(format!("dns answer: {e}")))?;
    match rr.rdata {
        DnsRdata::Null(data) => Ok(data.to_vec()),
        DnsRdata::Txt(data) => Ok(flatten_txt_rdata(data)),
        _ => Err(ClientError::Protocol(
            "unsupported handshake rr".to_string(),
        )),
    }
}

fn build_upstream_header(
    userid_char: u8,
    up_seq: u8,
    up_frag: u8,
    down_seq: u8,
    down_frag: u8,
    is_last: bool,
    cmc: usize,
) -> String {
    const CMC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let c1 = crate::encoding::base32::b32_5to8(((up_seq & 0x07) << 2) | ((up_frag & 0x0f) >> 2));
    let c2 = crate::encoding::base32::b32_5to8(((up_frag & 0x03) << 3) | (down_seq & 0x07));
    let c3 = crate::encoding::base32::b32_5to8(((down_frag & 0x0f) << 1) | u8::from(is_last));
    let c4 = CMC[cmc % CMC.len()];
    String::from_utf8(vec![userid_char, c1, c2, c3, c4]).expect("header is ascii")
}

fn compress_zlib(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

async fn send_c_ping(
    socket: &UdpSocket,
    nameserver: SocketAddr,
    topdomain: &str,
    dns_id: &mut u16,
    state: PingState,
    rand_seed: &mut u16,
) -> Result<(), ClientError> {
    let payload = [
        state.userid,
        ((state.down_ack_seq & 0x07) << 4) | (state.down_ack_frag & 0x0f),
        (*rand_seed >> 8) as u8,
        (*rand_seed & 0xff) as u8,
    ];
    *rand_seed = rand_seed.wrapping_add(1);
    let encoded = crate::encoding::base32::encode(&payload);
    let encoded = crate::encoding::inline_dotify(&encoded);
    let qname = format!("p{encoded}.{topdomain}");
    send_query(socket, nameserver, &qname, DNS_TYPE_NULL, dns_id).await
}

fn with_tun_header(ip_packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ip_packet.len() + 4);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(ip_packet);
    out
}

fn strip_tun_header(packet: &[u8]) -> &[u8] {
    if packet.len() >= 4 {
        &packet[4..]
    } else {
        packet
    }
}

fn login_hash(password: &str, seed: u32) -> [u8; 16] {
    let mut temp = [0u8; 32];
    let pass_bytes = password.as_bytes();
    let copy_len = pass_bytes.len().min(32);
    temp[..copy_len].copy_from_slice(&pass_bytes[..copy_len]);
    for chunk in temp.chunks_exact_mut(4) {
        let n = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ seed;
        chunk.copy_from_slice(&n.to_be_bytes());
    }
    crate::crypto::md5::compute_md5(&temp)
}
