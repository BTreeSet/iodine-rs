use clap::Args;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::warn;

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

    let mut dns_id: u16 = 1;
    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 2048];

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
                let encoded = crate::encoding::base32::encode(&tun_buf[..len]);
                let qname_wire = match build_qname_wire(&encoded, &topdomain) {
                    Some(v) => v,
                    None => {
                        warn!("invalid topdomain or qname encoding");
                        continue;
                    }
                };

                let mut query = BytesMut::with_capacity(2048);
                let header = DnsHeader {
                    id: dns_id,
                    flags: 0x0100,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                };
                dns_id = dns_id.wrapping_add(1);
                header.write_to(&mut query);
                DnsQuestion {
                    qname_wire: &qname_wire,
                    qtype: DNS_TYPE_NULL,
                    qclass: DNS_CLASS_IN,
                }
                .write_to(&mut query);

                if let Err(err) = socket.send_to(&query, nameserver).await {
                    warn!(error = %err, "udp send_to failed");
                    continue;
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
                let decoded = match rr.rdata {
                    DnsRdata::Null(data) => crate::encoding::base64::decode_bytes(data),
                    DnsRdata::Txt(data) => {
                        let txt = flatten_txt_rdata(data);
                        crate::encoding::base64::decode_bytes(&txt)
                    }
                    _ => continue,
                };
                if decoded.is_empty() {
                    continue;
                }
                if let Err(err) = tun_device.write_all(&decoded).await {
                    warn!(error = %err, "tun write_all failed");
                    continue;
                }
            }
        }
    }
}

fn build_qname_wire(first_label: &str, topdomain: &str) -> Option<Vec<u8>> {
    if first_label.is_empty() || first_label.len() > 63 {
        return None;
    }
    let mut out = Vec::with_capacity(first_label.len() + topdomain.len() + 4);
    out.push(first_label.len() as u8);
    out.extend_from_slice(first_label.as_bytes());
    for part in topdomain.trim_matches('.').split('.') {
        if part.is_empty() || part.len() > 63 {
            return None;
        }
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
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
