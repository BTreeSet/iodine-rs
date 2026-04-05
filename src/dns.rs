use std::io::Cursor;

use bytes::{BufMut, BytesMut};
use thiserror::Error;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_NULL: u16 = 10;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn parse(buf: &mut Cursor<&[u8]>) -> Result<Self, DnsError> {
        let raw = *buf.get_ref();
        let pos = buf.position() as usize;
        if raw.len().saturating_sub(pos) < 12 {
            return Err(DnsError::BufferTooShort);
        }

        let header = Self {
            id: u16::from_be_bytes([raw[pos], raw[pos + 1]]),
            flags: u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]),
            qdcount: u16::from_be_bytes([raw[pos + 4], raw[pos + 5]]),
            ancount: u16::from_be_bytes([raw[pos + 6], raw[pos + 7]]),
            nscount: u16::from_be_bytes([raw[pos + 8], raw[pos + 9]]),
            arcount: u16::from_be_bytes([raw[pos + 10], raw[pos + 11]]),
        };
        buf.set_position((pos + 12) as u64);

        let opcode = header.opcode();
        if opcode > 2 {
            return Err(DnsError::InvalidOpcode(opcode));
        }

        Ok(header)
    }

    pub fn write_to(self, buf: &mut BytesMut) {
        buf.put_u16(self.id);
        buf.put_u16(self.flags);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }

    pub fn is_response(self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    pub fn rcode(self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQuestion<'a> {
    pub qname_wire: &'a [u8],
    pub qtype: u16,
    pub qclass: u16,
}

impl<'a> DnsQuestion<'a> {
    pub fn parse(buf: &mut Cursor<&'a [u8]>) -> Result<Self, DnsError> {
        let raw = *buf.get_ref();
        let start = buf.position() as usize;
        let end = skip_name(raw, start)?;

        if raw.len().saturating_sub(end) < 4 {
            return Err(DnsError::BufferTooShort);
        }

        let qtype = u16::from_be_bytes([raw[end], raw[end + 1]]);
        let qclass = u16::from_be_bytes([raw[end + 2], raw[end + 3]]);
        buf.set_position((end + 4) as u64);

        Ok(Self {
            qname_wire: &raw[start..end],
            qtype,
            qclass,
        })
    }

    pub fn write_to(self, buf: &mut BytesMut) {
        buf.put_slice(self.qname_wire);
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRdata<'a> {
    A([u8; 4]),
    Cname(&'a [u8]),
    Null(&'a [u8]),
    Txt(&'a [u8]),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target_wire: &'a [u8],
    },
    Raw(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResourceRecord<'a> {
    pub name_wire: &'a [u8],
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: DnsRdata<'a>,
}

impl<'a> DnsResourceRecord<'a> {
    pub fn parse(buf: &mut Cursor<&'a [u8]>) -> Result<Self, DnsError> {
        let raw = *buf.get_ref();
        let start = buf.position() as usize;
        let end = skip_name(raw, start)?;

        if raw.len().saturating_sub(end) < 10 {
            return Err(DnsError::BufferTooShort);
        }

        let rr_type = u16::from_be_bytes([raw[end], raw[end + 1]]);
        let class = u16::from_be_bytes([raw[end + 2], raw[end + 3]]);
        let ttl = u32::from_be_bytes([raw[end + 4], raw[end + 5], raw[end + 6], raw[end + 7]]);
        let rdlen = u16::from_be_bytes([raw[end + 8], raw[end + 9]]) as usize;
        let rdata_start = end + 10;
        let rdata_end = rdata_start.saturating_add(rdlen);

        if rdata_end > raw.len() {
            return Err(DnsError::BufferTooShort);
        }

        let rdata_slice = &raw[rdata_start..rdata_end];
        let rdata = match rr_type {
            DNS_TYPE_A if rdlen == 4 => DnsRdata::A([
                rdata_slice[0],
                rdata_slice[1],
                rdata_slice[2],
                rdata_slice[3],
            ]),
            DNS_TYPE_CNAME => DnsRdata::Cname(rdata_slice),
            DNS_TYPE_NULL => DnsRdata::Null(rdata_slice),
            DNS_TYPE_TXT => DnsRdata::Txt(rdata_slice),
            DNS_TYPE_SRV if rdlen >= 6 => DnsRdata::Srv {
                priority: u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]),
                weight: u16::from_be_bytes([rdata_slice[2], rdata_slice[3]]),
                port: u16::from_be_bytes([rdata_slice[4], rdata_slice[5]]),
                target_wire: &rdata_slice[6..],
            },
            _ => DnsRdata::Raw(rdata_slice),
        };

        buf.set_position(rdata_end as u64);

        Ok(Self {
            name_wire: &raw[start..end],
            rr_type,
            class,
            ttl,
            rdata,
        })
    }

    pub fn write_to(self, buf: &mut BytesMut) {
        buf.put_slice(self.name_wire);
        buf.put_u16(self.rr_type);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);

        match self.rdata {
            DnsRdata::A(addr) => {
                buf.put_u16(4);
                buf.put_slice(&addr);
            }
            DnsRdata::Cname(name_wire) => {
                buf.put_u16(name_wire.len() as u16);
                buf.put_slice(name_wire);
            }
            DnsRdata::Null(data) => {
                buf.put_u16(data.len() as u16);
                buf.put_slice(data);
            }
            DnsRdata::Txt(data) => {
                let txt_len = txt_encoded_len(data);
                buf.put_u16(txt_len as u16);
                write_txt_data(buf, data);
            }
            DnsRdata::Srv {
                priority,
                weight,
                port,
                target_wire,
            } => {
                let rdlen = 6usize.saturating_add(target_wire.len());
                buf.put_u16(rdlen as u16);
                buf.put_u16(priority);
                buf.put_u16(weight);
                buf.put_u16(port);
                buf.put_slice(target_wire);
            }
            DnsRdata::Raw(data) => {
                buf.put_u16(data.len() as u16);
                buf.put_slice(data);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket<'a> {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion<'a>>,
    pub answers: Vec<DnsResourceRecord<'a>>,
    pub authorities: Vec<DnsResourceRecord<'a>>,
    pub additionals: Vec<DnsResourceRecord<'a>>,
}

impl<'a> DnsPacket<'a> {
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.header.write_to(buf);

        for q in &self.questions {
            q.write_to(buf);
        }
        for rr in &self.answers {
            rr.write_to(buf);
        }
        for rr in &self.authorities {
            rr.write_to(buf);
        }
        for rr in &self.additionals {
            rr.write_to(buf);
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid opcode: {0}")]
    InvalidOpcode(u8),
    #[error("label too long: {0}")]
    LabelTooLong(u8),
    #[error("invalid name pointer: {0}")]
    InvalidNamePointer(u16),
    #[error("pointer loop detected")]
    PointerLoop,
    #[error("unterminated DNS name")]
    UnterminatedName,
}

pub fn try_packet_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 12 {
        return None;
    }

    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

pub fn parse_packet(packet: &[u8]) -> Result<DnsPacket<'_>, DnsError> {
    let mut cursor = Cursor::new(packet);
    let header = DnsHeader::parse(&mut cursor)?;

    let mut questions = Vec::with_capacity(header.qdcount as usize);
    for _ in 0..header.qdcount {
        questions.push(DnsQuestion::parse(&mut cursor)?);
    }

    let mut answers = Vec::with_capacity(header.ancount as usize);
    for _ in 0..header.ancount {
        answers.push(DnsResourceRecord::parse(&mut cursor)?);
    }

    let mut authorities = Vec::with_capacity(header.nscount as usize);
    for _ in 0..header.nscount {
        authorities.push(DnsResourceRecord::parse(&mut cursor)?);
    }

    let mut additionals = Vec::with_capacity(header.arcount as usize);
    for _ in 0..header.arcount {
        additionals.push(DnsResourceRecord::parse(&mut cursor)?);
    }

    Ok(DnsPacket {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn txt_encoded_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 1;
    }

    let chunks = data.len().div_ceil(255);
    data.len().saturating_add(chunks)
}

fn write_txt_data(buf: &mut BytesMut, data: &[u8]) {
    if data.is_empty() {
        buf.put_u8(0);
        return;
    }

    let mut start = 0usize;
    while start < data.len() {
        let end = (start + 255).min(data.len());
        let chunk = &data[start..end];
        buf.put_u8(chunk.len() as u8);
        buf.put_slice(chunk);
        start = end;
    }
}

fn skip_name(packet: &[u8], start: usize) -> Result<usize, DnsError> {
    if start >= packet.len() {
        return Err(DnsError::BufferTooShort);
    }

    let mut idx = start;
    let mut consumed_end = None;
    let mut jumps = 0usize;

    loop {
        if idx >= packet.len() {
            return Err(DnsError::BufferTooShort);
        }

        let len = packet[idx];
        if (len & 0xC0) == 0xC0 {
            if idx + 1 >= packet.len() {
                return Err(DnsError::BufferTooShort);
            }
            let ptr = (((len as u16 & 0x3F) << 8) | packet[idx + 1] as u16) as usize;
            if ptr >= packet.len() {
                return Err(DnsError::InvalidNamePointer(ptr as u16));
            }
            if consumed_end.is_none() {
                consumed_end = Some(idx + 2);
            }
            idx = ptr;
            jumps += 1;
            if jumps > packet.len() {
                return Err(DnsError::PointerLoop);
            }
            continue;
        }

        if len == 0 {
            return Ok(consumed_end.unwrap_or(idx + 1));
        }

        if len > 63 {
            return Err(DnsError::LabelTooLong(len));
        }

        let next = idx + 1 + len as usize;
        if next > packet.len() {
            return Err(DnsError::UnterminatedName);
        }
        idx = next;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bytes::BytesMut;

    use super::{
        parse_packet, try_packet_id, DnsHeader, DnsPacket, DnsQuestion, DnsRdata,
        DnsResourceRecord, DNS_CLASS_IN, DNS_TYPE_NULL, DNS_TYPE_OPT,
    };

    const QUERY_PACKET: &[u8] =
        b"\x05\x39\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x2D\x41\x6A\x62\x63\
\x75\x79\x74\x63\x70\x65\x62\x30\x67\x71\x30\x6C\x74\x65\x62\x75\x78\x67\x69\x64\x75\x6E\
\x62\x73\x73\x61\x33\x64\x66\x6F\x6E\x30\x63\x61\x7A\x64\x62\x6F\x72\x71\x71\x04\x6B\x72\
\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00";

    const ANSWER_PACKET: &[u8] =
        b"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C\
\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04\x63\x6F\x64\x65\x04\
\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\
\x00\x23\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\
\x74\x6F\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";

    const ANSWER_PACKET_HIGH_TRANS_ID: &[u8] =
        b"\x85\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\
\x6C\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04\x63\x6F\x64\x65\
\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\
\x00\x00\x23\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\
\x20\x74\x6F\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";

    #[test]
    fn parse_header_from_raw_dns_query() {
        let raw: [u8; 12] = [
            0x1a, 0x2b, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];

        let mut cur = Cursor::new(raw.as_slice());
        let header = DnsHeader::parse(&mut cur).expect("header should parse");
        assert_eq!(header.id, 0x1a2b);
        assert_eq!(header.qdcount, 1);
        assert!(!header.is_response());
    }

    #[test]
    fn parse_question_from_raw_dns_query_without_allocating_vec() {
        let raw: [u8; 33] = [
            0x1a, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let mut cur = Cursor::new(raw.as_slice());
        let _ = DnsHeader::parse(&mut cur).expect("header should parse");
        let question = DnsQuestion::parse(&mut cur).expect("question should parse");

        assert_eq!(question.qtype, 1);
        assert_eq!(question.qclass, 1);
        assert_eq!(question.qname_wire[0], 0x03);
    }

    #[test]
    fn parse_packet_with_a_answer_and_pointer_name() {
        let packet: [u8; 49] = [
            0x1a, 0x2b, // id
            0x81, 0x80, // flags response noerror
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, // pointer to qname
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x04, // RDLEN
            0x5D, 0xB8, 0xD8, 0x22, // 93.184.216.34
        ];

        let parsed = parse_packet(&packet).expect("packet should parse");
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rr_type, 1);
        assert_eq!(
            parsed.answers[0].rdata,
            DnsRdata::A([0x5D, 0xB8, 0xD8, 0x22])
        );
    }

    #[test]
    fn write_query_matches_upstream_vector() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1337,
                flags: 0x0100,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 1,
            },
            questions: vec![DnsQuestion {
                qname_wire: b"\x2D\x41\x6A\x62\x63\x75\x79\x74\x63\x70\x65\x62\x30\x67\x71\x30\
\x6C\x74\x65\x62\x75\x78\x67\x69\x64\x75\x6E\x62\x73\x73\x61\x33\x64\x66\x6F\x6E\x30\x63\
\x61\x7A\x64\x62\x6F\x72\x71\x71\x04\x6B\x72\x79\x6F\x02\x73\x65\x00",
                qtype: DNS_TYPE_NULL,
                qclass: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: vec![DnsResourceRecord {
                name_wire: b"\x00",
                rr_type: DNS_TYPE_OPT,
                class: 0x1000,
                ttl: 0x0000_8000,
                rdata: DnsRdata::Raw(b""),
            }],
        };

        let mut out = BytesMut::with_capacity(512);
        packet.write_to(&mut out);
        assert_eq!(out.as_ref(), QUERY_PACKET);
    }

    #[test]
    fn write_answer_matches_upstream_vector() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1337,
                flags: 0x8400,
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname_wire: b"\x05\x73\x69\x6C\x6C\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\
\x6F\x64\x69\x6E\x65\x04\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00",
                qtype: DNS_TYPE_NULL,
                qclass: DNS_CLASS_IN,
            }],
            answers: vec![DnsResourceRecord {
                name_wire: b"\xC0\x0C",
                rr_type: DNS_TYPE_NULL,
                class: DNS_CLASS_IN,
                ttl: 0,
                rdata: DnsRdata::Null(b"this is the message to be delivered"),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let mut out = BytesMut::with_capacity(512);
        packet.write_to(&mut out);
        assert_eq!(out.as_ref(), ANSWER_PACKET);
    }

    #[test]
    fn parse_answer_vector_keeps_id_and_payload() {
        let parsed = parse_packet(ANSWER_PACKET).expect("answer should parse");
        assert_eq!(parsed.header.id, 0x0539);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].rdata,
            DnsRdata::Null(b"this is the message to be delivered")
        );
    }

    #[test]
    fn get_id_matches_upstream_vectors() {
        assert_eq!(try_packet_id(&[5, 5, 5, 5, 5]), None);
        assert_eq!(try_packet_id(ANSWER_PACKET), Some(1337));
        assert_eq!(try_packet_id(ANSWER_PACKET_HIGH_TRANS_ID), Some(0x8539));
    }

    #[test]
    fn packet_id_distinguishes_short_packet_from_valid_zero() {
        let valid_zero = [
            0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(try_packet_id(&valid_zero), Some(0));
        assert_eq!(try_packet_id(&valid_zero[..11]), None);
    }
}
