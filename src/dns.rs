use std::io::Cursor;

use bytes::{Buf, Bytes};
use thiserror::Error;

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

        let mut b = Bytes::copy_from_slice(&raw[pos..pos + 12]);
        let header = Self {
            id: b.get_u16(),
            flags: b.get_u16(),
            qdcount: b.get_u16(),
            ancount: b.get_u16(),
            nscount: b.get_u16(),
            arcount: b.get_u16(),
        };
        buf.set_position((pos + 12) as u64);

        let opcode = header.opcode();
        if opcode > 2 {
            return Err(DnsError::InvalidOpcode(opcode));
        }

        Ok(header)
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResourceRecord<'a> {
    pub name_wire: &'a [u8],
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
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

        buf.set_position(rdata_end as u64);

        Ok(Self {
            name_wire: &raw[start..end],
            rr_type,
            class,
            ttl,
            rdata: &raw[rdata_start..rdata_end],
        })
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

    use super::{parse_packet, DnsHeader, DnsQuestion};

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
        assert_eq!(parsed.answers[0].rdata, &[0x5D, 0xB8, 0xD8, 0x22]);
    }
}
