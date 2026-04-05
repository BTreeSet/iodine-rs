use std::io::Cursor;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

pub const CLASS_IN: u16 = 1;
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_NULL: u16 = 10;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;

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

    pub fn write_to(self, buf: &mut BytesMut) -> Result<(), DnsError> {
        validate_name_wire_for_write(self.qname_wire)?;
        buf.put_slice(self.qname_wire);
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);
        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordData<'a> {
    Txt(&'a [u8]),
    Null(&'a [u8]),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target_wire: &'a [u8],
    },
    Cname(&'a [u8]),
    A([u8; 4]),
    Raw {
        rr_type: u16,
        data: &'a [u8],
    },
}

impl<'a> DnsRecordData<'a> {
    fn rr_type(self) -> u16 {
        match self {
            Self::Txt(_) => TYPE_TXT,
            Self::Null(_) => TYPE_NULL,
            Self::Srv { .. } => TYPE_SRV,
            Self::Cname(_) => TYPE_CNAME,
            Self::A(_) => TYPE_A,
            Self::Raw { rr_type, .. } => rr_type,
        }
    }

    fn encoded_len(self) -> Result<usize, DnsError> {
        match self {
            Self::Txt(text) => {
                if text.len() > u8::MAX as usize {
                    return Err(DnsError::RdataTooLong(text.len()));
                }
                Ok(1 + text.len())
            }
            Self::Null(data) => Ok(data.len()),
            Self::Srv { target_wire, .. } => {
                validate_name_wire_for_write(target_wire)?;
                Ok(6 + target_wire.len())
            }
            Self::Cname(name_wire) => {
                validate_name_wire_for_write(name_wire)?;
                Ok(name_wire.len())
            }
            Self::A(_) => Ok(4),
            Self::Raw { data, .. } => Ok(data.len()),
        }
    }

    fn write_rdata(self, buf: &mut BytesMut) -> Result<(), DnsError> {
        match self {
            Self::Txt(text) => {
                if text.len() > u8::MAX as usize {
                    return Err(DnsError::RdataTooLong(text.len()));
                }
                buf.put_u8(text.len() as u8);
                buf.put_slice(text);
            }
            Self::Null(data) => buf.put_slice(data),
            Self::Srv {
                priority,
                weight,
                port,
                target_wire,
            } => {
                validate_name_wire_for_write(target_wire)?;
                buf.put_u16(priority);
                buf.put_u16(weight);
                buf.put_u16(port);
                buf.put_slice(target_wire);
            }
            Self::Cname(name_wire) => {
                validate_name_wire_for_write(name_wire)?;
                buf.put_slice(name_wire);
            }
            Self::A(addr) => buf.put_slice(&addr),
            Self::Raw { data, .. } => buf.put_slice(data),
        }

        Ok(())
    }
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

    pub fn from_data(name_wire: &'a [u8], class: u16, ttl: u32, data: DnsRecordData<'a>) -> Self {
        Self {
            name_wire,
            rr_type: data.rr_type(),
            class,
            ttl,
            rdata: data_bytes(data),
        }
    }

    pub fn data(self) -> Result<DnsRecordData<'a>, DnsError> {
        match self.rr_type {
            TYPE_TXT => {
                if self.rdata.is_empty() {
                    return Err(DnsError::BufferTooShort);
                }
                let len = self.rdata[0] as usize;
                if self.rdata.len().saturating_sub(1) < len {
                    return Err(DnsError::BufferTooShort);
                }
                Ok(DnsRecordData::Txt(&self.rdata[1..1 + len]))
            }
            TYPE_NULL => Ok(DnsRecordData::Null(self.rdata)),
            TYPE_SRV => {
                if self.rdata.len() < 7 {
                    return Err(DnsError::BufferTooShort);
                }
                let priority = u16::from_be_bytes([self.rdata[0], self.rdata[1]]);
                let weight = u16::from_be_bytes([self.rdata[2], self.rdata[3]]);
                let port = u16::from_be_bytes([self.rdata[4], self.rdata[5]]);
                skip_name(self.rdata, 6)?;
                Ok(DnsRecordData::Srv {
                    priority,
                    weight,
                    port,
                    target_wire: &self.rdata[6..],
                })
            }
            TYPE_CNAME => {
                skip_name(self.rdata, 0)?;
                Ok(DnsRecordData::Cname(self.rdata))
            }
            TYPE_A => {
                if self.rdata.len() != 4 {
                    return Err(DnsError::RdataLengthMismatch {
                        rr_type: TYPE_A,
                        expected: 4,
                        actual: self.rdata.len(),
                    });
                }
                Ok(DnsRecordData::A([
                    self.rdata[0],
                    self.rdata[1],
                    self.rdata[2],
                    self.rdata[3],
                ]))
            }
            other => Ok(DnsRecordData::Raw {
                rr_type: other,
                data: self.rdata,
            }),
        }
    }

    pub fn write_to(self, data: DnsRecordData<'a>, buf: &mut BytesMut) -> Result<(), DnsError> {
        validate_name_wire_for_write(self.name_wire)?;
        let rdlen = data.encoded_len()?;
        if rdlen > u16::MAX as usize {
            return Err(DnsError::RdataTooLong(rdlen));
        }

        buf.put_slice(self.name_wire);
        buf.put_u16(self.rr_type);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(rdlen as u16);
        data.write_rdata(buf)
    }
}

fn data_bytes<'a>(data: DnsRecordData<'a>) -> &'a [u8] {
    match data {
        DnsRecordData::Txt(s)
        | DnsRecordData::Null(s)
        | DnsRecordData::Cname(s)
        | DnsRecordData::Raw { data: s, .. } => s,
        DnsRecordData::Srv { target_wire, .. } => target_wire,
        DnsRecordData::A(_) => &[],
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
    #[error("record data too long: {0}")]
    RdataTooLong(usize),
    #[error("record data length mismatch for type {rr_type}: expected {expected}, got {actual}")]
    RdataLengthMismatch {
        rr_type: u16,
        expected: usize,
        actual: usize,
    },
    #[error("packet section count mismatch")]
    CountMismatch,
}

impl<'a> DnsPacket<'a> {
    pub fn write_to(
        &self,
        buf: &mut BytesMut,
        records: &DnsSectionData<'a>,
    ) -> Result<(), DnsError> {
        if self.questions.len() != self.header.qdcount as usize
            || self.answers.len() != self.header.ancount as usize
            || self.authorities.len() != self.header.nscount as usize
            || self.additionals.len() != self.header.arcount as usize
            || self.answers.len() != records.answers.len()
            || self.authorities.len() != records.authorities.len()
            || self.additionals.len() != records.additionals.len()
        {
            return Err(DnsError::CountMismatch);
        }

        self.header.write_to(buf);

        for question in &self.questions {
            question.write_to(buf)?;
        }

        for (record, data) in self.answers.iter().zip(&records.answers) {
            record.write_to(*data, buf)?;
        }
        for (record, data) in self.authorities.iter().zip(&records.authorities) {
            record.write_to(*data, buf)?;
        }
        for (record, data) in self.additionals.iter().zip(&records.additionals) {
            record.write_to(*data, buf)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSectionData<'a> {
    pub answers: Vec<DnsRecordData<'a>>,
    pub authorities: Vec<DnsRecordData<'a>>,
    pub additionals: Vec<DnsRecordData<'a>>,
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

fn validate_name_wire_for_write(name_wire: &[u8]) -> Result<(), DnsError> {
    if name_wire.is_empty() {
        return Err(DnsError::BufferTooShort);
    }

    let mut idx = 0usize;
    while idx < name_wire.len() {
        let len = name_wire[idx];
        if (len & 0xC0) == 0xC0 {
            if idx + 1 >= name_wire.len() {
                return Err(DnsError::BufferTooShort);
            }
            return Ok(());
        }
        if len == 0 {
            return Ok(());
        }
        if len > 63 {
            return Err(DnsError::LabelTooLong(len));
        }
        idx += 1 + len as usize;
    }

    Err(DnsError::UnterminatedName)
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
    use bytes::BytesMut;

    use super::{
        parse_packet, DnsHeader, DnsPacket, DnsQuestion, DnsRecordData, DnsResourceRecord,
        DnsSectionData, CLASS_IN, TYPE_NULL,
    };

    const QUERY_PACKET: [u8; 82] = [
        0x05, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2D, 0x41, 0x6A,
        0x62, 0x63, 0x75, 0x79, 0x74, 0x63, 0x70, 0x65, 0x62, 0x30, 0x67, 0x71, 0x30, 0x6C, 0x74,
        0x65, 0x62, 0x75, 0x78, 0x67, 0x69, 0x64, 0x75, 0x6E, 0x62, 0x73, 0x73, 0x61, 0x33, 0x64,
        0x66, 0x6F, 0x6E, 0x30, 0x63, 0x61, 0x7A, 0x64, 0x62, 0x6F, 0x72, 0x71, 0x71, 0x04, 0x6B,
        0x72, 0x79, 0x6F, 0x02, 0x73, 0x65, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ];

    const ANSWER_PACKET: [u8; 98] = [
        0x05, 0x39, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x73, 0x69,
        0x6C, 0x6C, 0x79, 0x04, 0x68, 0x6F, 0x73, 0x74, 0x02, 0x6F, 0x66, 0x06, 0x69, 0x6F, 0x64,
        0x69, 0x6E, 0x65, 0x04, 0x63, 0x6F, 0x64, 0x65, 0x04, 0x6B, 0x72, 0x79, 0x6F, 0x02, 0x73,
        0x65, 0x00, 0x00, 0x0A, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x23, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x6F, 0x20, 0x62, 0x65, 0x20, 0x64,
        0x65, 0x6C, 0x69, 0x76, 0x65, 0x72, 0x65, 0x64,
    ];

    #[test]
    fn parse_query_packet_from_upstream_vector() {
        let parsed = parse_packet(&QUERY_PACKET).expect("query parse");
        assert_eq!(parsed.header.id, 0x0539);
        assert_eq!(parsed.header.qdcount, 1);
        assert_eq!(parsed.header.arcount, 1);
        assert_eq!(parsed.questions[0].qtype, TYPE_NULL);
        assert_eq!(parsed.questions[0].qclass, CLASS_IN);
        assert_eq!(parsed.additionals[0].rr_type, 41);
        assert_eq!(parsed.additionals[0].class, 4096);
        assert_eq!(parsed.additionals[0].ttl, 0x0000_8000);
        assert!(parsed.additionals[0].rdata.is_empty());
    }

    #[test]
    fn parse_answer_packet_from_upstream_vector() {
        let parsed = parse_packet(&ANSWER_PACKET).expect("answer parse");
        assert_eq!(parsed.header.id, 0x0539);
        assert!(parsed.header.is_response());
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rr_type, TYPE_NULL);
        assert_eq!(
            parsed.answers[0].rdata,
            b"this is the message to be delivered"
        );
    }

    #[test]
    fn serialize_query_packet_matches_upstream_bytes() {
        let parsed = parse_packet(&QUERY_PACKET).expect("parse source query");
        let question_name = parsed.questions[0].qname_wire;
        let root_name = parsed.additionals[0].name_wire;

        let packet = DnsPacket {
            header: DnsHeader {
                id: 0x0539,
                flags: 0x0100,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 1,
            },
            questions: vec![DnsQuestion {
                qname_wire: question_name,
                qtype: TYPE_NULL,
                qclass: CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: vec![DnsResourceRecord {
                name_wire: root_name,
                rr_type: 41,
                class: 4096,
                ttl: 0x0000_8000,
                rdata: &[],
            }],
        };

        let mut out = BytesMut::with_capacity(QUERY_PACKET.len());
        packet
            .write_to(
                &mut out,
                &DnsSectionData {
                    answers: Vec::new(),
                    authorities: Vec::new(),
                    additionals: vec![DnsRecordData::Raw {
                        rr_type: 41,
                        data: &[],
                    }],
                },
            )
            .expect("serialize query");

        assert_eq!(out.as_ref(), QUERY_PACKET);
    }

    #[test]
    fn serialize_answer_packet_matches_upstream_bytes() {
        let parsed = parse_packet(&ANSWER_PACKET).expect("parse source answer");
        let question_name = parsed.questions[0].qname_wire;
        let pointer_name = parsed.answers[0].name_wire;
        let msg_data = b"this is the message to be delivered";

        let packet = DnsPacket {
            header: DnsHeader {
                id: 0x0539,
                flags: 0x8400,
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname_wire: question_name,
                qtype: TYPE_NULL,
                qclass: CLASS_IN,
            }],
            answers: vec![DnsResourceRecord {
                name_wire: pointer_name,
                rr_type: TYPE_NULL,
                class: CLASS_IN,
                ttl: 0,
                rdata: msg_data,
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let mut out = BytesMut::with_capacity(ANSWER_PACKET.len());
        packet
            .write_to(
                &mut out,
                &DnsSectionData {
                    answers: vec![DnsRecordData::Null(msg_data)],
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                },
            )
            .expect("serialize answer");

        assert_eq!(out.as_ref(), ANSWER_PACKET);
    }
}
