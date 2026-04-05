use bytes::{Buf, Bytes};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Name(String),
    Txt(Vec<u8>),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsParseError {
    Truncated,
    LabelTooLong,
    InvalidPointer,
    PointerLoop,
    NameNotUtf8,
}

pub fn parse_packet(packet: &[u8]) -> Result<DnsPacket, DnsParseError> {
    let mut cursor = Bytes::copy_from_slice(packet);
    if cursor.remaining() < 12 {
        return Err(DnsParseError::Truncated);
    }

    let header = DnsHeader {
        id: cursor.get_u16(),
        flags: cursor.get_u16(),
        qdcount: cursor.get_u16(),
        ancount: cursor.get_u16(),
        nscount: cursor.get_u16(),
        arcount: cursor.get_u16(),
    };

    let mut offset = 12usize;

    let mut questions = Vec::with_capacity(header.qdcount as usize);
    for _ in 0..header.qdcount {
        let (name, next) = parse_name(packet, offset)?;
        offset = next;
        if packet.len().saturating_sub(offset) < 4 {
            return Err(DnsParseError::Truncated);
        }
        let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        offset += 4;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::with_capacity(header.ancount as usize);
    for _ in 0..header.ancount {
        let (rr, next) = parse_record(packet, offset)?;
        offset = next;
        answers.push(rr);
    }

    let mut authorities = Vec::with_capacity(header.nscount as usize);
    for _ in 0..header.nscount {
        let (rr, next) = parse_record(packet, offset)?;
        offset = next;
        authorities.push(rr);
    }

    let mut additionals = Vec::with_capacity(header.arcount as usize);
    for _ in 0..header.arcount {
        let (rr, next) = parse_record(packet, offset)?;
        offset = next;
        additionals.push(rr);
    }

    Ok(DnsPacket {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn parse_record(packet: &[u8], offset: usize) -> Result<(DnsRecord, usize), DnsParseError> {
    let (name, mut at) = parse_name(packet, offset)?;

    if packet.len().saturating_sub(at) < 10 {
        return Err(DnsParseError::Truncated);
    }
    let rtype = u16::from_be_bytes([packet[at], packet[at + 1]]);
    let class = u16::from_be_bytes([packet[at + 2], packet[at + 3]]);
    let ttl = u32::from_be_bytes([
        packet[at + 4],
        packet[at + 5],
        packet[at + 6],
        packet[at + 7],
    ]);
    let rdlen = u16::from_be_bytes([packet[at + 8], packet[at + 9]]) as usize;
    at += 10;

    if packet.len().saturating_sub(at) < rdlen {
        return Err(DnsParseError::Truncated);
    }

    let rdata = match rtype {
        1 if rdlen == 4 => {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&packet[at..at + 4]);
            DnsRecordData::A(ip)
        }
        28 if rdlen == 16 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&packet[at..at + 16]);
            DnsRecordData::Aaaa(ip)
        }
        5 | 2 | 12 => {
            let (target, _) = parse_name(packet, at)?;
            DnsRecordData::Name(target)
        }
        16 => DnsRecordData::Txt(packet[at..at + rdlen].to_vec()),
        _ => DnsRecordData::Unknown(packet[at..at + rdlen].to_vec()),
    };

    Ok((
        DnsRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        },
        at + rdlen,
    ))
}

fn parse_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsParseError> {
    if start >= packet.len() {
        return Err(DnsParseError::Truncated);
    }

    let mut labels = Vec::new();
    let mut idx = start;
    let mut next_offset = None;
    let mut jumps = 0usize;

    loop {
        if idx >= packet.len() {
            return Err(DnsParseError::Truncated);
        }

        let len = packet[idx];
        if (len & 0xC0) == 0xC0 {
            if idx + 1 >= packet.len() {
                return Err(DnsParseError::Truncated);
            }
            let ptr = (((len as u16 & 0x3F) << 8) | packet[idx + 1] as u16) as usize;
            if ptr >= packet.len() {
                return Err(DnsParseError::InvalidPointer);
            }
            if next_offset.is_none() {
                next_offset = Some(idx + 2);
            }
            idx = ptr;
            jumps += 1;
            if jumps > packet.len() {
                return Err(DnsParseError::PointerLoop);
            }
            continue;
        }

        if len == 0 {
            let end = next_offset.unwrap_or(idx + 1);
            let name = if labels.is_empty() {
                String::new()
            } else {
                labels.join(".")
            };
            return Ok((name, end));
        }

        if len > 63 {
            return Err(DnsParseError::LabelTooLong);
        }

        let end = idx + 1 + len as usize;
        if end > packet.len() {
            return Err(DnsParseError::Truncated);
        }

        let label =
            std::str::from_utf8(&packet[idx + 1..end]).map_err(|_| DnsParseError::NameNotUtf8)?;
        labels.push(label.to_string());
        idx = end;
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_packet, DnsRecordData};

    #[test]
    fn parse_simple_query_packet() {
        let packet: [u8; 33] = [
            0x1a, 0x2b, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, // A
            0x00, 0x01, // IN
        ];

        let parsed = parse_packet(&packet).expect("query should parse");
        assert_eq!(parsed.header.id, 0x1a2b);
        assert!(!parsed.header.is_response());
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "www.example.com");
        assert_eq!(parsed.questions[0].qtype, 1);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn parse_a_answer_with_name_pointer() {
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

        let parsed = parse_packet(&packet).expect("response should parse");
        assert!(parsed.header.is_response());
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "www.example.com");
        assert_eq!(parsed.answers[0].rtype, 1);
        assert_eq!(parsed.answers[0].ttl, 60);
        assert_eq!(
            parsed.answers[0].rdata,
            DnsRecordData::A([0x5D, 0xB8, 0xD8, 0x22])
        );
    }
}
