use std::net::SocketAddr;

use thiserror::Error;

use crate::dns::{DnsError, DnsPacket, DnsQuestion};

pub const FW_QUERY_CACHE_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwQuery {
    pub addr: SocketAddr,
    pub addrlen: usize,
    pub id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardQuery<'a> {
    pub source: FwQuery,
    pub question: DnsQuestion<'a>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FwQueryError {
    #[error("missing DNS question")]
    MissingQuestion,
    #[error("dns parse error: {0}")]
    Dns(#[from] DnsError),
}

impl<'a> ForwardQuery<'a> {
    pub fn from_dns_packet(
        packet: &'a [u8],
        addr: SocketAddr,
        addrlen: usize,
    ) -> Result<Self, FwQueryError> {
        let parsed = crate::dns::parse_packet(packet)?;
        let question = *parsed
            .questions
            .first()
            .ok_or(FwQueryError::MissingQuestion)?;

        Ok(Self {
            source: FwQuery {
                addr,
                addrlen,
                id: parsed.header.id,
            },
            question,
        })
    }

    pub fn from_parsed_packet(
        packet: &'a DnsPacket<'a>,
        addr: SocketAddr,
        addrlen: usize,
    ) -> Result<Self, FwQueryError> {
        let question = *packet
            .questions
            .first()
            .ok_or(FwQueryError::MissingQuestion)?;
        Ok(Self {
            source: FwQuery {
                addr,
                addrlen,
                id: packet.header.id,
            },
            question,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FwQueryCache {
    ring: Vec<Option<FwQuery>>,
    next: usize,
}

impl Default for FwQueryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FwQueryCache {
    pub fn new() -> Self {
        Self::with_capacity(FW_QUERY_CACHE_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ring: vec![None; capacity],
            next: 0,
        }
    }

    pub fn put(&mut self, query: FwQuery) {
        if self.ring.is_empty() {
            return;
        }

        self.ring[self.next] = Some(query);
        self.next += 1;
        if self.next >= self.ring.len() {
            self.next = 0;
        }
    }

    pub fn get(&self, id: u16) -> Option<&FwQuery> {
        self.ring
            .iter()
            .filter_map(Option::as_ref)
            .find(|query| query.id == id)
    }

    pub fn clear(&mut self) {
        self.ring.fill(None);
        self.next = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::dns::TYPE_NULL;

    use super::{ForwardQuery, FwQuery, FwQueryCache, FW_QUERY_CACHE_SIZE};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn fw_query_simple_matches_upstream_behavior() {
        let mut cache = FwQueryCache::new();

        let query = FwQuery {
            addr: localhost(5353),
            addrlen: 33,
            id: 0x848A,
        };

        assert!(cache.get(0x848A).is_none());
        cache.put(query.clone());

        let found = cache.get(0x848A).expect("cached entry");
        assert_eq!(found.addrlen, 33);
        assert_eq!(found.id, 0x848A);
        assert_eq!(found.addr, query.addr);
    }

    #[test]
    fn fw_query_ring_edge_matches_upstream_behavior() {
        let mut cache = FwQueryCache::new();

        let mut addrlen = 33usize;
        let mut id = 0x848A;
        cache.put(FwQuery {
            addr: localhost(5300),
            addrlen,
            id,
        });

        for _ in 1..FW_QUERY_CACHE_SIZE {
            addrlen += 1;
            id = id.wrapping_add(1);
            cache.put(FwQuery {
                addr: localhost(5300),
                addrlen,
                id,
            });
        }

        let first = cache.get(0x848A).expect("first entry still present");
        assert_eq!(first.addrlen, 33);
        assert_eq!(first.id, 0x848A);

        addrlen += 1;
        id = id.wrapping_add(1);
        cache.put(FwQuery {
            addr: localhost(5300),
            addrlen,
            id,
        });

        assert!(cache.get(0x848A).is_none());
    }

    #[test]
    fn forward_query_extracts_dns_identity() {
        let packet: [u8; 37] = [
            0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'f',
            b'o', b'o', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let fw = ForwardQuery::from_dns_packet(&packet[..26], localhost(5301), 16).expect("parsed");
        assert_eq!(fw.source.id, 0x1337);
        assert_eq!(fw.source.addrlen, 16);
        assert_eq!(fw.question.qtype, TYPE_NULL);
    }
}
