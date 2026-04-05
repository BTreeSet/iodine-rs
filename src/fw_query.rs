use std::net::SocketAddr;

use bytes::Bytes;

use crate::dns::DnsQuestion;

pub const FW_QUERY_CACHE_SIZE: usize = 16;
pub const SOCKADDR_IN_LEN: usize = 16;
pub const SOCKADDR_IN6_LEN: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwQuery {
    pub addr: SocketAddr,
    pub addrlen: usize,
    pub id: u16,
    pub qtype: u16,
    pub qname_wire: Bytes,
}

impl FwQuery {
    pub fn from_dns_question(addr: SocketAddr, id: u16, question: DnsQuestion<'_>) -> Self {
        Self {
            addr,
            addrlen: match addr {
                SocketAddr::V4(_) => SOCKADDR_IN_LEN,
                SocketAddr::V6(_) => SOCKADDR_IN6_LEN,
            },
            id,
            qtype: question.qtype,
            qname_wire: Bytes::copy_from_slice(question.qname_wire),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FwQueryCache {
    ring: Vec<FwQuery>,
    cap: usize,
    next: usize,
}

impl Default for FwQueryCache {
    fn default() -> Self {
        Self::with_capacity(FW_QUERY_CACHE_SIZE)
    }
}

impl FwQueryCache {
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            ring: Vec::with_capacity(cap),
            cap,
            next: 0,
        }
    }

    pub fn put(&mut self, query: FwQuery) {
        if self.ring.len() < self.cap {
            self.ring.push(query);
            return;
        }

        self.ring[self.next] = query;
        self.next = (self.next + 1) % self.cap;
    }

    pub fn get(&self, id: u16) -> Option<&FwQuery> {
        self.ring.iter().find(|q| q.id == id)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use crate::dns::DnsQuestion;

    use super::{FwQuery, FwQueryCache, FW_QUERY_CACHE_SIZE};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353)
    }

    #[test]
    fn fw_query_simple_matches_upstream_behavior() {
        let mut cache = FwQueryCache::default();

        assert!(cache.get(0x848A).is_none());

        cache.put(FwQuery {
            addr: dummy_addr(),
            addrlen: 33,
            id: 0x848A,
            qtype: 10,
            qname_wire: Bytes::new(),
        });

        let found = cache.get(0x848A).expect("query should be cached");
        assert_eq!(found.addrlen, 33);
        assert_eq!(found.id, 0x848A);
    }

    #[test]
    fn fw_query_edge_overwrite_matches_upstream_behavior() {
        let mut cache = FwQueryCache::with_capacity(FW_QUERY_CACHE_SIZE);

        let mut q = FwQuery {
            addr: dummy_addr(),
            addrlen: 33,
            id: 0x848A,
            qtype: 10,
            qname_wire: Bytes::new(),
        };

        cache.put(q.clone());

        for _ in 1..FW_QUERY_CACHE_SIZE {
            q.addrlen += 1;
            q.id = q.id.wrapping_add(1);
            cache.put(q.clone());
        }

        let found = cache.get(0x848A).expect("first item should still exist");
        assert_eq!(found.addrlen, 33);
        assert_eq!(found.id, 0x848A);

        q.addrlen += 1;
        q.id = q.id.wrapping_add(1);
        cache.put(q);

        assert!(cache.get(0x848A).is_none());
    }

    #[test]
    fn from_dns_question_bridges_dns_primitives() {
        let q = DnsQuestion {
            qname_wire: b"\x04test\x00",
            qtype: 10,
            qclass: 1,
        };

        let fw = FwQuery::from_dns_question(dummy_addr(), 1337, q);
        assert_eq!(fw.id, 1337);
        assert_eq!(fw.qtype, 10);
        assert_eq!(fw.qname_wire.as_ref(), b"\x04test\x00");
    }
}
