use super::base32::{b32_5to8, b32_8to5};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownstreamHeader {
    pub up_ack_seq: u8,
    pub up_ack_frag: u8,
    pub down_seq: u8,
    pub down_frag: u8,
    pub last_frag: bool,
}

impl DownstreamHeader {
    pub fn parse(bytes: [u8; 2]) -> Self {
        Self {
            up_ack_seq: (bytes[0] >> 4) & 0x07,
            up_ack_frag: bytes[0] & 0x0f,
            down_seq: (bytes[1] >> 5) & 0x07,
            down_frag: (bytes[1] >> 1) & 0x0f,
            last_frag: (bytes[1] & 0x01) != 0,
        }
    }

    pub fn parse_payload(payload: &[u8]) -> Option<(Self, &[u8])> {
        let (&b0, rest) = payload.split_first()?;
        let (&b1, fragment) = rest.split_first()?;
        Some((Self::parse([b0, b1]), fragment))
    }

    pub fn to_bytes(self) -> [u8; 2] {
        [
            ((self.up_ack_seq & 0x07) << 4) | (self.up_ack_frag & 0x0f),
            ((self.down_seq & 0x07) << 5)
                | ((self.down_frag & 0x0f) << 1)
                | u8::from(self.last_frag),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamHeader {
    pub up_seq: u8,
    pub up_frag: u8,
    pub down_seq: u8,
    pub down_frag: u8,
    pub last_frag: bool,
}

impl UpstreamHeader {
    pub fn parse_encoded(chars: [u8; 3]) -> Option<Self> {
        if !chars.iter().all(|b| is_base32_symbol(*b)) {
            return None;
        }
        let c1 = b32_8to5(chars[0]);
        let c2 = b32_8to5(chars[1]);
        let c3 = b32_8to5(chars[2]);
        Some(Self {
            up_seq: (c1 >> 2) & 0x07,
            up_frag: ((c1 & 0x03) << 2) | ((c2 >> 3) & 0x03),
            down_seq: c2 & 0x07,
            down_frag: (c3 >> 1) & 0x0f,
            last_frag: (c3 & 0x01) != 0,
        })
    }

    pub fn encode_chars(self) -> [u8; 3] {
        [
            b32_5to8(((self.up_seq & 0x07) << 2) | ((self.up_frag & 0x0f) >> 2)),
            b32_5to8(((self.up_frag & 0x03) << 3) | (self.down_seq & 0x07)),
            b32_5to8(((self.down_frag & 0x0f) << 1) | u8::from(self.last_frag)),
        ]
    }

    pub fn parse_ack_byte(byte: u8) -> (u8, u8) {
        ((byte >> 4) & 0x07, byte & 0x0f)
    }
}

fn is_base32_symbol(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || (b'0'..=b'5').contains(&byte)
}
