pub const DNS_HEADER_LEN: usize = 12;
pub const DNS_PACKET_BUFFER_SIZE: usize = 2048;

pub const PROTOCOL_VERSION: u32 = 0x0000_0502;

pub const PACKET_TYPE_CODEC_CHECK: u8 = b'y';
pub const PACKET_TYPE_VERSION: u8 = b'v';
pub const PACKET_TYPE_LOGIN: u8 = b'l';
pub const PACKET_TYPE_PING: u8 = b'p';
pub const PACKET_TYPE_CODEC: u8 = b's';
pub const PACKET_TYPE_IP: u8 = b'i';
pub const PACKET_TYPE_ECHO: u8 = b'z';
pub const PACKET_TYPE_ENCODING: u8 = b'o';
pub const PACKET_TYPE_FRAG_SIZE: u8 = b'r';
pub const PACKET_TYPE_FRAG_ACK: u8 = b'n';

pub const PACKET_PREFIX_VACK: &[u8] = b"VACK";
pub const PACKET_PREFIX_LNAK: &[u8] = b"LNAK";
