pub mod base128;
pub mod base32;
pub mod base64;
pub mod hostname;

pub use hostname::{build_hostname, inline_dotify, inline_undotify, unpack_data, EncoderKind};
