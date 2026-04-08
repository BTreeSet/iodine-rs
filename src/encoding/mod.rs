pub mod base128;
pub mod base32;
pub mod base64;
pub mod base64u;
pub mod framing;
pub mod hostname;

pub use hostname::{
    build_hostname, inline_dotify, inline_dotify_bytes, inline_undotify, inline_undotify_bytes,
    unpack_data, EncoderKind,
};

use crate::server::state::Codec;
use bytes::Bytes;

#[derive(thiserror::Error, Debug)]
pub enum EncodingError {
    #[error("base32 decode error: {0}")]
    Base32(#[from] data_encoding::DecodeError),
    #[error("base64 decode error: {0}")]
    Base64(data_encoding::DecodeError),
    #[error("base64u decode error: {0}")]
    Base64u(data_encoding::DecodeError),
}

pub fn decode_upstream(codec: Codec, input: &[u8]) -> Result<Bytes, EncodingError> {
    match codec {
        Codec::Base32 => Ok(Bytes::from(base32::decode_bytes(input)?)),
        Codec::Base64 => base64::decode_bytes(input)
            .map(Bytes::from)
            .map_err(EncodingError::Base64),
        Codec::Base64u => base64u::decode_bytes(input)
            .map(Bytes::from)
            .map_err(EncodingError::Base64u),
        Codec::Base128 => Ok(Bytes::from(base128::decode(input))),
    }
}
