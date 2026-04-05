use data_encoding::Encoding;
use data_encoding_macro::new_encoding;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz012345";
const IODINE_BASE32: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz012345",
    padding: None,
};

fn rev32(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' => byte - b'a',
        b'A'..=b'Z' => byte - b'A',
        b'0'..=b'5' => byte - b'0' + 26,
        _ => 0,
    }
}

fn encoded_len(input_len: usize) -> usize {
    let full = (input_len / 5) * 8;
    let rem = match input_len % 5 {
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 5,
        _ => 7,
    };
    full + rem
}

pub fn b32_5to8(input: u8) -> u8 {
    ALPHABET[(input & 31) as usize]
}

pub fn b32_8to5(input: u8) -> u8 {
    rev32(input)
}

pub fn encode(data: &[u8]) -> String {
    encode_with_limit(data, usize::MAX).0
}

pub fn encode_with_limit(data: &[u8], max_output: usize) -> (String, usize) {
    let mut consumed = 0usize;
    while consumed < data.len() && encoded_len(consumed + 1) <= max_output {
        consumed += 1;
    }

    (IODINE_BASE32.encode(&data[..consumed]), consumed)
}

pub fn decode(input: &str) -> Vec<u8> {
    decode_bytes(input.as_bytes())
}

pub fn decode_bytes(input: &[u8]) -> Vec<u8> {
    let normalized: Vec<u8> = input.iter().map(|b| b.to_ascii_lowercase()).collect();
    IODINE_BASE32.decode(&normalized).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{b32_5to8, b32_8to5, decode, encode, encode_with_limit};

    #[test]
    fn base32_vectors_from_upstream_tests() {
        let pairs: &[(&[u8], &str)] = &[
            (b"iodinetestingtesting", "nfxwi0lomv0gk21unfxgo3dfon0gs1th"),
            (b"abc123", "mfrggmjsgm"),
            (b"test", "orsxg3a"),
            (b"tst", "orzxi"),
            (b"", ""),
        ];

        for (raw, enc) in pairs {
            assert_eq!(encode(raw), *enc);
            assert_eq!(decode(enc), *raw);
        }
    }

    #[test]
    fn base32_5to8_8to5_roundtrip() {
        for i in 0..32u8 {
            assert_eq!(b32_8to5(b32_5to8(i)), i);
        }
    }

    #[test]
    fn base32_block_size_behavior_matches_c_tests() {
        let raw = [b'A'; 5];
        let (enc, consumed) = encode_with_limit(&raw, 8);

        assert_eq!(consumed, 5);
        assert_eq!(enc.len(), 8);

        let dec = decode(&enc);
        assert_eq!(dec.len(), 5);
        assert!(dec.iter().all(|&b| b == b'A'));
    }
}
