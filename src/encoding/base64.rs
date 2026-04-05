use data_encoding::{Encoding, Specification};

fn encoding() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols
        .push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+");
    spec.padding = None;
    spec.encoding().expect("valid base64 specification")
}

fn encoded_len(input_len: usize) -> usize {
    let full = (input_len / 3) * 4;
    let rem = match input_len % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    full + rem
}

pub fn encode(data: &[u8]) -> String {
    encode_with_limit(data, usize::MAX).0
}

pub fn encode_with_limit(data: &[u8], max_output: usize) -> (String, usize) {
    let mut consumed = 0usize;
    while consumed < data.len() && encoded_len(consumed + 1) <= max_output {
        consumed += 1;
    }

    (encoding().encode(&data[..consumed]), consumed)
}

pub fn decode(input: &str) -> Vec<u8> {
    decode_bytes(input.as_bytes())
}

pub fn decode_bytes(input: &[u8]) -> Vec<u8> {
    encoding().decode(input).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, encode_with_limit};

    #[test]
    fn base64_vectors_from_upstream_tests() {
        let pairs: &[(&[u8], &str)] = &[
            (b"iodinetestingtesting", "Aw8KAw4LDgvZDgLUz2rLC2rPBMC"),
            (b"abc1231", "ywjJmtiZmq"),
            (
                b"\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68\
\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\
\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40\x3F\x3F\x3C\xEF\xAE\x78\
\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68\x9E\x69\x64\x8E\x28\x60\
\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\
\x1C\x61\x44\x0C\x20\x40\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\
\xBE\xEB\x6C\xAE\xAA\x68\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\
\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40",
                "+9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcbapZ776543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba+9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
            ),
            (
                b"\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68\
\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\
\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40\x3F\x3F\x3C\xEF\xAE\x78\
\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xA1\x61\x91\x61\x61\x81\x28\x60\
\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\
\x1C\x61\x44\x0C\x20\x40\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\
\xBE\xEB\x6C\xAE\xA1\x61\x91\x61\x61\x81\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\
\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40",
                "+9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcbapZ776543210-ZYXWVUTSRQfHKwfHGsHGFEDCBAzyxwvutsrqponmlkjihgfedcba+9876543210-ZYXWVUTSRQfHKwfHGsHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
            ),
            (b"", ""),
        ];

        for (raw, enc) in pairs {
            assert_eq!(encode(raw), *enc);
            assert_eq!(decode(enc), *raw);
        }
    }

    #[test]
    fn base64_block_size_behavior_matches_c_tests() {
        let raw = [b'A'; 3];
        let (enc, consumed) = encode_with_limit(&raw, 4);

        assert_eq!(consumed, 3);
        assert_eq!(enc.len(), 4);

        let dec = decode(&enc);
        assert_eq!(dec.len(), 3);
        assert!(dec.iter().all(|&b| b == b'A'));
    }
}
