const ALPHABET: &[u8; 64] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+";

fn rev64(byte: u8) -> u8 {
    ALPHABET
        .iter()
        .position(|&b| b == byte)
        .map(|i| i as u8)
        .unwrap_or(0)
}

pub fn encode(data: &[u8]) -> String {
    encode_with_limit(data, usize::MAX).0
}

pub fn encode_with_limit(data: &[u8], max_output: usize) -> (String, usize) {
    let size = data.len();
    let mut out = Vec::new();
    let mut iin = 0usize;

    loop {
        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[((data[iin] & 0xfc) >> 2) as usize]);

        if out.len() >= max_output || iin >= size {
            out.pop();
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x03) << 4)
                | if iin + 1 < size {
                    (data[iin + 1] & 0xf0) >> 4
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x0f) << 2)
                | if iin + 1 < size {
                    (data[iin + 1] & 0xc0) >> 6
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[(data[iin] & 0x3f) as usize]);
        iin += 1;
    }

    (
        String::from_utf8(out).expect("base64 alphabet must be utf-8"),
        iin,
    )
}

pub fn decode(input: &str) -> Vec<u8> {
    decode_bytes(input.as_bytes())
}

pub fn decode_bytes(input: &[u8]) -> Vec<u8> {
    let slen = input.len();
    let mut out = Vec::new();
    let mut iin = 0usize;

    loop {
        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev64(input[iin]) & 0x3f) << 2) | ((rev64(input[iin + 1]) & 0x30) >> 4));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev64(input[iin]) & 0x0f) << 4) | ((rev64(input[iin + 1]) & 0x3c) >> 2));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev64(input[iin]) & 0x03) << 6) | (rev64(input[iin + 1]) & 0x3f));
        iin += 2;
    }

    out
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
