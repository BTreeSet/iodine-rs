const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz012345";

fn rev32(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' => byte - b'a',
        b'A'..=b'Z' => byte - b'A',
        b'0'..=b'5' => byte - b'0' + 26,
        _ => 0,
    }
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
    let size = data.len();
    let mut out = Vec::new();
    let mut iin = 0usize;

    loop {
        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[((data[iin] & 0xf8) >> 3) as usize]);

        if out.len() >= max_output || iin >= size {
            out.pop();
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x07) << 2)
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
        out.push(ALPHABET[((data[iin] & 0x3e) >> 1) as usize]);

        if out.len() >= max_output || iin >= size {
            out.pop();
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x01) << 4)
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
            ALPHABET[(((data[iin] & 0x0f) << 1)
                | if iin + 1 < size {
                    (data[iin + 1] & 0x80) >> 7
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[((data[iin] & 0x7c) >> 2) as usize]);

        if out.len() >= max_output || iin >= size {
            out.pop();
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x03) << 3)
                | if iin + 1 < size {
                    (data[iin + 1] & 0xe0) >> 5
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[(data[iin] & 0x1f) as usize]);
        iin += 1;
    }

    (
        String::from_utf8(out).expect("base32 alphabet must be utf-8"),
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
        out.push(((rev32(input[iin]) & 0x1f) << 3) | ((rev32(input[iin + 1]) & 0x1c) >> 2));
        iin += 1;

        if iin + 2 >= slen || input[iin] == 0 || input[iin + 1] == 0 || input[iin + 2] == 0 {
            break;
        }
        out.push(
            ((rev32(input[iin]) & 0x03) << 6)
                | ((rev32(input[iin + 1]) & 0x1f) << 1)
                | ((rev32(input[iin + 2]) & 0x10) >> 4),
        );
        iin += 2;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev32(input[iin]) & 0x0f) << 4) | ((rev32(input[iin + 1]) & 0x1e) >> 1));
        iin += 1;

        if iin + 2 >= slen || input[iin] == 0 || input[iin + 1] == 0 || input[iin + 2] == 0 {
            break;
        }
        out.push(
            ((rev32(input[iin]) & 0x01) << 7)
                | ((rev32(input[iin + 1]) & 0x1f) << 2)
                | ((rev32(input[iin + 2]) & 0x18) >> 3),
        );
        iin += 2;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev32(input[iin]) & 0x07) << 5) | (rev32(input[iin + 1]) & 0x1f));
        iin += 2;
    }

    out
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
