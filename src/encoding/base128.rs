const ALPHABET: [u8; 128] = [
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
    b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'A', b'B', b'C', b'D', b'E', b'F',
    b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V',
    b'W', b'X', b'Y', b'Z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', 0xbc, 0xbd,
    0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
    0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
    0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
    0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
];

fn rev128(byte: u8) -> u8 {
    ALPHABET
        .iter()
        .position(|&b| b == byte)
        .map(|i| i as u8)
        .unwrap_or(0)
}

pub fn encode(data: &[u8]) -> Vec<u8> {
    encode_with_limit(data, usize::MAX).0
}

pub fn encode_with_limit(data: &[u8], max_output: usize) -> (Vec<u8>, usize) {
    let size = data.len();
    let mut out = Vec::new();
    let mut iin = 0usize;

    loop {
        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(ALPHABET[((data[iin] & 0xfe) >> 1) as usize]);

        if out.len() >= max_output || iin >= size {
            out.pop();
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x01) << 6)
                | if iin + 1 < size {
                    (data[iin + 1] & 0xfc) >> 2
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x03) << 5)
                | if iin + 1 < size {
                    (data[iin + 1] & 0xf8) >> 3
                } else {
                    0
                }) as usize],
        );
        iin += 1;

        if out.len() >= max_output || iin >= size {
            break;
        }
        out.push(
            ALPHABET[(((data[iin] & 0x07) << 4)
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
            ALPHABET[(((data[iin] & 0x0f) << 3)
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
        out.push(
            ALPHABET[(((data[iin] & 0x1f) << 2)
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
        out.push(
            ALPHABET[(((data[iin] & 0x3f) << 1)
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
        out.push(ALPHABET[(data[iin] & 0x7f) as usize]);
        iin += 1;
    }

    (out, iin)
}

pub fn decode(input: &[u8]) -> Vec<u8> {
    let slen = input.len();
    let mut out = Vec::new();
    let mut iin = 0usize;

    loop {
        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x7f) << 1) | ((rev128(input[iin + 1]) & 0x40) >> 6));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x3f) << 2) | ((rev128(input[iin + 1]) & 0x60) >> 5));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x1f) << 3) | ((rev128(input[iin + 1]) & 0x70) >> 4));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x0f) << 4) | ((rev128(input[iin + 1]) & 0x78) >> 3));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x07) << 5) | ((rev128(input[iin + 1]) & 0x7c) >> 2));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x03) << 6) | ((rev128(input[iin + 1]) & 0x7e) >> 1));
        iin += 1;

        if iin + 1 >= slen || input[iin] == 0 || input[iin + 1] == 0 {
            break;
        }
        out.push(((rev128(input[iin]) & 0x01) << 7) | (rev128(input[iin + 1]) & 0x7f));
        iin += 2;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, encode_with_limit};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn base128_known_vectors_from_upstream_c_reference() {
        let v1 = b"iodinetestingtesting";
        assert_eq!(
            hex(&encode(v1)),
            "30d9eac4c935c8f259daecc4c935ccf259daecc4c935cc"
        );

        let v2 = b"abc1231";
        assert_eq!(hex(&encode(v2)), "57d6ca5a6ac6e458");

        let v3: &[u8] = b"\x00\x00\x00\x00\xff\xff\xff\xff\x55\x55\x55\x55\xaa\xaa\xaa\xaa\
\x81\x63\xc8\xd2\xc7\x7c\xb2\x17\x5f\x4f\xce\xc9\x49\x2d\x52\x21\
\x61\xa9\x71\x20\x25\xb3\x06\x73\xe6\xd8\x44\x30\x79\x50\x57\xbf";
        assert_eq!(
            hex(&encode(v3)),
            "6161616168fdfdfdfdd351d351d4d351d351ce77454a4cc5bc53c0f3f8bd44c74bc951496c67d0ef716a32575acdcbd6496d707663dcfc"
        );
    }

    #[test]
    fn base128_roundtrip_and_blocksize_behavior() {
        let raw = [b'A'; 7];
        let (enc, consumed) = encode_with_limit(&raw, 8);

        assert_eq!(consumed, 7);
        assert_eq!(enc.len(), 8);

        let dec = decode(&enc);
        assert_eq!(dec.len(), 7);
        assert!(dec.iter().all(|&b| b == b'A'));
    }
}
