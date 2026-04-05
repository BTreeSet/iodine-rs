use super::{base128, base32, base64};

#[derive(Debug, Clone, Copy)]
pub enum EncoderKind {
    Base32,
    Base64,
    Base128,
}

impl EncoderKind {
    pub fn places_dots(self) -> bool {
        false
    }

    pub fn eats_dots(self) -> bool {
        false
    }

    pub fn encode_with_limit(self, data: &[u8], max_output: usize) -> (Vec<u8>, usize) {
        match self {
            Self::Base32 => {
                let (s, consumed) = base32::encode_with_limit(data, max_output);
                (s.into_bytes(), consumed)
            }
            Self::Base64 => {
                let (s, consumed) = base64::encode_with_limit(data, max_output);
                (s.into_bytes(), consumed)
            }
            Self::Base128 => base128::encode_with_limit(data, max_output),
        }
    }

    pub fn decode(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Base32 => base32::decode_bytes(data),
            Self::Base64 => base64::decode_bytes(data),
            Self::Base128 => base128::decode(data),
        }
    }
}

pub fn inline_dotify(input: &str) -> String {
    String::from_utf8(inline_dotify_bytes(input.as_bytes())).expect("input must remain utf-8")
}

pub fn inline_dotify_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 57 + 1);
    for (i, b) in input.iter().enumerate() {
        out.push(*b);
        if (i + 1) % 57 == 0 {
            out.push(b'.');
        }
    }
    out
}

pub fn inline_undotify(input: &str) -> String {
    String::from_utf8(inline_undotify_bytes(input.as_bytes())).expect("input must remain utf-8")
}

pub fn inline_undotify_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|&b| b != b'.').collect()
}

pub fn build_hostname(
    data: &[u8],
    topdomain: &str,
    encoder: EncoderKind,
    maxlen: usize,
) -> (String, usize) {
    let mut space = maxlen.saturating_sub(topdomain.len() + 8);
    if !encoder.places_dots() {
        space = space.saturating_sub(space / 57);
    }

    let (mut encoded, consumed) = encoder.encode_with_limit(data, space);

    if !encoder.places_dots() {
        encoded = inline_dotify_bytes(&encoded);
    }

    if !encoded.ends_with(b".") {
        encoded.push(b'.');
    }
    encoded.extend_from_slice(topdomain.as_bytes());

    (
        String::from_utf8(encoded).expect("hostname must be valid utf-8 for textual encodings"),
        consumed,
    )
}

pub fn unpack_data(encoded: &[u8], encoder: EncoderKind) -> Vec<u8> {
    let data = if encoder.eats_dots() {
        encoded.to_vec()
    } else {
        inline_undotify_bytes(encoded)
    };
    encoder.decode(&data)
}

#[cfg(test)]
mod tests {
    use super::{build_hostname, inline_dotify, inline_undotify, EncoderKind};

    #[test]
    fn inline_dotify_vectors_from_upstream_tests() {
        let tests = [
            (
                "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("abc123", "abc123"),
        ];

        for (input, expected) in tests {
            assert_eq!(inline_dotify(input), expected);
        }
    }

    #[test]
    fn inline_undotify_vectors_from_upstream_tests() {
        let tests = [
            (
                "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa",
                "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("abc123", "abc123"),
        ];

        for (input, expected) in tests {
            assert_eq!(inline_undotify(input), expected);
        }
    }

    #[test]
    fn build_hostname_has_no_double_dots_like_upstream_test() {
        let topdomain = "a.c";
        let data: Vec<u8> = (0u16..256).map(|v| (v & 0xFF) as u8).collect();

        for i in 1..data.len() {
            let (host, consumed) = build_hostname(&data[..i], topdomain, EncoderKind::Base32, 1024);
            assert!(consumed <= i);
            assert!(!host.contains(".."), "double dots at len {i}: {host}");
        }
    }
}
