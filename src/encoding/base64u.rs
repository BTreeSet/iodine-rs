use data_encoding::Encoding;
use data_encoding_macro::new_encoding;

const IODINE_BASE64U: Encoding = new_encoding! {
    // Iodine's Base64u codec uses DNS-safe substitutions:
    // '_' and '-' instead of standard '/' and '+'.
    symbols: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789-",
    padding: None,
};

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

    (IODINE_BASE64U.encode(&data[..consumed]), consumed)
}

pub fn decode(input: &str) -> Result<Vec<u8>, data_encoding::DecodeError> {
    decode_bytes(input.as_bytes())
}

pub fn decode_bytes(input: &[u8]) -> Result<Vec<u8>, data_encoding::DecodeError> {
    IODINE_BASE64U.decode(input)
}
