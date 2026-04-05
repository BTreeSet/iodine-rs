use iodine_rs::crypto::md5::compute_md5;
use iodine_rs::encoding::base32;

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[test]
fn protocol_md5_matches_upstream_login_vector() {
    let pass = b"iodine is the shit";
    let mut temp = [0u8; 32];
    temp[..pass.len()].copy_from_slice(pass);

    let seed = 15i32;
    for chunk in temp.chunks_exact_mut(4) {
        let mut n = i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        n ^= seed;
        let b = n.to_be_bytes();
        chunk.copy_from_slice(&b);
    }

    let digest = compute_md5(&temp);
    assert_eq!(
        to_hex(&digest),
        "2a8a12b4e042eeabd019171e44a088cd",
        "must match upstream tests/login.c expected digest"
    );
}

#[test]
fn protocol_base32_matches_upstream_dns_payload() {
    let raw = b"iodinetestingtesting";
    let encoded = base32::encode(raw);
    assert_eq!(encoded, "nfxwi0lomv0gk21unfxgo3dfon0gs1th");
    assert_eq!(base32::decode(&encoded), raw);
}

#[test]
fn protocol_base32_invalid_input_returns_empty_like_current_impl() {
    // Current decode behavior is permissive and returns empty output on invalid input.
    assert!(base32::decode("@@@").is_empty());
}
