use iodine_rs::crypto::md5::compute_md5;
use iodine_rs::encoding::base32;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn iodine_base32_matches_upstream_vectors() {
    let vectors = [
        (
            b"iodinetestingtesting".as_slice(),
            "nfxwi0lomv0gk21unfxgo3dfon0gs1th",
        ),
        (b"abc123".as_slice(), "mfrggmjsgm"),
        (b"test".as_slice(), "orsxg3a"),
        (b"tst".as_slice(), "orzxi"),
        (b"".as_slice(), ""),
    ];

    for (raw, encoded) in vectors {
        assert_eq!(base32::encode(raw), encoded);
        assert_eq!(base32::decode(encoded), raw);
    }
}

#[test]
fn iodine_md5_login_vector_matches_upstream_output() {
    let seed = 15i32;
    let mut pass_block = [0u8; 32];
    pass_block[..18].copy_from_slice(b"iodine is the shit");

    for chunk in pass_block.chunks_exact_mut(4) {
        let value = i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ seed;
        chunk.copy_from_slice(&value.to_be_bytes());
    }

    let expected_from_upstream = "2a8a12b4e042eeabd019171e44a088cd";
    assert_eq!(to_hex(&compute_md5(&pass_block)), expected_from_upstream);
}
