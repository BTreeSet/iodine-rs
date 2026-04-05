use md5::{Digest, Md5 as Md5Hasher};

#[derive(Debug, Clone)]
pub struct Md5 {
    hasher: Md5Hasher,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            hasher: Md5Hasher::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self) -> [u8; 16] {
        self.hasher.finalize().into()
    }
}

pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(data);
    md5.finalize()
}

#[cfg(test)]
mod tests {
    use super::{compute_md5, Md5};

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc1321_test_vectors() {
        let vectors = [
            (b"".as_slice(), "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a".as_slice(), "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc".as_slice(), "900150983cd24fb0d6963f7d28e17f72"),
            (
                b"message digest".as_slice(),
                "f96b697d7cb7938d525a2f31aaf161d0",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz".as_slice(),
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_slice(),
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    .as_slice(),
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(to_hex(&compute_md5(input)), expected);
        }
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        let data = b"iodinetestingtesting";

        let one_shot = compute_md5(data);

        let mut md5 = Md5::new();
        md5.update(&data[..3]);
        md5.update(&data[3..9]);
        md5.update(&data[9..]);
        let incremental = md5.finalize();

        assert_eq!(one_shot, incremental);
    }
}
