#[derive(Debug, Clone)]
pub struct Md5 {
    state: [u32; 4],
    count_bits: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            count_bits: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        self.count_bits = self.count_bits.wrapping_add((data.len() as u64) * 8);

        let mut input = data;
        if self.buffer_len > 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.process_block(&block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len_le = self.count_bits.to_le_bytes();

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            64 + 56 - self.buffer_len
        };

        let mut pad = vec![0u8; pad_len];
        pad[0] = 0x80;
        self.update(&pad);
        self.update(&bit_len_le);

        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        const K: [u32; 64] = [
            0xd76a_a478,
            0xe8c7_b756,
            0x2420_70db,
            0xc1bd_ceee,
            0xf57c_0faf,
            0x4787_c62a,
            0xa830_4613,
            0xfd46_9501,
            0x6980_98d8,
            0x8b44_f7af,
            0xffff_5bb1,
            0x895c_d7be,
            0x6b90_1122,
            0xfd98_7193,
            0xa679_438e,
            0x49b4_0821,
            0xf61e_2562,
            0xc040_b340,
            0x265e_5a51,
            0xe9b6_c7aa,
            0xd62f_105d,
            0x0244_1453,
            0xd8a1_e681,
            0xe7d3_fbc8,
            0x21e1_cde6,
            0xc337_07d6,
            0xf4d5_0d87,
            0x455a_14ed,
            0xa9e3_e905,
            0xfcef_a3f8,
            0x676f_02d9,
            0x8d2a_4c8a,
            0xfffa_3942,
            0x8771_f681,
            0x6d9d_6122,
            0xfde5_380c,
            0xa4be_ea44,
            0x4bde_cfa9,
            0xf6bb_4b60,
            0xbebf_bc70,
            0x289b_7ec6,
            0xeaa1_27fa,
            0xd4ef_3085,
            0x0488_1d05,
            0xd9d4_d039,
            0xe6db_99e5,
            0x1fa2_7cf8,
            0xc4ac_5665,
            0xf429_2244,
            0x432a_ff97,
            0xab94_23a7,
            0xfc93_a039,
            0x655b_59c3,
            0x8f0c_cc92,
            0xffef_f47d,
            0x8584_5dd1,
            0x6fa8_7e4f,
            0xfe2c_e6e0,
            0xa301_4314,
            0x4e08_11a1,
            0xf753_7e82,
            0xbd3a_f235,
            0x2ad7_d2bb,
            0xeb86_d391,
        ];

        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(x[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
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
