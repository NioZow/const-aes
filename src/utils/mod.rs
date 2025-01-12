pub mod encrypt;
pub mod decrypt;

pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

pub const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

pub const fn sub_bytes(block: &mut [u8; 16], sbox: &[u8; 256]) {
    let mut i: u8 = 0;

    while i < 16 {
        block[i as usize] = sbox[block[i as usize] as usize];
        i += 1;
    }
}

pub const fn add_round_key(block: &mut [u8; 16], round_key: &[u8; 16]) {
    let mut i = 0;

    while i < 16 {
        block[i] ^= round_key[i];
        i += 1;
    }
}

/// helper function for Galois Field multiplication
pub const fn gf_multiply(a: u8, b: u8) -> u8 {
    let mut result = 0;
    let mut a = a;
    let mut b = b;

    while b != 0 {

        if (b & 1) != 0 {
            result ^= a;
        }

        let high_bit_set = (a & 0x80) != 0;
        a <<= 1;

        if high_bit_set {
            // AES irreducible polynomial
            a ^= 0x1B;
        }

        b >>= 1;
    }

    result
}

///
/// AES 128 bit key derivation algorithm.
///
/// It derives the encryption into 10 round keys to later encrypt blocks.
///
pub const fn key_schedule(key: &[u8; 16]) -> [[u8; 16]; 11] {

    let mut keys = [[0u8; 16]; 11];

    //
    // first round key is the original key
    // so just copy it
    //
    let mut i = 0;

    while i < 16 {
        keys[0][i] = key[i];
        i += 1;
    }

    //
    // generate the remaining round keys
    //
    let mut round = 1;

    while round < 11 {

        let mut temp = [0u8; 4];

        //
        // operations on the previous round key
        //
        let t = SBOX[keys[round - 1][12] as usize];
        temp[0] = SBOX[keys[round - 1][13] as usize] ^ RCON[round - 1];
        temp[1] = SBOX[keys[round - 1][14] as usize];
        temp[2] = SBOX[keys[round - 1][15] as usize];
        temp[3] = t;

        //
        // generate new round key
        //
        i = 0;
        while i < 4 {

            let mut j = 0;

            while j < 4 {
                let idx = i * 4 + j;

                if i == 0 {
                    keys[round][idx] = keys[round - 1][idx] ^ temp[j];
                } else {
                    keys[round][idx] = keys[round - 1][idx] ^ keys[round][idx - 4];
                }

                j += 1;
            }

            i += 1;
        }

        round += 1;
    }

    keys
}

#[cfg(test)]
mod tests {
    use crate::utils::decrypt::{calculate_rsbox, mix_columns_rev, shift_rows_rev};
    use crate::utils::encrypt::{mix_columns, shift_rows};
    use super::*;

    #[test]
    fn test_add_round_key() {
        let mut block = [
            0x04, 0xe0, 0x48, 0x28,
            0x66, 0xcb, 0xf8, 0x06,
            0x81, 0x19, 0xd3, 0x26,
            0xe5, 0x9a, 0x7a, 0x4c
        ];

        let round_key = [
            0xa0, 0x88, 0x23, 0x2a,
            0xfa, 0x54, 0xa3, 0x6c,
            0xfe, 0x2c, 0x39, 0x76,
            0x17, 0xb1, 0x39, 0x05
        ];

        let expected = [
            0xa4, 0x68, 0x6b, 0x02,
            0x9c, 0x9f, 0x5b, 0x6a,
            0x7f, 0x35, 0xea, 0x50,
            0xf2, 0x2b, 0x43, 0x49
        ];

        add_round_key(&mut block, &round_key);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_sub_bytes_double(){
        let mut block = [
            0xfe, 0xd7, 0xab, 0x76,
            0x30, 0x01, 0x67, 0x2b,
            0xf2, 0x6b, 0x6f, 0xc5,
            0x63, 0x7c, 0x77, 0x7b
        ];

        let expected = block;

        let rsbox = calculate_rsbox();

        sub_bytes(&mut block, &SBOX);
        sub_bytes(&mut block, &rsbox);

        assert_eq!(block, expected);
    }


    #[test]
    fn test_shift_rows_double() {
        let mut block = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        ];

        let expected = block;

        shift_rows(&mut block);
        shift_rows_rev(&mut block);

        assert_eq!(block, expected);
    }

    #[test]
    fn test_mix_columns_double() {
        let mut block = [
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ];

        let expected = block;

        mix_columns(&mut block);
        mix_columns_rev(&mut block);

        assert_eq!(block, expected);
    }

    #[test]
    fn test_key_schedule_aes128(){
        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ];

        const EXPECTED: [u8; 16] = [
            0xd0, 0x14, 0xf9, 0xa8,
            0xc9, 0xee, 0x25, 0x89,
            0xe1, 0x3f, 0x0c, 0xc8,
            0xb6, 0x63, 0x0c, 0xa6
        ];

        const ROUND_KEYS: [[u8; 16]; 11] = key_schedule(&KEY);

        assert_eq!(ROUND_KEYS[10], EXPECTED);
    }
}