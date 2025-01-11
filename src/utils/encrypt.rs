use crate::utils::{add_round_key, gf_multiply, sub_bytes, SBOX};

pub const fn shift_rows(block: &mut [u8; 16]) {
    let temp = *block;

    let mut row = 1;

    while row < 4 {

        let mut col = 0;

        while col < 4 {
            block[row + 4 * col] = temp[row + 4 * ((col + row) % 4)];
            col += 1;
        }

        row += 1;
    }
}

pub const fn mix_columns(block: &mut [u8; 16]) {
    let temp = *block;

    let mut col = 0;

    while col < 4 {
        let i = col * 4;

        // matrix multiplication for each column
        block[i] = gf_multiply(0x02, temp[i]) ^
            gf_multiply(0x03, temp[i + 1]) ^
            temp[i + 2] ^
            temp[i + 3];

        block[i + 1] = temp[i] ^
            gf_multiply(0x02, temp[i + 1]) ^
            gf_multiply(0x03, temp[i + 2]) ^
            temp[i + 3];

        block[i + 2] = temp[i] ^
            temp[i + 1] ^
            gf_multiply(0x02, temp[i + 2]) ^
            gf_multiply(0x03, temp[i + 3]);

        block[i + 3] = gf_multiply(0x03, temp[i]) ^
            temp[i + 1] ^
            temp[i + 2] ^
            gf_multiply(0x02, temp[i + 3]);

        col += 1;
    }
}

pub const fn pkcs7_byte(block_length: usize) -> u8 {
    if block_length % 16 != 0 {
        (16 - block_length % 16) as u8
    } else {
        16
    }
}

pub const fn block_length_with_pkcs7_padding(block_length: usize) -> usize {
    if block_length % 16 != 0 {
        block_length + (16 - block_length % 16)
    } else {
        block_length + 16
    }
}

pub const fn encrypt_block(block: &[u8; 16], keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut encrypted = *block;
    add_round_key(&mut encrypted, &keys[0]);

    let mut i = 1;

    while i < 10 {
        sub_bytes(&mut encrypted, &SBOX);
        shift_rows(&mut encrypted);
        mix_columns(&mut encrypted);
        add_round_key(&mut encrypted, &keys[i]);

        i += 1;
    }

    sub_bytes(&mut encrypted, &SBOX);
    shift_rows(&mut encrypted);
    add_round_key(&mut encrypted, &keys[10]);

    encrypted
}

#[cfg(test)]
mod tests {
    use crate::utils::{key_schedule, sub_bytes, SBOX};
    use super::*;

    #[test]
    fn test_sub_bytes() {
        let mut block = [
            0x0c, 0x0d, 0x0e, 0x0f,
            0x08, 0x09, 0x0a, 0x0b,
            0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03
        ];

        let expected = [
            0xfe, 0xd7, 0xab, 0x76,
            0x30, 0x01, 0x67, 0x2b,
            0xf2, 0x6b, 0x6f, 0xc5,
            0x63, 0x7c, 0x77, 0x7b
        ];

        sub_bytes(&mut block, &SBOX);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_shift_rows() {
        let mut block = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        ];

        let expected = [
            0x00, 0x05, 0x0A, 0x0F,
            0x04, 0x09, 0x0E, 0x03,
            0x08, 0x0D, 0x02, 0x07,
            0x0C, 0x01, 0x06, 0x0B
        ];

        shift_rows(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_mix_columns() {
        let mut block = [
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ];

        let expected = [
            0x8e, 0x4d, 0xa1, 0xbc,
            0x9f, 0xdc, 0x58, 0x9d,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ];

        mix_columns(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_encrypt_block(){
        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ];

        const BLOCK: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34
        ];

        const EXPECTED: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32
        ];

        const ROUND_KEYS: [[u8; 16]; 11] = key_schedule(&KEY);

        const ENCRYPTED_BLOCK: [u8; 16] = encrypt_block(&BLOCK, &ROUND_KEYS);

        assert_eq!(ENCRYPTED_BLOCK, EXPECTED);
    }
}
