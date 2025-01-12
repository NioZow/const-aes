use crate::Aes128CBC;
use crate::utils::decrypt::{decrypt_block, remove_pkcs7_padding};
use crate::utils::encrypt::{block_length_with_pkcs7_padding, encrypt_block, pkcs7_byte};
use crate::utils::key_schedule;

impl Aes128CBC {
    pub const fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            key,
            iv,
        }
    }

    pub const fn encrypt<const PLAIN_LENGTH: usize, const CIPHER_LENGTH: usize>(
        &self,
        plain: &[u8; PLAIN_LENGTH],
    ) -> [u8; CIPHER_LENGTH] {

        //
        // check block size
        //
        if CIPHER_LENGTH != block_length_with_pkcs7_padding(PLAIN_LENGTH) {
            panic!("Incorrect cipher length");
        }

        //
        // init
        //
        let mut cipher = [0u8; CIPHER_LENGTH];
        let keys = key_schedule(&self.key);

        //
        // copy plain into cipher
        //
        let mut i = 0;
        while i < PLAIN_LENGTH {
            cipher[i] = plain[i];
            i += 1;
        }

        //
        // add pkcs7 bytes
        //
        let pkcs7 = pkcs7_byte(PLAIN_LENGTH);
        while i < CIPHER_LENGTH {
            cipher[i] = pkcs7;

            i += 1;
        }

        //
        // convert to 16 bytes blocks and encrypt the blocks
        //
        i = 0;
        let mut block = [0u8; 16];
        let mut j = 0;

        while i < CIPHER_LENGTH {

            block[j] = cipher[i];

            if i % 16 == 15 {

                //
                // xor the plaintext with the previous block or iv
                //
                let mut k = 0;
                while k < 16 {
                    if i < 16 {
                        block[k] ^= self.iv[k];
                    } else {
                        block[k] ^= cipher[i + k - 31];
                    }

                    k += 1;
                }

                //
                // encrypt that block
                //
                let block_enc = encrypt_block(&block, &keys);

                //
                // copy the bytes of that block
                //
                let mut k = 0;
                while k < 16 {
                    cipher[i - 15 + k] = block_enc[k];
                    k += 1;
                }

                j = 0;
            } else {
                j += 1;
            }

            i += 1;
        }

        cipher
    }

    pub fn decrypt<const CIPHER_LENGTH: usize>(
        &self,
        cipher: &[u8; CIPHER_LENGTH]
    ) -> Vec<u8> {

        //
        // check cipher length
        //
        if CIPHER_LENGTH % 16 != 0 {
            panic!("Incorrect cipher length");
        }

        //
        // init
        //
        let mut plain = [0u8; CIPHER_LENGTH];
        let keys = key_schedule(&self.key);

        //
        // convert to 16 bytes blocks and encrypt the blocks
        //
        let mut i = 0;
        let mut block = [0u8; 16];
        let mut j = 0;

        while i < CIPHER_LENGTH {
            block[j] = cipher[i];

            if i % 16 == 15 {
                //
                // encrypt that block
                //
                let block_enc = decrypt_block(&block, &keys);

                //
                // that block was originally xored using iv or prev block
                // and copy the bytes of that block
                //
                let mut k = 0;
                while k < 16 {

                    if i < 16 {
                        plain[i - 15 + k] = block_enc[k] ^ self.iv[k];
                    } else {
                        plain[i + k - 15] = block_enc[k] ^ cipher[i + k - 31];
                    }

                    k += 1;
                }

                j = 0;
            } else {
                j += 1;
            }

            i += 1;
        }

        //
        // remove the padding
        //
        remove_pkcs7_padding(&plain)
    }
}

#[cfg(test)]
mod tests {
    use crate::Aes128CBC;

    #[test]
    fn test_encrypt_decrypt_aes128_cbc(){
        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];

        const IV: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ];

        const PLAIN: [u8; 15] = [
            0x6b, 0xc1, 0xbe, 0xe2,
            0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11,
            0x73, 0x93, 0x17
        ];

        const CTX: Aes128CBC = Aes128CBC::new(KEY, IV);
        const CIPHER: [u8; 16] = CTX.encrypt::<15, 16>(&PLAIN);

        let plain = CTX.decrypt::<16>(&CIPHER);

        assert_eq!(PLAIN, plain.as_slice());
    }
}
