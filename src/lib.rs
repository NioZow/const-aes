pub mod utils;
pub mod aes;

pub struct Aes128ECB {
    key: [u8; 16],
}

pub struct Aes128CBC {
    key: [u8; 16],
    iv: [u8; 16],
}