/// convert a string to bytes at compile time
pub const fn str_to_bytes<const LENGTH: usize>(s: &str) -> [u8; LENGTH] {
    //
    // verify the string length at compile time
    //
    assert!(s.len() >= LENGTH, "String is shorter than LENGTH");

    let mut arr = [0u8; LENGTH];
    let bytes = s.as_bytes();
    let mut i = 0;

    //
    // convert to bytes
    //
    while i < LENGTH {
        arr[i] = bytes[i];
        i += 1;
    }

    arr
}

const KEY: [u8; 16] = [0u8; 16];
const IV: [u8; 16] = [0u8; 16];

macro_rules! ctencrypt {
    ($str:literal) => {{
        const LENGTH: usize = $str.len();
        const LENGTH_WITH_PADDING: usize = const_aes::utils::encrypt::block_length_with_pkcs7_padding(LENGTH);
        const TEXT: [u8; LENGTH] = str_to_bytes($str);

        //
        // encrypt at compile time
        //
        const CTX: const_aes::Aes128CBC = const_aes::Aes128CBC::new(KEY, IV);
        const CIPHER: [u8; LENGTH_WITH_PADDING] = CTX.encrypt(&TEXT);

        //
        // decrypt at runtime
        //
        let plain = CTX.decrypt(&CIPHER);

        //
        // convert back to a string
        //
        match String::from_utf8(plain.to_vec()) {
            Ok(s) => s,
            Err(_) => panic!("Invalid UTF-8")
        }
    }};
}

fn main(){
    println!("Top secret: {}", ctencrypt!("This is a top secret message"));
}