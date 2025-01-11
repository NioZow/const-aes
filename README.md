# const-aes

> [!NOTE]
> AES 128 rust library that can be used at compile time

> [!WARNING]
> That library is not fast because of the requirements rust puts on const functions

## Explanations

This lib was created in order to be able to easily encrypt things at compile time that would then be decrypted at runtime without any trouble.

This lib does not implement a macro to do so because random number generations (at some random generation) can only be done at **BUILD** time in rust, not **COMPILE** time.
So as this project is made to be used as a library the lib will be only be built once and so keys won't be generated at each build.
That's why I've not included any macro to encrypt things at compile time in this project. However you may something like use the following:

```rust

//
// generate this one at build time
//
const KEY: [u8; 16] = [0u8; 16];

#[macro_export]
macro_rules! ctencrypt {
    ($str:literal) => {{
        const LENGTH: usize = $str.len();
        const TEXT: [u8; LENGTH] = $crate::utils::str_to_bytes($str);
        
        // 
        // generate this one at build too
        //
        const IV: [u8; 16] = [0u8; 16];

        //
        // encrypt at compile time
        //
        const CTX: const_aes::Aes128CBC = const_aes::Aes128CBC::new($crate::KEY, IV);
        const CIPHER: [u8; 16] = CTX.encrypt(&TEXT);

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
```

## Tests

This library was properly against NIST FIPS 197 AES standard. You can run the tests using the `cargo test` command.