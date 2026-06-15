# otp-cipher

A minimal, correct Rust implementation of the One-Time Pad (OTP) encryption scheme.

[![Crates.io](https://img.shields.io/crates/v/otp-cipher.svg)](https://crates.io/crates/otp-cipher)
[![Documentation](https://docs.rs/otp-cipher/badge.svg)](https://docs.rs/otp-cipher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

`otp-cipher` is a pure Rust implementation of the One-Time Pad (OTP) cipher. The project focuses on correctness, simplicity, and adherence to the theoretical properties of perfect secrecy rather than production cryptographic deployment. It demonstrates how a theoretically unbreakable cipher can be implemented using modern systems programming techniques.

---

## Key Properties

- XOR-based encryption and decryption
- Cryptographically secure key generation using OS entropy (`OsRng`)
- Strict requirement: key length must be greater than or equal to plaintext length
- No panics in core library (Result-based API)
- Minimal dependency surface

---

## Theoretical Background

The One-Time Pad is the only encryption scheme proven to achieve perfect secrecy under Shannon's model.

### Perfect Secrecy Condition

$$P(M = m \mid C = c) = P(M = m)$$

### Mutual Information

$$I(M; C) = 0$$

### Encryption Model

$$C = M \oplus K$$
$$M = C \oplus K$$

OTP is secure only if:
- the key is truly random
- the key is used exactly once
- the key length is at least equal to the message length ($|K| \ge |M|$)

---

## API Overview

```rust
use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Debug, PartialEq, Eq)]
pub enum OtpError {
    /// The provided key is shorter than the input data.
    KeyTooShort {
        expected: usize,
        found: usize,
    },
}

pub fn generate_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    OsRng.fill_bytes(&mut key);
    key
}

fn xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    if key.len() < data.len() {
        return Err(OtpError::KeyTooShort {
            expected: data.len(),
            found: key.len(),
        });
    }

    Ok(data.iter().zip(key.iter()).map(|(&a, &b)| a ^ b).collect())
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    xor(plaintext, key)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    xor(ciphertext, key)
}

```

---

## Quick Start

### Installation

```toml
[dependencies]
otp-cipher = "0.1.0"

```

### Example

```rust
use otp_cipher::{generate_key, encrypt, decrypt};

fn main() {
    let plaintext = b"hello rust";

    let key = generate_key(plaintext.len());

    let ciphertext = encrypt(plaintext, &key).unwrap();
    let decrypted = decrypt(&ciphertext, &key).unwrap();

    assert_eq!(plaintext.to_vec(), decrypted);
}

```

---

## Security Notes

This implementation is intended for educational purposes.

### Limitations

* No authentication (malleability due to XOR linearity)
* No integrity protection
* Secure out-of-band key distribution is outside scope
* Memory boundaries are not zeroized after use

OTP security depends entirely on correct operational key handling.

---

## Performance

* Time complexity: O(n)
* Space complexity: O(n)
* Linear XOR transformation over input bytes with SIMD auto-vectorization capabilities

---

## License

Distributed under the MIT License.