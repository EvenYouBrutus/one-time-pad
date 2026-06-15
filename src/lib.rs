use rand::RngCore;
use rand::rngs::OsRng;

/// Error type for One-Time Pad operations.
///
/// Indicates that the provided key does not satisfy OTP requirements.
#[derive(Debug, PartialEq, Eq)]
pub enum OtpError {
    /// The key length is insufficient for the input data.
    ///
    /// OTP requires the key to be at least as long as the input.
    KeyTooShort {
        /// Required key length in bytes.
        expected: usize,
        /// Provided key length in bytes.
        found: usize,
    },
}

/// Generates a cryptographically secure random key.
///
/// The key is generated from the operating system entropy source.
///
/// # Security
///
/// The output is suitable for cryptographic use, assuming the underlying
/// OS RNG is secure.
///
/// OTP requirements are NOT enforced here; the caller must ensure:
/// - key length matches the message length
/// - key is used only once
pub fn generate_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    OsRng.fill_bytes(&mut key);
    key
}

/// Core XOR operation used for both encryption and decryption.
///
/// OTP property:
/// - ciphertext = plaintext XOR key
/// - plaintext = ciphertext XOR key
///
/// # Errors
///
/// Returns [`OtpError::KeyTooShort`] if `key.len() < data.len()`.
fn xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    if key.len() < data.len() {
        return Err(OtpError::KeyTooShort {
            expected: data.len(),
            found: key.len(),
        });
    }

    let mut result = Vec::with_capacity(data.len());
    result.extend(data.iter().zip(key.iter()).map(|(&a, &b)| a ^ b));
    Ok(result)
}

/// Encrypts plaintext using the One-Time Pad cipher.
///
/// OTP security holds only if:
/// - the key is truly random
/// - the key is at least as long as the plaintext
/// - the key is never reused
/// - the key remains secret
///
/// # Errors
///
/// Returns [`OtpError::KeyTooShort`] if the key is insufficient.
///
/// # Notes
///
/// Encryption and decryption are identical under XOR.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    xor(plaintext, key)
}

/// Decrypts ciphertext using the One-Time Pad cipher.
///
/// This operation is identical to encryption due to XOR symmetry.
///
/// # Errors
///
/// Returns [`OtpError::KeyTooShort`] if the key is insufficient.
///
/// # Security
///
/// Reuse of a One-Time Pad key breaks all confidentiality guarantees.
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    xor(ciphertext, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_length() {
        let len = 32;
        let key = generate_key(len);
        assert_eq!(key.len(), len);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello rust and cryptography";
        let key = generate_key(plaintext.len());

        let ciphertext = encrypt(plaintext, &key).expect("encryption failed");

        let decrypted = decrypt(&ciphertext, &key).expect("decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_error_when_key_too_short_encrypt() {
        let data = b"hello world";
        let key = vec![1, 2, 3]; // intentionally too short

        let result = encrypt(data, &key);

        assert!(result.is_err());

        match result {
            Err(OtpError::KeyTooShort { expected, found }) => {
                assert_eq!(expected, data.len());
                assert_eq!(found, key.len());
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_error_when_key_too_short_decrypt() {
        let data = b"hello world";
        let key = vec![1, 2]; // too short

        let result = decrypt(data, &key);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_same_output_shape() {
        let data = b"structure test data";
        let key = generate_key(data.len());

        let enc = encrypt(data, &key).unwrap();

        assert_eq!(enc.len(), data.len());
    }
}
