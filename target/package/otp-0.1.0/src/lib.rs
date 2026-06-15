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

    Ok(data.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect())
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
