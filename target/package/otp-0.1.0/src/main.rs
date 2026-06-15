use otp;

/// Demonstration of One-Time Pad encryption and decryption.
///
/// This example shows a full encryption cycle:
/// plaintext → encryption → ciphertext → decryption → original text.
///
/// OTP properties demonstrated:
/// - Encryption and decryption are symmetric (XOR-based)
/// - Same key is required for both operations
/// - Output is non-readable without key
fn main() {
    /// Original message to be encrypted.
    let plaintext = "Hello rust and cryptography";

    /// Convert string into raw bytes for cryptographic processing.
    let plaintext_bytes = plaintext.as_bytes();

    /// Generate a cryptographically secure random key
    /// with the same length as the plaintext.
    ///
    /// NOTE: In One-Time Pad, key length MUST match message length.
    let key = otp::generate_key(plaintext_bytes.len());

    /// Encrypt the plaintext using OTP.
    let ciphertext = otp::encrypt(plaintext_bytes, &key).expect("encryption failed");

    /// Decrypt the ciphertext back into original plaintext.
    let decrypted_bytes = otp::decrypt(&ciphertext, &key).expect("decryption failed");

    /// Convert decrypted bytes back into UTF-8 string.
    let decrypted_text = String::from_utf8(decrypted_bytes).expect("invalid UTF-8 output");

    /// Print cryptographic material and results.
    ///
    /// WARNING: In real applications, printing keys is insecure.
    println!("Key: {:?}", key);
    println!("Encrypted data: {:?}", ciphertext);
    println!("Decrypted data: {}", decrypted_text);
}