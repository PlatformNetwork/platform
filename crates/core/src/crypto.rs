//! Cryptographic utilities using sr25519 (Substrate standard)
//!
//! This module provides sr25519 keypair management compatible with Substrate/Bittensor.
//! Validators derive their hotkey from BIP39 mnemonics, producing SS58 addresses
//! that can be verified against the Bittensor metagraph for stake lookup.

use crate::{Hotkey, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_core::{sr25519, Pair};

/// SS58 address prefix for Bittensor (network ID 42 for generic Substrate)
pub const SS58_PREFIX: u16 = 42;

/// Keypair for signing using sr25519 (Substrate/Bittensor compatible)
#[derive(Clone)]
pub struct Keypair {
    pair: sr25519::Pair,
    /// Mini secret seed (32 bytes) - stored for roundtrip capability
    mini_seed: Option<[u8; 32]>,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let pair = sr25519::Pair::from_seed(&seed);
        Self {
            pair,
            mini_seed: Some(seed),
        }
    }

    /// Create from BIP39 mnemonic phrase (12/24 words)
    /// This is the standard way for validators to derive their hotkey
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let (pair, seed) = sr25519::Pair::from_phrase(mnemonic, None)
            .map_err(|e| MiniChainError::Crypto(format!("Invalid mnemonic: {:?}", e)))?;

        // Convert seed to array
        let mut mini_seed = [0u8; 32];
        mini_seed.copy_from_slice(&seed.as_ref()[..32]);

        Ok(Self {
            pair,
            mini_seed: Some(mini_seed),
        })
    }

    /// Create from seed bytes (32 bytes mini secret)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let pair = sr25519::Pair::from_seed(seed);
        Ok(Self {
            pair,
            mini_seed: Some(*seed),
        })
    }

    /// Get the public key as Hotkey (32 bytes)
    pub fn hotkey(&self) -> Hotkey {
        Hotkey(self.pair.public().0)
    }

    /// Get the SS58 address (human-readable format like 5GziQCc...)
    pub fn ss58_address(&self) -> String {
        self.hotkey().to_ss58()
    }

    /// Get the seed bytes (32 bytes mini secret for backup/storage)
    /// Returns the original seed if available, otherwise derives from pair
    pub fn seed(&self) -> [u8; 32] {
        if let Some(seed) = self.mini_seed {
            seed
        } else {
            // Fallback: try to extract from raw (not guaranteed to work for all cases)
            let raw = self.pair.to_raw_vec();
            let mut seed = [0u8; 32];
            if raw.len() >= 32 {
                seed.copy_from_slice(&raw[..32]);
            }
            seed
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        let signature = self.pair.sign(message);
        SignedMessage {
            message: message.to_vec(),
            signature: signature.0.to_vec(),
            signer: self.hotkey(),
        }
    }

    /// Sign with additional data (for structured messages)
    pub fn sign_data<T: Serialize>(&self, data: &T) -> Result<SignedMessage> {
        let message =
            bincode::serialize(data).map_err(|e| MiniChainError::Serialization(e.to_string()))?;
        Ok(self.sign(&message))
    }

    /// Sign raw bytes and return only the signature bytes (for governance)
    pub fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.pair.sign(data);
        Ok(signature.0.to_vec())
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keypair({})", self.ss58_address())
    }
}

/// A signed message using sr25519
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer: Hotkey,
}

impl SignedMessage {
    /// Verify the sr25519 signature
    pub fn verify(&self) -> Result<bool> {
        use sp_core::crypto::Pair as _;

        if self.signature.len() != 64 {
            return Err(MiniChainError::Crypto(
                "Invalid signature length (expected 64 bytes)".into(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = sr25519::Signature::from_raw(sig_bytes);

        let public = sr25519::Public::from_raw(self.signer.0);

        Ok(sr25519::Pair::verify(&signature, &self.message, &public))
    }

    /// Deserialize the message content
    pub fn deserialize<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        bincode::deserialize(&self.message)
            .map_err(|e| MiniChainError::Serialization(e.to_string()))
    }
}

/// Hash data using SHA256
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash and return as hex string
pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

/// Hash serializable data
pub fn hash_data<T: Serialize>(data: &T) -> Result<[u8; 32]> {
    let bytes =
        bincode::serialize(data).map_err(|e| MiniChainError::Serialization(e.to_string()))?;
    Ok(hash(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(kp1.hotkey(), kp2.hotkey());
    }

    #[test]
    fn test_sign_verify() {
        let kp = Keypair::generate();
        let message = b"Hello, world!";
        let signed = kp.sign(message);

        assert!(signed.verify().unwrap());
        assert_eq!(signed.signer, kp.hotkey());
    }

    #[test]
    fn test_sign_data() {
        let kp = Keypair::generate();

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            value: u64,
            name: String,
        }

        let data = TestData {
            value: 42,
            name: "test".into(),
        };

        let signed = kp.sign_data(&data).unwrap();
        assert!(signed.verify().unwrap());

        let recovered: TestData = signed.deserialize().unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_mnemonic_derivation() {
        // Test with a known mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let kp = Keypair::from_mnemonic(mnemonic).unwrap();

        // The hotkey should be deterministic
        let ss58 = kp.ss58_address();
        assert!(ss58.starts_with("5"), "SS58 address should start with 5");

        // Same mnemonic should produce same keypair
        let kp2 = Keypair::from_mnemonic(mnemonic).unwrap();
        assert_eq!(kp.hotkey(), kp2.hotkey());
    }

    #[test]
    fn test_ss58_address_format() {
        let kp = Keypair::generate();
        let ss58 = kp.ss58_address();

        // SS58 addresses for Substrate start with 5 and are ~48 chars
        assert!(ss58.starts_with("5"));
        assert!(ss58.len() >= 46 && ss58.len() <= 50);
    }

    #[test]
    fn test_hash() {
        let data = b"test data";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);

        let h3 = hash(b"different data");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_seed_roundtrip() {
        let kp1 = Keypair::generate();
        let seed = kp1.seed();
        let kp2 = Keypair::from_seed(&seed).unwrap();
        assert_eq!(kp1.hotkey(), kp2.hotkey());
    }

    #[test]
    fn test_keypair_debug() {
        let kp = Keypair::generate();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("Keypair"));
        assert!(debug.contains("5")); // SS58 starts with 5
    }

    #[test]
    fn test_signed_message_invalid_signature() {
        let kp = Keypair::generate();
        let mut signed = kp.sign(b"test message");
        signed.signature[0] ^= 0xff; // Corrupt signature
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signed_message_wrong_signer() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let mut signed = kp1.sign(b"test");
        signed.signer = kp2.hotkey(); // Wrong signer
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signed_message_invalid_signature_length() {
        let signed = SignedMessage {
            message: b"test".to_vec(),
            signature: vec![0; 32], // Wrong length (should be 64)
            signer: Hotkey([0; 32]),
        };
        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_hash_hex() {
        let data = b"hello";
        let hex = hash_hex(data);
        assert_eq!(hex.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_data() {
        #[derive(Serialize)]
        struct Data {
            x: u32,
        }

        let d1 = Data { x: 42 };
        let d2 = Data { x: 42 };
        let d3 = Data { x: 99 };

        assert_eq!(hash_data(&d1).unwrap(), hash_data(&d2).unwrap());
        assert_ne!(hash_data(&d1).unwrap(), hash_data(&d3).unwrap());
    }

    #[test]
    fn test_hash_empty() {
        let h = hash(b"");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_mnemonic_produces_deterministic_hotkey() {
        // Test that mnemonic derivation is deterministic using a well-known test vector
        // This mnemonic is NOT a production key - it's a standard BIP-39 test vector
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let kp = Keypair::from_mnemonic(test_mnemonic).unwrap();

        // The hotkey should be deterministic for the same mnemonic
        let hotkey_hex = kp.hotkey().to_hex();
        assert_eq!(hotkey_hex.len(), 64);

        // Creating from same mnemonic should produce same hotkey
        let kp2 = Keypair::from_mnemonic(test_mnemonic).unwrap();
        assert_eq!(kp.hotkey().to_hex(), kp2.hotkey().to_hex());
    }

    #[test]
    fn test_keypair_seed_method() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keypair = Keypair::from_mnemonic(mnemonic).unwrap();
        let seed = keypair.seed();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_sign_bytes() {
        let keypair = Keypair::generate();
        let message = b"test message";
        let signature = keypair.sign_bytes(message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify signature works
        let signed_msg = SignedMessage {
            message: message.to_vec(),
            signature,
            signer: keypair.hotkey(),
        };
        assert!(signed_msg.verify().unwrap());
    }

    #[test]
    fn test_signed_message_debug() {
        let keypair = Keypair::generate();
        let message = b"test";
        let signature = keypair.sign_bytes(message).unwrap();
        let signed_msg = SignedMessage {
            message: message.to_vec(),
            signature,
            signer: keypair.hotkey(),
        };
        let debug_str = format!("{:?}", signed_msg);
        assert!(debug_str.contains("SignedMessage"));
    }

    #[test]
    fn test_keypair_seed_fallback() {
        // Force the fallback branch by creating a keypair and removing mini_seed
        let mut keypair = Keypair::generate();
        keypair.mini_seed = None;

        // Call seed() which should hit the fallback path
        let seed = keypair.seed();
        assert_eq!(seed.len(), 32);

        // Verify the fallback extracts from raw_vec
        let raw = keypair.pair.to_raw_vec();
        if raw.len() >= 32 {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&raw[..32]);
            assert_eq!(seed, expected);
        }
    }

    #[test]
    fn test_sign_data_serialization_error() {
        // Test that sign_data properly handles serialization errors
        let keypair = Keypair::generate();

        // Create a type that always fails to serialize
        struct FailSerialize;
        impl serde::Serialize for FailSerialize {
            fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }

        let result = keypair.sign_data(&FailSerialize);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MiniChainError::Serialization(_)
        ));
    }

    #[test]
    fn test_hash_data_serialization_error() {
        // Test hash_data with a type that fails to serialize
        struct FailSerialize;
        impl serde::Serialize for FailSerialize {
            fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }

        let result = hash_data(&FailSerialize);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MiniChainError::Serialization(_)
        ));
    }
}
