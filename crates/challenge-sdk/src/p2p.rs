//! P2P Communication Interface for Challenges
//!
//! Provides traits and types for challenges to communicate with the validator network.

use crate::{
    DecryptionKeyReveal, EncryptedSubmission, SubmissionAck, ValidatorEvaluation,
    VerifiedSubmission, WeightCalculationResult,
};
use async_trait::async_trait;
use platform_core::Hotkey;
use serde::{Deserialize, Serialize};

/// Messages that challenges can send/receive via P2P
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChallengeP2PMessage {
    /// Encrypted submission from a miner
    EncryptedSubmission(EncryptedSubmission),

    /// Acknowledgment of receiving a submission
    SubmissionAck(SubmissionAck),

    /// Decryption key reveal after quorum
    KeyReveal(DecryptionKeyReveal),

    /// Evaluation result from a validator
    EvaluationResult(EvaluationResultMessage),

    /// Request evaluations for weight calculation
    RequestEvaluations(RequestEvaluationsMessage),

    /// Response with evaluations
    EvaluationsResponse(EvaluationsResponseMessage),

    /// Weight calculation result (for consensus)
    WeightResult(WeightResultMessage),

    /// Request API key decryption from platform validator
    DecryptApiKeyRequest(DecryptApiKeyRequest),

    /// Response with decrypted API key
    DecryptApiKeyResponse(DecryptApiKeyResponse),
}

/// Evaluation result message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResultMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// The evaluation data
    pub evaluation: ValidatorEvaluation,
    /// Signature from validator
    pub signature: Vec<u8>,
}

/// Request evaluations for an epoch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestEvaluationsMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// Epoch to get evaluations for
    pub epoch: u64,
    /// Requesting validator
    pub requester: Hotkey,
}

/// Response with evaluations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationsResponseMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// Epoch
    pub epoch: u64,
    /// All evaluations from this validator
    pub evaluations: Vec<ValidatorEvaluation>,
    /// Signature
    pub signature: Vec<u8>,
}

/// Weight result message for consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightResultMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// Epoch
    pub epoch: u64,
    /// Calculated weights
    pub result: WeightCalculationResult,
    /// Validator who calculated
    pub validator: Hotkey,
    /// Signature
    pub signature: Vec<u8>,
}

/// Request to decrypt an API key
/// Challenge container sends this to its host platform validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptApiKeyRequest {
    /// Challenge ID making the request
    pub challenge_id: String,
    /// Agent hash this decryption is for
    pub agent_hash: String,
    /// The encrypted API key data
    pub encrypted_key: EncryptedApiKey,
    /// Request ID for correlation
    pub request_id: String,
}

/// Encrypted API key structure (matches term-challenge format)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedApiKey {
    /// Validator hotkey this key is encrypted for (SS58 format)
    pub validator_hotkey: String,
    /// Ephemeral X25519 public key used for encryption (hex)
    pub ephemeral_public_key: String,
    /// Encrypted ciphertext (hex)
    pub ciphertext: String,
    /// Nonce used for encryption (hex)
    pub nonce: String,
}

/// Response with decrypted API key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptApiKeyResponse {
    /// Challenge ID
    pub challenge_id: String,
    /// Agent hash
    pub agent_hash: String,
    /// Request ID for correlation
    pub request_id: String,
    /// Success flag
    pub success: bool,
    /// Decrypted API key (only if success)
    pub api_key: Option<String>,
    /// Error message (only if !success)
    pub error: Option<String>,
}

/// Handler for P2P messages in a challenge
#[async_trait]
pub trait ChallengeP2PHandler: Send + Sync {
    /// Handle an incoming P2P message
    async fn handle_message(
        &self,
        from: Hotkey,
        message: ChallengeP2PMessage,
    ) -> Option<ChallengeP2PMessage>;

    /// Get the challenge ID this handler is for
    fn challenge_id(&self) -> &str;
}

/// Interface for challenges to send P2P messages
#[async_trait]
pub trait P2PBroadcaster: Send + Sync {
    /// Broadcast a message to all validators
    async fn broadcast(&self, message: ChallengeP2PMessage) -> Result<(), P2PError>;

    /// Send a message to a specific validator
    async fn send_to(&self, target: &Hotkey, message: ChallengeP2PMessage) -> Result<(), P2PError>;

    /// Get current validator set with stakes
    async fn get_validators(&self) -> Vec<(Hotkey, u64)>;

    /// Get total network stake
    async fn get_total_stake(&self) -> u64;

    /// Get our own hotkey
    fn our_hotkey(&self) -> &Hotkey;

    /// Get our own stake
    fn our_stake(&self) -> u64;
}

/// Callback for when quorum is reached on a submission
#[async_trait]
pub trait QuorumCallback: Send + Sync {
    /// Called when quorum is reached for a submission
    async fn on_quorum_reached(&self, submission_hash: [u8; 32], acks: Vec<SubmissionAck>);

    /// Called when a submission is fully verified (decrypted)
    async fn on_submission_verified(&self, submission: VerifiedSubmission);

    /// Called when a submission fails
    async fn on_submission_failed(&self, submission_hash: [u8; 32], reason: String);
}

/// Callback for evaluation events
#[async_trait]
pub trait EvaluationCallback: Send + Sync {
    /// Called when we should evaluate a submission
    async fn on_evaluate(&self, submission: &VerifiedSubmission) -> Option<ValidatorEvaluation>;

    /// Called when we receive an evaluation from another validator
    async fn on_remote_evaluation(&self, evaluation: ValidatorEvaluation);
}

/// Callback for weight calculation events
#[async_trait]
pub trait WeightCallback: Send + Sync {
    /// Called when it's time to calculate weights
    async fn on_calculate_weights(&self, epoch: u64) -> Option<WeightCalculationResult>;

    /// Called when we receive weight results from another validator
    async fn on_remote_weights(&self, result: WeightResultMessage);

    /// Called when weight consensus is reached
    async fn on_weight_consensus(&self, epoch: u64, weights: Vec<(String, f64)>);
}

#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    #[error("Not connected to network")]
    NotConnected,
    #[error("Target validator not found")]
    ValidatorNotFound,
    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Decrypt an API key that was encrypted for this validator
/// 
/// Uses X25519 key exchange + ChaCha20-Poly1305 (same scheme as term-challenge)
pub fn decrypt_api_key(
    encrypted: &EncryptedApiKey,
    validator_secret: &[u8; 32],
) -> Result<String, P2PError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    const NONCE_SIZE: usize = 12;

    // Convert ed25519 private key to X25519 using SHA-512 clamping
    fn ed25519_to_x25519_private(ed25519_secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ed25519-to-x25519");
        hasher.update(ed25519_secret);
        let hash = hasher.finalize();
        let mut x25519_key: [u8; 32] = hash.into();
        // Clamp for X25519
        x25519_key[0] &= 248;
        x25519_key[31] &= 127;
        x25519_key[31] |= 64;
        x25519_key
    }

    // Convert validator's ed25519 private key to X25519
    let x25519_secret_bytes = ed25519_to_x25519_private(validator_secret);
    let validator_x25519 = StaticSecret::from(x25519_secret_bytes);

    // Parse ephemeral public key
    let ephemeral_bytes: [u8; 32] = hex::decode(&encrypted.ephemeral_public_key)
        .map_err(|e| P2PError::DecryptionFailed(format!("Invalid ephemeral key hex: {}", e)))?
        .try_into()
        .map_err(|_| P2PError::DecryptionFailed("Invalid ephemeral key length".to_string()))?;
    let ephemeral_public = X25519PublicKey::from(ephemeral_bytes);

    // Perform X25519 key exchange
    let shared_secret = validator_x25519.diffie_hellman(&ephemeral_public);

    // Derive decryption key
    let validator_x25519_public = X25519PublicKey::from(&validator_x25519);
    let mut hasher = Sha256::new();
    hasher.update(b"term-challenge-api-key-encryption");
    hasher.update(shared_secret.as_bytes());
    hasher.update(ephemeral_bytes);
    hasher.update(validator_x25519_public.as_bytes());
    let decryption_key = hasher.finalize();

    // Parse nonce
    let nonce_bytes: [u8; NONCE_SIZE] = hex::decode(&encrypted.nonce)
        .map_err(|e| P2PError::DecryptionFailed(format!("Invalid nonce hex: {}", e)))?
        .try_into()
        .map_err(|_| P2PError::DecryptionFailed("Invalid nonce size".to_string()))?;
    let nonce = *Nonce::from_slice(&nonce_bytes);

    // Parse ciphertext
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|e| P2PError::DecryptionFailed(format!("Invalid ciphertext hex: {}", e)))?;

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&decryption_key)
        .map_err(|e| P2PError::DecryptionFailed(format!("Cipher init failed: {}", e)))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| P2PError::DecryptionFailed("Authentication failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| P2PError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
}

/// Helper to create a signed P2P message
pub fn sign_message(
    message: &ChallengeP2PMessage,
    keypair: &platform_core::Keypair,
) -> Result<Vec<u8>, P2PError> {
    let data =
        bincode::serialize(message).map_err(|e| P2PError::SerializationFailed(e.to_string()))?;

    let signed = keypair.sign(&data);
    Ok(signed.signature)
}

/// Helper to verify a signed P2P message
pub fn verify_signature(message: &ChallengeP2PMessage, signature: &[u8], signer: &Hotkey) -> bool {
    let Ok(data) = bincode::serialize(message) else {
        return false;
    };

    // Verify using ed25519
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(verifying_key) = VerifyingKey::from_bytes(signer.as_bytes()) else {
        return false;
    };

    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };

    verifying_key.verify(&data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = ChallengeP2PMessage::RequestEvaluations(RequestEvaluationsMessage {
            challenge_id: "test".to_string(),
            epoch: 1,
            requester: Hotkey([1u8; 32]),
        });

        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ChallengeP2PMessage = bincode::deserialize(&serialized).unwrap();

        match deserialized {
            ChallengeP2PMessage::RequestEvaluations(req) => {
                assert_eq!(req.challenge_id, "test");
                assert_eq!(req.epoch, 1);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
