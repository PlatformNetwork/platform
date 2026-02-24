//! Authentication for RPC requests
//!
//! Validators authenticate using their hotkey signature (sr25519).
//!
//! For challenge routes, the signed message format is:
//! `challenge:{challenge_id}:{method}:{path}:{body_hash}:{nonce}`
//! where body_hash is SHA256 of the request body.

use platform_core::Hotkey;
use sha2::{Digest, Sha256};
use sp_core::{crypto::Pair as _, sr25519};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Verify a signed message from a validator (sr25519)
pub fn verify_validator_signature(
    hotkey_hex: &str,
    message: &str,
    signature_hex: &str,
) -> Result<bool, AuthError> {
    // Parse hotkey
    let hotkey = Hotkey::from_hex(hotkey_hex).ok_or(AuthError::InvalidHotkey)?;

    // Parse signature
    let signature_bytes = hex::decode(signature_hex).map_err(|_| AuthError::InvalidSignature)?;

    if signature_bytes.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }

    // Verify using sr25519
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature_bytes);
    let signature = sr25519::Signature::from_raw(sig_bytes);

    let public = sr25519::Public::from_raw(hotkey.0);
    let is_valid = sr25519::Pair::verify(&signature, message.as_bytes(), &public);

    if !is_valid {
        warn!("Invalid signature for hotkey: {}", &hotkey_hex[..16]);
    }

    Ok(is_valid)
}

/// Create a message for signing
pub fn create_auth_message(action: &str, timestamp: i64, nonce: &str) -> String {
    format!("{}:{}:{}", action, timestamp, nonce)
}

/// Verify message is recent (within 5 minutes)
pub fn verify_timestamp(timestamp: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    let diff = (now - timestamp).abs();
    diff < 300 // 5 minutes
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid hotkey format")]
    InvalidHotkey,

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Message expired")]
    MessageExpired,

    #[error("Missing authentication header")]
    MissingHeader,

    #[error("Invalid nonce format")]
    InvalidNonce,
}

/// Verify challenge route authentication from headers
///
/// Expected headers (case-insensitive):
/// - `x-hotkey`: Hotkey public key (hex, 64 chars)
/// - `x-signature`: sr25519 signature (hex, 128 chars)
/// - `x-nonce`: Unique nonce containing timestamp (format: `{timestamp}:{random}`)
///
/// The signed message format is:
/// `challenge:{challenge_id}:{method}:{path}:{body_hash}:{nonce}`
pub fn verify_route_auth(
    headers: &HashMap<String, String>,
    challenge_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, AuthError> {
    // Headers are case-insensitive, normalize to lowercase
    let headers_lower: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let hotkey = headers_lower
        .get("x-hotkey")
        .ok_or(AuthError::MissingHeader)?;
    let signature = headers_lower
        .get("x-signature")
        .ok_or(AuthError::MissingHeader)?;
    let nonce = headers_lower
        .get("x-nonce")
        .ok_or(AuthError::MissingHeader)?;

    // Verify nonce contains valid timestamp (anti-replay)
    let timestamp: i64 = nonce
        .split(':')
        .next()
        .and_then(|t| t.parse().ok())
        .ok_or(AuthError::InvalidNonce)?;

    if !verify_timestamp(timestamp) {
        return Err(AuthError::MessageExpired);
    }

    // Hash the body for signature verification.
    // Canonicalize JSON body (sort keys) so key order doesn't matter.
    let body_hash = {
        let canonical = if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
            canonicalize_json_value(&val).into_bytes()
        } else {
            body.to_vec()
        };
        hex::encode(Sha256::digest(&canonical))
    };

    // Build the signed message
    let message = format!(
        "challenge:{}:{}:{}:{}:{}",
        challenge_id, method, path, body_hash, nonce
    );

    debug!(
        hotkey = %&hotkey[..16.min(hotkey.len())],
        method = %method,
        path = %path,
        "Verifying route authentication"
    );

    match verify_validator_signature(hotkey, &message, signature)? {
        true => Ok(hotkey.clone()),
        false => Err(AuthError::VerificationFailed),
    }
}

/// Create a challenge route auth message for signing
pub fn create_route_auth_message(
    challenge_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &str,
) -> String {
    let body_hash = {
        let canonical = if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
            canonicalize_json_value(&val).into_bytes()
        } else {
            body.to_vec()
        };
        hex::encode(Sha256::digest(&canonical))
    };
    format!(
        "challenge:{}:{}:{}:{}:{}",
        challenge_id, method, path, body_hash, nonce
    )
}

/// Recursively sort JSON object keys for deterministic hashing.
fn canonicalize_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonicalize_json_value(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize_json_value).collect();
            format!("[{}]", inner.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Parse and verify a Bearer session token.
///
/// Token format: `{hotkey_hex}:{expiry_ms}:{nonce}:{signature_hex}`
/// Signed message: `session:{hotkey_ss58}:{expiry_ms}:{nonce}`
///
/// Returns the hotkey hex string if the token is valid.
/// Does NOT check revocation (that requires a WASM call to the auth challenge).
pub fn verify_bearer_token(token: &str) -> Result<BearerTokenInfo, AuthError> {
    let parts: Vec<&str> = token.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err(AuthError::InvalidSignature);
    }

    let hotkey_hex = parts[0];
    let expiry_str = parts[1];
    let nonce = parts[2];
    let signature_hex = parts[3];

    // Parse hotkey
    let hotkey = Hotkey::from_hex(hotkey_hex).ok_or(AuthError::InvalidHotkey)?;

    // Parse expiry
    let expiry: i64 = expiry_str.parse().map_err(|_| AuthError::InvalidNonce)?;

    // Check expiry
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > expiry {
        return Err(AuthError::MessageExpired);
    }

    // Verify signature
    let hotkey_ss58 = hotkey.to_ss58();
    let message = format!("session:{}:{}:{}", hotkey_ss58, expiry, nonce);

    match verify_validator_signature(hotkey_hex, &message, signature_hex)? {
        true => Ok(BearerTokenInfo {
            hotkey_hex: hotkey_hex.to_string(),
            expiry,
            nonce: nonce.to_string(),
        }),
        false => Err(AuthError::VerificationFailed),
    }
}

/// Parsed and verified bearer token info.
pub struct BearerTokenInfo {
    pub hotkey_hex: String,
    pub expiry: i64,
    pub nonce: String,
}

/// Extract Bearer token from Authorization header.
pub fn extract_bearer_token(headers: &HashMap<String, String>) -> Option<String> {
    let headers_lower: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    headers_lower
        .get("authorization")
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(|t| t.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::Keypair;

    #[test]
    fn test_create_auth_message() {
        let msg = create_auth_message("register", 1234567890, "abc123");
        assert_eq!(msg, "register:1234567890:abc123");
    }

    #[test]
    fn test_verify_timestamp() {
        let now = chrono::Utc::now().timestamp();
        assert!(verify_timestamp(now));
        assert!(verify_timestamp(now - 60)); // 1 minute ago
        assert!(!verify_timestamp(now - 600)); // 10 minutes ago
    }

    #[test]
    fn test_signature_verification() {
        let kp = Keypair::generate();
        let message = "test:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());

        let hotkey_hex = kp.hotkey().to_hex();
        let sig_hex = hex::encode(&signed.signature);

        let result = verify_validator_signature(&hotkey_hex, message, &sig_hex);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_signature_verification_invalid_hotkey() {
        let result = verify_validator_signature("invalid_hotkey", "message", "signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification_invalid_signature_hex() {
        let kp = Keypair::generate();
        let result = verify_validator_signature(&kp.hotkey().to_hex(), "message", "not_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification_wrong_signature() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let message = "test:1234567890:nonce";
        let signed = kp1.sign(message.as_bytes());

        // Use kp2's hotkey but kp1's signature - should fail
        let hotkey_hex = kp2.hotkey().to_hex();
        let sig_hex = hex::encode(&signed.signature);

        let result = verify_validator_signature(&hotkey_hex, message, &sig_hex);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Signature doesn't match
    }

    #[test]
    fn test_signature_verification_wrong_message() {
        let kp = Keypair::generate();
        let message1 = "test:1234567890:nonce1";
        let message2 = "test:1234567890:nonce2";
        let signed = kp.sign(message1.as_bytes());

        let hotkey_hex = kp.hotkey().to_hex();
        let sig_hex = hex::encode(&signed.signature);

        // Try to verify with different message - should fail
        let result = verify_validator_signature(&hotkey_hex, message2, &sig_hex);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_timestamp_edge_case() {
        let now = chrono::Utc::now().timestamp();
        // Test exactly at 5 minute boundary
        assert!(!verify_timestamp(now - 301)); // 5 minutes 1 second ago
        assert!(verify_timestamp(now - 299)); // 4 minutes 59 seconds ago
    }

    #[test]
    fn test_verify_timestamp_future() {
        let now = chrono::Utc::now().timestamp();
        assert!(verify_timestamp(now + 10)); // Future timestamp within 5 min should be valid
        assert!(verify_timestamp(now + 299)); // Just under 5 minutes in future
    }

    #[test]
    fn test_signature_verification_invalid_length() {
        let kp = Keypair::generate();
        let message = "test:1234567890:nonce";

        // Test with signature that's too short (not 64 bytes)
        let short_sig = hex::encode([0u8; 32]); // Only 32 bytes
        let result = verify_validator_signature(&kp.hotkey().to_hex(), message, &short_sig);
        assert!(result.is_err());

        // Test with signature that's too long
        let long_sig = hex::encode([0u8; 128]); // 128 bytes
        let result = verify_validator_signature(&kp.hotkey().to_hex(), message, &long_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_route_auth_success() {
        let kp = Keypair::generate();
        let challenge_id = "test-challenge-id";
        let method = "POST";
        let path = "/register";
        let body = b"test body";
        let nonce = format!("{}:random123", chrono::Utc::now().timestamp());

        // Create the signed message
        let message = create_route_auth_message(challenge_id, method, path, body, &nonce);
        let signed = kp.sign(message.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-hotkey".to_string(), kp.hotkey().to_hex());
        headers.insert("x-signature".to_string(), hex::encode(&signed.signature));
        headers.insert("x-nonce".to_string(), nonce);

        let result = verify_route_auth(&headers, challenge_id, method, path, body);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), kp.hotkey().to_hex());
    }

    #[test]
    fn test_verify_route_auth_missing_header() {
        let headers = HashMap::new();
        let result = verify_route_auth(&headers, "challenge", "GET", "/", b"");
        assert!(matches!(result, Err(AuthError::MissingHeader)));
    }

    #[test]
    fn test_verify_route_auth_expired() {
        let kp = Keypair::generate();
        let old_timestamp = chrono::Utc::now().timestamp() - 600; // 10 minutes ago
        let nonce = format!("{}:random", old_timestamp);

        let message = create_route_auth_message("challenge", "GET", "/", b"", &nonce);
        let signed = kp.sign(message.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-hotkey".to_string(), kp.hotkey().to_hex());
        headers.insert("x-signature".to_string(), hex::encode(&signed.signature));
        headers.insert("x-nonce".to_string(), nonce);

        let result = verify_route_auth(&headers, "challenge", "GET", "/", b"");
        assert!(matches!(result, Err(AuthError::MessageExpired)));
    }

    #[test]
    fn test_verify_route_auth_wrong_body() {
        let kp = Keypair::generate();
        let nonce = format!("{}:random", chrono::Utc::now().timestamp());

        // Sign with one body
        let message = create_route_auth_message("challenge", "POST", "/", b"body1", &nonce);
        let signed = kp.sign(message.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-hotkey".to_string(), kp.hotkey().to_hex());
        headers.insert("x-signature".to_string(), hex::encode(&signed.signature));
        headers.insert("x-nonce".to_string(), nonce);

        // Verify with different body - should fail
        let result = verify_route_auth(&headers, "challenge", "POST", "/", b"body2");
        assert!(matches!(result, Err(AuthError::VerificationFailed)));
    }

    #[test]
    fn test_create_route_auth_message() {
        let msg = create_route_auth_message("cid", "POST", "/path", b"body", "123:abc");
        let body_hash = hex::encode(Sha256::digest(b"body"));
        assert_eq!(
            msg,
            format!("challenge:cid:POST:/path:{}:123:abc", body_hash)
        );
    }
}
