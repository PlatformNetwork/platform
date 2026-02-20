//! Production constants for Mini-Chain
//!
//! These values are hardcoded for the production network.

use crate::Hotkey;

// ============================================================================
// PROTOCOL VERSION - Update this when making breaking changes
// ============================================================================

/// Protocol major version - increment for breaking changes
pub const PROTOCOL_VERSION_MAJOR: u32 = 0;

/// Protocol minor version - increment for new features
pub const PROTOCOL_VERSION_MINOR: u32 = 1;

/// Protocol patch version - increment for bug fixes
pub const PROTOCOL_VERSION_PATCH: u32 = 0;

/// Full protocol version string
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Minimum compatible protocol version (validators below this are rejected)
pub const MIN_COMPATIBLE_VERSION_MAJOR: u32 = 0;
pub const MIN_COMPATIBLE_VERSION_MINOR: u32 = 1;

/// Check if a version is compatible with current protocol
pub fn is_version_compatible(major: u32, minor: u32, _patch: u32) -> bool {
    if major != PROTOCOL_VERSION_MAJOR {
        return false;
    }
    minor >= MIN_COMPATIBLE_VERSION_MINOR
}

/// Get protocol version as tuple (major, minor, patch)
pub fn protocol_version() -> (u32, u32, u32) {
    (
        PROTOCOL_VERSION_MAJOR,
        PROTOCOL_VERSION_MINOR,
        PROTOCOL_VERSION_PATCH,
    )
}

// ============================================================================
// SUDO KEY (sr25519 - Substrate/Bittensor compatible)
// ============================================================================

/// Production Sudo Key (sr25519 public key)
/// SS58 Address: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At
/// All requests signed by this key are treated as root and can update the network.
pub const SUDO_KEY_BYTES: [u8; 32] = [
    0xda, 0x22, 0x04, 0x09, 0x67, 0x8d, 0xf5, 0xf0, 0x60, 0x74, 0xa6, 0x71, 0xab, 0xdc, 0x1f, 0x19,
    0xbc, 0x2b, 0xa1, 0x51, 0x72, 0x9f, 0xdb, 0x9a, 0x8e, 0x4b, 0xe2, 0x84, 0xe6, 0x0c, 0x94, 0x01,
];

/// Production Sudo Key as hex string (sr25519)
pub const SUDO_KEY_HEX: &str = "da220409678df5f06074a671abdc1f19bc2ba151729fdb9a8e4be284e60c9401";

/// Production Sudo Key SS58 address
pub const SUDO_KEY_SS58: &str = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At";

/// Get the production sudo key
pub fn production_sudo_key() -> Hotkey {
    Hotkey(SUDO_KEY_BYTES)
}

/// Check if a hotkey is the production sudo key
pub fn is_production_sudo(hotkey: &Hotkey) -> bool {
    hotkey.0 == SUDO_KEY_BYTES
}

/// Subnet ID for production
pub const SUBNET_ID: u16 = 100;

/// Minimum validator stake in RAO (10000 TAO)
/// Note: Actual stake validation should come from Bittensor metagraph
pub const MIN_VALIDATOR_STAKE_RAO: u64 = 10_000_000_000_000;

/// Minimum validator stake in TAO
pub const MIN_VALIDATOR_STAKE_TAO: u64 = 10_000;

/// Number of epochs during which UID 0 dominates weight setting
pub const BOOTSTRAP_PERIOD_EPOCHS: u64 = 100;

/// Weight assigned to UID 0 during the bootstrap period
pub const BOOTSTRAP_UID0_WEIGHT: u16 = u16::MAX;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_key_hex() {
        let key = production_sudo_key();
        assert_eq!(key.to_hex(), SUDO_KEY_HEX);
    }

    #[test]
    fn test_is_production_sudo() {
        let key = production_sudo_key();
        assert!(is_production_sudo(&key));

        let other = Hotkey([0u8; 32]);
        assert!(!is_production_sudo(&other));
    }

    #[test]
    fn test_protocol_version() {
        let (major, minor, patch) = protocol_version();
        assert_eq!(major, PROTOCOL_VERSION_MAJOR);
        assert_eq!(minor, PROTOCOL_VERSION_MINOR);
        assert_eq!(patch, PROTOCOL_VERSION_PATCH);
    }

    #[test]
    fn test_version_compatibility() {
        // Same version is compatible
        assert!(is_version_compatible(0, 1, 0));

        // Higher minor version is compatible
        assert!(is_version_compatible(0, 2, 0));

        // Lower minor version is not compatible
        assert!(!is_version_compatible(0, 0, 0));

        // Different major version is not compatible
        assert!(!is_version_compatible(1, 1, 0));
    }
}
