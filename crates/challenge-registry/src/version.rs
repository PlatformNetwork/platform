//! Challenge versioning support

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// Semantic version for challenges
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChallengeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
}

impl ChallengeVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let parts: Vec<&str> = s.split('-').collect();
        let version_parts: Vec<&str> = parts[0].split('.').collect();

        if version_parts.len() < 3 {
            return None;
        }

        Some(Self {
            major: version_parts[0].parse().ok()?,
            minor: version_parts[1].parse().ok()?,
            patch: version_parts[2].parse().ok()?,
            prerelease: parts.get(1).map(|s| s.to_string()),
        })
    }

    /// Check if this version is compatible with another (same major version)
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self > other
    }
}

impl fmt::Display for ChallengeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.prerelease {
            Some(pre) => write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, pre),
            None => write!(f, "{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl PartialOrd for ChallengeVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChallengeVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl Default for ChallengeVersion {
    fn default() -> Self {
        Self::new(0, 1, 0)
    }
}

/// Version constraint for challenge compatibility
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VersionConstraint {
    /// Exact version match
    Exact(ChallengeVersion),
    /// Minimum version (>=)
    AtLeast(ChallengeVersion),
    /// Version range [min, max)
    Range {
        min: ChallengeVersion,
        max: ChallengeVersion,
    },
    /// Compatible with major version (^)
    Compatible(ChallengeVersion),
    /// Any version
    Any,
}

impl VersionConstraint {
    pub fn satisfies(&self, version: &ChallengeVersion) -> bool {
        match self {
            Self::Exact(v) => version == v,
            Self::AtLeast(v) => version >= v,
            Self::Range { min, max } => version >= min && version < max,
            Self::Compatible(v) => version.major == v.major && version >= v,
            Self::Any => true,
        }
    }
}

/// A challenge with version information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedChallenge {
    pub challenge_id: String,
    pub version: ChallengeVersion,
    pub min_platform_version: Option<ChallengeVersion>,
    pub deprecated: bool,
    pub deprecation_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = ChallengeVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v2 = ChallengeVersion::parse("v2.0.0-beta").unwrap();
        assert_eq!(v2.major, 2);
        assert_eq!(v2.prerelease, Some("beta".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(1, 1, 0);
        let v3 = ChallengeVersion::new(2, 0, 0);

        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_version_constraints() {
        let v = ChallengeVersion::new(1, 5, 0);

        assert!(VersionConstraint::Any.satisfies(&v));
        assert!(VersionConstraint::AtLeast(ChallengeVersion::new(1, 0, 0)).satisfies(&v));
        assert!(!VersionConstraint::Exact(ChallengeVersion::new(1, 0, 0)).satisfies(&v));
        assert!(VersionConstraint::Compatible(ChallengeVersion::new(1, 0, 0)).satisfies(&v));
    }
}
