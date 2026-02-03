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
    use std::collections::HashMap;

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

    #[test]
    fn test_version_default() {
        let v = ChallengeVersion::default();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);
        assert_eq!(v.prerelease, None);
    }

    #[test]
    fn test_version_display() {
        let v1 = ChallengeVersion::new(1, 2, 3);
        assert_eq!(format!("{}", v1), "1.2.3");

        let v2 = ChallengeVersion {
            major: 2,
            minor: 0,
            patch: 0,
            prerelease: Some("alpha".to_string()),
        };
        assert_eq!(format!("{}", v2), "2.0.0-alpha");

        let v3 = ChallengeVersion {
            major: 0,
            minor: 0,
            patch: 1,
            prerelease: Some("rc1".to_string()),
        };
        assert_eq!(format!("{}", v3), "0.0.1-rc1");

        let v4 = ChallengeVersion::new(10, 20, 30);
        assert_eq!(v4.to_string(), "10.20.30");
    }

    #[test]
    fn test_version_parsing_invalid() {
        assert!(ChallengeVersion::parse("").is_none());
        assert!(ChallengeVersion::parse("1").is_none());
        assert!(ChallengeVersion::parse("1.2").is_none());
        assert!(ChallengeVersion::parse("a.b.c").is_none());
        assert!(ChallengeVersion::parse("1.2.x").is_none());
        assert!(ChallengeVersion::parse("-1.2.3").is_none());
        assert!(ChallengeVersion::parse("1.2.3.4").is_some()); // Extra parts are ignored
    }

    #[test]
    fn test_version_parsing_edge_cases() {
        let v1 = ChallengeVersion::parse("0.0.0").unwrap();
        assert_eq!(v1.major, 0);
        assert_eq!(v1.minor, 0);
        assert_eq!(v1.patch, 0);

        let v2 = ChallengeVersion::parse("99.99.99").unwrap();
        assert_eq!(v2.major, 99);
        assert_eq!(v2.minor, 99);
        assert_eq!(v2.patch, 99);

        let v3 = ChallengeVersion::parse("v0.0.1").unwrap();
        assert_eq!(v3.major, 0);
        assert_eq!(v3.minor, 0);
        assert_eq!(v3.patch, 1);

        let v4 = ChallengeVersion::parse("1.0.0-beta.1").unwrap();
        assert_eq!(v4.prerelease, Some("beta.1".to_string()));
    }

    #[test]
    fn test_version_ordering() {
        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(1, 0, 1);
        let v3 = ChallengeVersion::new(1, 1, 0);
        let v4 = ChallengeVersion::new(2, 0, 0);
        let v5 = ChallengeVersion::new(0, 9, 9);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert!(v5 < v1);

        let mut versions = vec![v4.clone(), v2.clone(), v5.clone(), v1.clone(), v3.clone()];
        versions.sort();
        assert_eq!(versions, vec![v5, v1, v2, v3, v4]);
    }

    #[test]
    fn test_version_partial_ord() {
        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(1, 0, 1);
        let v3 = ChallengeVersion::new(1, 0, 0);

        assert_eq!(v1.partial_cmp(&v2), Some(Ordering::Less));
        assert_eq!(v2.partial_cmp(&v1), Some(Ordering::Greater));
        assert_eq!(v1.partial_cmp(&v3), Some(Ordering::Equal));
    }

    #[test]
    fn test_version_equality() {
        let v1 = ChallengeVersion::new(1, 2, 3);
        let v2 = ChallengeVersion::new(1, 2, 3);
        let v3 = ChallengeVersion::new(1, 2, 4);

        assert_eq!(v1, v2);
        assert_ne!(v1, v3);

        let v4 = ChallengeVersion {
            major: 1,
            minor: 2,
            patch: 3,
            prerelease: Some("alpha".to_string()),
        };
        let v5 = ChallengeVersion {
            major: 1,
            minor: 2,
            patch: 3,
            prerelease: Some("alpha".to_string()),
        };
        let v6 = ChallengeVersion {
            major: 1,
            minor: 2,
            patch: 3,
            prerelease: Some("beta".to_string()),
        };

        assert_eq!(v4, v5);
        assert_ne!(v4, v6);
        assert_ne!(v1, v4);
    }

    #[test]
    fn test_version_hash() {
        let mut map: HashMap<ChallengeVersion, &str> = HashMap::new();

        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(2, 0, 0);
        let v3 = ChallengeVersion::new(1, 0, 0);

        map.insert(v1.clone(), "version_one");
        map.insert(v2.clone(), "version_two");

        assert_eq!(map.get(&v1), Some(&"version_one"));
        assert_eq!(map.get(&v2), Some(&"version_two"));
        assert_eq!(map.get(&v3), Some(&"version_one"));

        map.insert(v3, "version_one_updated");
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&ChallengeVersion::new(1, 0, 0)),
            Some(&"version_one_updated")
        );
    }

    #[test]
    fn test_version_constraint_range() {
        let min = ChallengeVersion::new(1, 0, 0);
        let max = ChallengeVersion::new(2, 0, 0);
        let range = VersionConstraint::Range {
            min: min.clone(),
            max: max.clone(),
        };

        assert!(range.satisfies(&ChallengeVersion::new(1, 0, 0)));
        assert!(range.satisfies(&ChallengeVersion::new(1, 5, 0)));
        assert!(range.satisfies(&ChallengeVersion::new(1, 99, 99)));
        assert!(!range.satisfies(&ChallengeVersion::new(2, 0, 0)));
        assert!(!range.satisfies(&ChallengeVersion::new(0, 9, 9)));
        assert!(!range.satisfies(&ChallengeVersion::new(3, 0, 0)));

        let tight_range = VersionConstraint::Range {
            min: ChallengeVersion::new(1, 2, 3),
            max: ChallengeVersion::new(1, 2, 5),
        };
        assert!(!tight_range.satisfies(&ChallengeVersion::new(1, 2, 2)));
        assert!(tight_range.satisfies(&ChallengeVersion::new(1, 2, 3)));
        assert!(tight_range.satisfies(&ChallengeVersion::new(1, 2, 4)));
        assert!(!tight_range.satisfies(&ChallengeVersion::new(1, 2, 5)));
    }

    #[test]
    fn test_versioned_challenge_creation() {
        let challenge = VersionedChallenge {
            challenge_id: "test-challenge".to_string(),
            version: ChallengeVersion::new(1, 0, 0),
            min_platform_version: Some(ChallengeVersion::new(0, 5, 0)),
            deprecated: false,
            deprecation_message: None,
        };

        assert_eq!(challenge.challenge_id, "test-challenge");
        assert_eq!(challenge.version, ChallengeVersion::new(1, 0, 0));
        assert_eq!(
            challenge.min_platform_version,
            Some(ChallengeVersion::new(0, 5, 0))
        );
        assert!(!challenge.deprecated);
        assert!(challenge.deprecation_message.is_none());

        let deprecated_challenge = VersionedChallenge {
            challenge_id: "old-challenge".to_string(),
            version: ChallengeVersion::new(0, 1, 0),
            min_platform_version: None,
            deprecated: true,
            deprecation_message: Some("Use new-challenge instead".to_string()),
        };

        assert!(deprecated_challenge.deprecated);
        assert_eq!(
            deprecated_challenge.deprecation_message,
            Some("Use new-challenge instead".to_string())
        );
    }

    #[test]
    fn test_version_compatible_same_major() {
        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(1, 1, 0);
        let v3 = ChallengeVersion::new(1, 99, 99);

        assert!(v1.is_compatible_with(&v2));
        assert!(v2.is_compatible_with(&v1));
        assert!(v1.is_compatible_with(&v3));
        assert!(v3.is_compatible_with(&v1));
        assert!(v2.is_compatible_with(&v3));

        let v0 = ChallengeVersion::new(0, 1, 0);
        let v0_2 = ChallengeVersion::new(0, 2, 0);
        assert!(v0.is_compatible_with(&v0_2));
    }

    #[test]
    fn test_version_compatible_different_major() {
        let v1 = ChallengeVersion::new(1, 0, 0);
        let v2 = ChallengeVersion::new(2, 0, 0);
        let v3 = ChallengeVersion::new(3, 5, 10);
        let v0 = ChallengeVersion::new(0, 9, 9);

        assert!(!v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v3));
        assert!(!v2.is_compatible_with(&v3));
        assert!(!v0.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v0));
    }
}
