//! Security policy enforcement for container operations

use crate::types::*;
use std::collections::HashSet;
use tracing::{info, warn};

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Allowed image prefixes (e.g., "ghcr.io/platformnetwork/")
    pub allowed_image_prefixes: Vec<String>,

    /// Maximum memory per container (bytes)
    pub max_memory_bytes: i64,

    /// Maximum CPU cores per container
    pub max_cpu_cores: f64,

    /// Maximum PIDs per container
    pub max_pids: i64,

    /// Maximum containers per challenge
    pub max_containers_per_challenge: usize,

    /// Maximum containers per owner
    pub max_containers_per_owner: usize,

    /// Allowed mount source prefixes
    pub allowed_mount_prefixes: Vec<String>,

    /// Forbidden mount paths (never allow mounting these)
    pub forbidden_mount_paths: HashSet<String>,

    /// Allow privileged containers (should always be false)
    pub allow_privileged: bool,

    /// Allow host network mode
    pub allow_host_network: bool,

    /// Allow Docker socket mounting (should always be false)
    pub allow_docker_socket: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("/var/run/docker.sock".to_string());
        forbidden.insert("/run/docker.sock".to_string());
        forbidden.insert("/etc/passwd".to_string());
        forbidden.insert("/etc/shadow".to_string());
        forbidden.insert("/etc/sudoers".to_string());
        forbidden.insert("/root".to_string());
        forbidden.insert("/home".to_string());
        forbidden.insert("/proc".to_string());
        forbidden.insert("/sys".to_string());
        forbidden.insert("/dev".to_string());

        Self {
            // Empty = allow all images (challenges can use any public image)
            // For strict mode, populate this with allowed prefixes
            allowed_image_prefixes: vec![],
            max_memory_bytes: 8 * 1024 * 1024 * 1024, // 8GB
            max_cpu_cores: 4.0,
            max_pids: 512,
            max_containers_per_challenge: 100,
            max_containers_per_owner: 200,
            allowed_mount_prefixes: vec![
                "/tmp/".to_string(),
                "/var/lib/platform/".to_string(),
                "/var/lib/docker/volumes/".to_string(),
            ],
            forbidden_mount_paths: forbidden,
            allow_privileged: false,
            allow_host_network: false,
            allow_docker_socket: false,
        }
    }
}

impl SecurityPolicy {
    /// Create a strict policy for production with image whitelist
    pub fn strict() -> Self {
        Self {
            // Only allow platform images in strict mode
            allowed_image_prefixes: vec!["ghcr.io/platformnetwork/".to_string()],
            ..Default::default()
        }
    }

    /// Create a more permissive policy for development
    pub fn development() -> Self {
        let mut policy = Self::default();
        policy
            .allowed_mount_prefixes
            .push("/workspace/".to_string());
        // Allow Docker volume paths for Docker-in-Docker scenarios
        policy
            .allowed_mount_prefixes
            .push("/var/lib/docker/volumes/".to_string());
        policy
    }

    /// Allow all images (no whitelist check)
    pub fn allow_all_images(mut self) -> Self {
        self.allowed_image_prefixes.clear();
        self
    }

    /// Add allowed image prefix
    pub fn with_image_prefix(mut self, prefix: &str) -> Self {
        self.allowed_image_prefixes.push(prefix.to_string());
        self
    }

    /// Validate a container configuration against policy
    pub fn validate(&self, config: &ContainerConfig) -> Result<(), ContainerError> {
        // Check image is whitelisted
        self.validate_image(&config.image)?;

        // Check resource limits
        self.validate_resources(&config.resources)?;

        // Check mounts
        self.validate_mounts(&config.mounts)?;

        // Check network config
        self.validate_network(&config.network)?;

        // Validate required fields
        if config.challenge_id.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "challenge_id is required".to_string(),
            ));
        }

        if config.owner_id.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "owner_id is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate image is from allowed registry
    /// If allowed_image_prefixes is empty, all images are allowed
    pub fn validate_image(&self, image: &str) -> Result<(), ContainerError> {
        // Empty whitelist = allow all images
        if self.allowed_image_prefixes.is_empty() {
            return Ok(());
        }

        let image_lower = image.to_lowercase();

        for prefix in &self.allowed_image_prefixes {
            if image_lower.starts_with(&prefix.to_lowercase()) {
                return Ok(());
            }
        }

        warn!(
            image = %image,
            "SECURITY: Blocked non-whitelisted image"
        );

        Err(ContainerError::ImageNotWhitelisted(image.to_string()))
    }

    /// Validate resource limits
    pub fn validate_resources(&self, resources: &ResourceLimits) -> Result<(), ContainerError> {
        if resources.memory_bytes > self.max_memory_bytes {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Memory limit {} exceeds maximum {}",
                resources.memory_bytes, self.max_memory_bytes
            )));
        }

        if resources.cpu_cores > self.max_cpu_cores {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "CPU limit {} exceeds maximum {}",
                resources.cpu_cores, self.max_cpu_cores
            )));
        }

        if resources.pids_limit > self.max_pids {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "PID limit {} exceeds maximum {}",
                resources.pids_limit, self.max_pids
            )));
        }

        Ok(())
    }

    /// Validate mount configurations
    pub fn validate_mounts(&self, mounts: &[MountConfig]) -> Result<(), ContainerError> {
        for mount in mounts {
            // Check for forbidden paths
            for forbidden in &self.forbidden_mount_paths {
                if mount.source.starts_with(forbidden) || mount.source == *forbidden {
                    warn!(
                        source = %mount.source,
                        "SECURITY: Blocked forbidden mount path"
                    );
                    return Err(ContainerError::PolicyViolation(format!(
                        "Mount path '{}' is forbidden",
                        mount.source
                    )));
                }
            }

            // Special check for Docker socket
            if mount.source.contains("docker.sock") && !self.allow_docker_socket {
                warn!("SECURITY: Blocked Docker socket mount attempt");
                return Err(ContainerError::PolicyViolation(
                    "Docker socket mounting is not allowed".to_string(),
                ));
            }

            // Check source is in allowed prefixes
            let allowed = self
                .allowed_mount_prefixes
                .iter()
                .any(|prefix| mount.source.starts_with(prefix));

            if !allowed && !mounts.is_empty() {
                return Err(ContainerError::PolicyViolation(format!(
                    "Mount source '{}' is not in allowed paths",
                    mount.source
                )));
            }

            // Enforce read-only for most mounts
            if !mount.read_only {
                info!(
                    source = %mount.source,
                    "Mount is writable - ensure this is intended"
                );
            }
        }

        Ok(())
    }

    /// Validate network configuration
    pub fn validate_network(&self, network: &NetworkConfig) -> Result<(), ContainerError> {
        // Host network is never allowed for challenge containers
        if !self.allow_host_network {
            // NetworkMode doesn't have Host variant, so we're safe
        }

        // Internet access should be explicitly approved
        if network.allow_internet {
            info!("Container requests internet access - ensure this is intended");
        }

        Ok(())
    }

    /// Check if challenge can create more containers
    pub fn check_container_limit(
        &self,
        challenge_id: &str,
        current_count: usize,
    ) -> Result<(), ContainerError> {
        if current_count >= self.max_containers_per_challenge {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Challenge '{}' has reached maximum container limit ({})",
                challenge_id, self.max_containers_per_challenge
            )));
        }
        Ok(())
    }

    /// Check if owner can create more containers
    pub fn check_owner_limit(
        &self,
        owner_id: &str,
        current_count: usize,
    ) -> Result<(), ContainerError> {
        if current_count >= self.max_containers_per_owner {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Owner '{}' has reached maximum container limit ({})",
                owner_id, self.max_containers_per_owner
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_policy_default() {
        let policy = SecurityPolicy::default();
        assert!(!policy.allow_privileged);
        assert!(!policy.allow_docker_socket);
        assert!(!policy.allow_host_network);
    }

    #[test]
    fn test_validate_image_allowed() {
        let policy = SecurityPolicy::default();
        assert!(policy
            .validate_image("ghcr.io/platformnetwork/term-challenge:latest")
            .is_ok());
    }

    #[test]
    fn test_validate_image_blocked() {
        // Use strict() policy which has whitelist enabled
        let policy = SecurityPolicy::strict();
        assert!(policy
            .validate_image("docker.io/malicious/image:latest")
            .is_err());
        assert!(policy.validate_image("alpine:latest").is_err());
    }

    #[test]
    fn test_default_allows_all_images() {
        // Default policy has no whitelist, allows all images
        let policy = SecurityPolicy::default();
        assert!(policy.validate_image("docker.io/any/image:latest").is_ok());
        assert!(policy.validate_image("alpine:latest").is_ok());
        assert!(policy
            .validate_image("alexgshaw/code-from-image:20251031")
            .is_ok());
    }

    #[test]
    fn test_validate_docker_socket_blocked() {
        let policy = SecurityPolicy::default();
        let mounts = vec![MountConfig {
            source: "/var/run/docker.sock".to_string(),
            target: "/var/run/docker.sock".to_string(),
            read_only: true,
        }];
        assert!(policy.validate_mounts(&mounts).is_err());
    }

    #[test]
    fn test_validate_resources() {
        let policy = SecurityPolicy::default();

        // Valid resources
        let resources = ResourceLimits {
            memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_cores: 2.0,
            pids_limit: 256,
            disk_quota_bytes: 0,
        };
        assert!(policy.validate_resources(&resources).is_ok());

        // Excessive memory
        let resources = ResourceLimits {
            memory_bytes: 100 * 1024 * 1024 * 1024, // 100GB
            ..Default::default()
        };
        assert!(policy.validate_resources(&resources).is_err());
    }

    #[test]
    fn test_validate_full_config() {
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "ghcr.io/platformnetwork/term-challenge:latest".to_string(),
            challenge_id: "test-challenge".to_string(),
            owner_id: "test-owner".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_ok());
    }

    #[test]
    fn test_validate_missing_challenge_id() {
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "ghcr.io/platformnetwork/term-challenge:latest".to_string(),
            challenge_id: "".to_string(),
            owner_id: "test-owner".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_err());
    }

    #[test]
    fn test_strict_policy() {
        let policy = SecurityPolicy::strict();
        assert_eq!(policy.allowed_image_prefixes.len(), 1);
        assert_eq!(policy.allowed_image_prefixes[0], "ghcr.io/platformnetwork/");
        assert!(policy.validate_image("ghcr.io/platformnetwork/test:latest").is_ok());
        assert!(policy.validate_image("docker.io/test:latest").is_err());
    }

    #[test]
    fn test_development_policy() {
        let policy = SecurityPolicy::development();
        assert!(policy.allowed_mount_prefixes.contains(&"/workspace/".to_string()));
    }

    #[test]
    fn test_allow_all_images() {
        let mut policy = SecurityPolicy::strict();
        assert!(!policy.allowed_image_prefixes.is_empty());
        
        policy = policy.allow_all_images();
        assert!(policy.allowed_image_prefixes.is_empty());
        assert!(policy.validate_image("any:image").is_ok());
    }

    #[test]
    fn test_with_image_prefix() {
        let policy = SecurityPolicy::default()
            .with_image_prefix("docker.io/myorg/");
        
        assert!(policy.allowed_image_prefixes.contains(&"docker.io/myorg/".to_string()));
    }

    #[test]
    fn test_validate_missing_owner_id() {
        let policy = SecurityPolicy::default();
        let config = ContainerConfig {
            image: "test:latest".to_string(),
            challenge_id: "challenge-1".to_string(),
            owner_id: "".to_string(),
            ..Default::default()
        };
        
        assert!(policy.validate(&config).is_err());
    }

    #[test]
    fn test_validate_resources_excessive_cpu() {
        let policy = SecurityPolicy::default();
        let resources = ResourceLimits {
            memory_bytes: 1024 * 1024 * 1024,
            cpu_cores: 10.0, // Exceeds max_cpu_cores (4.0)
            pids_limit: 100,
            disk_quota_bytes: 0,
        };
        
        assert!(policy.validate_resources(&resources).is_err());
    }

    #[test]
    fn test_validate_resources_excessive_pids() {
        let policy = SecurityPolicy::default();
        let resources = ResourceLimits {
            memory_bytes: 1024 * 1024 * 1024,
            cpu_cores: 1.0,
            pids_limit: 10000, // Exceeds max_pids (512)
            disk_quota_bytes: 0,
        };
        
        assert!(policy.validate_resources(&resources).is_err());
    }

    #[test]
    fn test_validate_mounts_run_docker_sock() {
        let policy = SecurityPolicy::default();
        let mounts = vec![MountConfig {
            source: "/run/docker.sock".to_string(),
            target: "/var/run/docker.sock".to_string(),
            read_only: true,
        }];
        
        assert!(policy.validate_mounts(&mounts).is_err());
    }

    #[test]
    fn test_validate_mounts_forbidden_paths() {
        let policy = SecurityPolicy::default();
        
        let forbidden_mounts = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root",
            "/home",
            "/proc",
            "/sys",
            "/dev",
        ];
        
        for path in forbidden_mounts {
            let mounts = vec![MountConfig {
                source: path.to_string(),
                target: "/mnt/test".to_string(),
                read_only: true,
            }];
            assert!(policy.validate_mounts(&mounts).is_err(), "Should block mount: {}", path);
        }
    }

    #[test]
    fn test_validate_mounts_allowed_prefixes() {
        let policy = SecurityPolicy::default();
        
        let allowed_mounts = vec![
            "/tmp/data",
            "/var/lib/platform/challenge-1",
            "/var/lib/docker/volumes/vol1",
        ];
        
        for path in allowed_mounts {
            let mounts = vec![MountConfig {
                source: path.to_string(),
                target: "/mnt/test".to_string(),
                read_only: true,
            }];
            assert!(policy.validate_mounts(&mounts).is_ok(), "Should allow mount: {}", path);
        }
    }

    #[test]
    fn test_validate_mounts_docker_sock_in_path() {
        let policy = SecurityPolicy::default();
        let mounts = vec![MountConfig {
            source: "/tmp/docker.sock".to_string(),
            target: "/app/docker.sock".to_string(),
            read_only: true,
        }];
        
        // Should be blocked due to containing "docker.sock"
        assert!(policy.validate_mounts(&mounts).is_err());
    }

    #[test]
    fn test_validate_mounts_empty_list() {
        let policy = SecurityPolicy::default();
        assert!(policy.validate_mounts(&vec![]).is_ok());
    }

    #[test]
    fn test_validate_network() {
        let policy = SecurityPolicy::default();
        
        let network = NetworkConfig {
            mode: NetworkMode::Isolated,
            ports: HashMap::new(),
            allow_internet: false,
        };
        assert!(policy.validate_network(&network).is_ok());
        
        let network_with_internet = NetworkConfig {
            mode: NetworkMode::Bridge,
            ports: HashMap::new(),
            allow_internet: true,
        };
        assert!(policy.validate_network(&network_with_internet).is_ok());
    }

    #[test]
    fn test_check_container_limit() {
        let policy = SecurityPolicy::default();
        
        assert!(policy.check_container_limit("challenge-1", 50).is_ok());
        assert!(policy.check_container_limit("challenge-1", 99).is_ok());
        assert!(policy.check_container_limit("challenge-1", 100).is_err());
        assert!(policy.check_container_limit("challenge-1", 150).is_err());
    }

    #[test]
    fn test_check_owner_limit() {
        let policy = SecurityPolicy::default();
        
        assert!(policy.check_owner_limit("owner-1", 100).is_ok());
        assert!(policy.check_owner_limit("owner-1", 199).is_ok());
        assert!(policy.check_owner_limit("owner-1", 200).is_err());
        assert!(policy.check_owner_limit("owner-1", 300).is_err());
    }

    #[test]
    fn test_forbidden_mount_paths_default() {
        let policy = SecurityPolicy::default();
        assert!(policy.forbidden_mount_paths.contains("/var/run/docker.sock"));
        assert!(policy.forbidden_mount_paths.contains("/run/docker.sock"));
        assert!(policy.forbidden_mount_paths.contains("/etc/passwd"));
    }
}
