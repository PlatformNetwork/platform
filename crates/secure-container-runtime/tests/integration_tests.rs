//! Integration tests for secure container runtime
//!
//! These tests verify:
//! 1. Security policy enforcement
//! 2. Container lifecycle management
//! 3. Resource limits
//! 4. Network isolation
//! 5. Audit logging
//!
//! Run with: cargo test --test integration_tests -- --ignored

use secure_container_runtime::*;
use std::time::Duration;
use tokio::time::sleep;

const TEST_IMAGE: &str = "ghcr.io/platformnetwork/term-challenge:latest";
const MALICIOUS_IMAGE: &str = "docker.io/malicious/evil:latest";

// ============================================================================
// Security Policy Tests
// ============================================================================

#[test]
fn test_default_policy_blocks_docker_socket() {
    let policy = SecurityPolicy::default();

    let mounts = vec![MountConfig {
        source: "/var/run/docker.sock".to_string(),
        target: "/var/run/docker.sock".to_string(),
        read_only: true,
    }];

    let result = policy.validate_mounts(&mounts);
    assert!(result.is_err());

    match result.unwrap_err() {
        ContainerError::PolicyViolation(msg) => {
            assert!(msg.contains("Docker socket") || msg.contains("forbidden"));
        }
        _ => panic!("Expected PolicyViolation error"),
    }
}

#[test]
fn test_default_policy_blocks_malicious_images() {
    let policy = SecurityPolicy::default();

    // Blocked images
    let blocked = vec![
        "alpine:latest",
        "ubuntu:22.04",
        "docker.io/library/nginx:latest",
        "malicious/miner:latest",
        "gcr.io/some-project/image:latest",
    ];

    for image in blocked {
        let result = policy.validate_image(image);
        assert!(result.is_err(), "Image should be blocked: {}", image);
    }

    // Allowed images
    let allowed = vec![
        "ghcr.io/platformnetwork/term-challenge:latest",
        "ghcr.io/platformnetwork/validator:v1.0.0",
        "GHCR.IO/PLATFORMNETWORK/test:latest", // Case insensitive
    ];

    for image in allowed {
        let result = policy.validate_image(image);
        assert!(result.is_ok(), "Image should be allowed: {}", image);
    }
}

#[test]
fn test_policy_enforces_resource_limits() {
    let policy = SecurityPolicy::default();

    // Valid resources
    let valid = ResourceLimits {
        memory_bytes: 2 * 1024 * 1024 * 1024, // 2GB
        cpu_cores: 2.0,
        pids_limit: 256,
        disk_quota_bytes: 0,
    };
    assert!(policy.validate_resources(&valid).is_ok());

    // Excessive memory
    let excess_memory = ResourceLimits {
        memory_bytes: 100 * 1024 * 1024 * 1024, // 100GB
        ..valid.clone()
    };
    assert!(policy.validate_resources(&excess_memory).is_err());

    // Excessive CPU
    let excess_cpu = ResourceLimits {
        cpu_cores: 100.0,
        ..valid.clone()
    };
    assert!(policy.validate_resources(&excess_cpu).is_err());

    // Excessive PIDs
    let excess_pids = ResourceLimits {
        pids_limit: 100000,
        ..valid.clone()
    };
    assert!(policy.validate_resources(&excess_pids).is_err());
}

#[test]
fn test_policy_blocks_sensitive_mounts() {
    let policy = SecurityPolicy::default();

    let sensitive_paths = vec![
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root",
        "/home",
        "/proc",
        "/sys",
        "/dev",
    ];

    for path in sensitive_paths {
        let mounts = vec![MountConfig {
            source: path.to_string(),
            target: "/mnt/test".to_string(),
            read_only: true,
        }];

        let result = policy.validate_mounts(&mounts);
        assert!(result.is_err(), "Mount should be blocked: {}", path);
    }
}

#[test]
fn test_policy_container_limits() {
    let policy = SecurityPolicy::default();

    // Under limit
    assert!(policy.check_container_limit("challenge-1", 5).is_ok());

    // At limit
    let at_limit = policy.max_containers_per_challenge;
    assert!(policy
        .check_container_limit("challenge-1", at_limit)
        .is_err());

    // Over limit
    assert!(policy
        .check_container_limit("challenge-1", at_limit + 1)
        .is_err());
}

#[test]
fn test_full_config_validation() {
    let policy = SecurityPolicy::default();

    // Valid config
    let valid = ContainerConfig {
        image: TEST_IMAGE.to_string(),
        challenge_id: "test-challenge".to_string(),
        owner_id: "test-owner".to_string(),
        ..Default::default()
    };
    assert!(policy.validate(&valid).is_ok());

    // Missing challenge_id
    let missing_challenge = ContainerConfig {
        image: TEST_IMAGE.to_string(),
        challenge_id: "".to_string(),
        owner_id: "test-owner".to_string(),
        ..Default::default()
    };
    assert!(policy.validate(&missing_challenge).is_err());

    // Missing owner_id
    let missing_owner = ContainerConfig {
        image: TEST_IMAGE.to_string(),
        challenge_id: "test-challenge".to_string(),
        owner_id: "".to_string(),
        ..Default::default()
    };
    assert!(policy.validate(&missing_owner).is_err());

    // Malicious image
    let malicious = ContainerConfig {
        image: MALICIOUS_IMAGE.to_string(),
        challenge_id: "test-challenge".to_string(),
        owner_id: "test-owner".to_string(),
        ..Default::default()
    };
    assert!(policy.validate(&malicious).is_err());
}

// ============================================================================
// Protocol Tests
// ============================================================================

#[test]
fn test_request_serialization_roundtrip() {
    let configs = vec![
        Request::Ping {
            request_id: "test-1".to_string(),
        },
        Request::Create {
            config: ContainerConfig {
                image: TEST_IMAGE.to_string(),
                challenge_id: "challenge-1".to_string(),
                owner_id: "owner-1".to_string(),
                ..Default::default()
            },
            request_id: "test-2".to_string(),
        },
        Request::Start {
            container_id: "abc123".to_string(),
            request_id: "test-3".to_string(),
        },
        Request::Stop {
            container_id: "abc123".to_string(),
            timeout_secs: 30,
            request_id: "test-4".to_string(),
        },
        Request::Exec {
            container_id: "abc123".to_string(),
            command: vec!["ls".to_string(), "-la".to_string()],
            working_dir: Some("/app".to_string()),
            timeout_secs: 60,
            request_id: "test-5".to_string(),
        },
    ];

    for request in configs {
        let json = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(request.request_id(), decoded.request_id());
    }
}

#[test]
fn test_response_serialization_roundtrip() {
    let responses = vec![
        Response::Pong {
            version: "1.0.0".to_string(),
            request_id: "test-1".to_string(),
        },
        Response::Created {
            container_id: "abc123".to_string(),
            container_name: "test-container".to_string(),
            request_id: "test-2".to_string(),
        },
        Response::Error {
            error: ContainerError::ImageNotWhitelisted("bad-image".to_string()),
            request_id: "test-3".to_string(),
        },
        Response::ExecResult {
            result: ExecResult {
                stdout: "hello".to_string(),
                stderr: "".to_string(),
                exit_code: 0,
                duration_ms: 100,
                timed_out: false,
            },
            request_id: "test-4".to_string(),
        },
    ];

    for response in responses {
        let json = serde_json::to_string(&response).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(response.request_id(), decoded.request_id());
    }
}

// ============================================================================
// Client Builder Tests
// ============================================================================

#[test]
fn test_container_config_builder() {
    let config = client::ContainerConfigBuilder::new(TEST_IMAGE, "test-challenge", "test-owner")
        .name("my-container")
        .cmd(vec!["python3".to_string(), "/app/main.py".to_string()])
        .env("DEBUG", "true")
        .env("PORT", "8080")
        .working_dir("/app")
        .memory_gb(4.0)
        .cpu(2.0)
        .pids(512)
        .network_mode(NetworkMode::Isolated)
        .expose(8080)
        .expose(9090)
        .mount_readonly("/tmp/data", "/data")
        .label("version", "1.0.0")
        .build();

    assert_eq!(config.image, TEST_IMAGE);
    assert_eq!(config.challenge_id, "test-challenge");
    assert_eq!(config.owner_id, "test-owner");
    assert_eq!(config.name, Some("my-container".to_string()));
    assert_eq!(
        config.cmd,
        Some(vec!["python3".to_string(), "/app/main.py".to_string()])
    );
    assert_eq!(config.env.get("DEBUG"), Some(&"true".to_string()));
    assert_eq!(config.env.get("PORT"), Some(&"8080".to_string()));
    assert_eq!(config.working_dir, Some("/app".to_string()));
    assert_eq!(config.resources.memory_bytes, 4 * 1024 * 1024 * 1024);
    assert_eq!(config.resources.cpu_cores, 2.0);
    assert_eq!(config.resources.pids_limit, 512);
    assert_eq!(config.network.mode, NetworkMode::Isolated);
    assert!(config.network.ports.contains_key(&8080));
    assert!(config.network.ports.contains_key(&9090));
    assert_eq!(config.mounts.len(), 1);
    assert_eq!(config.mounts[0].source, "/tmp/data");
    assert!(config.mounts[0].read_only);
    assert_eq!(config.labels.get("version"), Some(&"1.0.0".to_string()));
}

// ============================================================================
// Type Tests
// ============================================================================

#[test]
fn test_container_state_serialization() {
    let states = vec![
        ContainerState::Creating,
        ContainerState::Running,
        ContainerState::Paused,
        ContainerState::Stopped,
        ContainerState::Removing,
        ContainerState::Dead,
        ContainerState::Unknown,
    ];

    for state in states {
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ContainerState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }
}

#[test]
fn test_network_mode_serialization() {
    let modes = vec![
        NetworkMode::None,
        NetworkMode::Bridge,
        NetworkMode::Isolated,
    ];

    for mode in modes {
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: NetworkMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, decoded);
    }
}

#[test]
fn test_container_error_serialization() {
    let errors = vec![
        ContainerError::ImageNotWhitelisted("bad-image".to_string()),
        ContainerError::PolicyViolation("forbidden mount".to_string()),
        ContainerError::ContainerNotFound("abc123".to_string()),
        ContainerError::ResourceLimitExceeded("memory".to_string()),
        ContainerError::PermissionDenied("no access".to_string()),
        ContainerError::InvalidConfig("missing field".to_string()),
        ContainerError::DockerError("connection failed".to_string()),
        ContainerError::InternalError("unexpected".to_string()),
    ];

    for error in errors {
        let json = serde_json::to_string(&error).unwrap();
        let decoded: ContainerError = serde_json::from_str(&json).unwrap();
        assert_eq!(error.to_string(), decoded.to_string());
    }
}

// ============================================================================
// Integration Tests (require Docker)
// ============================================================================

#[tokio::test]
#[ignore = "requires Docker daemon"]
async fn test_broker_lifecycle() {
    use tempfile::tempdir;

    // Create broker
    let broker = ContainerBroker::new()
        .await
        .expect("Failed to create broker");

    // Create socket in temp directory
    let temp = tempdir().unwrap();
    let socket_path = temp.path().join("broker.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();

    // Start broker in background
    let broker_handle = {
        let socket = socket_str.clone();
        tokio::spawn(async move { broker.run(&socket).await })
    };

    // Wait for broker to start
    sleep(Duration::from_millis(100)).await;

    // Create client
    let client = SecureContainerClient::new(&socket_str);

    // Test ping
    let version = client.ping().await.expect("Ping failed");
    assert!(!version.is_empty());

    // Test create container
    let config = client::ContainerConfigBuilder::new(TEST_IMAGE, "test-challenge", "test-owner")
        .cmd(vec!["sleep".to_string(), "30".to_string()])
        .memory_gb(1.0)
        .cpu(0.5)
        .build();

    let (container_id, container_name) = client
        .create_container(config)
        .await
        .expect("Create failed");

    assert!(!container_id.is_empty());
    assert!(container_name.starts_with("platform-"));

    // Test start
    let start_result = client
        .start_container(&container_id)
        .await
        .expect("Start failed");

    assert_eq!(start_result.container_id, container_id);

    // Test inspect
    let info = client.inspect(&container_id).await.expect("Inspect failed");

    assert_eq!(info.challenge_id, "test-challenge");
    assert_eq!(info.owner_id, "test-owner");
    assert_eq!(info.state, ContainerState::Running);

    // Test exec
    let exec_result = client
        .exec(
            &container_id,
            vec!["echo".to_string(), "hello".to_string()],
            None,
            30,
        )
        .await
        .expect("Exec failed");

    assert_eq!(exec_result.exit_code, 0);
    assert!(exec_result.stdout.contains("hello"));

    // Test list
    let containers = client
        .list(Some("test-challenge"), None)
        .await
        .expect("List failed");

    assert!(!containers.is_empty());
    assert!(containers.iter().any(|c| c.id == container_id));

    // Test stop
    client
        .stop_container(&container_id, 10)
        .await
        .expect("Stop failed");

    // Verify stopped
    let info = client.inspect(&container_id).await.expect("Inspect failed");
    assert_eq!(info.state, ContainerState::Stopped);

    // Test remove
    client
        .remove_container(&container_id, false)
        .await
        .expect("Remove failed");

    // Verify removed
    let result = client.inspect(&container_id).await;
    assert!(result.is_err());

    // Cleanup
    broker_handle.abort();
}

#[tokio::test]
#[ignore = "requires Docker daemon"]
async fn test_broker_blocks_malicious_image() {
    let broker = ContainerBroker::new()
        .await
        .expect("Failed to create broker");

    let config = ContainerConfig {
        image: MALICIOUS_IMAGE.to_string(),
        challenge_id: "test".to_string(),
        owner_id: "test".to_string(),
        ..Default::default()
    };

    let response = broker
        .handle_request(Request::Create {
            config,
            request_id: "test".to_string(),
        })
        .await;

    match response {
        Response::Error { error, .. } => {
            assert!(matches!(error, ContainerError::ImageNotWhitelisted(_)));
        }
        _ => panic!("Expected error response"),
    }
}

#[tokio::test]
#[ignore = "requires Docker daemon"]
async fn test_broker_blocks_docker_socket_mount() {
    let broker = ContainerBroker::new()
        .await
        .expect("Failed to create broker");

    let config = ContainerConfig {
        image: TEST_IMAGE.to_string(),
        challenge_id: "test".to_string(),
        owner_id: "test".to_string(),
        mounts: vec![MountConfig {
            source: "/var/run/docker.sock".to_string(),
            target: "/var/run/docker.sock".to_string(),
            read_only: true,
        }],
        ..Default::default()
    };

    let response = broker
        .handle_request(Request::Create {
            config,
            request_id: "test".to_string(),
        })
        .await;

    match response {
        Response::Error { error, .. } => {
            assert!(matches!(error, ContainerError::PolicyViolation(_)));
        }
        _ => panic!("Expected error response"),
    }
}

#[tokio::test]
#[ignore = "requires Docker daemon"]
async fn test_image_pull_whitelist() {
    let broker = ContainerBroker::new()
        .await
        .expect("Failed to create broker");

    // Allowed image
    let response = broker
        .handle_request(Request::Pull {
            image: TEST_IMAGE.to_string(),
            request_id: "test-1".to_string(),
        })
        .await;

    // May fail if network issues, but should not be a whitelist error
    match response {
        Response::Pulled { .. } => {}
        Response::Error { error, .. } => {
            assert!(!matches!(error, ContainerError::ImageNotWhitelisted(_)));
        }
        _ => panic!("Unexpected response"),
    }

    // Blocked image
    let response = broker
        .handle_request(Request::Pull {
            image: MALICIOUS_IMAGE.to_string(),
            request_id: "test-2".to_string(),
        })
        .await;

    match response {
        Response::Error { error, .. } => {
            assert!(matches!(error, ContainerError::ImageNotWhitelisted(_)));
        }
        _ => panic!("Expected whitelist error"),
    }
}
