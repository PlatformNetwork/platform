//! Auto-updater - pulls new images and triggers restart

use crate::{UpdateRequirement, Version, VersionWatcher};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use std::{future::Future, pin::Pin};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Auto-updater that pulls new Docker images and signals for restart
pub struct AutoUpdater {
    docker: Docker,
    watcher: Arc<VersionWatcher>,
    restart_sender: broadcast::Sender<RestartSignal>,
    #[cfg(test)]
    pull_hook: Option<PullHook>,
}

#[cfg(test)]
type PullHook =
    Arc<dyn Fn(&str) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

#[cfg(test)]
const SHUTDOWN_DELAY_SECS: u64 = 0;
#[cfg(not(test))]
const SHUTDOWN_DELAY_SECS: u64 = 5;

impl AutoUpdater {
    pub async fn new(watcher: Arc<VersionWatcher>) -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        docker.ping().await?;

        let (restart_sender, _) = broadcast::channel(16);

        Ok(Self {
            docker,
            watcher,
            restart_sender,
            #[cfg(test)]
            pull_hook: None,
        })
    }

    /// Subscribe to restart signals
    pub fn subscribe_restart(&self) -> broadcast::Receiver<RestartSignal> {
        self.restart_sender.subscribe()
    }

    /// Start the auto-update loop
    pub async fn start(self: Arc<Self>) {
        let mut update_rx = self.watcher.subscribe();

        tokio::spawn(async move {
            loop {
                match update_rx.recv().await {
                    Ok(requirement) => {
                        if let Err(e) = self.handle_update(requirement).await {
                            error!(error = %e, "Failed to handle update");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Update receiver lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Update channel closed, stopping auto-updater");
                        break;
                    }
                }
            }
        });
    }

    /// Handle a version update
    async fn handle_update(&self, requirement: UpdateRequirement) -> anyhow::Result<()> {
        let current = Version::current();

        if !current.needs_update(&requirement.min_version) {
            debug!("Already on required version or newer");
            return Ok(());
        }

        info!(
            current = %current,
            required = %requirement.min_version,
            image = %requirement.docker_image,
            "Pulling new version"
        );

        // Pull the new image
        self.pull_image(&requirement.docker_image).await?;

        info!(image = %requirement.docker_image, "New image pulled successfully");

        // Signal for restart
        let signal = RestartSignal {
            new_version: requirement.recommended_version,
            image: requirement.docker_image,
            mandatory: requirement.mandatory,
        };

        let _ = self.restart_sender.send(signal);

        // If mandatory, exit to trigger restart
        if requirement.mandatory {
            info!("Mandatory update - initiating graceful shutdown");
            // Give time for cleanup
            tokio::time::sleep(Duration::from_secs(SHUTDOWN_DELAY_SECS)).await;
            // Exit with code 0 - systemd/Docker will restart with new image
            #[cfg(not(test))]
            std::process::exit(0);
            #[cfg(test)]
            {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Pull a Docker image
    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.pull_hook {
            return (hook)(image).await;
        }

        let options = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(options), None, None);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        debug!(status = %status, "Pull progress");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Pull warning");
                }
            }
        }

        Ok(())
    }

    /// Manually trigger an update check and pull
    pub async fn check_and_update(&self) -> anyhow::Result<UpdateResult> {
        let Some(requirement) = self.watcher.get_requirement() else {
            return Ok(UpdateResult::NoUpdateAvailable);
        };

        let current = Version::current();
        if !current.needs_update(&requirement.min_version) {
            return Ok(UpdateResult::AlreadyUpToDate);
        }

        self.pull_image(&requirement.docker_image).await?;

        Ok(UpdateResult::Updated {
            from: current,
            to: requirement.recommended_version,
            image: requirement.docker_image,
        })
    }

    /// Get the image name for the current version
    pub fn current_image(&self) -> String {
        let version = Version::current();
        format!("cortexlm/platform-validator:{}", version)
    }
}

/// Signal to restart the validator
#[derive(Clone, Debug)]
pub struct RestartSignal {
    pub new_version: Version,
    pub image: String,
    pub mandatory: bool,
}

/// Result of an update check
#[derive(Debug)]
pub enum UpdateResult {
    NoUpdateAvailable,
    AlreadyUpToDate,
    Updated {
        from: Version,
        to: Version,
        image: String,
    },
}

/// Graceful shutdown handler for updates
pub struct GracefulShutdown {
    shutdown_sender: broadcast::Sender<()>,
}

impl GracefulShutdown {
    pub fn new() -> Self {
        let (shutdown_sender, _) = broadcast::channel(1);
        Self { shutdown_sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_sender.subscribe()
    }

    pub fn trigger(&self) {
        let _ = self.shutdown_sender.send(());
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::sync::Mutex;
    use tokio::time::{sleep, timeout};

    #[test]
    fn test_restart_signal() {
        let signal = RestartSignal {
            new_version: Version::new(0, 2, 0),
            image: "cortexlm/validator:0.2.0".to_string(),
            mandatory: true,
        };

        assert!(signal.mandatory);
        assert_eq!(signal.new_version.to_string(), "0.2.0");
    }

    #[test]
    fn test_graceful_shutdown() {
        let shutdown = GracefulShutdown::new();
        let mut rx = shutdown.subscribe();

        shutdown.trigger();

        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_graceful_shutdown_default() {
        let shutdown: GracefulShutdown = Default::default();
        let mut rx = shutdown.subscribe();
        shutdown.trigger();
        assert!(rx.try_recv().is_ok());
    }

    fn make_test_docker() -> bollard::Docker {
        bollard::Docker::connect_with_local_defaults().unwrap()
    }

    fn make_test_watcher() -> Arc<crate::VersionWatcher> {
        Arc::new(crate::VersionWatcher::new(Duration::from_secs(60)))
    }

    #[tokio::test]
    async fn test_auto_updater_new_initializes_restart_sender() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater::new(watcher).await.expect("should construct");
        assert_eq!(updater.restart_sender.receiver_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_restart_receives_signal() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater::new(watcher).await.expect("should construct");
        let mut rx = updater.subscribe_restart();

        let signal = RestartSignal {
            new_version: Version::new(1, 0, 0),
            image: "test/image:1.0.0".to_string(),
            mandatory: false,
        };
        updater.restart_sender.send(signal.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.image, signal.image);
        assert_eq!(received.new_version, signal.new_version);
    }

    #[tokio::test]
    async fn test_current_image_format() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: tokio::sync::broadcast::channel(1).0,
            pull_hook: None,
        };
        let image = updater.current_image();
        assert!(image.starts_with("cortexlm/platform-validator:"));
    }

    #[tokio::test]
    async fn test_check_and_update_no_update() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: tokio::sync::broadcast::channel(1).0,
            pull_hook: None,
        };
        let result = updater.check_and_update().await.unwrap();
        assert!(matches!(
            result,
            UpdateResult::NoUpdateAvailable | UpdateResult::AlreadyUpToDate
        ));
    }

    #[tokio::test]
    async fn test_check_and_update_returns_already_up_to_date() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: tokio::sync::broadcast::channel(1).0,
            pull_hook: None,
        };

        let requirement = UpdateRequirement {
            min_version: Version::current(),
            recommended_version: Version::current(),
            docker_image: "same/version:latest".to_string(),
            mandatory: false,
            deadline_block: None,
            release_notes: None,
        };
        watcher.on_version_update(requirement);

        let result = updater.check_and_update().await.unwrap();
        assert!(matches!(result, UpdateResult::AlreadyUpToDate));
    }

    #[tokio::test]
    async fn test_handle_update_already_up_to_date() {
        let watcher = make_test_watcher();
        let updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: tokio::sync::broadcast::channel(1).0,
            pull_hook: None,
        };
        let req = UpdateRequirement {
            min_version: Version::current(),
            recommended_version: Version::current(),
            docker_image: "test-image:latest".to_string(),
            mandatory: false,
            deadline_block: None,
            release_notes: None,
        };
        let result = updater.handle_update(req).await;
        assert!(result.is_ok());
    }

    fn future_version() -> Version {
        let current = Version::current();
        if current.patch < u32::MAX {
            Version::new(current.major, current.minor, current.patch + 1)
        } else if current.minor < u32::MAX {
            Version::new(current.major, current.minor + 1, 0)
        } else if current.major < u32::MAX {
            Version::new(current.major + 1, 0, 0)
        } else {
            current
        }
    }

    fn make_future_requirement(image: &str, mandatory: bool) -> UpdateRequirement {
        let future = future_version();
        UpdateRequirement {
            min_version: future.clone(),
            recommended_version: future,
            docker_image: image.to_string(),
            mandatory,
            deadline_block: None,
            release_notes: None,
        }
    }

    #[tokio::test]
    async fn test_handle_update_triggers_restart_signal() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(4);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher,
            restart_sender: sender,
            pull_hook: None,
        };

        let pull_calls = Arc::new(Mutex::new(Vec::new()));
        let hook_calls = pull_calls.clone();
        updater.pull_hook = Some(Arc::new(move |image: &str| {
            let hook_calls = hook_calls.clone();
            let image = image.to_string();
            Box::pin(async move {
                hook_calls.lock().unwrap().push(image);
                Ok(())
            })
        }));

        let mut rx = updater.restart_sender.subscribe();
        let requirement = make_future_requirement("test/image:1.0.0", false);

        updater
            .handle_update(requirement.clone())
            .await
            .expect("update should succeed");

        let signal = rx.try_recv().expect("restart signal expected");
        assert_eq!(signal.image, requirement.docker_image);
        assert_eq!(signal.new_version, requirement.recommended_version);
        assert!(!signal.mandatory);
        assert_eq!(pull_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_check_and_update_reports_updated() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(4);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: sender,
            pull_hook: None,
        };

        let pull_calls = Arc::new(Mutex::new(Vec::new()));
        let hook_calls = pull_calls.clone();
        updater.pull_hook = Some(Arc::new(move |image: &str| {
            let hook_calls = hook_calls.clone();
            let image = image.to_string();
            Box::pin(async move {
                hook_calls.lock().unwrap().push(image);
                Ok(())
            })
        }));

        let requirement = make_future_requirement("test/image:2.0.0", false);
        watcher.on_version_update(requirement.clone());

        let result = updater
            .check_and_update()
            .await
            .expect("update should succeed");

        match result {
            UpdateResult::Updated { from, to, image } => {
                assert_eq!(from, Version::current());
                assert_eq!(to, requirement.recommended_version);
                assert_eq!(image, requirement.docker_image);
            }
            _ => panic!("expected Updated result"),
        }

        assert_eq!(pull_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_handle_update_mandatory_triggers_shutdown() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(4);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher,
            restart_sender: sender,
            pull_hook: None,
        };

        let pull_calls = Arc::new(Mutex::new(Vec::new()));
        let hook_calls = pull_calls.clone();
        updater.pull_hook = Some(Arc::new(move |image: &str| {
            let hook_calls = hook_calls.clone();
            let image = image.to_string();
            Box::pin(async move {
                hook_calls.lock().unwrap().push(image);
                Ok(())
            })
        }));

        let mut rx = updater.restart_sender.subscribe();
        let requirement = make_future_requirement("test/image:mandatory", true);

        updater
            .handle_update(requirement.clone())
            .await
            .expect("mandatory update should succeed");

        let signal = rx.try_recv().expect("restart signal expected");
        assert!(signal.mandatory);
        assert_eq!(signal.image, requirement.docker_image);
        assert_eq!(pull_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_handle_update_propagates_pull_error() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(4);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher,
            restart_sender: sender,
            pull_hook: None,
        };

        updater.pull_hook = Some(Arc::new(|_| {
            Box::pin(async { Err(anyhow!("pull failed")) })
        }));

        let requirement = make_future_requirement("test/image:error", false);
        let result = updater.handle_update(requirement).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pull_image_uses_test_hook() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(1);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher,
            restart_sender: sender,
            pull_hook: None,
        };

        let pull_calls = Arc::new(Mutex::new(Vec::new()));
        let hook_calls = pull_calls.clone();
        updater.pull_hook = Some(Arc::new(move |image: &str| {
            let hook_calls = hook_calls.clone();
            let image = image.to_string();
            Box::pin(async move {
                hook_calls.lock().unwrap().push(image);
                Ok(())
            })
        }));

        updater.pull_image("hook/test:1.0.0").await.unwrap();
        assert_eq!(pull_calls.lock().unwrap().as_slice(), ["hook/test:1.0.0"]);
    }

    #[tokio::test]
    async fn test_start_processes_incoming_requirements() {
        let watcher = make_test_watcher();
        let (sender, _) = broadcast::channel(4);
        let mut updater = AutoUpdater {
            docker: make_test_docker(),
            watcher: watcher.clone(),
            restart_sender: sender,
            pull_hook: None,
        };

        let pull_calls = Arc::new(Mutex::new(Vec::new()));
        let hook_calls = pull_calls.clone();
        updater.pull_hook = Some(Arc::new(move |image: &str| {
            let hook_calls = hook_calls.clone();
            let image = image.to_string();
            Box::pin(async move {
                hook_calls.lock().unwrap().push(image);
                Ok(())
            })
        }));

        let updater = Arc::new(updater);
        let mut rx = updater.subscribe_restart();
        let requirement = make_future_requirement("start/test:1.0", false);

        let updater_clone = updater.clone();
        tokio::spawn(async move {
            updater_clone.start().await;
        });

        sleep(Duration::from_millis(10)).await;
        watcher.on_version_update(requirement.clone());

        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("restart signal in time")
            .expect("channel open");
        assert_eq!(received.image, requirement.docker_image);
        assert_eq!(pull_calls.lock().unwrap().len(), 1);
    }
}
