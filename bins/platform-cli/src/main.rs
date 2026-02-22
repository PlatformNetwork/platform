//! Platform CLI — download and manage challenge CLIs
//!
//! Provides subcommands to download, update, list, run, and configure
//! challenge CLI binaries from GitHub releases.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

// ==================== Constants ====================

const PLATFORM_DIR_NAME: &str = ".platform";
const CONFIG_FILE_NAME: &str = "platform.toml";
const VERSIONS_FILE_NAME: &str = "versions.json";
const BIN_DIR_NAME: &str = "bin";
const GITHUB_API_BASE: &str = "https://api.github.com";

// ==================== Config ====================

#[derive(Debug, Serialize, Deserialize)]
struct PlatformConfig {
    network: NetworkConfig,
    #[serde(default)]
    challenges: HashMap<String, ChallengeConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkConfig {
    rpc_endpoint: String,
    netuid: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeConfig {
    github_repo: String,
    binary_name: String,
    command_alias: String,
    #[serde(default = "default_true")]
    auto_update: bool,
}

fn default_true() -> bool {
    true
}

impl Default for PlatformConfig {
    fn default() -> Self {
        let mut challenges = HashMap::new();
        challenges.insert(
            "bounty-challenge".to_string(),
            ChallengeConfig {
                github_repo: "PlatformNetwork/bounty-challenge".to_string(),
                binary_name: "bounty-cli".to_string(),
                command_alias: "bounty".to_string(),
                auto_update: true,
            },
        );
        Self {
            network: NetworkConfig {
                rpc_endpoint: "wss://chain.platform.network".to_string(),
                netuid: 100,
            },
            challenges,
        }
    }
}

// ==================== Version Tracking ====================

#[derive(Debug, Serialize, Deserialize)]
struct VersionInfo {
    version: String,
    binary_path: String,
    installed_at: DateTime<Utc>,
    github_repo: String,
}

type VersionStore = HashMap<String, VersionInfo>;

// ==================== GitHub API Types ====================

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

// ==================== CLI ====================

#[derive(Parser)]
#[command(name = "platform")]
#[command(about = "Platform CLI — download and manage challenge CLIs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download a challenge CLI binary from GitHub releases
    Download {
        /// Name of the challenge to download
        challenge_name: String,
    },
    /// Check for and install updates for a challenge CLI
    Update {
        /// Name of the challenge to update
        challenge_name: String,
    },
    /// List installed challenge CLIs
    List,
    /// Run an installed challenge CLI
    Run {
        /// Name of the challenge to run (or a command alias)
        challenge_name: String,
        /// Arguments to forward to the challenge CLI
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show current platform.toml config
    Config,
}

// ==================== Path Helpers ====================

fn platform_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(PLATFORM_DIR_NAME))
}

fn config_path() -> Result<PathBuf> {
    Ok(platform_dir()?.join(CONFIG_FILE_NAME))
}

fn versions_path() -> Result<PathBuf> {
    Ok(platform_dir()?.join(VERSIONS_FILE_NAME))
}

fn bin_dir() -> Result<PathBuf> {
    Ok(platform_dir()?.join(BIN_DIR_NAME))
}

/// Validate that a binary name does not contain path separators or traversal sequences.
///
/// Prevents a malicious config from escaping the `~/.platform/bin/` directory
/// via names like `../../usr/bin/evil` or `foo/bar`.
fn validate_binary_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Binary name must not be empty");
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        anyhow::bail!(
            "Invalid binary name '{}': must not contain path separators or '..'",
            name
        );
    }
    if name.starts_with('.') || name.starts_with('-') {
        anyhow::bail!(
            "Invalid binary name '{}': must not start with '.' or '-'",
            name
        );
    }
    Ok(())
}

// ==================== Config I/O ====================

fn load_config() -> Result<PlatformConfig> {
    let path = config_path()?;
    if !path.exists() {
        info!("Config not found at {}, creating default", path.display());
        let config = PlatformConfig::default();
        save_config(&config)?;
        return Ok(config);
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;
    let config: PlatformConfig = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse config at {}", path.display()))?;
    Ok(config)
}

fn save_config(config: &PlatformConfig) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let contents = toml::to_string_pretty(config).context("Failed to serialize config")?;
    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write config to {}", path.display()))?;
    debug!("Config saved to {}", path.display());
    Ok(())
}

// ==================== Version Store I/O ====================

fn load_versions() -> Result<VersionStore> {
    let path = versions_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read versions from {}", path.display()))?;
    let versions: VersionStore = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse versions at {}", path.display()))?;
    Ok(versions)
}

fn save_versions(versions: &VersionStore) -> Result<()> {
    let path = versions_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let contents =
        serde_json::to_string_pretty(versions).context("Failed to serialize versions")?;
    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write versions to {}", path.display()))?;
    debug!("Versions saved to {}", path.display());
    Ok(())
}

// ==================== Platform Detection ====================

fn platform_identifier() -> String {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    };
    let arch = std::env::consts::ARCH;
    format!("{}-{}", os, arch)
}

fn find_matching_asset(assets: &[GitHubAsset]) -> Option<&GitHubAsset> {
    let platform = platform_identifier();
    debug!("Looking for asset matching platform: {}", platform);

    assets
        .iter()
        .find(|asset| asset.name.contains(&platform))
        .or_else(|| {
            let os = std::env::consts::OS;
            let arch = std::env::consts::ARCH;
            assets
                .iter()
                .find(|asset| asset.name.contains(os) && asset.name.contains(arch))
        })
}

// ==================== GitHub API ====================

/// Validate that a GitHub repo string is in the expected `owner/repo` format.
///
/// Prevents URL path injection when the value is interpolated into API URLs.
/// Only alphanumeric characters, hyphens, underscores, and dots are permitted
/// in each segment.
fn validate_github_repo(repo: &str) -> Result<()> {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid github_repo '{}': must be in 'owner/repo' format",
            repo
        );
    }
    for part in &parts {
        if part.is_empty() {
            anyhow::bail!(
                "Invalid github_repo '{}': owner and repo must not be empty",
                repo
            );
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            anyhow::bail!(
                "Invalid github_repo '{}': contains disallowed characters",
                repo
            );
        }
    }
    Ok(())
}

async fn fetch_latest_release(
    client: &reqwest::Client,
    github_repo: &str,
) -> Result<GitHubRelease> {
    validate_github_repo(github_repo)?;
    let url = format!("{}/repos/{}/releases/latest", GITHUB_API_BASE, github_repo);
    debug!("Fetching latest release from {}", url);

    let response = client
        .get(&url)
        .header("User-Agent", "platform-cli")
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .with_context(|| format!("Failed to fetch releases from {}", url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        anyhow::bail!(
            "GitHub API returned {} for {}: {}",
            status,
            github_repo,
            body
        );
    }

    let release: GitHubRelease = response
        .json()
        .await
        .context("Failed to parse GitHub release response")?;

    Ok(release)
}

async fn download_binary(client: &reqwest::Client, url: &str, dest: &Path) -> Result<()> {
    let parsed_url =
        reqwest::Url::parse(url).with_context(|| format!("Invalid download URL: {}", url))?;
    if parsed_url.scheme() != "https" {
        anyhow::bail!(
            "Refusing to download from non-HTTPS URL: {}",
            parsed_url.scheme()
        );
    }
    info!("Downloading binary from {}", url);

    let response = client
        .get(url)
        .header("User-Agent", "platform-cli")
        .send()
        .await
        .with_context(|| format!("Failed to download from {}", url))?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("Download failed with status {}", status);
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read download response body")?;

    std::fs::write(dest, &bytes)
        .with_context(|| format!("Failed to write binary to {}", dest.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(dest, perms).with_context(|| {
            format!("Failed to set executable permissions on {}", dest.display())
        })?;
    }

    info!("Binary saved to {}", dest.display());
    Ok(())
}

// ==================== PATH Setup ====================

fn is_bin_in_path() -> Result<bool> {
    let bin = bin_dir()?;
    let bin_str = bin.to_string_lossy();
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for entry in path_var.split(sep) {
            if Path::new(entry) == bin.as_path() {
                return Ok(true);
            }
            if entry == bin_str.as_ref() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn try_add_to_path() {
    let bin = match bin_dir() {
        Ok(b) => b,
        Err(_) => return,
    };
    let bin_str = bin.display().to_string();

    if is_bin_in_path().unwrap_or(false) {
        return;
    }

    #[cfg(windows)]
    {
        try_add_to_path_windows(&bin_str);
    }

    #[cfg(unix)]
    {
        try_add_to_path_unix(&bin_str);
    }
}

#[cfg(windows)]
fn try_add_to_path_windows(bin_str: &str) {
    use std::process::Command;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = [Environment]::GetEnvironmentVariable('PATH','User'); \
                 if ($p -split ';' | Where-Object {{ $_ -eq '{}' }}) {{ exit 0 }} \
                 else {{ [Environment]::SetEnvironmentVariable('PATH', $p + ';{}', 'User'); exit 1 }}",
                bin_str, bin_str
            ),
        ])
        .output();

    match output {
        Ok(o) if o.status.code() == Some(0) => {}
        Ok(o) if o.status.code() == Some(1) => {
            println!();
            println!("  Added {} to your user PATH.", bin_str);
            println!("  Restart your terminal for the change to take effect.");
        }
        _ => {
            println!();
            println!("  Could not automatically update PATH.");
            print_path_instructions_windows(bin_str);
        }
    }
}

#[cfg(unix)]
fn try_add_to_path_unix(bin_str: &str) {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            print_path_instructions_unix(bin_str);
            return;
        }
    };

    let export_line = format!("export PATH=\"{}:$PATH\"", bin_str);

    let shell_files: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![home.join(".zshrc"), home.join(".bash_profile")]
    } else {
        vec![
            home.join(".bashrc"),
            home.join(".zshrc"),
            home.join(".profile"),
        ]
    };

    let mut added = false;
    for rc_file in &shell_files {
        if !rc_file.exists() {
            continue;
        }
        if let Ok(contents) = std::fs::read_to_string(rc_file) {
            if contents.contains(bin_str) {
                debug!("PATH entry already in {}", rc_file.display());
                return;
            }
        }
        let entry = format!("\n# Added by platform-cli\n{}\n", export_line);
        if std::fs::OpenOptions::new()
            .append(true)
            .open(rc_file)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(entry.as_bytes())
            })
            .is_ok()
        {
            println!();
            println!("  Added {} to {}", bin_str, rc_file.display());
            added = true;
            break;
        }
    }

    if added {
        println!("  Restart your terminal or run:");
        println!(
            "    source {}",
            shell_files.iter().find(|f| f.exists()).unwrap().display()
        );
    } else {
        print_path_instructions_unix(bin_str);
    }
}

#[cfg(windows)]
fn print_path_instructions_windows(bin_str: &str) {
    println!("  To add to PATH manually, run in PowerShell:");
    println!(
        "    [Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';{}', 'User')",
        bin_str
    );
    println!("  Then restart your terminal.");
}

#[cfg(unix)]
fn print_path_instructions_unix(bin_str: &str) {
    let shell_hint = if cfg!(target_os = "macos") {
        "~/.zshrc"
    } else {
        "~/.bashrc"
    };
    println!();
    println!(
        "  To add to PATH manually, add this line to {}:",
        shell_hint
    );
    println!("    export PATH=\"{}:$PATH\"", bin_str);
    println!("  Then restart your terminal or run: source {}", shell_hint);
}

// ==================== Challenge Lookup ====================

fn resolve_challenge_name(
    config: &PlatformConfig,
    name: &str,
) -> Option<(String, ChallengeConfig)> {
    if let Some(challenge) = config.challenges.get(name) {
        return Some((name.to_string(), challenge.clone()));
    }

    for (challenge_name, challenge) in &config.challenges {
        if challenge.command_alias == name {
            return Some((challenge_name.clone(), challenge.clone()));
        }
    }

    None
}

// ==================== Subcommand Handlers ====================

async fn cmd_download(challenge_name: &str) -> Result<()> {
    let config = load_config()?;
    let (canonical_name, challenge) = resolve_challenge_name(&config, challenge_name)
        .with_context(|| {
            format!(
                "Challenge '{}' not found in config. Add it to {} first.",
                challenge_name,
                config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "~/.platform/platform.toml".to_string())
            )
        })?;

    validate_binary_name(&challenge.binary_name)?;

    info!(
        "Downloading challenge '{}' from {}",
        canonical_name, challenge.github_repo
    );

    let client = reqwest::Client::new();
    let release = fetch_latest_release(&client, &challenge.github_repo).await?;

    let version = release.tag_name.trim_start_matches('v').to_string();
    info!("Latest release: v{}", version);

    let asset = find_matching_asset(&release.assets).with_context(|| {
        let available: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
        format!(
            "No binary found for platform '{}'. Available assets: {:?}",
            platform_identifier(),
            available
        )
    })?;

    let dest = bin_dir()?.join(&challenge.binary_name);
    download_binary(&client, &asset.browser_download_url, &dest).await?;

    let mut versions = load_versions()?;
    versions.insert(
        canonical_name.clone(),
        VersionInfo {
            version: version.clone(),
            binary_path: dest.display().to_string(),
            installed_at: Utc::now(),
            github_repo: challenge.github_repo.clone(),
        },
    );
    save_versions(&versions)?;

    info!(
        "Successfully installed {} v{} to {}",
        canonical_name,
        version,
        dest.display()
    );
    println!(
        "✓ {} v{} installed to {}",
        canonical_name,
        version,
        dest.display()
    );

    try_add_to_path();

    Ok(())
}

async fn cmd_update(challenge_name: &str) -> Result<()> {
    let config = load_config()?;
    let (canonical_name, challenge) = resolve_challenge_name(&config, challenge_name)
        .with_context(|| format!("Challenge '{}' not found in config", challenge_name))?;

    validate_binary_name(&challenge.binary_name)?;

    let versions = load_versions()?;
    let current_version = versions
        .get(&canonical_name)
        .map(|v| v.version.clone())
        .unwrap_or_default();

    info!(
        "Checking for updates to '{}' (current: {})",
        canonical_name,
        if current_version.is_empty() {
            "not installed"
        } else {
            &current_version
        }
    );

    let client = reqwest::Client::new();
    let release = fetch_latest_release(&client, &challenge.github_repo).await?;
    let latest_version = release.tag_name.trim_start_matches('v').to_string();

    if !current_version.is_empty() {
        let current = semver::Version::parse(&current_version);
        let latest = semver::Version::parse(&latest_version);

        match (current, latest) {
            (Ok(cur), Ok(lat)) if lat <= cur => {
                println!(
                    "✓ {} is already up to date (v{})",
                    canonical_name, current_version
                );
                return Ok(());
            }
            _ => {}
        }
    }

    info!(
        "Updating {} from v{} to v{}",
        canonical_name, current_version, latest_version
    );

    let asset = find_matching_asset(&release.assets)
        .with_context(|| format!("No binary found for platform '{}'", platform_identifier()))?;

    let dest = bin_dir()?.join(&challenge.binary_name);
    download_binary(&client, &asset.browser_download_url, &dest).await?;

    let mut versions = load_versions()?;
    versions.insert(
        canonical_name.clone(),
        VersionInfo {
            version: latest_version.clone(),
            binary_path: dest.display().to_string(),
            installed_at: Utc::now(),
            github_repo: challenge.github_repo.clone(),
        },
    );
    save_versions(&versions)?;

    println!(
        "✓ {} updated to v{} at {}",
        canonical_name,
        latest_version,
        dest.display()
    );

    Ok(())
}

fn cmd_list() -> Result<()> {
    let versions = load_versions()?;

    if versions.is_empty() {
        println!("No challenge CLIs installed.");
        println!("Use 'platform download <challenge-name>' to install one.");
        return Ok(());
    }

    let header_installed = "INSTALLED";
    println!(
        "{:<20} {:<12} {:<40} {}",
        "CHALLENGE", "VERSION", "PATH", header_installed
    );
    println!("{}", "-".repeat(90));

    let mut entries: Vec<_> = versions.iter().collect();
    entries.sort_by_key(|(name, _)| (*name).clone());

    for (name, info) in entries {
        println!(
            "{:<20} {:<12} {:<40} {}",
            name,
            info.version,
            info.binary_path,
            info.installed_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    Ok(())
}

async fn cmd_run(challenge_name: &str, args: &[String]) -> Result<()> {
    let config = load_config()?;
    let (canonical_name, challenge) = resolve_challenge_name(&config, challenge_name)
        .with_context(|| format!("Challenge '{}' not found in config", challenge_name))?;

    validate_binary_name(&challenge.binary_name)?;

    let versions = load_versions()?;
    let version_info = versions.get(&canonical_name).with_context(|| {
        format!(
            "Challenge '{}' is not installed. Run 'platform download {}' first.",
            canonical_name, canonical_name
        )
    })?;

    let binary_path = Path::new(&version_info.binary_path);
    if !binary_path.exists() {
        anyhow::bail!(
            "Binary not found at {}. Run 'platform download {}' to reinstall.",
            binary_path.display(),
            canonical_name
        );
    }

    if challenge.auto_update {
        let repo = challenge.github_repo.clone();
        let current_version = version_info.version.clone();
        let name_for_log = canonical_name.clone();
        tokio::spawn(async move {
            match check_for_update_quietly(&repo, &current_version).await {
                Ok(Some(new_version)) => {
                    eprintln!(
                        "ℹ A new version of {} is available: v{} (current: v{}). Run 'platform update {}'",
                        name_for_log, new_version, current_version, name_for_log
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("Auto-update check failed for {}: {}", name_for_log, e);
                }
            }
        });
    }

    debug!("Running {} with args: {:?}", binary_path.display(), args);

    let status = std::process::Command::new(binary_path)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute {}", binary_path.display()))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}

async fn check_for_update_quietly(
    github_repo: &str,
    current_version: &str,
) -> Result<Option<String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let release = fetch_latest_release(&client, github_repo).await?;
    let latest_version = release.tag_name.trim_start_matches('v').to_string();

    let current = semver::Version::parse(current_version)?;
    let latest = semver::Version::parse(&latest_version)?;

    if latest > current {
        Ok(Some(latest_version))
    } else {
        Ok(None)
    }
}

fn cmd_config() -> Result<()> {
    let path = config_path()?;
    if !path.exists() {
        info!("No config found, creating default at {}", path.display());
        let config = PlatformConfig::default();
        save_config(&config)?;
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;

    println!("# Config: {}", path.display());
    println!();
    print!("{}", contents);

    Ok(())
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,platform_cli=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Download { challenge_name } => cmd_download(&challenge_name).await,
        Commands::Update { challenge_name } => cmd_update(&challenge_name).await,
        Commands::List => cmd_list(),
        Commands::Run {
            challenge_name,
            args,
        } => cmd_run(&challenge_name, &args).await,
        Commands::Config => cmd_config(),
    }
}
