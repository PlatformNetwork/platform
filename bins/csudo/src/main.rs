//! Chain Sudo (csudo) - Beautiful Administrative CLI for Platform Chain
//!
//! Provides subnet owners with administrative commands for managing
//! challenges, validators, mechanisms, and network configuration.
//!
//! Usage:
//!   csudo list challenges        - List all challenges
//!   csudo list mechanisms        - List mechanism configs
//!   csudo list validators        - List validators
//!   csudo add challenge          - Add a new challenge (interactive)
//!   csudo edit challenge <id>    - Edit a challenge
//!   csudo remove challenge <id>  - Remove a challenge
//!   csudo status                 - Show network status

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use parking_lot::RwLock;
use platform_consensus::PBFTEngine;
use platform_core::{
    ChainState, ChallengeContainerConfig, ChallengeId, Hotkey, Keypair, NetworkConfig,
    SignedNetworkMessage, Stake, SudoAction, ValidatorInfo,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const BANNER: &str = r#"
   _____ _____ _   _ _____   ____  
  / ____/ ____| | | |  __ \ / __ \ 
 | |   | (___ | | | | |  | | |  | |
 | |    \___ \| | | | |  | | |  | |
 | |____  ___) | |__| | |__| | |__| |
  \_____|____/  \____/|_____/ \____/ 
                                     
  Platform Chain Admin CLI v0.1.0
"#;

#[derive(Parser, Debug)]
#[command(name = "csudo")]
#[command(about = "Platform Chain administrative CLI for subnet owners")]
#[command(version, author)]
struct Args {
    /// Secret key or mnemonic (REQUIRED - subnet owner must be registered)
    #[arg(short, long, env = "SUDO_SECRET_KEY", global = true)]
    secret_key: Option<String>,

    /// RPC server URL
    #[arg(
        short,
        long,
        default_value = "http://localhost:8080",
        env = "PLATFORM_RPC",
        global = true
    )]
    rpc: String,

    /// Quiet mode (less output)
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List resources (challenges, mechanisms, validators)
    #[command(subcommand)]
    List(ListCommands),

    /// Add resources
    #[command(subcommand)]
    Add(AddCommands),

    /// Edit resources
    #[command(subcommand)]
    Edit(EditCommands),

    /// Remove resources
    #[command(subcommand)]
    Remove(RemoveCommands),

    /// Set configuration
    #[command(subcommand)]
    Set(SetCommands),

    /// Show network status
    Status,

    /// Interactive mode - manage everything from a menu
    Interactive,

    /// Generate a new keypair
    Keygen,

    /// Emergency commands
    #[command(subcommand)]
    Emergency(EmergencyCommands),
}

#[derive(Subcommand, Debug)]
enum ListCommands {
    /// List all challenges
    Challenges,
    /// List mechanism configurations
    Mechanisms,
    /// List validators
    Validators,
    /// Show everything
    All,
}

#[derive(Subcommand, Debug)]
enum AddCommands {
    /// Add a new challenge
    Challenge {
        /// Challenge name (optional - interactive if not provided)
        #[arg(short, long)]
        name: Option<String>,
        /// Docker image
        #[arg(short, long)]
        docker_image: Option<String>,
        /// Mechanism ID
        #[arg(short, long)]
        mechanism_id: Option<u8>,
    },
    /// Add a validator
    Validator {
        /// Validator hotkey (hex)
        #[arg(short = 'k', long)]
        hotkey: Option<String>,
        /// Stake in TAO
        #[arg(short, long)]
        stake: Option<f64>,
    },
}

#[derive(Subcommand, Debug)]
enum EditCommands {
    /// Edit a challenge
    Challenge {
        /// Challenge ID (optional - select from list if not provided)
        id: Option<String>,
    },
    /// Edit mechanism config
    Mechanism {
        /// Mechanism ID
        id: Option<u8>,
    },
}

#[derive(Subcommand, Debug)]
enum RemoveCommands {
    /// Remove a challenge
    Challenge {
        /// Challenge ID (optional - select from list if not provided)
        id: Option<String>,
    },
    /// Remove a validator
    Validator {
        /// Validator hotkey
        hotkey: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SetCommands {
    /// Set challenge weight on mechanism
    Weight {
        /// Challenge ID
        #[arg(short, long)]
        challenge_id: Option<String>,
        /// Mechanism ID
        #[arg(short, long)]
        mechanism_id: Option<u8>,
        /// Weight ratio (0.0 - 1.0)
        #[arg(short, long)]
        weight: Option<f64>,
    },
    /// Set required validator version
    Version {
        /// Version string (e.g., "0.2.0")
        #[arg(short, long)]
        version: String,
        /// Docker image
        #[arg(short, long)]
        docker_image: String,
        /// Mandatory update
        #[arg(long)]
        mandatory: bool,
    },
}

#[derive(Subcommand, Debug)]
enum EmergencyCommands {
    /// Pause the network
    Pause {
        /// Reason for pause
        #[arg(short, long)]
        reason: String,
    },
    /// Resume the network
    Resume,
}

// ==================== State Fetching ====================

#[derive(Debug, Clone, Default)]
struct ChainStateData {
    block_height: u64,
    epoch: u64,
    challenges: Vec<ChallengeData>,
    mechanisms: Vec<MechanismData>,
    validators: Vec<ValidatorData>,
    challenge_weights: Vec<WeightData>,
}

#[derive(Debug, Clone)]
struct ChallengeData {
    id: String,
    name: String,
    docker_image: String,
    mechanism_id: u8,
    emission_weight: f64,
    timeout_secs: u64,
    cpu_cores: f64,
    memory_mb: u64,
    gpu_required: bool,
}

#[derive(Debug, Clone)]
struct MechanismData {
    id: u8,
    burn_rate: f64,
    max_cap: f64,
    min_threshold: f64,
    equal_distribution: bool,
    active: bool,
}

#[derive(Debug, Clone)]
struct ValidatorData {
    hotkey: String,
    stake: u64,
    stake_tao: f64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct WeightData {
    challenge_id: String,
    mechanism_id: u8,
    weight_ratio: f64,
    active: bool,
}

async fn fetch_chain_state(rpc_url: &str) -> Result<ChainStateData> {
    let client = reqwest::Client::new();
    let url = format!("{}/rpc", rpc_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "chain_getState",
            "params": [],
            "id": 1
        }))
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        anyhow::bail!("RPC Error: {}", error);
    }

    let state = result
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("No result"))?;

    let block_height = state
        .get("blockHeight")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let epoch = state.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);

    let mut data = ChainStateData {
        block_height,
        epoch,
        ..Default::default()
    };

    // Parse challenges
    if let Some(configs) = state.get("challenge_configs").and_then(|v| v.as_object()) {
        for (id, config) in configs {
            data.challenges.push(ChallengeData {
                id: id.clone(),
                name: config
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                docker_image: config
                    .get("docker_image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                mechanism_id: config
                    .get("mechanism_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u8,
                emission_weight: config
                    .get("emission_weight")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0),
                timeout_secs: config
                    .get("timeout_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3600),
                cpu_cores: config
                    .get("cpu_cores")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(2.0),
                memory_mb: config
                    .get("memory_mb")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4096),
                gpu_required: config
                    .get("gpu_required")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }
    }

    // Parse mechanisms
    if let Some(configs) = state.get("mechanism_configs").and_then(|v| v.as_object()) {
        for (id, config) in configs {
            data.mechanisms.push(MechanismData {
                id: id.parse().unwrap_or(0),
                burn_rate: config
                    .get("base_burn_rate")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                max_cap: config
                    .get("max_weight_cap")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5),
                min_threshold: config
                    .get("min_weight_threshold")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0001),
                equal_distribution: config
                    .get("equal_distribution")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                active: config
                    .get("is_active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
            });
        }
    }

    // Parse validators
    if let Some(validators) = state.get("validators").and_then(|v| v.as_object()) {
        for (hotkey, info) in validators {
            data.validators.push(ValidatorData {
                hotkey: hotkey.clone(),
                stake: info.get("stake").and_then(|v| v.as_u64()).unwrap_or(0),
                stake_tao: info
                    .get("stake_tao")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
            });
        }
    }

    // Parse weights
    if let Some(weights) = state.get("challenge_weights").and_then(|v| v.as_object()) {
        for (id, alloc) in weights {
            data.challenge_weights.push(WeightData {
                challenge_id: id.clone(),
                mechanism_id: alloc
                    .get("mechanism_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u8,
                weight_ratio: alloc
                    .get("weight_ratio")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0),
                active: alloc
                    .get("active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
            });
        }
    }

    Ok(data)
}

// ==================== Display Functions ====================

fn print_banner() {
    println!("{}", BANNER.cyan());
}

fn print_section(title: &str) {
    println!("\n{}", format!("━━━ {} ━━━", title).bright_blue().bold());
}

fn display_challenges(challenges: &[ChallengeData]) {
    if challenges.is_empty() {
        println!("{}", "  No challenges registered.".yellow());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Name").fg(Color::Cyan),
            Cell::new("ID").fg(Color::Cyan),
            Cell::new("Mechanism").fg(Color::Cyan),
            Cell::new("Weight").fg(Color::Cyan),
            Cell::new("Docker Image").fg(Color::Cyan),
            Cell::new("Resources").fg(Color::Cyan),
        ]);

    for c in challenges {
        let resources = format!(
            "{}cpu/{}MB{}",
            c.cpu_cores,
            c.memory_mb,
            if c.gpu_required { "/GPU" } else { "" }
        );
        table.add_row(vec![
            Cell::new(&c.name).fg(Color::Green),
            Cell::new(&c.id[..8.min(c.id.len())]),
            Cell::new(c.mechanism_id.to_string()),
            Cell::new(format!("{:.0}%", c.emission_weight * 100.0)),
            Cell::new(&c.docker_image[..40.min(c.docker_image.len())]),
            Cell::new(resources),
        ]);
    }

    println!("{table}");
}

fn display_mechanisms(mechanisms: &[MechanismData]) {
    if mechanisms.is_empty() {
        println!("{}", "  No mechanism configs (using defaults).".yellow());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ID").fg(Color::Cyan),
            Cell::new("Burn Rate").fg(Color::Cyan),
            Cell::new("Max Cap").fg(Color::Cyan),
            Cell::new("Min Threshold").fg(Color::Cyan),
            Cell::new("Equal Dist").fg(Color::Cyan),
            Cell::new("Active").fg(Color::Cyan),
        ]);

    for m in mechanisms {
        table.add_row(vec![
            Cell::new(m.id.to_string()).fg(Color::Green),
            Cell::new(format!("{:.1}%", m.burn_rate * 100.0)),
            Cell::new(format!("{:.1}%", m.max_cap * 100.0)),
            Cell::new(format!("{:.4}", m.min_threshold)),
            Cell::new(if m.equal_distribution { "Yes" } else { "No" }),
            Cell::new(if m.active { "✓" } else { "✗" }).fg(if m.active {
                Color::Green
            } else {
                Color::Red
            }),
        ]);
    }

    println!("{table}");
}

fn display_validators(validators: &[ValidatorData]) {
    if validators.is_empty() {
        println!("{}", "  No validators registered.".yellow());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Hotkey").fg(Color::Cyan),
            Cell::new("Stake (TAO)").fg(Color::Cyan),
            Cell::new("Stake (RAO)").fg(Color::Cyan),
        ]);

    for v in validators {
        table.add_row(vec![
            Cell::new(&v.hotkey[..16.min(v.hotkey.len())]).fg(Color::Green),
            Cell::new(format!("{:.2}", v.stake_tao)),
            Cell::new(v.stake.to_string()),
        ]);
    }

    println!("{table}");
}

fn display_status(state: &ChainStateData) {
    println!("\n{}", "Network Status".bright_green().bold());
    println!(
        "  {} {}",
        "Block Height:".bright_white(),
        state.block_height.to_string().cyan()
    );
    println!(
        "  {} {}",
        "Epoch:".bright_white(),
        state.epoch.to_string().cyan()
    );
    println!(
        "  {} {}",
        "Challenges:".bright_white(),
        state.challenges.len().to_string().cyan()
    );
    println!(
        "  {} {}",
        "Mechanisms:".bright_white(),
        state.mechanisms.len().to_string().cyan()
    );
    println!(
        "  {} {}",
        "Validators:".bright_white(),
        state.validators.len().to_string().cyan()
    );
}

// ==================== Action Submission ====================

async fn submit_action(rpc_url: &str, keypair: &Keypair, action: SudoAction) -> Result<()> {
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        keypair.hotkey(),
        NetworkConfig::default(),
    )));

    let (msg_tx, mut msg_rx) = mpsc::channel::<SignedNetworkMessage>(100);
    let consensus = PBFTEngine::new(keypair.clone(), chain_state.clone(), msg_tx);

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message("Creating signed action...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let _proposal_id = consensus.propose_sudo(action).await?;

    let mut messages: Vec<SignedNetworkMessage> = Vec::new();
    while let Ok(msg) = msg_rx.try_recv() {
        messages.push(msg);
    }

    if messages.is_empty() {
        pb.finish_with_message("No messages generated".red().to_string());
        return Ok(());
    }

    pb.set_message("Submitting to network...");

    let client = reqwest::Client::new();
    let url = format!("{}/rpc", rpc_url.trim_end_matches('/'));

    for msg in &messages {
        let serialized = bincode::serialize(&msg)?;
        let hex_encoded = hex::encode(&serialized);

        let response = client
            .post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "sudo_submit",
                "params": { "signedMessage": hex_encoded },
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(error) = result.get("error") {
            pb.finish_with_message(format!("{} {}", "Error:".red(), error));
            anyhow::bail!("RPC Error: {}", error);
        }
    }

    pb.finish_with_message(format!("{} Action submitted successfully!", "✓".green()));
    Ok(())
}

// ==================== Interactive Functions ====================

fn get_keypair(secret: &Option<String>) -> Result<Keypair> {
    let secret = match secret {
        Some(s) => s.clone(),
        None => Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter secret key or mnemonic")
            .interact_text()?,
    };

    let secret = secret.trim();
    let hex_str = secret.strip_prefix("0x").unwrap_or(secret);

    if hex_str.len() == 64 {
        if let Ok(bytes) = hex::decode(hex_str) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(Keypair::from_seed(&arr)?);
            }
        }
    }

    Ok(Keypair::from_mnemonic(secret)?)
}

async fn interactive_add_challenge(rpc_url: &str, keypair: &Keypair) -> Result<()> {
    print_section("Add New Challenge");

    let name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Challenge name")
        .interact_text()?;

    let docker_image: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Docker image (e.g., ghcr.io/org/image:tag)")
        .interact_text()?;

    let mechanism_id: u8 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Mechanism ID")
        .default(0)
        .interact_text()?;

    let emission_weight: f64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Emission weight (0.0-1.0)")
        .default(1.0)
        .interact_text()?;

    let timeout: u64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Timeout (seconds)")
        .default(3600)
        .interact_text()?;

    let cpu_cores: f64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("CPU cores")
        .default(2.0)
        .interact_text()?;

    let memory_mb: u64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Memory (MB)")
        .default(4096)
        .interact_text()?;

    let gpu_required = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Requires GPU?")
        .default(false)
        .interact()?;

    println!("\n{}", "Challenge Configuration:".bright_yellow());
    println!("  Name: {}", name.green());
    println!("  Docker: {}", docker_image.cyan());
    println!("  Mechanism: {}", mechanism_id.to_string().cyan());
    println!("  Weight: {:.0}%", emission_weight * 100.0);
    println!(
        "  Resources: {}cpu / {}MB{}",
        cpu_cores,
        memory_mb,
        if gpu_required { " / GPU" } else { "" }
    );

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Submit this challenge?")
        .default(true)
        .interact()?
    {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }

    let config = ChallengeContainerConfig {
        challenge_id: ChallengeId::new(),
        name,
        docker_image,
        mechanism_id,
        emission_weight,
        timeout_secs: timeout,
        cpu_cores,
        memory_mb,
        gpu_required,
    };

    submit_action(rpc_url, keypair, SudoAction::AddChallenge { config }).await
}

async fn interactive_edit_challenge(
    rpc_url: &str,
    keypair: &Keypair,
    state: &ChainStateData,
    challenge_id: Option<String>,
) -> Result<()> {
    if state.challenges.is_empty() {
        println!("{}", "No challenges to edit.".yellow());
        return Ok(());
    }

    let challenge = if let Some(id) = challenge_id {
        state
            .challenges
            .iter()
            .find(|c| c.id.starts_with(&id))
            .ok_or_else(|| anyhow::anyhow!("Challenge not found: {}", id))?
    } else {
        let options: Vec<String> = state
            .challenges
            .iter()
            .map(|c| format!("{} ({})", c.name, &c.id[..8]))
            .collect();

        let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select challenge to edit")
            .items(&options)
            .interact()?;

        &state.challenges[selection]
    };

    print_section(&format!("Edit Challenge: {}", challenge.name));

    let edit_options = vec![
        "Docker Image",
        "Emission Weight",
        "Timeout",
        "CPU Cores",
        "Memory",
        "GPU Required",
        "Done (submit changes)",
        "Cancel",
    ];

    let mut config = ChallengeContainerConfig {
        challenge_id: ChallengeId(uuid::Uuid::parse_str(&challenge.id)?),
        name: challenge.name.clone(),
        docker_image: challenge.docker_image.clone(),
        mechanism_id: challenge.mechanism_id,
        emission_weight: challenge.emission_weight,
        timeout_secs: challenge.timeout_secs,
        cpu_cores: challenge.cpu_cores,
        memory_mb: challenge.memory_mb,
        gpu_required: challenge.gpu_required,
    };

    loop {
        println!("\n{}", "Current values:".bright_white());
        println!("  Docker: {}", config.docker_image.cyan());
        println!("  Weight: {:.0}%", config.emission_weight * 100.0);
        println!("  Timeout: {}s", config.timeout_secs);
        println!("  CPU: {}", config.cpu_cores);
        println!("  Memory: {}MB", config.memory_mb);
        println!("  GPU: {}", if config.gpu_required { "Yes" } else { "No" });

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What to edit?")
            .items(&edit_options)
            .interact()?;

        match selection {
            0 => {
                config.docker_image = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("New Docker image")
                    .default(config.docker_image.clone())
                    .interact_text()?;
            }
            1 => {
                config.emission_weight = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Emission weight (0.0-1.0)")
                    .default(config.emission_weight)
                    .interact_text()?;
            }
            2 => {
                config.timeout_secs = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Timeout (seconds)")
                    .default(config.timeout_secs)
                    .interact_text()?;
            }
            3 => {
                config.cpu_cores = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("CPU cores")
                    .default(config.cpu_cores)
                    .interact_text()?;
            }
            4 => {
                config.memory_mb = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Memory (MB)")
                    .default(config.memory_mb)
                    .interact_text()?;
            }
            5 => {
                config.gpu_required = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Requires GPU?")
                    .default(config.gpu_required)
                    .interact()?;
            }
            6 => {
                // Submit
                return submit_action(rpc_url, keypair, SudoAction::UpdateChallenge { config })
                    .await;
            }
            7 => {
                println!("{}", "Cancelled.".yellow());
                return Ok(());
            }
            _ => {}
        }
    }
}

async fn interactive_remove_challenge(
    rpc_url: &str,
    keypair: &Keypair,
    state: &ChainStateData,
    challenge_id: Option<String>,
) -> Result<()> {
    if state.challenges.is_empty() {
        println!("{}", "No challenges to remove.".yellow());
        return Ok(());
    }

    let challenge = if let Some(id) = challenge_id {
        state
            .challenges
            .iter()
            .find(|c| c.id.starts_with(&id))
            .ok_or_else(|| anyhow::anyhow!("Challenge not found: {}", id))?
    } else {
        let options: Vec<String> = state
            .challenges
            .iter()
            .map(|c| format!("{} ({})", c.name, &c.id[..8]))
            .collect();

        let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select challenge to remove")
            .items(&options)
            .interact()?;

        &state.challenges[selection]
    };

    println!("\n{} You are about to remove:", "Warning:".red().bold());
    println!("  Name: {}", challenge.name.red());
    println!("  ID: {}", challenge.id);

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure?")
        .default(false)
        .interact()?
    {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }

    let id = ChallengeId(uuid::Uuid::parse_str(&challenge.id)?);
    submit_action(rpc_url, keypair, SudoAction::RemoveChallenge { id }).await
}

async fn interactive_mode(rpc_url: &str, keypair: &Keypair) -> Result<()> {
    let term = Term::stdout();

    loop {
        term.clear_screen()?;
        print_banner();

        let state = fetch_chain_state(rpc_url).await?;
        display_status(&state);

        println!();
        let menu_options = vec![
            "📋 List Challenges",
            "➕ Add Challenge",
            "✏️  Edit Challenge",
            "🗑️  Remove Challenge",
            "⚙️  Configure Mechanism",
            "👥 List Validators",
            "🔄 Refresh",
            "🚪 Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&menu_options)
            .default(0)
            .interact()?;

        match selection {
            0 => {
                print_section("Challenges");
                display_challenges(&state.challenges);
                println!("\n{}", "Press Enter to continue...".dimmed());
                let _ = term.read_line();
            }
            1 => {
                interactive_add_challenge(rpc_url, keypair).await?;
                println!("\n{}", "Press Enter to continue...".dimmed());
                let _ = term.read_line();
            }
            2 => {
                interactive_edit_challenge(rpc_url, keypair, &state, None).await?;
                println!("\n{}", "Press Enter to continue...".dimmed());
                let _ = term.read_line();
            }
            3 => {
                interactive_remove_challenge(rpc_url, keypair, &state, None).await?;
                println!("\n{}", "Press Enter to continue...".dimmed());
                let _ = term.read_line();
            }
            4 => {
                print_section("Mechanisms");
                display_mechanisms(&state.mechanisms);
                println!("\n{}", "Mechanism editing coming soon...".dimmed());
                let _ = term.read_line();
            }
            5 => {
                print_section("Validators");
                display_validators(&state.validators);
                println!("\n{}", "Press Enter to continue...".dimmed());
                let _ = term.read_line();
            }
            6 => continue,
            7 => {
                println!("{}", "Goodbye!".green());
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup minimal logging unless quiet
    if !args.quiet {
        tracing_subscriber::fmt()
            .with_env_filter("warn")
            .with_target(false)
            .init();
    }

    // Handle keygen separately
    if matches!(args.command, Commands::Keygen) {
        let keypair = Keypair::generate();
        println!("{}", "Generated new sr25519 keypair:".green().bold());
        println!(
            "  {} {}",
            "Hotkey:".bright_white(),
            keypair.hotkey().to_hex().cyan()
        );
        println!(
            "  {} {}",
            "SS58:".bright_white(),
            keypair.ss58_address().cyan()
        );
        println!(
            "  {} {}",
            "Seed:".bright_white(),
            hex::encode(keypair.seed()).yellow()
        );
        println!();
        println!("{}", "To use with csudo:".dimmed());
        println!("  export SUDO_SECRET_KEY=\"your-mnemonic-or-seed\"");
        return Ok(());
    }

    // For all other commands, we need the keypair
    let keypair = get_keypair(&args.secret_key)?;

    if !args.quiet {
        println!(
            "{} {}",
            "Subnet Owner:".bright_white(),
            keypair.ss58_address().cyan()
        );
    }

    match args.command {
        Commands::Keygen => unreachable!(),

        Commands::List(list_cmd) => {
            let state = fetch_chain_state(&args.rpc).await?;

            match list_cmd {
                ListCommands::Challenges => {
                    print_section("Challenges");
                    display_challenges(&state.challenges);
                }
                ListCommands::Mechanisms => {
                    print_section("Mechanisms");
                    display_mechanisms(&state.mechanisms);
                }
                ListCommands::Validators => {
                    print_section("Validators");
                    display_validators(&state.validators);
                }
                ListCommands::All => {
                    display_status(&state);
                    print_section("Challenges");
                    display_challenges(&state.challenges);
                    print_section("Mechanisms");
                    display_mechanisms(&state.mechanisms);
                    print_section("Validators");
                    display_validators(&state.validators);
                }
            }
        }

        Commands::Add(add_cmd) => {
            match add_cmd {
                AddCommands::Challenge {
                    name,
                    docker_image,
                    mechanism_id,
                } => {
                    if let (Some(name), Some(docker_image), Some(mechanism_id)) =
                        (name, docker_image, mechanism_id)
                    {
                        // Non-interactive
                        let config = ChallengeContainerConfig {
                            challenge_id: ChallengeId::new(),
                            name,
                            docker_image,
                            mechanism_id,
                            emission_weight: 1.0,
                            timeout_secs: 3600,
                            cpu_cores: 2.0,
                            memory_mb: 4096,
                            gpu_required: false,
                        };
                        submit_action(&args.rpc, &keypair, SudoAction::AddChallenge { config })
                            .await?;
                    } else {
                        interactive_add_challenge(&args.rpc, &keypair).await?;
                    }
                }
                AddCommands::Validator { hotkey, stake } => {
                    let hk = if let Some(h) = hotkey {
                        h
                    } else {
                        Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Validator hotkey (hex)")
                            .interact_text()?
                    };
                    let stake_tao = stake.unwrap_or_else(|| {
                        Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Stake (TAO)")
                            .default(10.0)
                            .interact_text()
                            .unwrap_or(10.0)
                    });

                    let hotkey =
                        Hotkey::from_hex(&hk).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
                    let stake_raw = (stake_tao * 1_000_000_000.0) as u64;
                    let info = ValidatorInfo::new(hotkey, Stake::new(stake_raw));
                    submit_action(&args.rpc, &keypair, SudoAction::AddValidator { info }).await?;
                }
            }
        }

        Commands::Edit(edit_cmd) => {
            let state = fetch_chain_state(&args.rpc).await?;
            match edit_cmd {
                EditCommands::Challenge { id } => {
                    interactive_edit_challenge(&args.rpc, &keypair, &state, id).await?;
                }
                EditCommands::Mechanism { id: _ } => {
                    println!("{}", "Mechanism editing coming soon...".yellow());
                }
            }
        }

        Commands::Remove(remove_cmd) => {
            let state = fetch_chain_state(&args.rpc).await?;
            match remove_cmd {
                RemoveCommands::Challenge { id } => {
                    interactive_remove_challenge(&args.rpc, &keypair, &state, id).await?;
                }
                RemoveCommands::Validator { hotkey } => {
                    let hk = if let Some(h) = hotkey {
                        h
                    } else {
                        let options: Vec<String> = state
                            .validators
                            .iter()
                            .map(|v| format!("{} ({:.2} TAO)", &v.hotkey[..16], v.stake_tao))
                            .collect();

                        if options.is_empty() {
                            println!("{}", "No validators to remove.".yellow());
                            return Ok(());
                        }

                        let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                            .with_prompt("Select validator to remove")
                            .items(&options)
                            .interact()?;

                        state.validators[selection].hotkey.clone()
                    };

                    let hotkey =
                        Hotkey::from_hex(&hk).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
                    submit_action(&args.rpc, &keypair, SudoAction::RemoveValidator { hotkey })
                        .await?;
                }
            }
        }

        Commands::Set(set_cmd) => match set_cmd {
            SetCommands::Weight {
                challenge_id,
                mechanism_id,
                weight,
            } => {
                let state = fetch_chain_state(&args.rpc).await?;

                let cid = if let Some(id) = challenge_id {
                    id
                } else {
                    let options: Vec<String> = state
                        .challenges
                        .iter()
                        .map(|c| format!("{} ({})", c.name, &c.id[..8]))
                        .collect();

                    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                        .with_prompt("Select challenge")
                        .items(&options)
                        .interact()?;

                    state.challenges[selection].id.clone()
                };

                let mech_id = mechanism_id.unwrap_or_else(|| {
                    Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Mechanism ID")
                        .default(0)
                        .interact_text()
                        .unwrap_or(0)
                });

                let weight_ratio = weight.unwrap_or_else(|| {
                    Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Weight ratio (0.0-1.0)")
                        .default(1.0)
                        .interact_text()
                        .unwrap_or(1.0)
                });

                let challenge_id = ChallengeId(uuid::Uuid::parse_str(&cid)?);
                submit_action(
                    &args.rpc,
                    &keypair,
                    SudoAction::SetChallengeWeight {
                        challenge_id,
                        mechanism_id: mech_id,
                        weight_ratio,
                    },
                )
                .await?;
            }
            SetCommands::Version {
                version,
                docker_image,
                mandatory,
            } => {
                submit_action(
                    &args.rpc,
                    &keypair,
                    SudoAction::SetRequiredVersion {
                        min_version: version.clone(),
                        recommended_version: version,
                        docker_image,
                        mandatory,
                        deadline_block: None,
                        release_notes: None,
                    },
                )
                .await?;
            }
        },

        Commands::Status => {
            let state = fetch_chain_state(&args.rpc).await?;
            display_status(&state);
            print_section("Challenges");
            display_challenges(&state.challenges);
        }

        Commands::Interactive => {
            interactive_mode(&args.rpc, &keypair).await?;
        }

        Commands::Emergency(cmd) => match cmd {
            EmergencyCommands::Pause { reason } => {
                println!("{} Pausing the network!", "⚠️ WARNING:".red().bold());
                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you absolutely sure?")
                    .default(false)
                    .interact()?
                {
                    submit_action(&args.rpc, &keypair, SudoAction::EmergencyPause { reason })
                        .await?;
                }
            }
            EmergencyCommands::Resume => {
                submit_action(&args.rpc, &keypair, SudoAction::Resume).await?;
            }
        },
    }

    Ok(())
}
