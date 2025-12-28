//! Chain Sudo (csudo) - Administrative CLI for Platform Chain
//!
//! Interactive and non-interactive CLI for managing challenges on chain.platform.network
//!
//! Usage:
//!   csudo                          # Interactive mode
//!   csudo list challenges          # Non-interactive
//!   csudo add challenge --name "Term Bench" --image "ghcr.io/..." --mechanism 1

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use platform_core::Keypair;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const DEFAULT_SERVER: &str = "https://chain.platform.network";

#[derive(Parser, Debug)]
#[command(name = "csudo")]
#[command(about = "Platform Chain administrative CLI")]
#[command(version, author)]
struct Args {
    /// Secret key or mnemonic (subnet owner)
    #[arg(short = 'k', long, env = "SUDO_SECRET_KEY", global = true)]
    secret_key: Option<String>,

    /// Platform server URL
    #[arg(
        long,
        default_value = DEFAULT_SERVER,
        env = "PLATFORM_SERVER",
        global = true
    )]
    server: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List resources
    #[command(subcommand)]
    List(ListCommands),

    /// Add a challenge
    #[command(subcommand)]
    Add(AddCommands),

    /// Start a challenge container
    #[command(subcommand)]
    Start(StartCommands),

    /// Stop a challenge container
    #[command(subcommand)]
    Stop(StopCommands),

    /// Remove a challenge
    #[command(subcommand)]
    Remove(RemoveCommands),

    /// Show server status
    Status,

    /// Generate a new keypair
    Keygen,

    /// Interactive mode (default if no command given)
    Interactive,
}

#[derive(Subcommand, Debug)]
enum ListCommands {
    /// List all challenges
    Challenges,
}

#[derive(Subcommand, Debug)]
enum AddCommands {
    /// Add a new challenge
    Challenge {
        /// Challenge ID (e.g., "term-bench")
        #[arg(long)]
        id: String,
        /// Challenge name (e.g., "Terminal Bench")
        #[arg(long)]
        name: String,
        /// Docker image
        #[arg(long)]
        image: String,
        /// Mechanism ID (default: 1)
        #[arg(long, default_value = "1")]
        mechanism: u8,
        /// Emission weight (default: 1.0)
        #[arg(long, default_value = "1.0")]
        weight: f64,
        /// Timeout in seconds (default: 600)
        #[arg(long, default_value = "600")]
        timeout: u64,
        /// CPU cores (default: 2.0)
        #[arg(long, default_value = "2.0")]
        cpu: f64,
        /// Memory in MB (default: 4096)
        #[arg(long, default_value = "4096")]
        memory: u64,
        /// Requires GPU
        #[arg(long, default_value = "false")]
        gpu: bool,
    },
}

#[derive(Subcommand, Debug)]
enum StartCommands {
    /// Start a challenge container
    Challenge {
        /// Challenge ID
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum StopCommands {
    /// Stop a challenge container
    Challenge {
        /// Challenge ID
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum RemoveCommands {
    /// Remove a challenge
    Challenge {
        /// Challenge ID
        id: String,
    },
}

// ==================== API Types ====================

#[derive(Debug, Serialize)]
struct RegisterChallengeRequest {
    id: String,
    name: String,
    docker_image: String,
    mechanism_id: u8,
    emission_weight: f64,
    timeout_secs: u64,
    cpu_cores: f64,
    memory_mb: u64,
    gpu_required: bool,
    owner_hotkey: String,
    signature: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Challenge {
    id: String,
    name: String,
    docker_image: String,
    mechanism_id: i32,
    emission_weight: f64,
    #[serde(default)]
    timeout_secs: u64,
    #[serde(default)]
    cpu_cores: f64,
    #[serde(default)]
    memory_mb: u64,
    #[serde(default)]
    gpu_required: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    is_healthy: bool,
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    success: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    challenge_id: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    #[serde(default)]
    version: Option<String>,
}

// ==================== Client ====================

struct PlatformClient {
    base_url: String,
    client: Client,
    keypair: Keypair,
}

impl PlatformClient {
    fn new(base_url: &str, keypair: Keypair) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            keypair,
        }
    }

    fn sign(&self, message: &str) -> String {
        let signed = self.keypair.sign(message.as_bytes());
        format!("0x{}", hex::encode(&signed.signature))
    }

    fn hotkey(&self) -> String {
        self.keypair.ss58_address()
    }

    async fn health(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.base_url);
        let resp = self.client.get(&url).send().await?;
        let text = resp.text().await?;

        // Try JSON first, fall back to plain text
        if let Ok(json) = serde_json::from_str::<HealthResponse>(&text) {
            Ok(json)
        } else {
            Ok(HealthResponse {
                status: text.trim().to_string(),
                version: None,
            })
        }
    }

    async fn list_challenges(&self) -> Result<Vec<Challenge>> {
        let url = format!("{}/api/v1/challenges", self.base_url);
        let resp: Vec<Challenge> = self.client.get(&url).send().await?.json().await?;
        Ok(resp)
    }

    async fn register_challenge(&self, req: RegisterChallengeRequest) -> Result<ApiResponse> {
        let url = format!("{}/api/v1/challenges", self.base_url);
        let resp = self.client.post(&url).json(&req).send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            anyhow::bail!("API error: {}", text);
        }

        Ok(resp.json().await?)
    }

    async fn start_challenge(&self, id: &str) -> Result<ApiResponse> {
        let url = format!("{}/api/v1/challenges/{}/start", self.base_url, id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let message = format!("start_challenge:{}:{}", id, timestamp);
        let signature = self.sign(&message);

        let body = serde_json::json!({
            "owner_hotkey": self.hotkey(),
            "signature": signature,
            "timestamp": timestamp
        });

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            anyhow::bail!("API error: {}", text);
        }

        Ok(resp.json().await?)
    }

    async fn stop_challenge(&self, id: &str) -> Result<ApiResponse> {
        let url = format!("{}/api/v1/challenges/{}/stop", self.base_url, id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let message = format!("stop_challenge:{}:{}", id, timestamp);
        let signature = self.sign(&message);

        let body = serde_json::json!({
            "owner_hotkey": self.hotkey(),
            "signature": signature,
            "timestamp": timestamp
        });

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            anyhow::bail!("API error: {}", text);
        }

        Ok(resp.json().await?)
    }

    async fn remove_challenge(&self, id: &str) -> Result<ApiResponse> {
        let url = format!("{}/api/v1/challenges/{}", self.base_url, id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let message = format!("remove_challenge:{}:{}", id, timestamp);
        let signature = self.sign(&message);

        let body = serde_json::json!({
            "owner_hotkey": self.hotkey(),
            "signature": signature,
            "timestamp": timestamp
        });

        let resp = self.client.delete(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            anyhow::bail!("API error: {}", text);
        }

        Ok(resp.json().await?)
    }
}

// ==================== Display ====================

fn display_challenges(challenges: &[Challenge]) {
    if challenges.is_empty() {
        println!("{}", "No challenges registered.".yellow());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ID").fg(Color::Cyan),
            Cell::new("Name").fg(Color::Cyan),
            Cell::new("Mech").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
            Cell::new("Healthy").fg(Color::Cyan),
            Cell::new("Endpoint").fg(Color::Cyan),
        ]);

    for c in challenges {
        let status_color = match c.status.as_str() {
            "active" => Color::Green,
            "stopped" => Color::Yellow,
            _ => Color::White,
        };
        let health_color = if c.is_healthy {
            Color::Green
        } else {
            Color::Red
        };

        table.add_row(vec![
            Cell::new(&c.id).fg(Color::White),
            Cell::new(&c.name).fg(Color::Green),
            Cell::new(c.mechanism_id.to_string()),
            Cell::new(&c.status).fg(status_color),
            Cell::new(if c.is_healthy { "Y" } else { "N" }).fg(health_color),
            Cell::new(c.endpoint.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");
}

// ==================== Interactive Mode ====================

async fn interactive_mode(server: &str) -> Result<()> {
    let term = Term::stdout();
    let theme = ColorfulTheme::default();

    println!("\n{}", "=== Platform Chain Sudo ===".cyan().bold());
    println!("Server: {}\n", server.green());

    // Get secret key
    let secret: String = Password::with_theme(&theme)
        .with_prompt("Enter secret key or mnemonic")
        .interact()?;

    let keypair = load_keypair(&secret)?;
    let client = PlatformClient::new(server, keypair);

    println!("\n{} {}", "Owner:".bright_white(), client.hotkey().cyan());

    // Check server health
    match client.health().await {
        Ok(h) => println!("{} {}\n", "Server status:".bright_white(), h.status.green()),
        Err(e) => {
            println!("{} {}\n", "Server error:".red(), e);
            return Ok(());
        }
    }

    loop {
        let actions = vec![
            "List challenges",
            "Add challenge",
            "Start challenge",
            "Stop challenge",
            "Remove challenge",
            "Refresh status",
            "Exit",
        ];

        let selection = Select::with_theme(&theme)
            .with_prompt("Select action")
            .items(&actions)
            .default(0)
            .interact()?;

        term.clear_last_lines(1)?;

        match selection {
            0 => {
                // List challenges
                println!("\n{}", "Challenges:".bright_white().bold());
                match client.list_challenges().await {
                    Ok(challenges) => display_challenges(&challenges),
                    Err(e) => println!("{} {}", "Error:".red(), e),
                }
                println!();
            }
            1 => {
                // Add challenge
                println!("\n{}", "Add New Challenge".bright_white().bold());

                let id: String = Input::with_theme(&theme)
                    .with_prompt("Challenge ID (e.g., term-bench)")
                    .interact_text()?;

                let name: String = Input::with_theme(&theme)
                    .with_prompt("Challenge name")
                    .interact_text()?;

                let image: String = Input::with_theme(&theme)
                    .with_prompt("Docker image")
                    .interact_text()?;

                let mechanism: u8 = Input::with_theme(&theme)
                    .with_prompt("Mechanism ID")
                    .default(1)
                    .interact_text()?;

                let weight: f64 = Input::with_theme(&theme)
                    .with_prompt("Emission weight")
                    .default(1.0)
                    .interact_text()?;

                let timeout: u64 = Input::with_theme(&theme)
                    .with_prompt("Timeout (seconds)")
                    .default(600)
                    .interact_text()?;

                let cpu: f64 = Input::with_theme(&theme)
                    .with_prompt("CPU cores")
                    .default(2.0)
                    .interact_text()?;

                let memory: u64 = Input::with_theme(&theme)
                    .with_prompt("Memory (MB)")
                    .default(4096)
                    .interact_text()?;

                let gpu = Confirm::with_theme(&theme)
                    .with_prompt("Requires GPU?")
                    .default(false)
                    .interact()?;

                let message = format!("register_challenge:{}", id);
                let signature = client.sign(&message);

                let req = RegisterChallengeRequest {
                    id: id.clone(),
                    name: name.clone(),
                    docker_image: image,
                    mechanism_id: mechanism,
                    emission_weight: weight,
                    timeout_secs: timeout,
                    cpu_cores: cpu,
                    memory_mb: memory,
                    gpu_required: gpu,
                    owner_hotkey: client.hotkey(),
                    signature,
                };

                println!("Registering {}...", name.green());

                match client.register_challenge(req).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge registered: {}\n", "OK".green(), id);
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}\n",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => println!("{} {}\n", "Error:".red(), e),
                }
            }
            2 => {
                // Start challenge
                let challenges = client.list_challenges().await.unwrap_or_default();
                if challenges.is_empty() {
                    println!("{}\n", "No challenges to start.".yellow());
                    continue;
                }

                let items: Vec<String> = challenges
                    .iter()
                    .map(|c| format!("{} - {}", c.id, c.name))
                    .collect();

                let idx = Select::with_theme(&theme)
                    .with_prompt("Select challenge to start")
                    .items(&items)
                    .interact()?;

                let id = &challenges[idx].id;
                println!("Starting {}...", id.green());

                match client.start_challenge(id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge started", "OK".green());
                        if let Some(endpoint) = resp.endpoint {
                            println!("  Endpoint: {}\n", endpoint.cyan());
                        }
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}\n",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => println!("{} {}\n", "Error:".red(), e),
                }
            }
            3 => {
                // Stop challenge
                let challenges = client.list_challenges().await.unwrap_or_default();
                let active: Vec<&Challenge> =
                    challenges.iter().filter(|c| c.status == "active").collect();

                if active.is_empty() {
                    println!("{}\n", "No active challenges to stop.".yellow());
                    continue;
                }

                let items: Vec<String> = active
                    .iter()
                    .map(|c| format!("{} - {}", c.id, c.name))
                    .collect();

                let idx = Select::with_theme(&theme)
                    .with_prompt("Select challenge to stop")
                    .items(&items)
                    .interact()?;

                let id = &active[idx].id;
                println!("Stopping {}...", id.yellow());

                match client.stop_challenge(id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge stopped\n", "OK".green());
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}\n",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => println!("{} {}\n", "Error:".red(), e),
                }
            }
            4 => {
                // Remove challenge
                let challenges = client.list_challenges().await.unwrap_or_default();
                if challenges.is_empty() {
                    println!("{}\n", "No challenges to remove.".yellow());
                    continue;
                }

                let items: Vec<String> = challenges
                    .iter()
                    .map(|c| format!("{} - {}", c.id, c.name))
                    .collect();

                let idx = Select::with_theme(&theme)
                    .with_prompt("Select challenge to remove")
                    .items(&items)
                    .interact()?;

                let id = &challenges[idx].id;

                let confirm = Confirm::with_theme(&theme)
                    .with_prompt(format!("Are you sure you want to remove {}?", id))
                    .default(false)
                    .interact()?;

                if !confirm {
                    println!("Cancelled.\n");
                    continue;
                }

                println!("Removing {}...", id.red());

                match client.remove_challenge(id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge removed\n", "OK".green());
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}\n",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => println!("{} {}\n", "Error:".red(), e),
                }
            }
            5 => {
                // Refresh status
                println!("\n{}", "Server Status:".bright_white().bold());
                match client.health().await {
                    Ok(h) => {
                        println!("  Status: {}", h.status.green());
                        if let Some(v) = h.version {
                            println!("  Version: {}", v);
                        }
                    }
                    Err(e) => println!("{} {}", "Error:".red(), e),
                }

                println!("\n{}", "Challenges:".bright_white().bold());
                match client.list_challenges().await {
                    Ok(challenges) => display_challenges(&challenges),
                    Err(e) => println!("{} {}", "Error:".red(), e),
                }
                println!();
            }
            6 => {
                // Exit
                println!("Goodbye!");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// ==================== Main ====================

fn load_keypair(secret: &str) -> Result<Keypair> {
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Default to interactive mode if no command given
    let command = args.command.unwrap_or(Commands::Interactive);

    // Handle keygen (doesn't require secret key)
    if matches!(command, Commands::Keygen) {
        let keypair = Keypair::generate();
        println!("{}", "Generated new sr25519 keypair:".green().bold());
        println!("  Hotkey: {}", keypair.ss58_address().cyan());
        println!("  Seed:   0x{}", hex::encode(keypair.seed()).yellow());
        return Ok(());
    }

    // Handle interactive mode
    if matches!(command, Commands::Interactive) {
        return interactive_mode(&args.server).await;
    }

    // Load keypair (required for all other commands)
    let secret_key = args.secret_key.ok_or_else(|| {
        anyhow::anyhow!("Secret key required. Use -k or set SUDO_SECRET_KEY env var")
    })?;
    let keypair = load_keypair(&secret_key)?;
    let client = PlatformClient::new(&args.server, keypair);

    println!("{} {}", "Owner:".bright_white(), client.hotkey().cyan());
    println!("{} {}", "Server:".bright_white(), args.server.cyan());

    match command {
        Commands::Keygen | Commands::Interactive => unreachable!(),

        Commands::Status => {
            match client.health().await {
                Ok(h) => {
                    println!("{} {}", "Status:".bright_white(), h.status.green());
                    if let Some(v) = h.version {
                        println!("{} {}", "Version:".bright_white(), v);
                    }
                }
                Err(e) => {
                    println!("{} {}", "Error:".red(), e);
                }
            }

            println!("\n{}", "Challenges:".bright_white());
            match client.list_challenges().await {
                Ok(challenges) => display_challenges(&challenges),
                Err(e) => println!("{} {}", "Error:".red(), e),
            }
        }

        Commands::List(cmd) => match cmd {
            ListCommands::Challenges => {
                let challenges = client.list_challenges().await?;
                display_challenges(&challenges);
            }
        },

        Commands::Add(cmd) => match cmd {
            AddCommands::Challenge {
                id,
                name,
                image,
                mechanism,
                weight,
                timeout,
                cpu,
                memory,
                gpu,
            } => {
                let message = format!("register_challenge:{}", id);
                let signature = client.sign(&message);

                let req = RegisterChallengeRequest {
                    id: id.clone(),
                    name: name.clone(),
                    docker_image: image,
                    mechanism_id: mechanism,
                    emission_weight: weight,
                    timeout_secs: timeout,
                    cpu_cores: cpu,
                    memory_mb: memory,
                    gpu_required: gpu,
                    owner_hotkey: client.hotkey(),
                    signature,
                };

                println!("Registering challenge: {}", name.green());

                match client.register_challenge(req).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge registered: {}", "OK".green(), id);
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".red(), e);
                    }
                }
            }
        },

        Commands::Start(cmd) => match cmd {
            StartCommands::Challenge { id } => {
                println!("Starting challenge: {}", id.green());

                match client.start_challenge(&id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge started", "OK".green());
                        if let Some(endpoint) = resp.endpoint {
                            println!("  Endpoint: {}", endpoint.cyan());
                        }
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".red(), e);
                    }
                }
            }
        },

        Commands::Stop(cmd) => match cmd {
            StopCommands::Challenge { id } => {
                println!("Stopping challenge: {}", id.yellow());

                match client.stop_challenge(&id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge stopped", "OK".green());
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".red(), e);
                    }
                }
            }
        },

        Commands::Remove(cmd) => match cmd {
            RemoveCommands::Challenge { id } => {
                println!("Removing challenge: {}", id.red());

                match client.remove_challenge(&id).await {
                    Ok(resp) if resp.success => {
                        println!("{} Challenge removed", "OK".green());
                    }
                    Ok(resp) => {
                        println!(
                            "{} {}",
                            "FAILED".red(),
                            resp.error.unwrap_or_else(|| "Unknown error".to_string())
                        );
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".red(), e);
                    }
                }
            }
        },
    }

    Ok(())
}
