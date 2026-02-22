//! Platform Sudo CLI — manage challenges as subnet owner

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use platform_core::ChallengeId;
use reqwest::Client;
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "platform-sudo")]
#[command(about = "Platform Sudo CLI — manage challenges as subnet owner")]
struct Cli {
    /// Validator RPC endpoint
    #[arg(long, default_value = "http://localhost:8080", env = "VALIDATOR_RPC")]
    rpc: String,

    /// Sudo secret key (hex or file path)
    #[arg(long, env = "SUDO_SECRET_KEY")]
    sudo_key: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a WASM challenge module
    Upload {
        /// Path to the WASM file
        #[arg(short, long)]
        file: PathBuf,
        /// Challenge ID (UUID format)
        #[arg(short, long)]
        id: String,
        /// Challenge name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Activate a challenge
    Activate {
        /// Challenge ID
        #[arg(short, long)]
        id: String,
    },
    /// Deactivate a challenge
    Deactivate {
        /// Challenge ID
        #[arg(short, long)]
        id: String,
    },
    /// List all challenges
    List,
    /// Show validator status
    Status,
    /// Interactive mode
    Interactive,
}

#[derive(Serialize)]
struct SudoRequest {
    action: String,
    challenge_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>, // base64-encoded WASM
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    signature: String,
    timestamp: i64,
}

#[derive(Deserialize)]
struct SudoResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    status: String,
    version: String,
    uptime_secs: u64,
}

#[derive(Deserialize)]
struct ChallengeInfo {
    id: String,
    name: String,
    is_active: bool,
}

struct SudoCli {
    client: Client,
    rpc_url: String,
    keypair: Option<sr25519::Pair>,
}

impl SudoCli {
    fn new(rpc_url: String, sudo_key: Option<String>) -> Result<Self> {
        let keypair = if let Some(key) = sudo_key {
            // Try to parse as mnemonic, hex, or file
            if key.contains(' ') {
                // Mnemonic phrase
                use sp_core::Pair;
                let pair = sr25519::Pair::from_phrase(&key, None)
                    .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {:?}", e))?
                    .0;
                Some(pair)
            } else {
                let key_bytes = if let Some(stripped) = key.strip_prefix("0x") {
                    hex::decode(stripped).context("Invalid hex key")?
                } else if std::path::Path::new(&key).exists() {
                    std::fs::read(&key).context("Failed to read key file")?
                } else {
                    hex::decode(&key).context("Invalid hex key")?
                };

                let seed: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Key must be 32 bytes"))?;
                Some(sr25519::Pair::from_seed(&seed))
            }
        } else {
            None
        };

        Ok(Self {
            client: Client::new(),
            rpc_url,
            keypair,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Sudo key not configured"))?;
        Ok(keypair.sign(data).0.to_vec())
    }

    async fn upload_wasm(
        &self,
        file: &PathBuf,
        challenge_id: &str,
        name: Option<String>,
    ) -> Result<()> {
        let wasm_bytes = std::fs::read(file).context("Failed to read WASM file")?;

        info!(file = %file.display(), size = wasm_bytes.len(), "Uploading WASM module");

        let challenge_id = if challenge_id == "new" {
            ChallengeId::new()
        } else {
            ChallengeId::from_string(challenge_id)
        };

        let timestamp = chrono::Utc::now().timestamp_millis();

        // Sign the message (format must match server: "sudo:{action}:{challenge_id}:{timestamp}")
        let msg_to_sign = format!("sudo:wasm_upload:{}:{}", challenge_id, timestamp);
        let signature = self.sign(msg_to_sign.as_bytes())?;

        // Send via RPC
        let request = SudoRequest {
            action: "wasm_upload".to_string(),
            challenge_id: challenge_id.to_string(),
            data: Some(base64::engine::general_purpose::STANDARD.encode(&wasm_bytes)),
            name: name.or_else(|| Some(challenge_id.to_string())),
            signature: hex::encode(&signature),
            timestamp,
        };

        let response = self
            .client
            .post(format!("{}/sudo/challenge", self.rpc_url))
            .json(&request)
            .send()
            .await
            .context("Failed to send request")?;

        if response.status().is_success() {
            let result: SudoResponse = response.json().await?;
            if result.success {
                info!(challenge_id = %challenge_id, "WASM module uploaded successfully");
            } else {
                warn!(message = %result.message, "Upload failed");
            }
        } else {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!(status = %status, body = %text, "RPC request failed");
        }

        Ok(())
    }

    async fn set_challenge_status(&self, challenge_id: &str, active: bool) -> Result<()> {
        let action = if active { "activate" } else { "deactivate" };
        let timestamp = chrono::Utc::now().timestamp_millis();

        let challenge_id = ChallengeId::from_string(challenge_id);

        // Sign the message (format must match server: "sudo:{action}:{challenge_id}:{timestamp}")
        let msg_to_sign = format!("sudo:{}:{}:{}", action, challenge_id, timestamp);
        let signature = self.sign(msg_to_sign.as_bytes())?;

        let request = SudoRequest {
            action: action.to_string(),
            challenge_id: challenge_id.to_string(),
            data: None,
            name: None,
            signature: hex::encode(&signature),
            timestamp,
        };

        let response = self
            .client
            .post(format!("{}/sudo/challenge", self.rpc_url))
            .json(&request)
            .send()
            .await
            .context("Failed to send request")?;

        if response.status().is_success() {
            let result: SudoResponse = response.json().await?;
            if result.success {
                info!(challenge_id = %challenge_id, action = action, "Challenge status updated");
            } else {
                warn!(message = %result.message, "Status update failed");
            }
        } else {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!(status = %status, body = %text, "RPC request failed");
        }

        Ok(())
    }

    async fn list_challenges(&self) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/challenges", self.rpc_url))
            .send()
            .await
            .context("Failed to get challenges")?;

        if response.status().is_success() {
            let challenges: Vec<ChallengeInfo> = response.json().await?;
            println!("\nChallenges:");
            println!("{:-<60}", "");
            for c in challenges {
                let status = if c.is_active { "active" } else { "inactive" };
                println!("  {} | {} | {}", c.id, c.name, status);
            }
            println!("{:-<60}", "");
        } else {
            println!("Failed to fetch challenges: {}", response.status());
        }

        Ok(())
    }

    async fn status(&self) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/health", self.rpc_url))
            .send()
            .await
            .context("Failed to get status")?;

        if response.status().is_success() {
            let status: StatusResponse = response.json().await?;
            println!("\nValidator Status:");
            println!("  Status:  {}", status.status);
            println!("  Version: {}", status.version);
            println!("  Uptime:  {} seconds", status.uptime_secs);
        } else {
            println!("Failed to fetch status: {}", response.status());
        }

        Ok(())
    }

    async fn interactive(&self) -> Result<()> {
        let mut rl = DefaultEditor::new()?;

        println!("\nPlatform Sudo CLI - Interactive Mode");
        println!("Type 'help' for available commands, 'exit' to quit\n");

        loop {
            let readline = rl.readline("sudo> ");
            match readline {
                Ok(line) => {
                    let _ = rl.add_history_entry(&line);
                    let parts: Vec<&str> = line.split_whitespace().collect();

                    if parts.is_empty() {
                        continue;
                    }

                    match parts[0] {
                        "help" | "?" => {
                            println!("\nCommands:");
                            println!("  upload <file> <challenge_id> [name]  - Upload WASM module");
                            println!("  activate <challenge_id>              - Activate challenge");
                            println!(
                                "  deactivate <challenge_id>            - Deactivate challenge"
                            );
                            println!(
                                "  list                                 - List all challenges"
                            );
                            println!(
                                "  status                               - Show validator status"
                            );
                            println!("  exit | quit                          - Exit CLI\n");
                        }
                        "upload" if parts.len() >= 3 => {
                            let file = PathBuf::from(parts[1]);
                            let id = parts[2];
                            let name = parts.get(3).map(|s| s.to_string());
                            if let Err(e) = self.upload_wasm(&file, id, name).await {
                                println!("Error: {}", e);
                            }
                        }
                        "activate" if parts.len() >= 2 => {
                            if let Err(e) = self.set_challenge_status(parts[1], true).await {
                                println!("Error: {}", e);
                            }
                        }
                        "deactivate" if parts.len() >= 2 => {
                            if let Err(e) = self.set_challenge_status(parts[1], false).await {
                                println!("Error: {}", e);
                            }
                        }
                        "list" => {
                            if let Err(e) = self.list_challenges().await {
                                println!("Error: {}", e);
                            }
                        }
                        "status" => {
                            if let Err(e) = self.status().await {
                                println!("Error: {}", e);
                            }
                        }
                        "exit" | "quit" => {
                            println!("Goodbye!");
                            break;
                        }
                        _ => {
                            println!("Unknown command. Type 'help' for available commands.");
                        }
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted)
                | Err(rustyline::error::ReadlineError::Eof) => {
                    println!("\nGoodbye!");
                    break;
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                    break;
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let sudo_cli = SudoCli::new(cli.rpc, cli.sudo_key)?;

    match cli.command {
        Some(Commands::Upload { file, id, name }) => {
            sudo_cli.upload_wasm(&file, &id, name).await?;
        }
        Some(Commands::Activate { id }) => {
            sudo_cli.set_challenge_status(&id, true).await?;
        }
        Some(Commands::Deactivate { id }) => {
            sudo_cli.set_challenge_status(&id, false).await?;
        }
        Some(Commands::List) => {
            sudo_cli.list_challenges().await?;
        }
        Some(Commands::Status) => {
            sudo_cli.status().await?;
        }
        Some(Commands::Interactive) | None => {
            sudo_cli.interactive().await?;
        }
    }

    Ok(())
}
