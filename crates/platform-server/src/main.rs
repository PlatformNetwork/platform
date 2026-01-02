//! Platform Server - Dynamic Challenge Orchestrator for Subnet Owners
//!
//! This server is the SINGLE SOURCE OF TRUTH for the Platform subnet.
//! Run ONLY by the subnet owner at chain.platform.network
//!
//! Architecture:
//! ```
//! Platform Server (this)
//!  ├── Control Plane API (REST)
//!  ├── Data API + Rule Engine  
//!  ├── Challenge Orchestrator (dynamic)
//!  │   └── Loads challenges from DB
//!  │   └── Starts Docker containers
//!  │   └── Routes /api/v1/challenges/{id}/*
//!  ├── WebSocket for validators
//!  └── PostgreSQL databases
//! ```

mod api;
mod challenge_proxy;
mod data_api;
mod db;
mod models;
mod observability;
mod orchestration;
mod rule_engine;
mod state;
mod websocket;

use crate::observability::init_sentry;
use crate::orchestration::ChallengeManager;
use crate::state::AppState;
use crate::websocket::handler::ws_handler;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use clap::Parser;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "platform-server")]
#[command(about = "Platform Network - Central API Server with Dynamic Challenge Orchestration")]
struct Args {
    /// Server port
    #[arg(short, long, default_value = "8080", env = "PORT")]
    port: u16,

    /// Server host
    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    host: String,

    /// Owner hotkey (subnet owner SS58 address)
    #[arg(
        long,
        env = "OWNER_HOTKEY",
        default_value = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At"
    )]
    owner_hotkey: String,

    /// PostgreSQL base URL (without database name)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://postgres:postgres@localhost:5432"
    )]
    database_url: String,

    /// Subtensor WebSocket endpoint
    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    subtensor_endpoint: String,

    /// Subnet UID for metagraph sync
    #[arg(long, env = "NETUID", default_value = "100")]
    netuid: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("platform_server=debug".parse().unwrap())
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let _sentry_guard = init_sentry();
    if _sentry_guard.is_some() {
        info!("Sentry error tracking enabled");
    }

    let args = Args::parse();

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║   Platform Server - Dynamic Challenge Orchestration          ║");
    info!("║              (Subnet Owner Only)                             ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!("");
    info!(
        "  Owner hotkey: {}...",
        &args.owner_hotkey[..16.min(args.owner_hotkey.len())]
    );
    info!("  Listening on: {}:{}", args.host, args.port);

    // Initialize database (creates platform_server database)
    let db = db::init_db(&args.database_url).await?;
    info!("  Database: platform_server");

    // Sync metagraph BEFORE accepting connections (blocking)
    info!("");
    info!("  Syncing metagraph (netuid={})...", args.netuid);
    let metagraph = match platform_bittensor::BittensorClient::new(&args.subtensor_endpoint).await {
        Ok(client) => match platform_bittensor::sync_metagraph(&client, args.netuid).await {
            Ok(mg) => {
                info!("  Metagraph synced: {} neurons", mg.n);
                Some(mg)
            }
            Err(e) => {
                warn!(
                    "  Metagraph sync failed: {} (validators will have stake=0)",
                    e
                );
                None
            }
        },
        Err(e) => {
            warn!(
                "  Could not connect to subtensor: {} (validators will have stake=0)",
                e
            );
            None
        }
    };

    // Initialize challenge orchestrator (loads challenges from DB)
    info!("");
    info!("  Initializing Challenge Orchestrator...");
    let challenge_manager = match ChallengeManager::new(db.clone()).await {
        Ok(cm) => {
            // Start all registered challenges
            if let Err(e) = cm.start_all().await {
                warn!("  Some challenges failed to start: {}", e);
            }
            Some(Arc::new(cm))
        }
        Err(e) => {
            warn!("  Challenge orchestrator disabled: {}", e);
            warn!("  (Docker may not be available)");
            None
        }
    };

    // Create application state
    let state = Arc::new(AppState::new_dynamic(
        db,
        Some(args.owner_hotkey.clone()),
        challenge_manager.clone(),
        metagraph,
    ));

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // WebSocket for validators
        .route("/ws", get(ws_handler))
        // === CONTROL PLANE API ===
        .route("/api/v1/auth", post(api::auth::authenticate))
        .route("/api/v1/validators", get(api::validators::list_validators))
        .route(
            "/api/v1/validators",
            post(api::validators::register_validator),
        )
        .route(
            "/api/v1/validators/:hotkey",
            get(api::validators::get_validator),
        )
        .route(
            "/api/v1/validators/heartbeat",
            post(api::validators::heartbeat),
        )
        .route(
            "/api/v1/validators/whitelist",
            get(api::validators::get_whitelisted_validators),
        )
        .route(
            "/api/v1/network/state",
            get(api::challenges::get_network_state),
        )
        // === CHALLENGES MANAGEMENT ===
        .route("/api/v1/challenges", get(list_challenges))
        .route("/api/v1/challenges", post(register_challenge))
        .route("/api/v1/challenges/:id", get(get_challenge))
        .route("/api/v1/challenges/:id/start", post(start_challenge))
        .route("/api/v1/challenges/:id/stop", post(stop_challenge))
        // === DYNAMIC CHALLENGE ROUTING ===
        .route("/api/v1/challenges/:id/*path", any(proxy_to_challenge))
        // === DATA API (with Claim/Lease) ===
        .route("/api/v1/data/tasks", get(data_api::list_tasks))
        .route("/api/v1/data/tasks/claim", post(data_api::claim_task))
        .route(
            "/api/v1/data/tasks/:task_id/renew",
            post(data_api::renew_task),
        )
        .route("/api/v1/data/tasks/:task_id/ack", post(data_api::ack_task))
        .route(
            "/api/v1/data/tasks/:task_id/fail",
            post(data_api::fail_task),
        )
        .route("/api/v1/data/results", post(data_api::write_result))
        .route(
            "/api/v1/data/results/:agent_hash",
            get(data_api::get_results),
        )
        .route("/api/v1/data/snapshot", get(data_api::get_snapshot))
        // === BRIDGE TO CHALLENGES (generic proxy) ===
        // Usage: /api/v1/bridge/{challenge_name}/{path}
        // Example: /api/v1/bridge/term-challenge/submit
        .route("/api/v1/bridge", get(api::bridge::list_bridges))
        .route(
            "/api/v1/bridge/:challenge/*path",
            any(api::bridge::bridge_to_challenge),
        )
        // === SUBMISSIONS & EVALUATIONS (deprecated - use /api/v1/submit) ===
        .route(
            "/api/v1/submissions",
            get(api::submissions::list_submissions),
        )
        .route("/api/v1/submissions", post(api::submissions::submit_agent))
        .route(
            "/api/v1/submissions/:id",
            get(api::submissions::get_submission),
        )
        .route(
            "/api/v1/submissions/:id/source",
            get(api::submissions::get_submission_source),
        )
        .route(
            "/api/v1/evaluations",
            post(api::evaluations::submit_evaluation),
        )
        .route(
            "/api/v1/evaluations/:agent_hash",
            get(api::evaluations::get_evaluations),
        )
        .route(
            "/api/v1/leaderboard",
            get(api::leaderboard::get_leaderboard),
        )
        .route(
            "/api/v1/leaderboard/:agent_hash",
            get(api::leaderboard::get_agent_rank),
        )
        // === JOB QUEUE (validators claim and complete jobs) ===
        .route("/api/v1/jobs/claim", post(api::jobs::claim_job))
        .route(
            "/api/v1/jobs/:job_id/progress",
            post(api::jobs::report_progress),
        )
        .route(
            "/api/v1/jobs/:job_id/complete",
            post(api::jobs::complete_job),
        )
        // === CENTRALIZED LLM PROXY ===
        .route("/api/v1/llm/chat", post(api::llm::chat))
        // === CHALLENGE EVENTS (broadcast to validators) ===
        .route(
            "/api/v1/events/broadcast",
            post(api::events::broadcast_event),
        )
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("");
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║  Server ready at http://{}                          ║",
        addr
    );
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Challenges:    /api/v1/challenges                          ║");
    info!("║  Challenge API: /api/v1/challenges/{{id}}/*                   ║");
    info!("║  Data API:      /api/v1/data/{{tasks,results,snapshot}}      ║");
    info!(
        "║  WebSocket:     ws://{}/ws                          ║",
        addr
    );
    info!("╚══════════════════════════════════════════════════════════════╝");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

// ============================================================================
// CHALLENGE MANAGEMENT HANDLERS
// ============================================================================

async fn list_challenges(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<models::RegisteredChallenge>>, StatusCode> {
    let challenges = db::queries::get_challenges(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(challenges))
}

async fn get_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<models::RegisteredChallenge>, StatusCode> {
    let challenge = db::queries::get_challenge(&state.db, &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(challenge))
}

async fn register_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<models::RegisterChallengeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify owner signature
    if !api::auth::verify_signature(
        &req.owner_hotkey,
        &format!("register_challenge:{}", req.id),
        &req.signature,
    ) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid signature".to_string()));
    }

    // Verify owner
    if state.owner_hotkey.as_ref() != Some(&req.owner_hotkey) {
        return Err((StatusCode::FORBIDDEN, "Not the subnet owner".to_string()));
    }

    let challenge = models::RegisteredChallenge {
        id: req.id.clone(),
        name: req.name,
        docker_image: req.docker_image,
        mechanism_id: req.mechanism_id,
        emission_weight: req.emission_weight,
        timeout_secs: req.timeout_secs,
        cpu_cores: req.cpu_cores,
        memory_mb: req.memory_mb,
        gpu_required: req.gpu_required,
        status: "active".to_string(),
        endpoint: None,
        container_id: None,
        last_health_check: None,
        is_healthy: false,
    };

    db::queries::register_challenge(&state.db, &challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        "Challenge registered: {} ({})",
        challenge.id, challenge.docker_image
    );

    // Broadcast to all connected validators
    state
        .broadcast_event(models::WsEvent::ChallengeRegistered(
            models::ChallengeRegisteredEvent {
                id: challenge.id.clone(),
                name: challenge.name.clone(),
                docker_image: challenge.docker_image.clone(),
                mechanism_id: challenge.mechanism_id,
                emission_weight: challenge.emission_weight,
            },
        ))
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "challenge_id": req.id
    })))
}

async fn start_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<models::ChallengeActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify timestamp is recent (within 5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (now - req.timestamp).abs() > 300 {
        return Err((StatusCode::BAD_REQUEST, "Timestamp too old".to_string()));
    }

    // Verify owner signature
    let message = format!("start_challenge:{}:{}", id, req.timestamp);
    if !api::auth::verify_signature(&req.owner_hotkey, &message, &req.signature) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid signature".to_string()));
    }

    // Verify owner
    if state.owner_hotkey.as_ref() != Some(&req.owner_hotkey) {
        return Err((StatusCode::FORBIDDEN, "Not the subnet owner".to_string()));
    }

    let manager = state.challenge_manager.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Orchestrator not available".to_string(),
    ))?;

    let challenge = db::queries::get_challenge(&state.db, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    let endpoint = manager
        .start_challenge(&challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Challenge {} started by owner {}", id, req.owner_hotkey);

    // Broadcast to validators
    state
        .broadcast_event(models::WsEvent::ChallengeStarted(
            models::ChallengeStartedEvent {
                id: id.clone(),
                endpoint: endpoint.clone(),
            },
        ))
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "endpoint": endpoint
    })))
}

async fn stop_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<models::ChallengeActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify timestamp is recent (within 5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (now - req.timestamp).abs() > 300 {
        return Err((StatusCode::BAD_REQUEST, "Timestamp too old".to_string()));
    }

    // Verify owner signature
    let message = format!("stop_challenge:{}:{}", id, req.timestamp);
    if !api::auth::verify_signature(&req.owner_hotkey, &message, &req.signature) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid signature".to_string()));
    }

    // Verify owner
    if state.owner_hotkey.as_ref() != Some(&req.owner_hotkey) {
        return Err((StatusCode::FORBIDDEN, "Not the subnet owner".to_string()));
    }

    let manager = state.challenge_manager.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Orchestrator not available".to_string(),
    ))?;

    manager
        .stop_challenge(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Challenge {} stopped by owner {}", id, req.owner_hotkey);

    // Broadcast to validators
    state
        .broadcast_event(models::WsEvent::ChallengeStopped(
            models::ChallengeStoppedEvent { id: id.clone() },
        ))
        .await;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Dynamic proxy to challenge containers
async fn proxy_to_challenge(
    State(state): State<Arc<AppState>>,
    Path((id, path)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let manager = match &state.challenge_manager {
        Some(m) => m,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Orchestrator not available",
            )
                .into_response()
        }
    };

    let endpoint = match manager.get_endpoint(&id) {
        Some(e) => e,
        None => {
            return (StatusCode::NOT_FOUND, "Challenge not found or not running").into_response()
        }
    };

    let url = format!("{}/{}", endpoint, path);
    let method = request.method().clone();
    let headers = request.headers().clone();

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .unwrap();

    let mut req_builder = client.request(method, &url);
    for (key, value) in headers.iter() {
        if key != "host" {
            req_builder = req_builder.header(key, value);
        }
    }

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();

            match resp.bytes().await {
                Ok(body) => {
                    let mut response = Response::builder().status(status);
                    for (key, value) in headers.iter() {
                        response = response.header(key, value);
                    }
                    response
                        .body(Body::from(body))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(e) => {
                    error!("Failed to read response: {}", e);
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "Challenge timeout").into_response()
            } else {
                error!("Proxy error: {}", e);
                StatusCode::BAD_GATEWAY.into_response()
            }
        }
    }
}
