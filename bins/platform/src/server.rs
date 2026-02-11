//! Server mode - Central Platform Server
//!
//! Runs the platform-server for challenge orchestration.
//! Only the subnet owner should run this.
//!
//! Also runs the container broker for challenges to create sandboxed containers.

use anyhow::Result;
use clap::Args;
use platform_server::orchestration::ChallengeManager;
use platform_server::state::AppState;
use platform_server::websocket::handler::ws_handler;
use platform_server::{api, data_api, db, models};
use secure_container_runtime::{ContainerBroker, SecurityPolicy, WsConfig};
use std::sync::Arc;
use tracing::{error, info, warn};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Simple registration request (for dev/testing without signatures)
#[derive(Debug, Deserialize)]
struct SimpleRegisterRequest {
    id: String,
    name: String,
    docker_image: String,
    #[serde(default = "default_mechanism_id")]
    mechanism_id: u8,
    #[serde(default = "default_emission_weight")]
    emission_weight: f64,
}

fn default_mechanism_id() -> u8 {
    1
}
fn default_emission_weight() -> f64 {
    1.0
}

/// Default owner hotkey (Platform Network subnet owner)
const DEFAULT_OWNER_HOTKEY: &str = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At";

#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Server port
    #[arg(short, long, default_value = "8080", env = "PORT")]
    pub port: u16,

    /// Server host
    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    pub host: String,

    /// Container broker WebSocket port (for challenges to create containers)
    #[arg(long, env = "BROKER_WS_PORT", default_value = "8090")]
    pub broker_port: u16,

    /// Owner hotkey (subnet owner SS58 address)
    #[arg(long, env = "OWNER_HOTKEY", default_value = DEFAULT_OWNER_HOTKEY)]
    pub owner_hotkey: String,

    /// PostgreSQL base URL (without database name)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://postgres:postgres@localhost:5432"
    )]
    pub database_url: String,

    /// Subtensor WebSocket endpoint
    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    pub subtensor_endpoint: String,

    /// Subnet UID for metagraph sync
    #[arg(long, env = "NETUID", default_value = "100")]
    pub netuid: u16,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    info!(
        "Owner hotkey: {}...",
        &args.owner_hotkey[..16.min(args.owner_hotkey.len())]
    );
    info!("Listening on: {}:{}", args.host, args.port);
    info!("Container broker on port: {}", args.broker_port);

    // Start container broker for challenges
    let broker_port = args.broker_port;
    tokio::spawn(async move {
        if let Err(e) = start_container_broker(broker_port).await {
            error!("Container broker failed: {}", e);
        }
    });

    // Initialize database
    let db = db::init_db(&args.database_url).await?;
    info!("Database: platform_server");

    // Sync metagraph and fetch tempo BEFORE accepting connections (blocking)
    info!("Syncing metagraph (netuid={})...", args.netuid);
    let (metagraph, tempo) =
        match platform_bittensor::BittensorClient::new(&args.subtensor_endpoint).await {
            Ok(client) => {
                // Fetch tempo from chain
                let tempo = match platform_bittensor::get_tempo(&client, args.netuid).await {
                    Ok(t) => {
                        info!("Tempo fetched from chain: {}", t);
                        t as u64
                    }
                    Err(e) => {
                        warn!("Failed to fetch tempo: {} (using default 360)", e);
                        360u64
                    }
                };

                // Sync metagraph
                let metagraph = match platform_bittensor::sync_metagraph(&client, args.netuid).await
                {
                    Ok(mg) => {
                        info!("Metagraph synced: {} neurons", mg.n);
                        Some(mg)
                    }
                    Err(e) => {
                        warn!(
                            "Metagraph sync failed: {} (validators will have stake=0)",
                            e
                        );
                        None
                    }
                };

                (metagraph, tempo)
            }
            Err(e) => {
                warn!(
                    "Could not connect to subtensor: {} (validators will have stake=0, tempo=360)",
                    e
                );
                (None, 360u64)
            }
        };

    // Initialize challenge orchestrator
    info!("Initializing Challenge Orchestrator...");
    let challenge_manager = match ChallengeManager::new(db.clone()).await {
        Ok(cm) => {
            if let Err(e) = cm.start_all().await {
                warn!("Some challenges failed to start: {}", e);
            }
            Some(Arc::new(cm))
        }
        Err(e) => {
            warn!("Challenge orchestrator disabled: {}", e);
            warn!("(Docker may not be available)");
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

    // Set cached tempo from Bittensor
    state.set_tempo(tempo);
    info!("Tempo cached: {} blocks per epoch", tempo);

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ws", get(ws_handler))
        // Control Plane API
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
        // Challenge Management
        .route("/api/v1/challenges", get(list_challenges))
        .route("/api/v1/challenges", post(register_challenge))
        .route("/api/v1/challenges/:id", get(get_challenge))
        .route("/api/v1/challenges/:id/start", post(start_challenge))
        .route("/api/v1/challenges/:id/stop", post(stop_challenge))
        .route("/api/v1/challenges/:id/*path", any(proxy_to_challenge))
        // Data API
        .route("/api/v1/data/tasks/claim", post(data_api::claim_task))
        .route("/api/v1/data/tasks/renew", post(data_api::renew_task))
        .route("/api/v1/data/tasks/ack", post(data_api::ack_task))
        .route("/api/v1/data/tasks/fail", post(data_api::fail_task))
        .route("/api/v1/data/results", post(data_api::write_result))
        .route("/api/v1/data/results", get(data_api::get_results))
        .route("/api/v1/data/snapshot", get(data_api::get_snapshot))
        // Bridge API - Generic proxy to challenge containers
        .route("/api/v1/bridge", get(api::bridge::list_bridges))
        .route(
            "/api/v1/bridge/:challenge/*path",
            any(api::bridge::bridge_to_challenge),
        )
        // Events API - Broadcast to validators (requires BROADCAST_SECRET)
        .route(
            "/api/v1/events/broadcast",
            post(api::events::broadcast_event),
        )
        // Submissions API
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
        // Evaluations API
        .route(
            "/api/v1/evaluations",
            post(api::evaluations::submit_evaluation),
        )
        .route(
            "/api/v1/evaluations",
            get(api::evaluations::get_evaluations),
        )
        // Metagraph API
        .route("/api/v1/metagraph", get(api::metagraph::get_metagraph))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║  Server ready at http://{}:{}                          ║",
        args.host, args.port
    );
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Challenges:    /api/v1/challenges                          ║");
    info!("║  Challenge API: /api/v1/challenges/{{id}}/*                   ║");
    info!("║  Bridge API:    /api/v1/bridge/{{challenge}}/*                ║");
    info!("║  Data API:      /api/v1/data/{{tasks,results,snapshot}}      ║");
    info!(
        "║  WebSocket:     ws://{}:{}                             ║",
        args.host, args.port
    );
    info!("╚══════════════════════════════════════════════════════════════╝");

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", args.host, args.port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn list_challenges(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<models::RegisteredChallenge>>, StatusCode> {
    db::queries::get_challenges(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn get_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<models::RegisteredChallenge>, StatusCode> {
    db::queries::get_challenge(&state.db, &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn register_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SimpleRegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut challenge = models::RegisteredChallenge::new(&req.id, &req.name, &req.docker_image);
    challenge.mechanism_id = req.mechanism_id;
    challenge.emission_weight = req.emission_weight;

    db::queries::register_challenge(&state.db, &challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        "Challenge registered: {} ({}) mechanism={}",
        challenge.id, challenge.docker_image, challenge.mechanism_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "challenge_id": challenge.id,
        "mechanism_id": challenge.mechanism_id
    })))
}

async fn start_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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

    info!("Challenge {} started at {}", id, endpoint);

    // Broadcast to all validators so they start their local containers
    state
        .broadcast_event(models::WsEvent::ChallengeStarted(
            models::ChallengeStartedEvent {
                id: id.clone(),
                endpoint: endpoint.clone(),
                docker_image: challenge.docker_image.clone(),
                mechanism_id: challenge.mechanism_id as u8,
                emission_weight: challenge.emission_weight,
                timeout_secs: 3600,
                cpu_cores: 2.0,
                memory_mb: 4096,
                gpu_required: false,
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let manager = state.challenge_manager.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Orchestrator not available".to_string(),
    ))?;

    manager
        .stop_challenge(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Challenge {} stopped", id);

    // Broadcast to all validators so they stop their local containers
    state
        .broadcast_event(models::WsEvent::ChallengeStopped(
            models::ChallengeStoppedEvent { id: id.clone() },
        ))
        .await;

    Ok(Json(serde_json::json!({
        "success": true
    })))
}

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
            error!("Proxy error: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Start the container broker WebSocket server
///
/// This allows challenges to create sandboxed containers without direct Docker access.
async fn start_container_broker(port: u16) -> Result<()> {
    info!("Starting container broker on port {}...", port);

    // Use development policy if BROKER_DEV_MODE is set, otherwise strict
    let policy = if std::env::var("BROKER_DEV_MODE").is_ok() {
        info!("Container broker using development security policy");
        SecurityPolicy::development()
    } else {
        info!("Container broker using default security policy");
        SecurityPolicy::default()
    };

    let broker = Arc::new(ContainerBroker::with_policy(policy).await?);

    info!("Container broker security policies:");
    info!("  - Only whitelisted images allowed");
    info!("  - Non-privileged containers only");
    info!("  - Docker socket mounting blocked");
    info!("  - Resource limits enforced");

    // WebSocket config with JWT auth
    let jwt_secret = std::env::var("BROKER_JWT_SECRET").ok();

    let ws_config = WsConfig {
        bind_addr: format!("0.0.0.0:{}", port),
        jwt_secret,
        allowed_challenges: vec![], // Allow all challenges
        max_connections_per_challenge: 10,
    };

    info!(
        "Container broker WebSocket listening on {}",
        ws_config.bind_addr
    );

    // Run the WebSocket server (this blocks)
    secure_container_runtime::run_ws_server(broker, ws_config).await?;

    Ok(())
}
