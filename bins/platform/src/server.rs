//! Server mode - Central Platform Server
//!
//! Runs the platform-server for challenge orchestration.
//! Only the subnet owner should run this.

use anyhow::Result;
use clap::Args;
use platform_server::orchestration::ChallengeManager;
use platform_server::state::AppState;
use platform_server::websocket::handler::ws_handler;
use platform_server::{api, challenge_proxy::ChallengeProxy, data_api, db, models, observability};
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
}

pub async fn run(args: ServerArgs) -> Result<()> {
    info!(
        "Owner hotkey: {}...",
        &args.owner_hotkey[..16.min(args.owner_hotkey.len())]
    );
    info!("Listening on: {}:{}", args.host, args.port);

    // Initialize database
    let db = db::init_db(&args.database_url).await?;
    info!("Database: platform_server");

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
    ));

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
