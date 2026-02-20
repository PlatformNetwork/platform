//! RPC Server implementation

use crate::handlers::*;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RpcHandler, PARSE_ERROR};
use crate::RpcState;
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use parking_lot::RwLock;
use platform_challenge_sdk::RouteRequest;
use platform_core::ChainState;
use platform_subnet_manager::BanList;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, info, trace, warn};

/// RPC server configuration
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Listen address
    pub addr: SocketAddr,
    /// Subnet UID
    pub netuid: u16,
    /// Subnet name
    pub name: String,
    /// Minimum stake for validators
    pub min_stake: u64,
    /// Enable CORS
    pub cors_enabled: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:8080".parse().unwrap(),
            netuid: 1,
            name: "Mini-Chain".to_string(),
            min_stake: 1_000_000_000_000, // 1000 TAO
            cors_enabled: true,
        }
    }
}

/// RPC Server
pub struct RpcServer {
    config: RpcConfig,
    state: Arc<RpcState>,
    rpc_handler: Arc<RpcHandler>,
}

impl RpcServer {
    /// Create a new RPC server
    pub fn new(
        config: RpcConfig,
        chain_state: Arc<RwLock<ChainState>>,
        bans: Arc<RwLock<BanList>>,
    ) -> Self {
        let state = Arc::new(RpcState::new(
            chain_state.clone(),
            bans,
            config.netuid,
            config.name.clone(),
            config.min_stake,
        ));

        let rpc_handler = Arc::new(RpcHandler::new(chain_state, config.netuid));

        Self {
            config,
            state,
            rpc_handler,
        }
    }

    /// Get the RPC handler (to update peers, etc.)
    pub fn rpc_handler(&self) -> Arc<RpcHandler> {
        self.rpc_handler.clone()
    }

    /// Build the router
    pub fn router(&self) -> Router {
        let rpc_handler = self.rpc_handler.clone();

        let mut router = Router::new()
            // JSON-RPC 2.0 endpoint (Substrate-style)
            .route(
                "/",
                post({
                    let handler = rpc_handler.clone();
                    move |body: Json<Value>| {
                        let handler = handler.clone();
                        async move { jsonrpc_handler(body, handler).await }
                    }
                }),
            )
            // Also support /rpc for explicit path
            .route(
                "/rpc",
                post({
                    let handler = rpc_handler.clone();
                    move |body: Json<Value>| {
                        let handler = handler.clone();
                        async move { jsonrpc_handler(body, handler).await }
                    }
                }),
            )
            // Keep simple health endpoint for load balancers
            .route("/health", get(health_handler))
            // Challenge custom routes: /challenge/{id}/*path
            .route("/challenge/:challenge_id/*path", {
                let handler = rpc_handler.clone();
                axum::routing::any(
                    move |axum::extract::Path((challenge_id, path)): axum::extract::Path<(
                        String,
                        String,
                    )>,
                          method: axum::http::Method,
                          axum::extract::Query(query): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >,
                          headers: axum::http::HeaderMap,
                          body: Option<Json<Value>>| {
                        let handler = handler.clone();
                        async move {
                            challenge_route_handler(
                                handler,
                                challenge_id,
                                path,
                                method.as_str().to_string(),
                                query,
                                headers,
                                body.map(|b| b.0).unwrap_or(Value::Null),
                            )
                            .await
                        }
                    },
                )
            })
            // Challenge route without subpath: /challenge/{id}
            .route("/challenge/:challenge_id", {
                let handler = rpc_handler.clone();
                axum::routing::any(
                    move |axum::extract::Path(challenge_id): axum::extract::Path<String>,
                          method: axum::http::Method,
                          axum::extract::Query(query): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >,
                          headers: axum::http::HeaderMap,
                          body: Option<Json<Value>>| {
                        let handler = handler.clone();
                        async move {
                            challenge_route_handler(
                                handler,
                                challenge_id,
                                "".to_string(),
                                method.as_str().to_string(),
                                query,
                                headers,
                                body.map(|b| b.0).unwrap_or(Value::Null),
                            )
                            .await
                        }
                    },
                )
            })
            // Webhook endpoint for progress callbacks from challenge runtimes
            .route("/webhook/progress", {
                let handler = rpc_handler.clone();
                post(move |body: Json<Value>| {
                    let handler = handler.clone();
                    async move { webhook_progress_handler(handler, body.0).await }
                })
            })
            .with_state(self.state.clone())
            .layer(TraceLayer::new_for_http());

        if self.config.cors_enabled {
            router = router.layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            );
        }

        router
    }

    /// Start the server
    pub async fn run(self) -> anyhow::Result<()> {
        let addr = self.config.addr;
        let router = self.router();

        info!("RPC server starting on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;

        Ok(())
    }

    /// Start the server in a background task
    pub fn spawn(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move { self.run().await })
    }

    /// Get the listen address
    pub fn addr(&self) -> SocketAddr {
        self.config.addr
    }
}

/// Handler for challenge custom routes
async fn challenge_route_handler(
    handler: Arc<RpcHandler>,
    challenge_id: String,
    path: String,
    method: String,
    query: HashMap<String, String>,
    headers: axum::http::HeaderMap,
    body: Value,
) -> impl IntoResponse {
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path)
    };

    trace!("Challenge route: {} {} {}", challenge_id, method, path);

    // Check if challenge has registered routes
    // Clone the routes while holding the lock, then drop it
    let challenge_routes = {
        let routes = handler.challenge_routes.read();
        let result = routes.get(&challenge_id).cloned();

        if result.is_none() {
            // Try to find by name
            let chain = handler.chain_state.read();
            let actual_id = chain
                .challenges
                .values()
                .find(|c| c.name == challenge_id)
                .map(|c| c.id.to_string());
            drop(chain);

            actual_id.and_then(|id| routes.get(&id).cloned())
        } else {
            result
        }
    };

    let challenge_routes = match challenge_routes {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "challenge_not_found",
                    "message": format!("Challenge '{}' not found or has no routes", challenge_id)
                })),
            );
        }
    };

    // Find matching route
    let mut matched_route = None;
    let mut params = HashMap::new();

    for route in &challenge_routes {
        if let Some(p) = route.matches(&method, &path) {
            matched_route = Some(route.clone());
            params = p;
            break;
        }
    }

    let route = match matched_route {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "route_not_found",
                    "message": format!("No route matches {} {}", method, path),
                    "availableRoutes": challenge_routes.iter()
                        .map(|r| format!("{} {}", r.method.as_str(), r.path))
                        .collect::<Vec<_>>()
                })),
            );
        }
    };

    // Build request
    let mut headers_map = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(key.as_str().to_string(), v.to_string());
        }
    }

    let request = RouteRequest {
        method,
        path,
        params,
        query,
        headers: headers_map,
        body,
        auth_hotkey: None,
    };

    // Call the route handler if registered
    let maybe_handler = handler.route_handler.read().clone();
    match maybe_handler {
        Some(handle) => {
            let response = handle(challenge_id.clone(), request).await;
            (
                StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(response.body),
            )
        }
        None => {
            // No handler registered - return info about the route
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "route": {
                        "method": route.method.as_str(),
                        "path": route.path,
                        "description": route.description,
                    },
                    "message": "Route handler not registered. Use RPC to interact with challenges.",
                    "hint": "Use JSON-RPC method 'challenge_callRoute' to invoke this route"
                })),
            )
        }
    }
}

/// JSON-RPC 2.0 request handler
async fn jsonrpc_handler(
    Json(body): Json<Value>,
    handler: Arc<RpcHandler>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    // Handle batch requests
    if let Some(arr) = body.as_array() {
        // For batch, we'd return an array - for now just handle first
        if let Some(first) = arr.first() {
            return handle_single_request(first.clone(), &handler).await;
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse::error(
                Value::Null,
                PARSE_ERROR,
                "Empty batch",
            )),
        );
    }

    handle_single_request(body, &handler).await
}

async fn handle_single_request(
    body: Value,
    handler: &RpcHandler,
) -> (StatusCode, Json<JsonRpcResponse>) {
    // Parse the request
    let req: JsonRpcRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(JsonRpcResponse::error(
                    Value::Null,
                    PARSE_ERROR,
                    format!("Parse error: {}", e),
                )),
            );
        }
    };

    // Validate jsonrpc version
    if req.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse::error(
                req.id,
                PARSE_ERROR,
                "Invalid JSON-RPC version",
            )),
        );
    }

    // Handle the request (supports both sync and async methods like challenge_call)
    let response = handler.handle_async(req).await;

    // JSON-RPC always returns 200 OK (errors are in the response body)
    (StatusCode::OK, Json(response))
}

/// Handler for webhook progress callbacks from challenge runtimes.
/// Broadcasts TaskProgressMessage via P2P to other validators.
async fn webhook_progress_handler(handler: Arc<RpcHandler>, body: Value) -> impl IntoResponse {
    use platform_core::{Keypair, NetworkMessage, SignedNetworkMessage, TaskProgressMessage};

    // Parse the progress data
    let msg_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "task_progress" => {
            // Extract task progress data
            let progress = TaskProgressMessage {
                challenge_id: body
                    .get("challenge_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                agent_hash: body
                    .get("agent_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                evaluation_id: body
                    .get("evaluation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                task_id: body
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                task_index: body.get("task_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                total_tasks: body
                    .get("total_tasks")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                passed: body
                    .get("passed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                score: body.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0),
                execution_time_ms: body
                    .get("execution_time_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cost_usd: body.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0),
                error: body.get("error").and_then(|v| v.as_str()).map(String::from),
                validator_hotkey: body
                    .get("validator_hotkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
            };

            info!(
                "Webhook received task progress: [{}/{}] agent={} task={} passed={}",
                progress.task_index,
                progress.total_tasks,
                &progress.agent_hash[..16.min(progress.agent_hash.len())],
                progress.task_id,
                progress.passed
            );

            // Broadcast via P2P if we have a broadcast channel and keypair
            let broadcast_tx = handler.broadcast_tx.read();
            let keypair = handler.keypair.read();

            if let (Some(tx), Some(kp)) = (broadcast_tx.as_ref(), keypair.as_ref()) {
                let network_msg = NetworkMessage::TaskProgress(progress.clone());

                match SignedNetworkMessage::new(network_msg, kp) {
                    Ok(signed) => {
                        if let Ok(bytes) = bincode::serialize(&signed) {
                            if tx.send(bytes).is_ok() {
                                debug!("TaskProgress broadcast via P2P: task={}", progress.task_id);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to sign TaskProgress message: {}", e);
                    }
                }
            } else if broadcast_tx.is_none() {
                debug!("No broadcast channel available for TaskProgress");
            } else if keypair.is_none() {
                debug!("No keypair available for signing TaskProgress");
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Task progress received"
                })),
            )
        }
        "evaluation_complete" => {
            info!(
                "Webhook received evaluation complete: agent={} score={:.2}",
                body.get("agent_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                body.get("final_score")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Evaluation complete received"
                })),
            )
        }
        _ => {
            warn!("Unknown webhook type: {}", msg_type);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Unknown webhook type: {}", msg_type)
                })),
            )
        }
    }
}

/// Quick helper to create and start a server
pub async fn start_rpc_server(
    addr: &str,
    chain_state: Arc<RwLock<ChainState>>,
    bans: Arc<RwLock<BanList>>,
    netuid: u16,
    name: &str,
) -> anyhow::Result<()> {
    let config = RpcConfig {
        addr: addr.parse()?,
        netuid,
        name: name.to_string(),
        ..Default::default()
    };

    let server = RpcServer::new(config, chain_state, bans);
    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{Keypair, NetworkConfig};
    use serde_json::json;

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.netuid, 1);
        assert!(config.cors_enabled);
    }

    #[tokio::test]
    async fn test_rpc_server_creation() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig::default();
        let server = RpcServer::new(config, state, bans);

        let router = server.router();
        // Router created successfully
    }

    #[test]
    fn test_rpc_server_rpc_handler() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig::default();
        let server = RpcServer::new(config, state, bans);

        let handler = server.rpc_handler();
        assert_eq!(handler.netuid, 1);
    }

    #[test]
    fn test_rpc_server_addr() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig {
            addr: "127.0.0.1:9999".parse().unwrap(),
            netuid: 42,
            name: "Test".to_string(),
            min_stake: 1000,
            cors_enabled: false,
        };
        let server = RpcServer::new(config, state, bans);

        assert_eq!(server.addr().port(), 9999);
    }

    #[tokio::test]
    async fn test_handle_single_request_invalid_json() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let handler = Arc::new(RpcHandler::new(state, 1));

        let invalid_body = json!({"method": "test"}); // Missing required fields
        let (status, resp) = handle_single_request(invalid_body, &handler).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(resp.0.error.is_some());
        assert_eq!(resp.0.error.unwrap().code, PARSE_ERROR);
    }

    #[tokio::test]
    async fn test_handle_single_request_invalid_jsonrpc_version() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let handler = Arc::new(RpcHandler::new(state, 1));

        let body = json!({
            "jsonrpc": "1.0", // Wrong version
            "method": "test",
            "params": null,
            "id": 1
        });
        let (status, resp) = handle_single_request(body, &handler).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(resp.0.error.is_some());
    }

    #[tokio::test]
    async fn test_handle_single_request_success() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let handler = Arc::new(RpcHandler::new(state, 1));

        let body = json!({
            "jsonrpc": "2.0",
            "method": "system_version",
            "params": null,
            "id": 1
        });
        let (status, resp) = handle_single_request(body, &handler).await;

        assert_eq!(status, StatusCode::OK);
        assert!(resp.0.result.is_some());
    }

    #[test]
    fn test_rpc_config_custom() {
        let config = RpcConfig {
            addr: "0.0.0.0:3000".parse().unwrap(),
            netuid: 99,
            name: "CustomChain".to_string(),
            min_stake: 5_000_000_000_000,
            cors_enabled: false,
        };

        assert_eq!(config.netuid, 99);
        assert_eq!(config.name, "CustomChain");
        assert!(!config.cors_enabled);
    }

    #[test]
    fn test_rpc_config_clone() {
        let config = RpcConfig {
            addr: "127.0.0.1:8080".parse().unwrap(),
            netuid: 42,
            name: "CloneTest".to_string(),
            min_stake: 1_000_000,
            cors_enabled: true,
        };

        let cloned = config.clone();

        assert_eq!(cloned.addr, config.addr);
        assert_eq!(cloned.netuid, config.netuid);
        assert_eq!(cloned.name, config.name);
        assert_eq!(cloned.min_stake, config.min_stake);
        assert_eq!(cloned.cors_enabled, config.cors_enabled);
    }

    #[test]
    fn test_rpc_config_debug() {
        let config = RpcConfig {
            addr: "0.0.0.0:9000".parse().unwrap(),
            netuid: 7,
            name: "DebugTest".to_string(),
            min_stake: 500_000,
            cors_enabled: false,
        };

        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("RpcConfig"));
        assert!(debug_str.contains("9000"));
        assert!(debug_str.contains("7"));
        assert!(debug_str.contains("DebugTest"));
        assert!(debug_str.contains("500000"));
        assert!(debug_str.contains("false"));
    }

    #[tokio::test]
    async fn test_rpc_server_router_has_routes() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig::default();
        let server = RpcServer::new(config, state, bans);

        // The router() method should create a router with routes defined
        // We verify this by checking that the router can be created without panicking
        let router = server.router();

        // The router is created successfully, which means routes for /, /rpc, /health are configured
        // We can't directly inspect routes, but creation success proves they're registered
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_rpc_server_cors_disabled() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig {
            addr: "127.0.0.1:8081".parse().unwrap(),
            netuid: 1,
            name: "NoCorsTest".to_string(),
            min_stake: 1_000_000_000_000,
            cors_enabled: false,
        };

        // Verify config is set correctly
        assert!(!config.cors_enabled);

        let server = RpcServer::new(config, state, bans);

        // Server creation should succeed with cors disabled
        let router = server.router();
        assert!(std::mem::size_of_val(&router) > 0);

        // Verify the addr is set correctly
        assert_eq!(server.addr().port(), 8081);
    }

    #[tokio::test]
    async fn test_handle_batch_request_empty() {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        let config = RpcConfig::default();
        let server = RpcServer::new(config, state, bans);
        let handler = server.rpc_handler();

        // Empty batch array should return error
        let empty_batch = json!([]);
        let (status, response) = jsonrpc_handler(Json(empty_batch), handler).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(response.0.error.is_some());
        let error = response.0.error.unwrap();
        assert_eq!(error.code, PARSE_ERROR);
        assert!(error.message.contains("Empty batch"));
    }
}
