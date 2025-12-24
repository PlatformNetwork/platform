//! Network node implementation

use crate::behaviour::{MiniChainBehaviour, MiniChainBehaviourEvent, SyncRequest, SyncResponse};
use futures::StreamExt;
use libp2p::{
    gossipsub, identify,
    identity::Keypair,
    mdns, noise,
    request_response::{self, ResponseChannel},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use parking_lot::RwLock;
use platform_core::SignedNetworkMessage;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Network node configuration
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Listen address
    pub listen_addr: Multiaddr,

    /// Bootstrap peers
    pub bootstrap_peers: Vec<Multiaddr>,

    /// Idle connection timeout
    pub idle_timeout: Duration,

    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,

    /// Optional seed for deterministic peer ID (32 bytes)
    /// If provided, the libp2p keypair will be derived from this seed
    /// This ensures stable peer ID across restarts
    pub identity_seed: Option<[u8; 32]>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: vec![],
            idle_timeout: Duration::from_secs(60),
            enable_mdns: false, // Disabled by default to avoid errors on special interfaces
            identity_seed: None,
        }
    }
}

/// Events emitted by the network node
#[derive(Debug)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),

    /// Peer disconnected
    PeerDisconnected(PeerId),

    /// Peer identified with hotkey (for stake validation)
    PeerIdentified {
        peer_id: PeerId,
        /// Hotkey extracted from agent_version (if present)
        hotkey: Option<String>,
        /// Full agent version string
        agent_version: String,
    },

    /// Message received from gossip
    MessageReceived { from: PeerId, data: Vec<u8> },

    /// Sync request received
    SyncRequest {
        from: PeerId,
        request: SyncRequest,
        channel: ResponseChannelWrapper,
    },
}

/// Wrapper for response channel (to make it Send)
pub struct ResponseChannelWrapper(pub ResponseChannel<SyncResponse>);

impl std::fmt::Debug for ResponseChannelWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResponseChannelWrapper(...)")
    }
}

unsafe impl Send for ResponseChannelWrapper {}
unsafe impl Sync for ResponseChannelWrapper {}

/// Network node
pub struct NetworkNode {
    /// libp2p swarm
    swarm: Swarm<MiniChainBehaviour>,

    /// Local peer ID
    local_peer_id: PeerId,

    /// Connected peers
    peers: Arc<RwLock<HashSet<PeerId>>>,

    /// Bootstrap peers to connect to
    bootstrap_peers: Vec<Multiaddr>,

    /// Bootstrap peer IDs (extracted from multiaddrs)
    bootstrap_peer_ids: HashSet<PeerId>,

    /// Whether we've ever successfully connected to a bootstrap peer
    bootstrap_connected: Arc<RwLock<bool>>,

    /// Event sender
    event_tx: mpsc::Sender<NetworkEvent>,

    /// Event receiver (to be taken by the consumer)
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
}

impl NetworkNode {
    /// Create a new network node
    pub async fn new(config: NodeConfig) -> anyhow::Result<Self> {
        Self::with_hotkey(config, None).await
    }

    /// Create a new network node with hotkey for identify protocol
    /// The hotkey is included in agent_version for stake validation
    pub async fn with_hotkey(config: NodeConfig, hotkey: Option<&str>) -> anyhow::Result<Self> {
        // Use provided seed for deterministic peer ID, or generate random
        let local_key = if let Some(seed) = config.identity_seed {
            // Derive libp2p Ed25519 keypair from seed
            let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(seed)
                .map_err(|e| anyhow::anyhow!("Invalid identity seed: {}", e))?;
            let ed25519_keypair = libp2p::identity::ed25519::Keypair::from(secret);
            Keypair::from(ed25519_keypair)
        } else {
            Keypair::generate_ed25519()
        };
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer ID: {}", local_peer_id);
        if config.identity_seed.is_some() {
            info!("Using deterministic peer ID from validator keypair");
        }
        if let Some(hk) = hotkey {
            info!(
                "Including hotkey in identify: {}...",
                &hk[..16.min(hk.len())]
            );
        }

        let behaviour = MiniChainBehaviour::with_hotkey(&local_key, config.enable_mdns, hotkey)?;

        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
            .build();

        let (event_tx, event_rx) = mpsc::channel(1000);

        // Extract peer IDs from bootstrap multiaddrs
        let bootstrap_peer_ids: HashSet<PeerId> = config
            .bootstrap_peers
            .iter()
            .filter_map(|addr| {
                addr.iter().find_map(|p| {
                    if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                        Some(peer_id)
                    } else {
                        None
                    }
                })
            })
            .collect();

        Ok(Self {
            swarm,
            local_peer_id,
            peers: Arc::new(RwLock::new(HashSet::new())),
            bootstrap_peers: config.bootstrap_peers.clone(),
            bootstrap_peer_ids,
            bootstrap_connected: Arc::new(RwLock::new(false)),
            event_tx,
            event_rx: Some(event_rx),
        })
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get connected peers
    pub fn peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().cloned().collect()
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NetworkEvent>> {
        self.event_rx.take()
    }

    /// Start listening
    pub async fn start(&mut self, config: &NodeConfig) -> anyhow::Result<()> {
        // Subscribe to gossip topic
        self.swarm.behaviour_mut().subscribe()?;

        // Start listening
        self.swarm.listen_on(config.listen_addr.clone())?;
        info!("Listening on {:?}", config.listen_addr);

        // Connect to bootstrap peers
        self.dial_bootstrap_peers();

        Ok(())
    }

    /// Dial all bootstrap peers
    pub fn dial_bootstrap_peers(&mut self) {
        for addr in self.bootstrap_peers.clone() {
            // Skip dialing ourselves (important for bootnode)
            let is_self = addr.iter().any(|p| {
                if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                    peer_id == self.local_peer_id
                } else {
                    false
                }
            });
            if is_self {
                info!("Skipping self-dial (we ARE the bootnode)");
                continue;
            }
            info!("Dialing bootstrap peer: {}", addr);
            if let Err(e) = self.swarm.dial(addr.clone()) {
                warn!("Failed to dial bootstrap peer {}: {}", addr, e);
            }
        }
    }

    /// Check if connected to any bootstrap peer
    pub fn has_bootstrap_connection(&self) -> bool {
        if self.bootstrap_peers.is_empty() {
            return true; // No bootstrap peers configured
        }
        // If we ARE the bootnode, we don't need to connect to ourselves
        if self.bootstrap_peer_ids.contains(&self.local_peer_id) {
            return true;
        }
        // Check if we're connected to at least one bootstrap peer
        let peers = self.peers.read();
        for peer in peers.iter() {
            if self.bootstrap_peer_ids.contains(peer) {
                return true;
            }
        }
        false
    }

    /// Retry connecting to bootstrap peers if not connected
    pub fn retry_bootstrap_if_needed(&mut self) {
        if self.bootstrap_peers.is_empty() {
            return; // No bootnode configured
        }

        if !self.has_bootstrap_connection() {
            info!("Not connected to bootnode, retrying in 30s...");
            self.dial_bootstrap_peers();
        }
    }

    /// Broadcast a message via gossip
    pub fn broadcast(&mut self, message: &SignedNetworkMessage) -> anyhow::Result<()> {
        let data = bincode::serialize(message)?;
        self.swarm.behaviour_mut().publish(data)?;
        debug!("Broadcast message: {:?}", message.message);
        Ok(())
    }

    /// Broadcast raw bytes via gossip (for pre-serialized messages)
    pub fn broadcast_raw(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        self.swarm.behaviour_mut().publish(data)?;
        Ok(())
    }

    /// Send a sync request to a peer
    pub fn send_sync_request(&mut self, peer: PeerId, request: SyncRequest) {
        self.swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, request);
    }

    /// Send a sync response
    pub fn send_sync_response(&mut self, channel: ResponseChannelWrapper, response: SyncResponse) {
        let _ = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_response(channel.0, response);
    }

    /// Process the next swarm event (single step)
    pub async fn process_next_event(&mut self) {
        let event = self.swarm.select_next_some().await;
        self.handle_swarm_event(event).await;
    }

    /// Run the event loop (should be spawned as a task)
    /// Includes automatic retry of bootstrap peers every 30 seconds if not connected
    pub async fn run(&mut self) {
        let mut bootstrap_retry_interval = tokio::time::interval(Duration::from_secs(30));
        bootstrap_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                _ = bootstrap_retry_interval.tick() => {
                    self.retry_bootstrap_if_needed();
                }
            }
        }
    }

    /// Handle a swarm event
    async fn handle_swarm_event(&mut self, event: SwarmEvent<MiniChainBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                let is_bootstrap = self.bootstrap_peer_ids.contains(&peer_id);
                let direction = if endpoint.is_dialer() {
                    "outbound"
                } else {
                    "inbound"
                };
                if is_bootstrap {
                    info!(
                        "Connected to bootnode: {} ({}, {} connections)",
                        peer_id, direction, num_established
                    );
                    *self.bootstrap_connected.write() = true;
                } else {
                    info!(
                        "Connected to peer: {} ({}, {} connections)",
                        peer_id, direction, num_established
                    );
                }
                self.peers.write().insert(peer_id);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerConnected(peer_id))
                    .await;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let is_bootstrap = self.bootstrap_peer_ids.contains(&peer_id);
                if is_bootstrap {
                    info!("Disconnected from bootnode: {}", peer_id);
                } else {
                    info!("Disconnected from peer: {}", peer_id);
                }
                self.peers.write().remove(&peer_id);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
            }
            SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } => {
                let is_bootstrap = self.bootstrap_peer_ids.contains(&peer_id);
                if is_bootstrap {
                    warn!(
                        "Failed to connect to bootnode {}: {} (will retry in 30s)",
                        peer_id, error
                    );
                } else {
                    warn!("Failed to connect to {}: {}", peer_id, error);
                }
            }
            SwarmEvent::OutgoingConnectionError { .. } => {}
            _ => {}
        }
    }

    async fn handle_behaviour_event(&mut self, event: MiniChainBehaviourEvent) {
        match event {
            MiniChainBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                debug!("Gossip message from {}", propagation_source);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::MessageReceived {
                        from: propagation_source,
                        data: message.data,
                    })
                    .await;
            }
            MiniChainBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                info!(
                    "Peer {} subscribed to topic: {}",
                    peer_id,
                    topic.as_str()
                );
                // NOTE: Do NOT call add_explicit_peer here!
                // Explicit peers become "direct peers" that bypass the mesh entirely.
                // Let gossipsub handle mesh formation automatically via GRAFT/PRUNE.
            }
            MiniChainBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                info!(
                    "Peer {} unsubscribed from topic: {}",
                    peer_id,
                    topic.as_str()
                );
            }
            MiniChainBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported {
                peer_id,
            }) => {
                warn!(
                    "Peer {} does not support gossipsub protocol - cannot exchange messages",
                    peer_id
                );
            }
            MiniChainBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, addr) in list {
                    info!("mDNS discovered peer: {} at {}", peer_id, addr);
                    // Just dial the peer - gossipsub will handle mesh formation
                    let _ = self.swarm.dial(addr);
                }
            }
            MiniChainBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, _) in list {
                    debug!("mDNS peer expired: {}", peer_id);
                }
            }
            MiniChainBehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
            }) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    debug!("Sync request from {}: {:?}", peer, request);
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::SyncRequest {
                            from: peer,
                            request,
                            channel: ResponseChannelWrapper(channel),
                        })
                        .await;
                }
                request_response::Message::Response { response, .. } => {
                    debug!("Sync response from {}: {:?}", peer, response);
                }
            },
            MiniChainBehaviourEvent::Identify(identify::Event::Received {
                peer_id, info, ..
            }) => {
                // Extract hotkey from agent_version if present
                // Format: "platform-validator/1.0.0/HOTKEY_HEX"
                let hotkey = info.agent_version.split('/').nth(2).map(String::from);

                info!(
                    "Identify received from {}: agent={}, hotkey={:?}",
                    peer_id,
                    info.agent_version,
                    hotkey.as_ref().map(|h| &h[..16.min(h.len())])
                );

                // Emit PeerIdentified event for stake validation
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerIdentified {
                        peer_id,
                        hotkey,
                        agent_version: info.agent_version.clone(),
                    })
                    .await;

                // NOTE: Do NOT call add_explicit_peer here!
                // Explicit peers become "direct peers" that bypass the gossipsub mesh.
                // The mesh should form automatically via the gossipsub protocol:
                // 1. Connection established -> gossipsub protocol negotiated
                // 2. SUBSCRIBE messages exchanged -> peers know each other's topics
                // 3. GRAFT/PRUNE in heartbeats -> mesh forms naturally

                // Also connect to other peers they know about through their observed addr
                // This helps with peer discovery in small networks
                for addr in info.listen_addrs {
                    // Only dial if it's a different peer and looks like a valid address
                    if !self.peers.read().contains(&peer_id) {
                        debug!("Discovered peer address via identify: {}", addr);
                    }
                }
            }
            MiniChainBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. }) => {
                debug!("Identify sent to {}", peer_id);
            }
            _ => {}
        }
    }

    /// Add a peer to connect to
    pub fn dial_peer(&mut self, addr: Multiaddr) -> anyhow::Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = NetworkNode::new(config).await;
        assert!(node.is_ok(), "Node creation failed: {:?}", node.err());
    }
}
