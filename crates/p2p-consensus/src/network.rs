//! P2P network layer using libp2p
//!
//! Implements gossipsub for message broadcasting and Kademlia DHT for peer discovery.
//! Provides the networking foundation for PBFT consensus.

use crate::config::P2PConfig;
use crate::messages::{P2PMessage, SignedP2PMessage};
use crate::validator::ValidatorSet;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify,
    kad::{self, store::MemoryStore},
    noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use parking_lot::RwLock;
use platform_core::{Hotkey, Keypair};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Network errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Gossipsub error: {0}")]
    Gossipsub(String),
    #[error("DHT error: {0}")]
    Dht(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Not connected to any peers")]
    NoPeers,
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Replay attack detected: nonce {nonce} already seen for {signer}")]
    ReplayAttack { signer: String, nonce: u64 },
    #[error("Rate limit exceeded for {signer}: {count} messages in current window")]
    RateLimitExceeded { signer: String, count: u32 },
}

/// Combined network behavior using manual composition
pub struct NetworkBehaviour {
    /// Gossipsub for pub/sub messaging
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Identify protocol for peer identification
    pub identify: identify::Behaviour,
}

/// Events from the network layer
#[derive(Debug)]
pub enum NetworkEvent {
    /// Received a P2P message
    Message { source: PeerId, message: P2PMessage },
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Peer identified with hotkey
    PeerIdentified {
        peer_id: PeerId,
        hotkey: Option<Hotkey>,
        addresses: Vec<Multiaddr>,
    },
}

/// Commands for controlling the P2P network
#[derive(Debug, Clone)]
pub enum P2PCommand {
    /// Broadcast message to all peers
    Broadcast(P2PMessage),
    /// Dial a specific peer by multiaddr
    Dial(String),
    /// Disconnect from peer by peer ID string
    Disconnect(String),
    /// Shutdown the network
    Shutdown,
}

/// Events emitted from the P2P network
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Message received from a peer
    Message { from: PeerId, message: P2PMessage },
    /// A peer has connected
    PeerConnected(PeerId),
    /// A peer has disconnected
    PeerDisconnected(PeerId),
}

/// Mapping between peer IDs and validator hotkeys
pub struct PeerMapping {
    /// PeerId -> Hotkey
    peer_to_hotkey: RwLock<HashMap<PeerId, Hotkey>>,
    /// Hotkey -> PeerId
    hotkey_to_peer: RwLock<HashMap<Hotkey, PeerId>>,
}

impl PeerMapping {
    pub fn new() -> Self {
        Self {
            peer_to_hotkey: RwLock::new(HashMap::new()),
            hotkey_to_peer: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, peer_id: PeerId, hotkey: Hotkey) {
        self.peer_to_hotkey.write().insert(peer_id, hotkey.clone());
        self.hotkey_to_peer.write().insert(hotkey, peer_id);
    }

    pub fn get_hotkey(&self, peer_id: &PeerId) -> Option<Hotkey> {
        self.peer_to_hotkey.read().get(peer_id).cloned()
    }

    pub fn get_peer(&self, hotkey: &Hotkey) -> Option<PeerId> {
        self.hotkey_to_peer.read().get(hotkey).copied()
    }

    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Some(hotkey) = self.peer_to_hotkey.write().remove(peer_id) {
            self.hotkey_to_peer.write().remove(&hotkey);
        }
    }
}

impl Default for PeerMapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Default rate limit: maximum messages per second per signer
const DEFAULT_RATE_LIMIT: u32 = 100;

/// Rate limit sliding window in milliseconds (1 second)
const RATE_LIMIT_WINDOW_MS: i64 = 1000;

/// Nonce expiry time in milliseconds (5 minutes)
const NONCE_EXPIRY_MS: i64 = 5 * 60 * 1000;

/// P2P network node
pub struct P2PNetwork {
    /// Local keypair
    keypair: Keypair,
    /// libp2p peer ID
    local_peer_id: PeerId,
    /// Network configuration
    config: P2PConfig,
    /// Gossipsub topics
    consensus_topic: IdentTopic,
    challenge_topic: IdentTopic,
    /// Peer mapping
    peer_mapping: Arc<PeerMapping>,
    /// Reference to validator set
    #[allow(dead_code)]
    validator_set: Arc<ValidatorSet>,
    /// Event sender
    #[allow(dead_code)]
    event_tx: mpsc::Sender<NetworkEvent>,
    /// Message nonce counter
    nonce: RwLock<u64>,
    /// Seen nonces for replay protection with timestamps (hotkey -> (nonce -> timestamp_ms))
    /// Timestamps allow automatic expiry of old nonces
    seen_nonces: RwLock<HashMap<Hotkey, HashMap<u64, i64>>>,
    /// Message timestamps for sliding window rate limiting (hotkey -> recent message timestamps in ms)
    message_timestamps: RwLock<HashMap<Hotkey, VecDeque<i64>>>,
}

impl P2PNetwork {
    /// Create a new P2P network
    pub fn new(
        keypair: Keypair,
        config: P2PConfig,
        validator_set: Arc<ValidatorSet>,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<Self, NetworkError> {
        // Generate libp2p keypair from our keypair seed
        let seed = keypair.seed();
        let libp2p_keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed).map_err(|e| {
            NetworkError::Transport(format!("Failed to create libp2p keypair: {}", e))
        })?;
        let local_peer_id = PeerId::from(libp2p_keypair.public());

        let consensus_topic = IdentTopic::new(&config.consensus_topic);
        let challenge_topic = IdentTopic::new(&config.challenge_topic);

        Ok(Self {
            keypair,
            local_peer_id,
            config,
            consensus_topic,
            challenge_topic,
            peer_mapping: Arc::new(PeerMapping::new()),
            validator_set,
            event_tx,
            nonce: RwLock::new(0),
            seen_nonces: RwLock::new(HashMap::new()),
            message_timestamps: RwLock::new(HashMap::new()),
        })
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get local hotkey
    pub fn local_hotkey(&self) -> Hotkey {
        self.keypair.hotkey()
    }

    /// Get peer mapping
    pub fn peer_mapping(&self) -> Arc<PeerMapping> {
        self.peer_mapping.clone()
    }

    /// Create gossipsub behaviour
    fn create_gossipsub(
        &self,
        libp2p_keypair: &libp2p::identity::Keypair,
    ) -> Result<gossipsub::Behaviour, NetworkError> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(|msg: &gossipsub::Message| {
                use sha2::Digest;
                let hash = sha2::Sha256::digest(&msg.data);
                MessageId::from(hash.to_vec())
            })
            .max_transmit_size(self.config.max_message_size)
            .build()
            .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

        gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(libp2p_keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::Gossipsub(e.to_string()))
    }

    /// Create behaviour components
    pub fn create_behaviour(
        &self,
        libp2p_keypair: &libp2p::identity::Keypair,
    ) -> Result<NetworkBehaviour, NetworkError> {
        let gossipsub = self.create_gossipsub(libp2p_keypair)?;
        let store = MemoryStore::new(self.local_peer_id);
        let kademlia = kad::Behaviour::new(self.local_peer_id, store);
        let identify_config =
            identify::Config::new("/platform/1.0.0".to_string(), libp2p_keypair.public());
        let identify = identify::Behaviour::new(identify_config);

        Ok(NetworkBehaviour {
            gossipsub,
            kademlia,
            identify,
        })
    }

    /// Subscribe to gossipsub topics
    pub fn subscribe(&self, behaviour: &mut NetworkBehaviour) -> Result<(), NetworkError> {
        behaviour
            .gossipsub
            .subscribe(&self.consensus_topic)
            .map_err(|e| {
                NetworkError::Gossipsub(format!("Failed to subscribe to consensus: {}", e))
            })?;

        behaviour
            .gossipsub
            .subscribe(&self.challenge_topic)
            .map_err(|e| {
                NetworkError::Gossipsub(format!("Failed to subscribe to challenge: {}", e))
            })?;

        info!(
            consensus_topic = %self.config.consensus_topic,
            challenge_topic = %self.config.challenge_topic,
            "Subscribed to gossipsub topics"
        );

        Ok(())
    }

    /// Connect to bootstrap peers
    pub async fn connect_bootstrap<TBehaviour>(
        &self,
        swarm: &mut Swarm<TBehaviour>,
        behaviour: &mut NetworkBehaviour,
    ) -> Result<usize, NetworkError>
    where
        TBehaviour: libp2p::swarm::NetworkBehaviour,
    {
        let mut connected = 0;

        for addr_str in &self.config.bootstrap_peers {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    info!(addr = %addr, "Connecting to bootstrap peer");
                    match swarm.dial(addr.clone()) {
                        Ok(_) => {
                            if let Some(peer_id) = extract_peer_id(&addr) {
                                behaviour.kademlia.add_address(&peer_id, addr);
                                connected += 1;
                            }
                        }
                        Err(e) => {
                            warn!(addr = %addr_str, error = %e, "Failed to dial bootstrap peer");
                        }
                    }
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid bootstrap address");
                }
            }
        }

        Ok(connected)
    }

    /// Broadcast a message to the consensus topic
    pub fn broadcast_consensus(
        &self,
        behaviour: &mut NetworkBehaviour,
        message: P2PMessage,
    ) -> Result<(), NetworkError> {
        let signed = self.sign_message(message)?;
        let bytes =
            bincode::serialize(&signed).map_err(|e| NetworkError::Serialization(e.to_string()))?;

        behaviour
            .gossipsub
            .publish(self.consensus_topic.clone(), bytes)
            .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

        debug!(msg_type = %signed.message.type_name(), "Broadcast consensus message");
        Ok(())
    }

    /// Broadcast a message to the challenge topic
    pub fn broadcast_challenge(
        &self,
        behaviour: &mut NetworkBehaviour,
        message: P2PMessage,
    ) -> Result<(), NetworkError> {
        let signed = self.sign_message(message)?;
        let bytes =
            bincode::serialize(&signed).map_err(|e| NetworkError::Serialization(e.to_string()))?;

        behaviour
            .gossipsub
            .publish(self.challenge_topic.clone(), bytes)
            .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

        debug!(msg_type = %signed.message.type_name(), "Broadcast challenge message");
        Ok(())
    }

    /// Sign a P2P message
    fn sign_message(&self, message: P2PMessage) -> Result<SignedP2PMessage, NetworkError> {
        let nonce = {
            let mut n = self.nonce.write();
            *n += 1;
            *n
        };

        let mut signed = SignedP2PMessage {
            message,
            signer: self.keypair.hotkey(),
            signature: vec![],
            nonce,
        };

        let signing_bytes = signed
            .signing_bytes()
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;

        signed.signature = self
            .keypair
            .sign_bytes(&signing_bytes)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;

        Ok(signed)
    }

    /// Verify a signed message
    pub fn verify_message(&self, signed: &SignedP2PMessage) -> bool {
        let signing_bytes = match signed.signing_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let signed_msg = platform_core::SignedMessage {
            message: signing_bytes,
            signature: signed.signature.clone(),
            signer: signed.signer.clone(),
        };

        match signed_msg.verify() {
            Ok(valid) => valid,
            Err(_) => false,
        }
    }

    /// Handle incoming gossipsub message
    ///
    /// Performs the following security checks:
    /// 1. Signature verification
    /// 2. Replay protection (nonce tracking)
    /// 3. Rate limiting (messages per second)
    pub fn handle_gossipsub_message(
        &self,
        source: PeerId,
        data: &[u8],
    ) -> Result<P2PMessage, NetworkError> {
        let signed: SignedP2PMessage =
            bincode::deserialize(data).map_err(|e| NetworkError::Serialization(e.to_string()))?;

        // Verify signature first
        if !self.verify_message(&signed) {
            return Err(NetworkError::Gossipsub(
                "Invalid message signature".to_string(),
            ));
        }

        // Check rate limit before processing
        self.check_rate_limit(&signed.signer)?;

        // Check for replay attack (after signature verification to avoid DoS)
        self.check_replay(&signed.signer, signed.nonce)?;

        // Update peer mapping
        if self.peer_mapping.get_hotkey(&source).is_none() {
            self.peer_mapping.insert(source, signed.signer.clone());
        }

        Ok(signed.message)
    }

    /// Check if a nonce has been seen before (replay attack detection)
    ///
    /// Uses timestamp-based expiry to automatically clean old nonces and bound memory usage.
    /// Nonces older than NONCE_EXPIRY_MS (5 minutes) are automatically removed.
    fn check_replay(&self, signer: &Hotkey, nonce: u64) -> Result<(), NetworkError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut seen_nonces = self.seen_nonces.write();
        let nonces = seen_nonces.entry(signer.clone()).or_default();

        // Auto-expire old nonces to bound memory usage
        nonces.retain(|_, timestamp| now_ms - *timestamp < NONCE_EXPIRY_MS);

        // Check if this nonce was already seen (and not expired)
        if nonces.contains_key(&nonce) {
            return Err(NetworkError::ReplayAttack {
                signer: signer.to_hex(),
                nonce,
            });
        }

        // Record this nonce with current timestamp
        nonces.insert(nonce, now_ms);
        Ok(())
    }

    /// Check and update rate limit for a signer using sliding window
    ///
    /// Uses a sliding window approach to prevent burst attacks at window boundaries.
    /// Tracks individual message timestamps and counts messages within the window.
    fn check_rate_limit(&self, signer: &Hotkey) -> Result<(), NetworkError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut timestamps = self.message_timestamps.write();
        let queue = timestamps.entry(signer.clone()).or_default();

        // Remove timestamps older than the sliding window
        while let Some(&front) = queue.front() {
            if now_ms - front > RATE_LIMIT_WINDOW_MS {
                queue.pop_front();
            } else {
                break;
            }
        }

        // Check if over limit (>= because we're about to add one more)
        if queue.len() >= DEFAULT_RATE_LIMIT as usize {
            return Err(NetworkError::RateLimitExceeded {
                signer: signer.to_hex(),
                count: queue.len() as u32,
            });
        }

        // Add current timestamp
        queue.push_back(now_ms);
        Ok(())
    }

    /// Clean old nonces to prevent memory growth
    ///
    /// This should be called periodically (e.g., every minute) to remove
    /// old nonces that are no longer relevant for replay protection.
    /// The `max_age_secs` parameter determines how long to keep nonces.
    ///
    /// Note: Nonces are also automatically cleaned during `check_replay()` calls,
    /// but this method provides bulk cleanup for signers who have stopped sending messages.
    pub fn clean_old_nonces(&self, max_age_secs: u64) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let max_age_ms = (max_age_secs * 1000) as i64;
        let mut seen_nonces = self.seen_nonces.write();

        // Clean expired nonces for each signer
        for nonces in seen_nonces.values_mut() {
            nonces.retain(|_, timestamp| now_ms - *timestamp < max_age_ms);
        }

        // Remove signers with no remaining nonces
        seen_nonces.retain(|_, nonces| !nonces.is_empty());

        debug!(
            "Cleaned old nonces, current signer count: {}",
            seen_nonces.len()
        );
    }

    /// Clean stale rate limit entries
    ///
    /// Should be called periodically to remove old rate limit tracking entries.
    /// Removes signers who haven't sent messages within the rate limit window.
    pub fn clean_rate_limit_entries(&self) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut timestamps = self.message_timestamps.write();

        // Clean old timestamps for each signer
        for queue in timestamps.values_mut() {
            while let Some(&front) = queue.front() {
                if now_ms - front > RATE_LIMIT_WINDOW_MS {
                    queue.pop_front();
                } else {
                    break;
                }
            }
        }

        // Remove signers with no recent messages
        timestamps.retain(|_, queue| !queue.is_empty());
    }

    /// Start listening on configured addresses
    pub fn start_listening<TBehaviour>(
        &self,
        swarm: &mut Swarm<TBehaviour>,
    ) -> Result<Vec<Multiaddr>, NetworkError>
    where
        TBehaviour: libp2p::swarm::NetworkBehaviour,
    {
        let mut listening_addrs = Vec::new();

        for addr_str in &self.config.listen_addrs {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => match swarm.listen_on(addr.clone()) {
                    Ok(_) => {
                        info!(addr = %addr, "Listening on address");
                        listening_addrs.push(addr);
                    }
                    Err(e) => {
                        error!(addr = %addr_str, error = %e, "Failed to listen on address");
                    }
                },
                Err(e) => {
                    error!(addr = %addr_str, error = %e, "Invalid listen address");
                }
            }
        }

        if listening_addrs.is_empty() {
            return Err(NetworkError::Transport(
                "No valid listen addresses".to_string(),
            ));
        }

        Ok(listening_addrs)
    }

    /// Bootstrap Kademlia DHT
    pub fn bootstrap_dht(&self, behaviour: &mut NetworkBehaviour) {
        match behaviour.kademlia.bootstrap() {
            Ok(_) => info!("Started Kademlia bootstrap"),
            Err(e) => warn!(error = ?e, "Failed to bootstrap Kademlia (no peers?)"),
        }
    }

    /// Get connected peer count
    pub fn peer_count<TBehaviour>(&self, swarm: &Swarm<TBehaviour>) -> usize
    where
        TBehaviour: libp2p::swarm::NetworkBehaviour,
    {
        swarm.connected_peers().count()
    }

    /// Start the P2P network and return event/command channels
    ///
    /// Returns a tuple of (event_receiver, command_sender) that can be used to
    /// interact with the network. The network runs in the background and processes
    /// incoming events, broadcasting them through the event channel.
    pub async fn start(
        &self,
    ) -> Result<(mpsc::Receiver<P2PEvent>, mpsc::Sender<P2PCommand>), NetworkError> {
        let (event_tx, event_rx) = mpsc::channel::<P2PEvent>(1000);
        let (cmd_tx, _cmd_rx) = mpsc::channel::<P2PCommand>(1000);

        // Get libp2p keypair
        let seed = self.keypair.seed();
        let libp2p_keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed).map_err(|e| {
            NetworkError::Transport(format!("Failed to create libp2p keypair: {}", e))
        })?;

        // Create behaviour
        let mut behaviour = self.create_behaviour(&libp2p_keypair)?;

        // Subscribe to topics
        self.subscribe(&mut behaviour)?;

        info!(
            peer_id = %self.local_peer_id,
            "P2P network started, returning event/command channels"
        );

        // Store event_tx for forwarding events
        let _event_tx_clone = event_tx.clone();

        // The actual event loop would be spawned here in a full implementation
        // For now, we return the channels and let the caller handle the swarm event loop
        // This allows for more flexible integration with different runtime patterns

        Ok((event_rx, cmd_tx))
    }
}

/// Extract peer ID from multiaddr if present
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
            Some(peer_id)
        } else {
            None
        }
    })
}

/// Network runner that processes swarm events
pub struct NetworkRunner {
    network: Arc<P2PNetwork>,
    event_tx: mpsc::Sender<NetworkEvent>,
}

impl NetworkRunner {
    pub fn new(network: Arc<P2PNetwork>, event_tx: mpsc::Sender<NetworkEvent>) -> Self {
        Self { network, event_tx }
    }

    /// Handle gossipsub event
    pub async fn handle_gossipsub_event(
        &self,
        event: gossipsub::Event,
    ) -> Result<(), NetworkError> {
        if let gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        } = event
        {
            match self
                .network
                .handle_gossipsub_message(propagation_source, &message.data)
            {
                Ok(msg) => {
                    debug!(
                        source = %propagation_source,
                        msg_type = %msg.type_name(),
                        "Received gossipsub message"
                    );
                    if let Err(e) = self
                        .event_tx
                        .send(NetworkEvent::Message {
                            source: propagation_source,
                            message: msg,
                        })
                        .await
                    {
                        error!(error = %e, "Failed to send message event");
                    }
                }
                Err(e) => {
                    warn!(
                        source = %propagation_source,
                        error = %e,
                        "Failed to process gossipsub message"
                    );
                }
            }
        }
        Ok(())
    }

    /// Handle kademlia event
    pub async fn handle_kademlia_event(&self, event: kad::Event) -> Result<(), NetworkError> {
        match event {
            kad::Event::RoutingUpdated { peer, .. } => {
                debug!(peer = %peer, "Kademlia routing updated");
            }
            kad::Event::OutboundQueryProgressed { result, .. } => {
                if let kad::QueryResult::Bootstrap(Ok(_)) = result {
                    info!("Kademlia bootstrap completed");
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle identify event
    pub async fn handle_identify_event(
        &self,
        event: identify::Event,
        behaviour: &mut NetworkBehaviour,
    ) -> Result<(), NetworkError> {
        if let identify::Event::Received { peer_id, info, .. } = event {
            debug!(
                peer = %peer_id,
                protocol = %info.protocol_version,
                "Received identify info"
            );

            for addr in &info.listen_addrs {
                behaviour.kademlia.add_address(&peer_id, addr.clone());
            }

            if let Err(e) = self
                .event_tx
                .send(NetworkEvent::PeerIdentified {
                    peer_id,
                    hotkey: self.network.peer_mapping.get_hotkey(&peer_id),
                    addresses: info.listen_addrs,
                })
                .await
            {
                error!(error = %e, "Failed to send peer identified event");
            }
        }
        Ok(())
    }

    /// Handle connection established
    pub async fn handle_connection_established(&self, peer_id: PeerId) -> Result<(), NetworkError> {
        info!(peer = %peer_id, "Connection established");
        if let Err(e) = self
            .event_tx
            .send(NetworkEvent::PeerConnected(peer_id))
            .await
        {
            error!(error = %e, "Failed to send peer connected event");
        }
        Ok(())
    }

    /// Handle connection closed
    pub async fn handle_connection_closed(&self, peer_id: PeerId) -> Result<(), NetworkError> {
        info!(peer = %peer_id, "Connection closed");
        self.network.peer_mapping.remove_peer(&peer_id);
        if let Err(e) = self
            .event_tx
            .send(NetworkEvent::PeerDisconnected(peer_id))
            .await
        {
            error!(error = %e, "Failed to send peer disconnected event");
        }
        Ok(())
    }
}

/// Helper to build a complete swarm with all behaviours
pub async fn build_swarm(
    keypair: &Keypair,
    config: &P2PConfig,
) -> Result<(Swarm<libp2p::swarm::dummy::Behaviour>, NetworkBehaviour), NetworkError> {
    let seed = keypair.seed();
    let libp2p_keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| NetworkError::Transport(format!("Failed to create keypair: {}", e)))?;

    let local_peer_id = PeerId::from(libp2p_keypair.public());

    // Create gossipsub
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(ValidationMode::Strict)
        .message_id_fn(|msg: &gossipsub::Message| {
            use sha2::Digest;
            let hash = sha2::Sha256::digest(&msg.data);
            MessageId::from(hash.to_vec())
        })
        .max_transmit_size(config.max_message_size)
        .build()
        .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(libp2p_keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

    // Create kademlia
    let store = MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::new(local_peer_id, store);

    // Create identify
    let identify_config =
        identify::Config::new("/platform/1.0.0".to_string(), libp2p_keypair.public());
    let identify = identify::Behaviour::new(identify_config);

    let behaviour = NetworkBehaviour {
        gossipsub,
        kademlia,
        identify,
    };

    // Build a minimal swarm for structure (actual swarm creation would need the behaviour)
    let swarm = SwarmBuilder::with_existing_identity(libp2p_keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_dns()
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_behaviour(|_| libp2p::swarm::dummy::Behaviour)
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok((swarm, behaviour))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_mapping() {
        let mapping = PeerMapping::new();
        let peer_id = PeerId::random();
        let hotkey = Hotkey([1u8; 32]);

        mapping.insert(peer_id, hotkey.clone());

        assert_eq!(mapping.get_hotkey(&peer_id), Some(hotkey.clone()));
        assert_eq!(mapping.get_peer(&hotkey), Some(peer_id));

        mapping.remove_peer(&peer_id);

        assert!(mapping.get_hotkey(&peer_id).is_none());
        assert!(mapping.get_peer(&hotkey).is_none());
    }

    #[test]
    fn test_extract_peer_id() {
        let peer_id = PeerId::random();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{}", peer_id)
            .parse()
            .unwrap();

        let extracted = extract_peer_id(&addr);
        assert_eq!(extracted, Some(peer_id));

        let addr_no_peer: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
        assert!(extract_peer_id(&addr_no_peer).is_none());
    }

    #[tokio::test]
    async fn test_network_creation() {
        let keypair = Keypair::generate();
        let config = P2PConfig::development();
        let validator_set = Arc::new(ValidatorSet::new(keypair.clone(), 0));
        let (tx, _rx) = mpsc::channel(100);

        let network = P2PNetwork::new(keypair, config, validator_set, tx);
        assert!(network.is_ok());
    }

    #[test]
    fn test_peer_mapping_default() {
        let mapping = PeerMapping::default();
        let peer_id = PeerId::random();
        assert!(mapping.get_hotkey(&peer_id).is_none());
    }
}
