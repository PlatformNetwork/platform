//! Bittensor client wrapper

use crate::BittensorConfig;
use anyhow::Result;
use bittensor_rs::chain::{signer_from_seed, BittensorClient, BittensorSigner};
use bittensor_rs::metagraph::{sync_metagraph, Metagraph};
use std::collections::HashMap;
use tracing::info;

/// Wrapper around bittensor-rs client for Mini-Chain
pub struct SubtensorClient {
    config: BittensorConfig,
    client: Option<BittensorClient>,
    signer: Option<BittensorSigner>,
    metagraph: Option<Metagraph>,
    uid_overrides: HashMap<String, u16>,
}

impl SubtensorClient {
    /// Create a new client (not connected yet)
    pub fn new(config: BittensorConfig) -> Self {
        Self {
            config,
            client: None,
            signer: None,
            metagraph: None,
            uid_overrides: HashMap::new(),
        }
    }

    /// Connect to Subtensor
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to Subtensor: {}", self.config.endpoint);

        let client = BittensorClient::new(&self.config.endpoint).await?;
        self.client = Some(client);

        info!("Connected to Subtensor");
        Ok(())
    }

    /// Set the signer from a seed phrase or key
    pub fn set_signer(&mut self, seed: &str) -> Result<()> {
        let signer = signer_from_seed(seed)?;
        self.signer = Some(signer);
        Ok(())
    }

    /// Get the inner client
    pub fn client(&self) -> Result<&BittensorClient> {
        self.client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to Subtensor"))
    }

    /// Get the signer (returns Result)
    pub fn signer(&self) -> Result<&BittensorSigner> {
        self.signer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signer not set"))
    }

    /// Get the signer (returns Option)
    pub fn get_signer(&self) -> Option<&BittensorSigner> {
        self.signer.as_ref()
    }

    /// Get the netuid
    pub fn netuid(&self) -> u16 {
        self.config.netuid
    }

    /// Get the version key
    pub fn version_key(&self) -> u64 {
        self.config.version_key
    }

    /// Check if commit-reveal is enabled
    pub fn use_commit_reveal(&self) -> bool {
        self.config.use_commit_reveal
    }

    /// Sync and get the current metagraph
    pub async fn sync_metagraph(&mut self) -> Result<&Metagraph> {
        let client = self.client()?;
        let metagraph = sync_metagraph(client, self.config.netuid).await?;
        self.metagraph = Some(metagraph);
        Ok(self.metagraph.as_ref().unwrap())
    }

    /// Get cached metagraph (sync first if needed)
    pub fn metagraph(&self) -> Option<&Metagraph> {
        self.metagraph.as_ref()
    }

    /// Get UID for a hotkey from cached metagraph
    pub fn get_uid_for_hotkey(&self, hotkey: &str) -> Option<u16> {
        if let Some(uid) = self.uid_overrides.get(hotkey) {
            return Some(*uid);
        }
        self.lookup_uid_in_metagraph(hotkey)
    }

    /// Get UIDs for a list of hotkeys
    pub fn get_uids_for_hotkeys(&self, hotkeys: &[String]) -> Vec<(String, u16)> {
        let mut results = Vec::new();
        for hotkey in hotkeys {
            if let Some(uid) = self.get_uid_for_hotkey(hotkey) {
                results.push((hotkey.clone(), uid));
            }
        }
        results
    }

    fn lookup_uid_in_metagraph(&self, hotkey: &str) -> Option<u16> {
        let metagraph = self.metagraph.as_ref()?;

        use sp_core::crypto::Ss58Codec;
        let account = sp_core::crypto::AccountId32::from_ss58check(hotkey).ok()?;
        let account_bytes: &[u8; 32] = account.as_ref();

        for (uid, neuron) in &metagraph.neurons {
            let neuron_hotkey: &[u8; 32] = neuron.hotkey.as_ref();
            if neuron_hotkey == account_bytes {
                return Some(*uid as u16);
            }
        }
        None
    }

    #[cfg(test)]
    pub fn set_uid_overrides(&mut self, entries: Vec<(String, u16)>) {
        self.uid_overrides = entries.into_iter().collect();
    }

    /// Get the number of mechanisms for the subnet
    /// Returns count of mechanisms (0 to count-1 are valid IDs)
    pub async fn get_mechanism_count(&self) -> Result<u8> {
        use bittensor_rs::get_mechanism_count;
        let client = self.client()?;
        get_mechanism_count(client, self.config.netuid).await
    }

    /// Get current epoch from Bittensor
    pub async fn get_current_epoch(&self) -> Result<u64> {
        use bittensor_rs::blocks::{BlockListener, BlockListenerConfig};

        let client = self.client()?;
        let config = BlockListenerConfig {
            netuid: self.config.netuid,
            ..Default::default()
        };
        let listener = BlockListener::new(config);
        let epoch_info = listener.current_epoch_info(client).await?;
        Ok(epoch_info.epoch_number)
    }

    /// Get current epoch info including phase from Bittensor
    pub async fn get_current_epoch_info(&self) -> Result<bittensor_rs::blocks::EpochInfo> {
        use bittensor_rs::blocks::{BlockListener, BlockListenerConfig};

        let client = self.client()?;
        let config = BlockListenerConfig {
            netuid: self.config.netuid,
            ..Default::default()
        };
        let listener = BlockListener::new(config);
        listener.current_epoch_info(client).await
    }

    /// Check if currently in reveal phase
    pub async fn is_in_reveal_phase(&self) -> Result<bool> {
        use bittensor_rs::blocks::EpochPhase;
        let info = self.get_current_epoch_info().await?;
        Ok(matches!(info.phase, EpochPhase::RevealWindow))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BittensorConfig;

    #[test]
    fn test_set_signer_initializes_signer_field() {
        let mut client = SubtensorClient::new(BittensorConfig::local(33));
        client.set_signer("//Alice").expect("set signer");
        assert!(client.get_signer().is_some());
    }

    #[test]
    fn test_client_returns_error_when_not_connected() {
        let client = SubtensorClient::new(BittensorConfig::local(9));
        assert!(client.client().is_err());
        assert!(client.signer().is_err());
        assert_eq!(client.netuid(), 9);
        assert!(!client.use_commit_reveal());
    }

    #[test]
    fn test_version_key_reflects_config() {
        let config = BittensorConfig {
            endpoint: "ws://node".into(),
            netuid: 12,
            use_commit_reveal: false,
            version_key: 99,
        };
        let client = SubtensorClient::new(config.clone());
        assert_eq!(client.version_key(), 99);
        assert_eq!(client.netuid(), config.netuid);
        assert_eq!(client.use_commit_reveal(), config.use_commit_reveal);
    }

    #[test]
    fn test_get_uid_for_hotkey_uses_overrides() {
        let mut client = SubtensorClient::new(BittensorConfig::local(2));
        client.set_uid_overrides(vec![("hk-a".to_string(), 5), ("hk-b".to_string(), 7)]);

        assert_eq!(client.get_uid_for_hotkey("hk-a"), Some(5));
        assert_eq!(client.get_uid_for_hotkey("hk-b"), Some(7));
        assert!(client.get_uid_for_hotkey("missing").is_none());
    }

    #[test]
    fn test_get_uids_for_hotkeys_filters_missing() {
        let mut client = SubtensorClient::new(BittensorConfig::local(4));
        client.set_uid_overrides(vec![("hk".to_string(), 11)]);

        let pairs = client.get_uids_for_hotkeys(&vec!["hk".to_string(), "unknown".to_string()]);

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("hk".to_string(), 11));
    }
}
