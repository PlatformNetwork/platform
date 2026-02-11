//! Metagraph API handler
//!
//! Exposes all registered neurons (miners + validators) from the cached metagraph.

use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;
use sp_core::crypto::Ss58Codec;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct NeuronInfo {
    pub uid: u64,
    pub hotkey: String,
    pub stake: u64,
}

/// GET /api/v1/metagraph - Get all registered neurons
pub async fn get_metagraph(State(state): State<Arc<AppState>>) -> Json<Vec<NeuronInfo>> {
    let mg = state.metagraph.read();
    let neurons = match *mg {
        Some(ref metagraph) => metagraph
            .neurons
            .iter()
            .map(|(uid, neuron)| NeuronInfo {
                uid: *uid,
                hotkey: neuron.hotkey.to_ss58check(),
                stake: neuron.stake.min(u64::MAX as u128) as u64,
            })
            .collect(),
        None => vec![],
    };
    Json(neurons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neuron_info_serialize() {
        let info = NeuronInfo {
            uid: 42,
            hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            stake: 10_000_000_000_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("5GrwvaEF"));
        assert!(json.contains("10000000000000"));
    }

    #[test]
    fn test_neuron_info_empty_vec_serialize() {
        let neurons: Vec<NeuronInfo> = vec![];
        let json = serde_json::to_string(&neurons).unwrap();
        assert_eq!(json, "[]");
    }
}
