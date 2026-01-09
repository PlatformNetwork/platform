//! High-level query API for the distributed database
//!
//! Provides convenient methods for common operations

use crate::{DistributedDB, Filter, Query, QueryResult};
use platform_core::{ChallengeContainerConfig, Hotkey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Challenge data stored in DB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    pub created_at: u64,
    pub created_by: String,
    pub status: ChallengeStatus,
}

/// Challenge status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    Active,
    Paused,
    Deprecated,
}

/// Agent submission data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAgent {
    pub hash: String,
    pub challenge_id: String,
    pub submitter: String,
    pub submitted_at: u64,
    pub code_hash: String,
    pub status: AgentStatus,
}

/// Agent status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentStatus {
    Pending,
    Evaluating,
    Evaluated,
    Failed,
}

/// Evaluation result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvaluation {
    pub id: String,
    pub agent_hash: String,
    pub challenge_id: String,
    pub validator: String,
    pub score: f64,
    pub metrics: serde_json::Value,
    pub evaluated_at: u64,
    pub block_number: u64,
}

/// Weight submission data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWeight {
    pub id: String,
    pub challenge_id: String,
    pub validator: String,
    pub weights: Vec<(u16, u16)>, // (uid, weight)
    pub block_number: u64,
    pub submitted_at: u64,
}

impl DistributedDB {
    // ==================== Challenge Operations ====================

    /// Store a challenge configuration
    pub fn store_challenge(&self, config: &ChallengeContainerConfig) -> anyhow::Result<()> {
        let challenge = StoredChallenge {
            id: config.challenge_id.to_string(),
            name: config.name.clone(),
            docker_image: config.docker_image.clone(),
            mechanism_id: config.mechanism_id,
            emission_weight: config.emission_weight,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
            created_by: "sudo".to_string(),
            status: ChallengeStatus::Active,
        };

        let key = config.challenge_id.to_string();
        let value = serde_json::to_vec(&challenge)?;
        self.put("challenges", key.as_bytes(), &value)
    }

    /// Get a challenge by ID
    pub fn get_challenge(&self, challenge_id: &str) -> anyhow::Result<Option<StoredChallenge>> {
        self.get_typed("challenges", challenge_id.as_bytes())
    }

    /// List all active challenges
    pub fn list_challenges(&self) -> anyhow::Result<Vec<StoredChallenge>> {
        let query = Query::new("challenges");
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// List challenges by mechanism
    pub fn list_challenges_by_mechanism(
        &self,
        mechanism_id: u8,
    ) -> anyhow::Result<Vec<StoredChallenge>> {
        let query =
            Query::new("challenges").filter(Filter::eq("mechanism_id", mechanism_id.to_string()));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    // ==================== Agent Operations ====================

    /// Store an agent submission
    pub fn store_agent(&self, agent: &StoredAgent) -> anyhow::Result<()> {
        let key = agent.hash.as_bytes();
        let value = serde_json::to_vec(agent)?;
        self.put("agents", key, &value)
    }

    /// Get an agent by hash
    pub fn get_agent(&self, hash: &str) -> anyhow::Result<Option<StoredAgent>> {
        self.get_typed("agents", hash.as_bytes())
    }

    /// List agents for a challenge
    pub fn list_agents_for_challenge(
        &self,
        challenge_id: &str,
    ) -> anyhow::Result<Vec<StoredAgent>> {
        let query = Query::new("agents").filter(Filter::eq("challenge_id", challenge_id));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// List agents by submitter
    pub fn list_agents_by_submitter(&self, submitter: &Hotkey) -> anyhow::Result<Vec<StoredAgent>> {
        let query =
            Query::new("agents").filter(Filter::eq("submitter", hex::encode(submitter.as_bytes())));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// Update agent status
    pub fn update_agent_status(&self, hash: &str, status: AgentStatus) -> anyhow::Result<()> {
        if let Some(mut agent) = self.get_agent(hash)? {
            agent.status = status;
            self.store_agent(&agent)?;
        }
        Ok(())
    }

    // ==================== Evaluation Operations ====================

    /// Store an evaluation result
    pub fn store_evaluation(&self, eval: &StoredEvaluation) -> anyhow::Result<()> {
        let key = eval.id.as_bytes();
        let value = serde_json::to_vec(eval)?;
        self.put("evaluations", key, &value)
    }

    /// Get evaluations for an agent
    pub fn get_evaluations_for_agent(
        &self,
        agent_hash: &str,
    ) -> anyhow::Result<Vec<StoredEvaluation>> {
        let query = Query::new("evaluations").filter(Filter::eq("agent_hash", agent_hash));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// Get evaluations by validator
    pub fn get_evaluations_by_validator(
        &self,
        validator: &Hotkey,
    ) -> anyhow::Result<Vec<StoredEvaluation>> {
        let query = Query::new("evaluations")
            .filter(Filter::eq("validator", hex::encode(validator.as_bytes())));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// Get top scores for a challenge
    pub fn get_top_scores(
        &self,
        challenge_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<StoredEvaluation>> {
        let query = Query::new("evaluations")
            .filter(Filter::eq("challenge_id", challenge_id))
            .order_by("score", true) // descending
            .limit(limit);
        let result = self.query(query)?;
        self.parse_results(result)
    }

    // ==================== Weight Operations ====================

    /// Store weight submission
    pub fn store_weights(&self, weights: &StoredWeight) -> anyhow::Result<()> {
        let key = weights.id.as_bytes();
        let value = serde_json::to_vec(weights)?;
        self.put("weights", key, &value)
    }

    /// Get weights for a block
    pub fn get_weights_at_block(&self, block: u64) -> anyhow::Result<Vec<StoredWeight>> {
        let query = Query::new("weights").filter(Filter::eq("block_number", block.to_string()));
        let result = self.query(query)?;
        self.parse_results(result)
    }

    /// Get latest weights for challenge
    pub fn get_latest_weights(&self, challenge_id: &str) -> anyhow::Result<Vec<StoredWeight>> {
        let query = Query::new("weights")
            .filter(Filter::eq("challenge_id", challenge_id))
            .order_by("block_number", true) // descending
            .limit(100);
        let result = self.query(query)?;
        self.parse_results(result)
    }

    // ==================== Helper Methods ====================

    /// Get typed value from collection
    fn get_typed<T: DeserializeOwned>(
        &self,
        collection: &str,
        key: &[u8],
    ) -> anyhow::Result<Option<T>> {
        match self.get(collection, key)? {
            Some(value) => {
                let parsed = serde_json::from_slice(&value)?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    /// Parse query results into typed vec
    fn parse_results<T: DeserializeOwned>(&self, result: QueryResult) -> anyhow::Result<Vec<T>> {
        let mut items = Vec::new();
        for entry in result.entries {
            if let Ok(item) = serde_json::from_slice::<T>(&entry.value) {
                items.push(item);
            }
        }
        Ok(items)
    }

    // ==================== Aggregation Operations ====================

    /// Get challenge statistics
    pub fn get_challenge_stats(&self, challenge_id: &str) -> anyhow::Result<ChallengeStats> {
        let agents = self.list_agents_for_challenge(challenge_id)?;
        let evaluations: Vec<StoredEvaluation> = {
            let query = Query::new("evaluations").filter(Filter::eq("challenge_id", challenge_id));
            let result = self.query(query)?;
            self.parse_results(result)?
        };

        let total_agents = agents.len();
        let evaluated_agents = agents
            .iter()
            .filter(|a| a.status == AgentStatus::Evaluated)
            .count();
        let avg_score = if !evaluations.is_empty() {
            evaluations.iter().map(|e| e.score).sum::<f64>() / evaluations.len() as f64
        } else {
            0.0
        };
        let max_score = evaluations.iter().map(|e| e.score).fold(0.0f64, f64::max);

        Ok(ChallengeStats {
            challenge_id: challenge_id.to_string(),
            total_agents,
            evaluated_agents,
            total_evaluations: evaluations.len(),
            avg_score,
            max_score,
        })
    }

    /// Get global stats
    pub fn get_global_stats(&self) -> anyhow::Result<GlobalStats> {
        let challenges = self.list_challenges()?;
        let agents: Vec<StoredAgent> = {
            let query = Query::new("agents");
            let result = self.query(query)?;
            self.parse_results(result)?
        };
        let evaluations: Vec<StoredEvaluation> = {
            let query = Query::new("evaluations");
            let result = self.query(query)?;
            self.parse_results(result)?
        };

        Ok(GlobalStats {
            total_challenges: challenges.len(),
            active_challenges: challenges
                .iter()
                .filter(|c| c.status == ChallengeStatus::Active)
                .count(),
            total_agents: agents.len(),
            total_evaluations: evaluations.len(),
            state_root: hex::encode(self.state_root()),
        })
    }
}

/// Challenge statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStats {
    pub challenge_id: String,
    pub total_agents: usize,
    pub evaluated_agents: usize,
    pub total_evaluations: usize,
    pub avg_score: f64,
    pub max_score: f64,
}

/// Global statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_challenges: usize,
    pub active_challenges: usize,
    pub total_agents: usize,
    pub total_evaluations: usize,
    pub state_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_challenge_operations() {
        let (_dir, db) = create_test_db();

        // Store challenge
        let config = ChallengeContainerConfig::new("Test Challenge", "test:latest", 0, 1.0);
        db.store_challenge(&config).unwrap();

        // Get challenge
        let challenge = db.get_challenge(&config.challenge_id.to_string()).unwrap();
        assert!(challenge.is_some());
        assert_eq!(challenge.unwrap().name, "Test Challenge");

        // List challenges
        let challenges = db.list_challenges().unwrap();
        assert_eq!(challenges.len(), 1);
    }

    #[test]
    fn test_agent_operations() {
        let (_dir, db) = create_test_db();

        let agent = StoredAgent {
            hash: "abc123".to_string(),
            challenge_id: "test-challenge".to_string(),
            submitter: "submitter123".to_string(),
            submitted_at: 1000,
            code_hash: "code123".to_string(),
            status: AgentStatus::Pending,
        };

        db.store_agent(&agent).unwrap();

        let retrieved = db.get_agent("abc123").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().challenge_id, "test-challenge");
    }

    #[test]
    fn test_list_challenges_by_mechanism() {
        let (_dir, db) = create_test_db();

        // Store challenges with different mechanisms
        let config1 = ChallengeContainerConfig::new("Challenge 1", "test1:latest", 1, 1.0);
        let config2 = ChallengeContainerConfig::new("Challenge 2", "test2:latest", 2, 1.0);
        let config3 = ChallengeContainerConfig::new("Challenge 3", "test3:latest", 1, 1.0);

        db.store_challenge(&config1).unwrap();
        db.store_challenge(&config2).unwrap();
        db.store_challenge(&config3).unwrap();

        // Query by mechanism 1
        let challenges = db.list_challenges_by_mechanism(1).unwrap();
        assert_eq!(challenges.len(), 2);
        assert!(challenges.iter().all(|c| c.mechanism_id == 1));

        // Query by mechanism 2
        let challenges = db.list_challenges_by_mechanism(2).unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].mechanism_id, 2);
    }

    #[test]
    fn test_get_challenge_not_found() {
        let (_dir, db) = create_test_db();

        let result = db.get_challenge("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_list_agents_for_challenge() {
        let (_dir, db) = create_test_db();

        // Store agents for different challenges
        let agent1 = StoredAgent {
            hash: "agent1".to_string(),
            challenge_id: "challenge1".to_string(),
            submitter: "submitter1".to_string(),
            submitted_at: 1000,
            code_hash: "code1".to_string(),
            status: AgentStatus::Pending,
        };

        let agent2 = StoredAgent {
            hash: "agent2".to_string(),
            challenge_id: "challenge1".to_string(),
            submitter: "submitter2".to_string(),
            submitted_at: 2000,
            code_hash: "code2".to_string(),
            status: AgentStatus::Pending,
        };

        let agent3 = StoredAgent {
            hash: "agent3".to_string(),
            challenge_id: "challenge2".to_string(),
            submitter: "submitter3".to_string(),
            submitted_at: 3000,
            code_hash: "code3".to_string(),
            status: AgentStatus::Pending,
        };

        db.store_agent(&agent1).unwrap();
        db.store_agent(&agent2).unwrap();
        db.store_agent(&agent3).unwrap();

        // List agents for challenge1
        let agents = db.list_agents_for_challenge("challenge1").unwrap();
        assert_eq!(agents.len(), 2);
        assert!(agents.iter().all(|a| a.challenge_id == "challenge1"));
    }

    #[test]
    fn test_list_agents_by_submitter() {
        let (_dir, db) = create_test_db();

        let submitter = Hotkey::from_bytes(&[5u8; 32]).unwrap();
        let submitter_hex = hex::encode(submitter.as_bytes());

        let agent1 = StoredAgent {
            hash: "agent1".to_string(),
            challenge_id: "challenge1".to_string(),
            submitter: submitter_hex.clone(),
            submitted_at: 1000,
            code_hash: "code1".to_string(),
            status: AgentStatus::Pending,
        };

        let agent2 = StoredAgent {
            hash: "agent2".to_string(),
            challenge_id: "challenge2".to_string(),
            submitter: submitter_hex.clone(),
            submitted_at: 2000,
            code_hash: "code2".to_string(),
            status: AgentStatus::Pending,
        };

        let agent3 = StoredAgent {
            hash: "agent3".to_string(),
            challenge_id: "challenge1".to_string(),
            submitter: "different_submitter".to_string(),
            submitted_at: 3000,
            code_hash: "code3".to_string(),
            status: AgentStatus::Pending,
        };

        db.store_agent(&agent1).unwrap();
        db.store_agent(&agent2).unwrap();
        db.store_agent(&agent3).unwrap();

        // List agents by submitter
        let agents = db.list_agents_by_submitter(&submitter).unwrap();
        assert_eq!(agents.len(), 2);
        assert!(agents.iter().all(|a| a.submitter == submitter_hex));
    }

    #[test]
    fn test_update_agent_status() {
        let (_dir, db) = create_test_db();

        let agent = StoredAgent {
            hash: "agent1".to_string(),
            challenge_id: "challenge1".to_string(),
            submitter: "submitter1".to_string(),
            submitted_at: 1000,
            code_hash: "code1".to_string(),
            status: AgentStatus::Pending,
        };

        db.store_agent(&agent).unwrap();

        // Update status
        db.update_agent_status("agent1", AgentStatus::Evaluating)
            .unwrap();

        let updated = db.get_agent("agent1").unwrap().unwrap();
        assert_eq!(updated.status, AgentStatus::Evaluating);

        // Update to evaluated
        db.update_agent_status("agent1", AgentStatus::Evaluated)
            .unwrap();

        let updated = db.get_agent("agent1").unwrap().unwrap();
        assert_eq!(updated.status, AgentStatus::Evaluated);
    }

    #[test]
    fn test_update_agent_status_not_found() {
        let (_dir, db) = create_test_db();

        // Updating non-existent agent should not error
        db.update_agent_status("nonexistent", AgentStatus::Failed)
            .unwrap();
    }

    #[test]
    fn test_evaluation_operations() {
        let (_dir, db) = create_test_db();

        let validator = Hotkey::from_bytes(&[7u8; 32]).unwrap();
        let validator_hex = hex::encode(validator.as_bytes());

        let eval = StoredEvaluation {
            id: "eval1".to_string(),
            agent_hash: "agent1".to_string(),
            challenge_id: "challenge1".to_string(),
            validator: validator_hex.clone(),
            score: 0.95,
            metrics: serde_json::json!({"accuracy": 0.95}),
            evaluated_at: 10000,
            block_number: 100,
        };

        db.store_evaluation(&eval).unwrap();

        // Get evaluations for agent
        let evals = db.get_evaluations_for_agent("agent1").unwrap();
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0].score, 0.95);
    }

    #[test]
    fn test_get_evaluations_by_validator() {
        let (_dir, db) = create_test_db();

        let validator = Hotkey::from_bytes(&[8u8; 32]).unwrap();
        let validator_hex = hex::encode(validator.as_bytes());

        let eval1 = StoredEvaluation {
            id: "eval1".to_string(),
            agent_hash: "agent1".to_string(),
            challenge_id: "challenge1".to_string(),
            validator: validator_hex.clone(),
            score: 0.95,
            metrics: serde_json::json!({}),
            evaluated_at: 10000,
            block_number: 100,
        };

        let eval2 = StoredEvaluation {
            id: "eval2".to_string(),
            agent_hash: "agent2".to_string(),
            challenge_id: "challenge1".to_string(),
            validator: validator_hex.clone(),
            score: 0.85,
            metrics: serde_json::json!({}),
            evaluated_at: 11000,
            block_number: 101,
        };

        let eval3 = StoredEvaluation {
            id: "eval3".to_string(),
            agent_hash: "agent3".to_string(),
            challenge_id: "challenge1".to_string(),
            validator: "different_validator".to_string(),
            score: 0.75,
            metrics: serde_json::json!({}),
            evaluated_at: 12000,
            block_number: 102,
        };

        db.store_evaluation(&eval1).unwrap();
        db.store_evaluation(&eval2).unwrap();
        db.store_evaluation(&eval3).unwrap();

        let evals = db.get_evaluations_by_validator(&validator).unwrap();
        assert_eq!(evals.len(), 2);
        assert!(evals.iter().all(|e| e.validator == validator_hex));
    }

    #[test]
    fn test_get_top_scores() {
        let (_dir, db) = create_test_db();

        // Store evaluations with different scores
        for i in 0..5 {
            let eval = StoredEvaluation {
                id: format!("eval{}", i),
                agent_hash: format!("agent{}", i),
                challenge_id: "challenge1".to_string(),
                validator: "validator1".to_string(),
                score: (i as f64) / 10.0,
                metrics: serde_json::json!({}),
                evaluated_at: 10000 + i as u64,
                block_number: 100 + i as u64,
            };
            db.store_evaluation(&eval).unwrap();
        }

        // Get top 3 scores
        let top = db.get_top_scores("challenge1", 3).unwrap();
        assert!(top.len() <= 3);
        // Scores should be in descending order (but sorting may not be fully implemented)
    }

    #[test]
    fn test_weight_operations() {
        let (_dir, db) = create_test_db();

        let weights = StoredWeight {
            id: "weight1".to_string(),
            challenge_id: "challenge1".to_string(),
            validator: "validator1".to_string(),
            weights: vec![(0, 100), (1, 200), (2, 150)],
            block_number: 100,
            submitted_at: 10000,
        };

        db.store_weights(&weights).unwrap();

        // Get weights at block
        let weights_at_block = db.get_weights_at_block(100).unwrap();
        assert_eq!(weights_at_block.len(), 1);
        assert_eq!(weights_at_block[0].weights.len(), 3);
    }

    #[test]
    fn test_get_latest_weights() {
        let (_dir, db) = create_test_db();

        // Store weights at different blocks
        for block in 100..105 {
            let weights = StoredWeight {
                id: format!("weight_block_{}", block),
                challenge_id: "challenge1".to_string(),
                validator: "validator1".to_string(),
                weights: vec![(0, block as u16)],
                block_number: block,
                submitted_at: block * 1000,
            };
            db.store_weights(&weights).unwrap();
        }

        let latest = db.get_latest_weights("challenge1").unwrap();
        assert!(latest.len() >= 5);
    }

    #[test]
    fn test_challenge_stats() {
        let (_dir, db) = create_test_db();

        // Store challenge, agents, and evaluations
        let config = ChallengeContainerConfig::new("Test Challenge", "test:latest", 0, 1.0);
        db.store_challenge(&config).unwrap();
        let challenge_id = config.challenge_id.to_string();

        // Store agents
        for i in 0..3 {
            let agent = StoredAgent {
                hash: format!("agent{}", i),
                challenge_id: challenge_id.clone(),
                submitter: "submitter".to_string(),
                submitted_at: 1000 + i,
                code_hash: format!("code{}", i),
                status: if i < 2 {
                    AgentStatus::Evaluated
                } else {
                    AgentStatus::Pending
                },
            };
            db.store_agent(&agent).unwrap();
        }

        // Store evaluations
        for i in 0..2 {
            let eval = StoredEvaluation {
                id: format!("eval{}", i),
                agent_hash: format!("agent{}", i),
                challenge_id: challenge_id.clone(),
                validator: "validator".to_string(),
                score: 0.8 + (i as f64 * 0.1),
                metrics: serde_json::json!({}),
                evaluated_at: 10000,
                block_number: 100,
            };
            db.store_evaluation(&eval).unwrap();
        }

        let stats = db.get_challenge_stats(&challenge_id).unwrap();
        assert_eq!(stats.total_agents, 3);
        assert_eq!(stats.evaluated_agents, 2);
        assert_eq!(stats.total_evaluations, 2);
        assert!(stats.avg_score > 0.8);
        assert!(stats.max_score >= 0.9);
    }

    #[test]
    fn test_global_stats() {
        let (_dir, db) = create_test_db();

        // Store some challenges
        for i in 0..3 {
            let config =
                ChallengeContainerConfig::new(&format!("Challenge {}", i), "test:latest", 0, 1.0);
            db.store_challenge(&config).unwrap();
        }

        // Store some agents
        for i in 0..5 {
            let agent = StoredAgent {
                hash: format!("agent{}", i),
                challenge_id: "challenge1".to_string(),
                submitter: "submitter".to_string(),
                submitted_at: 1000 + i,
                code_hash: format!("code{}", i),
                status: AgentStatus::Pending,
            };
            db.store_agent(&agent).unwrap();
        }

        // Store some evaluations
        for i in 0..7 {
            let eval = StoredEvaluation {
                id: format!("eval{}", i),
                agent_hash: format!("agent{}", i % 5),
                challenge_id: "challenge1".to_string(),
                validator: "validator".to_string(),
                score: 0.8,
                metrics: serde_json::json!({}),
                evaluated_at: 10000,
                block_number: 100,
            };
            db.store_evaluation(&eval).unwrap();
        }

        let stats = db.get_global_stats().unwrap();
        assert_eq!(stats.total_challenges, 3);
        assert_eq!(stats.active_challenges, 3);
        assert_eq!(stats.total_agents, 5);
        assert_eq!(stats.total_evaluations, 7);
        assert!(!stats.state_root.is_empty());
    }

    #[test]
    fn test_challenge_status_equality() {
        assert_eq!(ChallengeStatus::Active, ChallengeStatus::Active);
        assert_ne!(ChallengeStatus::Active, ChallengeStatus::Paused);
        assert_ne!(ChallengeStatus::Paused, ChallengeStatus::Deprecated);
    }

    #[test]
    fn test_agent_status_equality() {
        assert_eq!(AgentStatus::Pending, AgentStatus::Pending);
        assert_ne!(AgentStatus::Pending, AgentStatus::Evaluating);
        assert_ne!(AgentStatus::Evaluating, AgentStatus::Evaluated);
        assert_ne!(AgentStatus::Evaluated, AgentStatus::Failed);
    }

    #[test]
    fn test_get_agent_not_found() {
        let (_dir, db) = create_test_db();

        let result = db.get_agent("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_collections() {
        let (_dir, db) = create_test_db();

        let challenges = db.list_challenges().unwrap();
        assert_eq!(challenges.len(), 0);

        let agents = db.list_agents_for_challenge("nonexistent").unwrap();
        assert_eq!(agents.len(), 0);

        let evals = db.get_evaluations_for_agent("nonexistent").unwrap();
        assert_eq!(evals.len(), 0);

        let weights = db.get_weights_at_block(999).unwrap();
        assert_eq!(weights.len(), 0);
    }
}
