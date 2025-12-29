//! Database queries for Platform Server (PostgreSQL)

use crate::models::{
    ChallengeConfig, ChallengeStatus, Evaluation, EvaluationConfig, LeaderboardEntry,
    PricingConfig, Submission, SubmissionStatus, SubmitEvaluationRequest, TaskLease,
    TaskLeaseStatus, Validator,
};
use anyhow::{anyhow, Result};
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ============================================================================
// VALIDATORS
// ============================================================================

pub async fn upsert_validator(pool: &Pool, hotkey: &str, stake: u64) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO validators (hotkey, stake, last_seen, is_active)
         VALUES ($1, $2, NOW(), TRUE)
         ON CONFLICT(hotkey) DO UPDATE SET
            stake = EXCLUDED.stake,
            last_seen = EXCLUDED.last_seen,
            is_active = TRUE",
            &[&hotkey, &(stake as i64)],
        )
        .await?;
    Ok(())
}

pub async fn get_validators(pool: &Pool) -> Result<Vec<Validator>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT hotkey, stake, last_seen, is_active, created_at
         FROM validators WHERE is_active = TRUE ORDER BY stake DESC",
            &[],
        )
        .await?;

    let validators = rows
        .iter()
        .map(|row| Validator {
            hotkey: row.get(0),
            stake: row.get::<_, i64>(1) as u64,
            last_seen: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .map(|dt| dt.timestamp()),
            is_active: row.get(3),
            created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(4).timestamp(),
        })
        .collect();

    Ok(validators)
}

pub async fn get_validator(pool: &Pool, hotkey: &str) -> Result<Option<Validator>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT hotkey, stake, last_seen, is_active, created_at
         FROM validators WHERE hotkey = $1",
            &[&hotkey],
        )
        .await?;

    Ok(row.map(|row| Validator {
        hotkey: row.get(0),
        stake: row.get::<_, i64>(1) as u64,
        last_seen: row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
            .map(|dt| dt.timestamp()),
        is_active: row.get(3),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(4).timestamp(),
    }))
}

pub async fn get_total_stake(pool: &Pool) -> Result<u64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COALESCE(SUM(stake), 0)::BIGINT FROM validators WHERE is_active = TRUE",
            &[],
        )
        .await?;
    let stake: i64 = row.try_get(0).unwrap_or(0);
    Ok(stake as u64)
}

// ============================================================================
// SUBMISSIONS
// ============================================================================

pub fn compute_agent_hash(miner_hotkey: &str, source_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(miner_hotkey.as_bytes());
    hasher.update(source_code.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn create_submission(
    pool: &Pool,
    miner_hotkey: &str,
    source_code: &str,
    name: Option<&str>,
    api_key: Option<&str>,
    api_provider: Option<&str>,
    api_keys_encrypted: Option<&str>,
    epoch: u64,
) -> Result<Submission> {
    let client = pool.get().await?;
    let agent_hash = compute_agent_hash(miner_hotkey, source_code);
    let source_hash = hex::encode(Sha256::digest(source_code.as_bytes()));
    let provider = api_provider.unwrap_or("openrouter");

    let row = client.query_one(
        "INSERT INTO submissions (agent_hash, miner_hotkey, source_code, source_hash, name, epoch, status, api_key, api_provider, api_keys_encrypted)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
         RETURNING id, created_at",
        &[&agent_hash, &miner_hotkey, &source_code, &source_hash, &name, &(epoch as i64), &api_key, &provider, &api_keys_encrypted],
    ).await?;

    let id: Uuid = row.get(0);
    let created_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Submission {
        id: id.to_string(),
        agent_hash,
        miner_hotkey: miner_hotkey.to_string(),
        source_code: Some(source_code.to_string()),
        source_hash,
        name: name.map(|s| s.to_string()),
        version: "1.0.0".to_string(),
        epoch,
        status: SubmissionStatus::Pending,
        api_key: api_key.map(|s| s.to_string()),
        api_provider: Some(provider.to_string()),
        total_cost_usd: Some(0.0),
        api_keys_encrypted: api_keys_encrypted.map(|s| s.to_string()),
        created_at: created_at.timestamp(),
    })
}

pub async fn get_submission(pool: &Pool, id: &str) -> Result<Option<Submission>> {
    let client = pool.get().await?;
    let uuid = match Uuid::parse_str(id) {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };

    let row = client.query_opt(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE id = $1",
        &[&uuid]
    ).await?;

    Ok(row.map(|row| Submission {
        id: row.get::<_, Uuid>(0).to_string(),
        agent_hash: row.get(1),
        miner_hotkey: row.get(2),
        source_code: row.get(3),
        source_hash: row.get(4),
        name: row.get(5),
        version: row
            .get::<_, Option<String>>(6)
            .unwrap_or_else(|| "1.0.0".to_string()),
        epoch: row.get::<_, i64>(7) as u64,
        status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
        api_key: row.get(9),
        api_provider: row.get(10),
        total_cost_usd: row.get(11),
        api_keys_encrypted: row.get(12),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
    }))
}

pub async fn get_submission_by_hash(pool: &Pool, agent_hash: &str) -> Result<Option<Submission>> {
    let client = pool.get().await?;
    let row = client.query_opt(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE agent_hash = $1",
        &[&agent_hash]
    ).await?;

    Ok(row.map(|row| Submission {
        id: row.get::<_, Uuid>(0).to_string(),
        agent_hash: row.get(1),
        miner_hotkey: row.get(2),
        source_code: row.get(3),
        source_hash: row.get(4),
        name: row.get(5),
        version: row
            .get::<_, Option<String>>(6)
            .unwrap_or_else(|| "1.0.0".to_string()),
        epoch: row.get::<_, i64>(7) as u64,
        status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
        api_key: row.get(9),
        api_provider: row.get(10),
        total_cost_usd: row.get(11),
        api_keys_encrypted: row.get(12),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
    }))
}

pub async fn get_pending_submissions(pool: &Pool) -> Result<Vec<Submission>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE status = 'pending' ORDER BY created_at ASC",
        &[]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| Submission {
            id: row.get::<_, Uuid>(0).to_string(),
            agent_hash: row.get(1),
            miner_hotkey: row.get(2),
            source_code: row.get(3),
            source_hash: row.get(4),
            name: row.get(5),
            version: row
                .get::<_, Option<String>>(6)
                .unwrap_or_else(|| "1.0.0".to_string()),
            epoch: row.get::<_, i64>(7) as u64,
            status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
            api_key: row.get(9),
            api_provider: row.get(10),
            total_cost_usd: row.get(11),
            api_keys_encrypted: row.get(12),
            created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
        })
        .collect())
}

/// Update submission cost after evaluation
pub async fn update_submission_cost(pool: &Pool, id: &str, cost_usd: f64) -> Result<()> {
    let client = pool.get().await?;
    let uuid = Uuid::parse_str(id)?;
    client
        .execute(
            "UPDATE submissions SET total_cost_usd = COALESCE(total_cost_usd, 0) + $1 WHERE id = $2",
            &[&cost_usd, &uuid],
        )
        .await?;
    Ok(())
}

pub async fn update_submission_status(
    pool: &Pool,
    id: &str,
    status: SubmissionStatus,
) -> Result<()> {
    let client = pool.get().await?;
    let uuid = Uuid::parse_str(id)?;
    client
        .execute(
            "UPDATE submissions SET status = $1 WHERE id = $2",
            &[&status.to_string(), &uuid],
        )
        .await?;
    Ok(())
}

// ============================================================================
// EVALUATIONS
// ============================================================================

pub async fn create_evaluation(pool: &Pool, req: &SubmitEvaluationRequest) -> Result<Evaluation> {
    let client = pool.get().await?;
    let submission_uuid = Uuid::parse_str(&req.submission_id)?;
    let task_results_json: Option<serde_json::Value> = req.task_results.clone();

    let row = client.query_one(
        "INSERT INTO evaluations (submission_id, agent_hash, validator_hotkey, score, tasks_passed, tasks_total, tasks_failed, total_cost_usd, execution_time_ms, task_results, execution_log)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT(submission_id, validator_hotkey) DO UPDATE SET
            score = EXCLUDED.score,
            tasks_passed = EXCLUDED.tasks_passed,
            tasks_total = EXCLUDED.tasks_total,
            tasks_failed = EXCLUDED.tasks_failed,
            total_cost_usd = EXCLUDED.total_cost_usd,
            execution_time_ms = EXCLUDED.execution_time_ms,
            task_results = EXCLUDED.task_results,
            execution_log = EXCLUDED.execution_log,
            created_at = NOW()
         RETURNING id, created_at",
        &[
            &submission_uuid,
            &req.agent_hash,
            &req.validator_hotkey,
            &req.score,
            &(req.tasks_passed as i32),
            &(req.tasks_total as i32),
            &(req.tasks_failed as i32),
            &req.total_cost_usd,
            &req.execution_time_ms,
            &task_results_json,
            &req.execution_log,
        ],
    ).await?;

    let id: Uuid = row.get(0);
    let created_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Evaluation {
        id: id.to_string(),
        submission_id: req.submission_id.clone(),
        agent_hash: req.agent_hash.clone(),
        validator_hotkey: req.validator_hotkey.clone(),
        score: req.score,
        tasks_passed: req.tasks_passed,
        tasks_total: req.tasks_total,
        tasks_failed: req.tasks_failed,
        total_cost_usd: req.total_cost_usd,
        execution_time_ms: req.execution_time_ms,
        task_results: task_results_json.map(|v| v.to_string()),
        execution_log: req.execution_log.clone(),
        created_at: created_at.timestamp(),
    })
}

pub async fn get_evaluations_for_agent(pool: &Pool, agent_hash: &str) -> Result<Vec<Evaluation>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT id, submission_id, agent_hash, validator_hotkey, score, tasks_passed, tasks_total, tasks_failed, total_cost_usd, execution_time_ms, task_results, execution_log, created_at
         FROM evaluations WHERE agent_hash = $1 ORDER BY created_at DESC",
        &[&agent_hash]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| {
            let task_results: Option<serde_json::Value> = row.get(10);
            Evaluation {
                id: row.get::<_, Uuid>(0).to_string(),
                submission_id: row.get::<_, Uuid>(1).to_string(),
                agent_hash: row.get(2),
                validator_hotkey: row.get(3),
                score: row.get(4),
                tasks_passed: row.get::<_, i32>(5) as u32,
                tasks_total: row.get::<_, i32>(6) as u32,
                tasks_failed: row.get::<_, i32>(7) as u32,
                total_cost_usd: row.get(8),
                execution_time_ms: row.get(9),
                task_results: task_results.map(|v| v.to_string()),
                execution_log: row.get(11),
                created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(12).timestamp(),
            }
        })
        .collect())
}

// ============================================================================
// LEADERBOARD
// ============================================================================

pub async fn update_leaderboard(pool: &Pool, agent_hash: &str) -> Result<Option<LeaderboardEntry>> {
    let evaluations = get_evaluations_for_agent(pool, agent_hash).await?;
    if evaluations.is_empty() {
        return Ok(None);
    }

    let submission = get_submission_by_hash(pool, agent_hash)
        .await?
        .ok_or_else(|| anyhow!("Submission not found for agent_hash: {}", agent_hash))?;

    let scores: Vec<f64> = evaluations.iter().map(|e| e.score).collect();
    let consensus_score = scores.iter().sum::<f64>() / scores.len() as f64;
    let evaluation_count = evaluations.len() as i32;
    let first_epoch = submission.epoch as i64;

    let client = pool.get().await?;

    client.execute(
        "INSERT INTO leaderboard (agent_hash, miner_hotkey, name, consensus_score, evaluation_count, first_epoch, last_epoch, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT(agent_hash) DO UPDATE SET
            consensus_score = EXCLUDED.consensus_score,
            evaluation_count = EXCLUDED.evaluation_count,
            last_epoch = EXCLUDED.last_epoch,
            updated_at = EXCLUDED.updated_at",
        &[&agent_hash, &submission.miner_hotkey, &submission.name, &consensus_score, &evaluation_count, &first_epoch, &first_epoch],
    ).await?;

    // Update ranks
    client.execute(
        "UPDATE leaderboard SET rank = subq.new_rank
         FROM (SELECT agent_hash, ROW_NUMBER() OVER (ORDER BY consensus_score DESC) as new_rank FROM leaderboard) subq
         WHERE leaderboard.agent_hash = subq.agent_hash",
        &[]
    ).await?;

    get_leaderboard_entry(pool, agent_hash).await
}

pub async fn get_leaderboard_entry(
    pool: &Pool,
    agent_hash: &str,
) -> Result<Option<LeaderboardEntry>> {
    let client = pool.get().await?;
    let row = client.query_opt(
        "SELECT agent_hash, miner_hotkey, name, consensus_score, evaluation_count, rank, first_epoch, last_epoch, best_rank, total_rewards, updated_at
         FROM leaderboard WHERE agent_hash = $1",
        &[&agent_hash]
    ).await?;

    Ok(row.map(|row| LeaderboardEntry {
        agent_hash: row.get(0),
        miner_hotkey: row.get(1),
        name: row.get(2),
        consensus_score: row.get(3),
        evaluation_count: row.get::<_, i32>(4) as u32,
        rank: row.get::<_, Option<i32>>(5).unwrap_or(0) as u32,
        first_epoch: row.get::<_, i64>(6) as u64,
        last_epoch: row.get::<_, i64>(7) as u64,
        best_rank: row.get::<_, Option<i32>>(8).map(|r| r as u32),
        total_rewards: row.get(9),
        updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(10).timestamp(),
    }))
}

pub async fn get_leaderboard(pool: &Pool, limit: usize) -> Result<Vec<LeaderboardEntry>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT agent_hash, miner_hotkey, name, consensus_score, evaluation_count, rank, first_epoch, last_epoch, best_rank, total_rewards, updated_at
         FROM leaderboard ORDER BY rank ASC NULLS LAST LIMIT $1",
        &[&(limit as i64)]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| LeaderboardEntry {
            agent_hash: row.get(0),
            miner_hotkey: row.get(1),
            name: row.get(2),
            consensus_score: row.get(3),
            evaluation_count: row.get::<_, i32>(4) as u32,
            rank: row.get::<_, Option<i32>>(5).unwrap_or(0) as u32,
            first_epoch: row.get::<_, i64>(6) as u64,
            last_epoch: row.get::<_, i64>(7) as u64,
            best_rank: row.get::<_, Option<i32>>(8).map(|r| r as u32),
            total_rewards: row.get(9),
            updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(10).timestamp(),
        })
        .collect())
}

/// Get leaderboard for a specific challenge
/// For now, returns the global leaderboard (single challenge mode)
pub async fn get_leaderboard_for_challenge(
    pool: &Pool,
    _challenge_id: &str,
    limit: usize,
) -> Result<Vec<LeaderboardEntry>> {
    // Currently all submissions are for a single challenge
    // In the future, filter by challenge_id
    get_leaderboard(pool, limit).await
}

// ============================================================================
// CHALLENGE CONFIG
// ============================================================================

pub async fn get_challenge_config(pool: &Pool, id: &str) -> Result<Option<ChallengeConfig>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, name, description, mechanism_id, emission_weight, version, status,
                max_agents_per_epoch, min_stake, module_whitelist, model_whitelist, 
                pricing_config, evaluation_config, updated_at, updated_by
         FROM challenge_config WHERE id = $1",
            &[&id],
        )
        .await?;

    Ok(row.map(|row| {
        let module_whitelist: Option<serde_json::Value> = row.get(9);
        let model_whitelist: Option<serde_json::Value> = row.get(10);
        let pricing_config: Option<serde_json::Value> = row.get(11);
        let evaluation_config: Option<serde_json::Value> = row.get(12);
        let status_str: String = row.get(6);

        ChallengeConfig {
            id: row.get(0),
            name: row.get(1),
            description: row.get(2),
            mechanism_id: row.get::<_, i16>(3) as u8,
            emission_weight: row.get(4),
            version: row
                .get::<_, Option<String>>(5)
                .unwrap_or_else(|| "1.0.0".to_string()),
            status: match status_str.as_str() {
                "paused" => ChallengeStatus::Paused,
                "deprecated" => ChallengeStatus::Deprecated,
                _ => ChallengeStatus::Active,
            },
            max_agents_per_epoch: row.get(7),
            min_stake: row.get::<_, i64>(8) as u64,
            module_whitelist: module_whitelist.and_then(|v| serde_json::from_value(v).ok()),
            model_whitelist: model_whitelist.and_then(|v| serde_json::from_value(v).ok()),
            pricing_config: pricing_config.and_then(|v| serde_json::from_value(v).ok()),
            evaluation_config: evaluation_config.and_then(|v| serde_json::from_value(v).ok()),
            updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
            updated_by: row.get(14),
        }
    }))
}

pub async fn update_challenge_config(
    pool: &Pool,
    id: &str,
    config: &serde_json::Value,
    updated_by: &str,
) -> Result<()> {
    let client = pool.get().await?;

    if let Some(name) = config.get("name").and_then(|v| v.as_str()) {
        client.execute("UPDATE challenge_config SET name = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&name, &updated_by, &id]).await?;
    }
    if let Some(max_agents) = config.get("max_agents_per_epoch").and_then(|v| v.as_f64()) {
        client.execute("UPDATE challenge_config SET max_agents_per_epoch = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&max_agents, &updated_by, &id]).await?;
    }
    if let Some(modules) = config.get("module_whitelist") {
        client.execute("UPDATE challenge_config SET module_whitelist = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&modules, &updated_by, &id]).await?;
    }

    Ok(())
}

// ============================================================================
// NETWORK STATE
// ============================================================================

pub async fn get_network_state(pool: &Pool, key: &str) -> Result<Option<String>> {
    let client = pool.get().await?;
    let row = client
        .query_opt("SELECT value FROM network_state WHERE key = $1", &[&key])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

pub async fn set_network_state(pool: &Pool, key: &str, value: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO network_state (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
            &[&key, &value],
        )
        .await?;
    Ok(())
}

pub async fn get_current_epoch(pool: &Pool) -> Result<u64> {
    let value = get_network_state(pool, "current_epoch")
        .await?
        .unwrap_or_else(|| "0".to_string());
    Ok(value.parse().unwrap_or(0))
}

// ============================================================================
// TASK LEASES (Claim/Lease)
// ============================================================================

pub async fn claim_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    ttl_seconds: u64,
) -> Result<Option<TaskLease>> {
    let client = pool.get().await?;

    // Check if task is already claimed and not expired
    let existing = client.query_opt(
        "SELECT validator_hotkey, expires_at FROM task_leases WHERE task_id = $1 AND status = 'active' AND expires_at > NOW()",
        &[&task_id]
    ).await?;

    if let Some(row) = existing {
        let holder: String = row.get(0);
        if holder != validator_hotkey {
            return Ok(None); // Already claimed by another validator
        }
    }

    // Upsert lease
    let row = client
        .query_one(
            "INSERT INTO task_leases (task_id, validator_hotkey, claimed_at, expires_at, status)
         VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 second' * $3, 'active')
         ON CONFLICT(task_id) DO UPDATE SET
            validator_hotkey = EXCLUDED.validator_hotkey,
            claimed_at = EXCLUDED.claimed_at,
            expires_at = EXCLUDED.expires_at,
            status = 'active'
         RETURNING claimed_at, expires_at",
            &[&task_id, &validator_hotkey, &(ttl_seconds as f64)],
        )
        .await?;

    let claimed_at: chrono::DateTime<chrono::Utc> = row.get(0);
    let expires_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Some(TaskLease {
        task_id: task_id.to_string(),
        validator_hotkey: validator_hotkey.to_string(),
        claimed_at: claimed_at.timestamp(),
        expires_at: expires_at.timestamp(),
        status: TaskLeaseStatus::Active,
    }))
}

pub async fn renew_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    ttl_seconds: u64,
) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET expires_at = NOW() + INTERVAL '1 second' * $1
         WHERE task_id = $2 AND validator_hotkey = $3 AND status = 'active'",
            &[&(ttl_seconds as f64), &task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn ack_task(pool: &Pool, task_id: &str, validator_hotkey: &str) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET status = 'completed', ack_at = NOW()
         WHERE task_id = $1 AND validator_hotkey = $2 AND status = 'active'",
            &[&task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn fail_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET status = 'failed', fail_reason = $1
         WHERE task_id = $2 AND validator_hotkey = $3 AND status = 'active'",
            &[&reason, &task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn log_event(
    pool: &Pool,
    event_type: &str,
    entity_type: Option<&str>,
    entity_id: Option<&str>,
    payload: Option<&str>,
    actor: Option<&str>,
) -> Result<()> {
    let client = pool.get().await?;
    let payload_json: Option<serde_json::Value> =
        payload.and_then(|s| serde_json::from_str(s).ok());
    client.execute(
        "INSERT INTO events (event_type, entity_type, entity_id, payload, actor_hotkey) VALUES ($1, $2, $3, $4, $5)",
        &[&event_type, &entity_type, &entity_id, &payload_json, &actor],
    ).await?;
    Ok(())
}

// ============================================================================
// CHALLENGES (Dynamic Orchestration)
// ============================================================================

use crate::models::RegisteredChallenge;

/// Get all registered challenges
pub async fn get_challenges(pool: &Pool) -> Result<Vec<RegisteredChallenge>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, name, docker_image, mechanism_id, emission_weight, 
                    timeout_secs, cpu_cores, memory_mb, gpu_required, status,
                    endpoint, container_id, last_health_check, is_healthy,
                    created_at, updated_at
             FROM challenges ORDER BY created_at",
            &[],
        )
        .await?;

    let challenges = rows
        .iter()
        .map(|row| RegisteredChallenge {
            id: row.get(0),
            name: row.get(1),
            docker_image: row.get(2),
            mechanism_id: row.get::<_, i16>(3) as u8,
            emission_weight: row.get(4),
            timeout_secs: row.get::<_, i32>(5) as u64,
            cpu_cores: row.get(6),
            memory_mb: row.get::<_, i32>(7) as u64,
            gpu_required: row.get(8),
            status: row.get(9),
            endpoint: row.get(10),
            container_id: row.get(11),
            last_health_check: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(12)
                .map(|dt| dt.timestamp()),
            is_healthy: row.get(13),
        })
        .collect();

    Ok(challenges)
}

/// Get active challenges only
pub async fn get_active_challenges(pool: &Pool) -> Result<Vec<RegisteredChallenge>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, name, docker_image, mechanism_id, emission_weight, 
                    timeout_secs, cpu_cores, memory_mb, gpu_required, status,
                    endpoint, container_id, last_health_check, is_healthy,
                    created_at, updated_at
             FROM challenges WHERE status = 'active' ORDER BY created_at",
            &[],
        )
        .await?;

    let challenges = rows
        .iter()
        .map(|row| RegisteredChallenge {
            id: row.get(0),
            name: row.get(1),
            docker_image: row.get(2),
            mechanism_id: row.get::<_, i16>(3) as u8,
            emission_weight: row.get(4),
            timeout_secs: row.get::<_, i32>(5) as u64,
            cpu_cores: row.get(6),
            memory_mb: row.get::<_, i32>(7) as u64,
            gpu_required: row.get(8),
            status: row.get(9),
            endpoint: row.get(10),
            container_id: row.get(11),
            last_health_check: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(12)
                .map(|dt| dt.timestamp()),
            is_healthy: row.get(13),
        })
        .collect();

    Ok(challenges)
}

/// Get a single challenge by ID
pub async fn get_challenge(pool: &Pool, challenge_id: &str) -> Result<Option<RegisteredChallenge>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, name, docker_image, mechanism_id, emission_weight, 
                    timeout_secs, cpu_cores, memory_mb, gpu_required, status,
                    endpoint, container_id, last_health_check, is_healthy,
                    created_at, updated_at
             FROM challenges WHERE id = $1",
            &[&challenge_id],
        )
        .await?;

    Ok(row.map(|row| RegisteredChallenge {
        id: row.get(0),
        name: row.get(1),
        docker_image: row.get(2),
        mechanism_id: row.get::<_, i16>(3) as u8,
        emission_weight: row.get(4),
        timeout_secs: row.get::<_, i32>(5) as u64,
        cpu_cores: row.get(6),
        memory_mb: row.get::<_, i32>(7) as u64,
        gpu_required: row.get(8),
        status: row.get(9),
        endpoint: row.get(10),
        container_id: row.get(11),
        last_health_check: row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>(12)
            .map(|dt| dt.timestamp()),
        is_healthy: row.get(13),
    }))
}

/// Register a new challenge
pub async fn register_challenge(pool: &Pool, challenge: &RegisteredChallenge) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO challenges (id, name, docker_image, mechanism_id, emission_weight,
                                    timeout_secs, cpu_cores, memory_mb, gpu_required, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(id) DO UPDATE SET
                name = EXCLUDED.name,
                docker_image = EXCLUDED.docker_image,
                mechanism_id = EXCLUDED.mechanism_id,
                emission_weight = EXCLUDED.emission_weight,
                timeout_secs = EXCLUDED.timeout_secs,
                cpu_cores = EXCLUDED.cpu_cores,
                memory_mb = EXCLUDED.memory_mb,
                gpu_required = EXCLUDED.gpu_required,
                status = EXCLUDED.status,
                updated_at = NOW()",
            &[
                &challenge.id,
                &challenge.name,
                &challenge.docker_image,
                &(challenge.mechanism_id as i16),
                &challenge.emission_weight,
                &(challenge.timeout_secs as i32),
                &challenge.cpu_cores,
                &(challenge.memory_mb as i32),
                &challenge.gpu_required,
                &challenge.status,
            ],
        )
        .await?;
    Ok(())
}

/// Update challenge container info (endpoint, container_id, health)
pub async fn update_challenge_container(
    pool: &Pool,
    challenge_id: &str,
    endpoint: Option<&str>,
    container_id: Option<&str>,
    is_healthy: bool,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE challenges SET endpoint = $2, container_id = $3, 
             is_healthy = $4, last_health_check = NOW(), updated_at = NOW()
             WHERE id = $1",
            &[&challenge_id, &endpoint, &container_id, &is_healthy],
        )
        .await?;
    Ok(())
}

/// Update challenge status
pub async fn update_challenge_status(pool: &Pool, challenge_id: &str, status: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE challenges SET status = $2, updated_at = NOW() WHERE id = $1",
            &[&challenge_id, &status],
        )
        .await?;
    Ok(())
}

/// Delete a challenge
pub async fn delete_challenge(pool: &Pool, challenge_id: &str) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute("DELETE FROM challenges WHERE id = $1", &[&challenge_id])
        .await?;
    Ok(result > 0)
}

// ============================================================================
// EVALUATION JOB QUEUE
// ============================================================================

use crate::models::{EvaluationJob, JobStatus, TaskResultSummary};

/// Create a new evaluation job from a submission
pub async fn create_job(
    pool: &Pool,
    submission_id: &str,
    challenge_id: &str,
) -> Result<EvaluationJob> {
    let client = pool.get().await?;
    let job_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    // Get submission details
    let sub = get_submission(pool, submission_id)
        .await?
        .ok_or_else(|| anyhow!("Submission not found"))?;

    client
        .execute(
            "INSERT INTO evaluation_jobs (id, submission_id, agent_hash, miner_hotkey, 
             source_code, api_key, api_provider, challenge_id, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())",
            &[
                &job_id,
                &submission_id,
                &sub.agent_hash,
                &sub.miner_hotkey,
                &sub.source_code,
                &sub.api_key,
                &sub.api_provider,
                &challenge_id,
            ],
        )
        .await?;

    Ok(EvaluationJob {
        id: job_id,
        submission_id: submission_id.to_string(),
        agent_hash: sub.agent_hash,
        miner_hotkey: sub.miner_hotkey,
        source_code: sub.source_code.unwrap_or_default(),
        api_key: sub.api_key,
        api_provider: sub.api_provider,
        challenge_id: challenge_id.to_string(),
        created_at: now,
        status: JobStatus::Pending,
        assigned_validator: None,
        assigned_at: None,
    })
}

/// Claim the next pending job for a challenge
pub async fn claim_next_job(
    pool: &Pool,
    validator_hotkey: &str,
    challenge_id: &str,
) -> Result<Option<EvaluationJob>> {
    let client = pool.get().await?;

    // Use FOR UPDATE SKIP LOCKED for concurrent access
    let row = client
        .query_opt(
            "UPDATE evaluation_jobs SET 
                status = 'assigned',
                assigned_validator = $1,
                assigned_at = NOW()
             WHERE id = (
                SELECT id FROM evaluation_jobs 
                WHERE challenge_id = $2 
                AND status = 'pending'
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
             )
             RETURNING id, submission_id, agent_hash, miner_hotkey, source_code, 
                       api_key, api_provider, challenge_id, 
                       EXTRACT(EPOCH FROM created_at)::BIGINT as created_at",
            &[&validator_hotkey, &challenge_id],
        )
        .await?;

    Ok(row.map(|r| EvaluationJob {
        id: r.get(0),
        submission_id: r.get(1),
        agent_hash: r.get(2),
        miner_hotkey: r.get(3),
        source_code: r.get::<_, Option<String>>(4).unwrap_or_default(),
        api_key: r.get(5),
        api_provider: r.get(6),
        challenge_id: r.get(7),
        created_at: r.get(8),
        status: JobStatus::Assigned,
        assigned_validator: Some(validator_hotkey.to_string()),
        assigned_at: Some(chrono::Utc::now().timestamp()),
    }))
}

/// Get a job by ID
pub async fn get_job(pool: &Pool, job_id: &str) -> Result<Option<EvaluationJob>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, submission_id, agent_hash, miner_hotkey, source_code,
                    api_key, api_provider, challenge_id, 
                    EXTRACT(EPOCH FROM created_at)::BIGINT as created_at,
                    status, assigned_validator, 
                    EXTRACT(EPOCH FROM assigned_at)::BIGINT as assigned_at
             FROM evaluation_jobs WHERE id = $1",
            &[&job_id],
        )
        .await?;

    Ok(row.map(|r| {
        let status_str: String = r.get(9);
        EvaluationJob {
            id: r.get(0),
            submission_id: r.get(1),
            agent_hash: r.get(2),
            miner_hotkey: r.get(3),
            source_code: r.get::<_, Option<String>>(4).unwrap_or_default(),
            api_key: r.get(5),
            api_provider: r.get(6),
            challenge_id: r.get(7),
            created_at: r.get(8),
            status: match status_str.as_str() {
                "pending" => JobStatus::Pending,
                "assigned" => JobStatus::Assigned,
                "running" => JobStatus::Running,
                "completed" => JobStatus::Completed,
                "failed" => JobStatus::Failed,
                _ => JobStatus::Pending,
            },
            assigned_validator: r.get(10),
            assigned_at: r.get(11),
        }
    }))
}

/// Update job progress (task index and status)
pub async fn update_job_progress(
    pool: &Pool,
    job_id: &str,
    task_index: u32,
    status: &str,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE evaluation_jobs SET 
                status = 'running',
                current_task = $2,
                last_progress = $3,
                updated_at = NOW()
             WHERE id = $1",
            &[&job_id, &(task_index as i32), &status],
        )
        .await?;
    Ok(())
}

/// Mark job as completed
pub async fn complete_job(pool: &Pool, job_id: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE evaluation_jobs SET status = 'completed', updated_at = NOW() WHERE id = $1",
            &[&job_id],
        )
        .await?;
    Ok(())
}

/// Save evaluation result with task details
pub async fn save_evaluation(
    pool: &Pool,
    submission_id: &str,
    agent_hash: &str,
    validator_hotkey: &str,
    score: f64,
    tasks_passed: i32,
    tasks_total: i32,
    total_cost_usd: f64,
    execution_time_ms: i64,
    task_results: &[TaskResultSummary],
    execution_log: Option<&str>,
) -> Result<String> {
    let client = pool.get().await?;
    let eval_id = Uuid::new_v4().to_string();

    let task_results_json = serde_json::to_value(task_results)?;

    client
        .execute(
            "INSERT INTO evaluations (id, submission_id, agent_hash, validator_hotkey,
             score, tasks_passed, tasks_total, tasks_failed, total_cost_usd,
             execution_time_ms, task_results, execution_log, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())",
            &[
                &eval_id,
                &submission_id,
                &agent_hash,
                &validator_hotkey,
                &score,
                &tasks_passed,
                &tasks_total,
                &(tasks_total - tasks_passed),
                &total_cost_usd,
                &execution_time_ms,
                &task_results_json,
                &execution_log,
            ],
        )
        .await?;

    // Update submission status
    client
        .execute(
            "UPDATE submissions SET status = 'evaluating' WHERE id = $1",
            &[&submission_id],
        )
        .await?;

    Ok(eval_id)
}

/// Evaluation with validator stake for consensus calculation
pub struct EvaluationWithStake {
    pub score: f64,
    pub validator_stake: u64,
}

/// Get all evaluations for an agent with stake info for consensus
pub async fn get_evaluations_with_stake(
    pool: &Pool,
    agent_hash: &str,
) -> Result<Vec<EvaluationWithStake>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT e.score, COALESCE(v.stake, 0) as stake
             FROM evaluations e
             LEFT JOIN validators v ON e.validator_hotkey = v.hotkey
             WHERE e.agent_hash = $1",
            &[&agent_hash],
        )
        .await?;

    Ok(rows
        .iter()
        .map(|r| EvaluationWithStake {
            score: r.get(0),
            validator_stake: r.get::<_, i64>(1) as u64,
        })
        .collect())
}

// ============================================================================
// RATE LIMITING
// ============================================================================

/// Check if miner can submit (rate limit: 0.33 submissions per epoch = 1 every 3 epochs)
pub async fn can_miner_submit(pool: &Pool, miner_hotkey: &str, current_epoch: u64) -> Result<bool> {
    let client = pool.get().await?;

    // Count submissions in last 3 epochs
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM submissions 
             WHERE miner_hotkey = $1 AND epoch >= $2",
            &[&miner_hotkey, &((current_epoch.saturating_sub(2)) as i64)],
        )
        .await?;

    let count: i64 = row.get(0);
    Ok(count == 0) // Can submit if no submissions in last 3 epochs
}

/// Get miner's submission count in recent epochs
pub async fn get_miner_submission_count(
    pool: &Pool,
    miner_hotkey: &str,
    epochs_back: u64,
    current_epoch: u64,
) -> Result<i64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM submissions 
             WHERE miner_hotkey = $1 AND epoch >= $2",
            &[
                &miner_hotkey,
                &((current_epoch.saturating_sub(epochs_back)) as i64),
            ],
        )
        .await?;
    Ok(row.get(0))
}

// ============================================================================
// LLM COST TRACKING
// ============================================================================

/// Add cost to an agent's total (for LLM usage tracking)
pub async fn add_agent_cost(pool: &Pool, agent_hash: &str, cost_usd: f64) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE submissions SET total_cost_usd = COALESCE(total_cost_usd, 0) + $2 
             WHERE agent_hash = $1",
            &[&agent_hash, &cost_usd],
        )
        .await?;
    Ok(())
}

/// Get agent's total LLM cost
pub async fn get_agent_cost(pool: &Pool, agent_hash: &str) -> Result<f64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COALESCE(total_cost_usd, 0) FROM submissions WHERE agent_hash = $1",
            &[&agent_hash],
        )
        .await?;
    Ok(row.get(0))
}
