//! Database queries for Platform Server (PostgreSQL)

use crate::models::{
    Evaluation, LeaderboardEntry, RegisteredChallenge, Submission, SubmissionStatus,
    SubmitEvaluationRequest, TaskLease, TaskLeaseStatus, Validator,
};
use anyhow::{anyhow, Result};
use deadpool_postgres::Pool;
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

/// Get whitelisted validators (stake >= min_stake and last_seen within 24h)
pub async fn get_whitelisted_validators(pool: &Pool, min_stake: i64) -> Result<Vec<String>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT hotkey FROM validators 
             WHERE is_active = TRUE 
             AND stake >= $1 
             AND last_seen >= NOW() - INTERVAL '24 hours'
             ORDER BY stake DESC",
            &[&min_stake],
        )
        .await?;

    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Validator row with NaiveDateTime for last_seen (for stats endpoint)
pub struct ValidatorDbRow {
    pub hotkey: String,
    pub stake: i64,
    pub last_seen: Option<chrono::NaiveDateTime>,
    pub is_active: bool,
}

/// List all validators with NaiveDateTime for last_seen
pub async fn list_validators(pool: &Pool) -> Result<Vec<ValidatorDbRow>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT hotkey, stake, last_seen, is_active
             FROM validators WHERE is_active = TRUE ORDER BY stake DESC",
            &[],
        )
        .await?;

    let validators = rows
        .iter()
        .map(|row| ValidatorDbRow {
            hotkey: row.get(0),
            stake: row.get(1),
            last_seen: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .map(|dt| dt.naive_utc()),
            is_active: row.get(3),
        })
        .collect();

    Ok(validators)
}

// ============================================================================
// SUBMISSIONS
// ============================================================================

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

/// Calculate stake-weighted consensus score with outlier detection
///
/// Implements the formula from README:
/// $\bar{s}_i = \frac{\sum_{v \in \mathcal{V}'} S_v \cdot s_i^v}{\sum_{v \in \mathcal{V}'} S_v}$
///
/// Where $\mathcal{V}'$ is the set of validators after outlier removal (z-score > 2.0)
async fn calculate_stake_weighted_consensus_score(
    pool: &Pool,
    evaluations: &[Evaluation],
) -> Result<f64> {
    if evaluations.is_empty() {
        return Ok(0.0);
    }

    // Collect (score, stake) pairs for all evaluations
    let mut score_stake_pairs: Vec<(f64, u64)> = Vec::new();
    
    for eval in evaluations {
        // Look up validator stake (default to 0 if not found)
        let stake = if let Some(validator) = get_validator(pool, &eval.validator_hotkey).await? {
            validator.stake
        } else {
            // Validator not found in database - skip this evaluation
            // (or use 0 stake, which effectively excludes it)
            continue;
        };
        
        score_stake_pairs.push((eval.score, stake));
    }

    if score_stake_pairs.is_empty() {
        // Fallback to simple average if no validators found
        return Ok(evaluations.iter().map(|e| e.score).sum::<f64>() / evaluations.len() as f64);
    }

    // Outlier detection: Calculate z-scores and filter outliers
    let scores: Vec<f64> = score_stake_pairs.iter().map(|(s, _)| *s).collect();
    let mean = scores.iter().sum::<f64>() / scores.len() as f64;
    
    // Calculate standard deviation
    let variance = scores
        .iter()
        .map(|s| (*s - mean).powi(2))
        .sum::<f64>()
        / scores.len() as f64;
    let std_dev = variance.sqrt();
    
    // Filter outliers (z-score > 2.0 threshold)
    const Z_SCORE_THRESHOLD: f64 = 2.0;
    let filtered_pairs: Vec<(f64, u64)> = if std_dev > 0.0 {
        score_stake_pairs
            .into_iter()
            .filter(|(score, _)| {
                let z_score = (score - mean).abs() / std_dev;
                z_score <= Z_SCORE_THRESHOLD
            })
            .collect()
    } else {
        // If std_dev is 0, all scores are the same, no outliers
        score_stake_pairs
    };

    if filtered_pairs.is_empty() {
        // If all were outliers, fallback to mean
        return Ok(mean);
    }

    // Calculate stake-weighted average
    let total_weighted_score: f64 = filtered_pairs
        .iter()
        .map(|(score, stake)| *score * (*stake as f64))
        .sum();
    
    let total_stake: u64 = filtered_pairs.iter().map(|(_, stake)| *stake).sum();
    
    if total_stake == 0 {
        // Fallback to simple average if total stake is 0
        let avg_score: f64 = filtered_pairs.iter().map(|(s, _)| *s).sum::<f64>()
            / filtered_pairs.len() as f64;
        return Ok(avg_score);
    }

    Ok(total_weighted_score / (total_stake as f64))
}

pub async fn update_leaderboard(pool: &Pool, agent_hash: &str) -> Result<Option<LeaderboardEntry>> {
    let evaluations = get_evaluations_for_agent(pool, agent_hash).await?;
    if evaluations.is_empty() {
        return Ok(None);
    }

    let submission = get_submission_by_hash(pool, agent_hash)
        .await?
        .ok_or_else(|| anyhow!("Submission not found for agent_hash: {}", agent_hash))?;

    // Calculate stake-weighted consensus score with outlier detection
    let consensus_score = calculate_stake_weighted_consensus_score(pool, &evaluations).await?;
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

// ============================================================================
// CHALLENGES (Dynamic Orchestration)
// ============================================================================

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
