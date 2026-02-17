use crate::types::{EvalMetrics, Submission};

pub fn score_submission(submission: &Submission) -> (i64, EvalMetrics) {
    let total = submission.tasks.len() as u32;
    let mut passed: u32 = 0;
    let mut failed: u32 = 0;
    let mut total_execution_time_ms: u64 = 0;

    for result in &submission.tasks {
        if result.passed {
            passed += 1;
        } else {
            failed += 1;
        }
        total_execution_time_ms = total_execution_time_ms.saturating_add(result.execution_time_ms);
    }

    let pass_rate = if total > 0 {
        passed as f64 / total as f64
    } else {
        0.0
    };

    let score = (pass_rate.clamp(0.0, 1.0) * 10_000.0) as i64;

    let metrics = EvalMetrics {
        tasks_passed: passed,
        tasks_failed: failed,
        total_tasks: total,
        pass_rate,
        total_execution_time_ms,
    };

    (score, metrics)
}
