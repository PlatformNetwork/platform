use alloc::string::String;
use alloc::vec::Vec;

use platform_challenge_sdk_wasm::types::{EvaluationInput, EvaluationOutput};

use crate::scoring::score_submission;
use crate::types::{EvalParams, Submission};

pub fn evaluate(input: EvaluationInput) -> EvaluationOutput {
    let params: EvalParams = match bincode::deserialize(&input.params) {
        Ok(p) => p,
        Err(_) => return EvaluationOutput::failure("failed to deserialize evaluation params"),
    };

    let submission: Submission = match bincode::deserialize(&input.agent_data) {
        Ok(s) => s,
        Err(_) => return EvaluationOutput::failure("failed to deserialize agent submission"),
    };

    if submission.tasks.is_empty() {
        return EvaluationOutput::failure("submission contains no task results");
    }

    let expected_ids: Vec<&str> = params.tasks.iter().map(|t| t.id.as_str()).collect();
    for result in &submission.tasks {
        if !expected_ids.contains(&result.task_id.as_str()) {
            return EvaluationOutput::failure("submission contains unknown task id");
        }
    }

    let (score, metrics) = score_submission(&submission);

    let message = match bincode::serialize(&metrics) {
        Ok(encoded) => {
            let _ = host_storage_set_metrics(&encoded);
            alloc::format!(
                "passed={}/{} rate={:.2}%",
                metrics.tasks_passed,
                metrics.total_tasks,
                metrics.pass_rate * 100.0
            )
        }
        Err(_) => String::from("scored"),
    };

    EvaluationOutput {
        score,
        valid: true,
        message,
        metrics: None,
    }
}

fn host_storage_set_metrics(data: &[u8]) -> Result<(), i32> {
    let key = b"term_eval_metrics";
    platform_challenge_sdk_wasm::host_functions::host_storage_set(key, data)
}

pub fn validate(input: &EvaluationInput) -> bool {
    if input.agent_data.is_empty() {
        return false;
    }
    if input.params.is_empty() {
        return false;
    }
    let _params: EvalParams = match bincode::deserialize(&input.params) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let submission: Submission = match bincode::deserialize(&input.agent_data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    !submission.tasks.is_empty()
}
