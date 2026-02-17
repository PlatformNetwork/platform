use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub id: String,
    pub name: String,
    pub instruction: String,
    pub difficulty: Difficulty,
    pub timeout_secs: u64,
    pub docker_image: String,
    pub test_script: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub execution_time_ms: u64,
    pub output: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Submission {
    pub tasks: Vec<TaskResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalParams {
    pub tasks: Vec<TaskDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalMetrics {
    pub tasks_passed: u32,
    pub tasks_failed: u32,
    pub total_tasks: u32,
    pub pass_rate: f64,
    pub total_execution_time_ms: u64,
}
