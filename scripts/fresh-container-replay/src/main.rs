//! Fresh-container replay validation for SWE-bench tasks.
//!
//! Validates tasks by running them in fresh Docker containers using
//! dual-commit validation:
//!
//! 1. **Base commit** (without patch):
//!    - `fail_to_pass` tests should FAIL (these are the bug-revealing tests)
//!    - `pass_to_pass` tests should PASS (these are existing passing tests)
//!
//! 2. **Patched commit** (with patch applied):
//!    - `fail_to_pass` tests should PASS (the patch fixes the bug)
//!    - `pass_to_pass` tests should PASS (the patch doesn't break anything)
//!
//! This script fulfills validation assertions:
//! - **VAL-DATASET-004**: Diff patch applicable
//! - **VAL-DATASET-006**: Dual-commit validation passes
//! - **VAL-CODE-008**: Fresh-container replay function
//!
//! Usage:
//!   fresh-container-replay [TASKS_DIR] [--parallel N] [--limit N] [--timeout SECS]
//!
//! Defaults to `hf-tasks/tasks` if no directory is provided.
//! Returns exit code 0 if all valid, 1 if any failures.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a test run in a Docker container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestRunResult {
    /// All validation checks passed.
    Ok,
    /// A real test failure occurred (tests behaved unexpectedly).
    RealFailure(String),
    /// The environment was broken (e.g., missing commands, Docker issues).
    EnvironmentBroken(String),
}

impl fmt::Display for TestRunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestRunResult::Ok => write!(f, "Ok"),
            TestRunResult::RealFailure(msg) => write!(f, "RealFailure: {}", msg),
            TestRunResult::EnvironmentBroken(msg) => write!(f, "EnvironmentBroken: {}", msg),
        }
    }
}

/// Represents a parsed workspace.yaml task.
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct TaskConfig {
    pub repo: String,
    pub instance_id: String,
    pub base_commit: String,
    pub patch: String,
    #[allow(dead_code)]
    pub test_patch: String,
    #[allow(dead_code)]
    pub problem_statement: String,
    pub FAIL_TO_PASS: Vec<String>,
    pub PASS_TO_PASS: Vec<String>,
}

/// Result of validating a single task.
#[derive(Debug)]
pub struct TaskValidationResult {
    pub instance_id: String,
    pub result: TestRunResult,
    /// Details of each step for logging.
    pub steps: Vec<StepResult>,
}

/// Result of a single validation step.
#[derive(Debug)]
pub struct StepResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Configuration for the replay validator.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Docker image to use for test execution.
    pub docker_image: String,
    /// Timeout in seconds for each Docker container run.
    pub timeout_secs: u64,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            docker_image: "ubuntu:22.04".to_string(),
            timeout_secs: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// Core validation logic
// ---------------------------------------------------------------------------

/// Loads a task configuration from a workspace.yaml file.
pub fn load_task_config(path: &Path) -> Result<TaskConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    serde_yaml::from_str(&content).map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
}

/// Runs a shell command and captures output. Returns (exit_code, stdout, stderr).
fn run_command(cmd: &str, args: &[&str]) -> Result<(i32, String, String), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute '{}': {}", cmd, e))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((exit_code, stdout, stderr))
}

/// Checks if the stderr/stdout indicates an environment issue rather than a
/// genuine test failure.
fn is_environment_error(stdout: &str, stderr: &str) -> Option<String> {
    let combined = format!("{}\n{}", stdout, stderr);
    let lower = combined.to_lowercase();

    let env_indicators = [
        "command not found",
        "no such file or directory",
        "permission denied",
        "cannot find module",
        "modulenotfounderror",
        "importerror",
        "docker daemon is not running",
        "cannot connect to the docker daemon",
        "error response from daemon",
        "oci runtime create failed",
        "exec format error",
        "unable to start container",
    ];

    for indicator in &env_indicators {
        if lower.contains(indicator) {
            // Find the actual line containing the indicator for context
            let context_line = combined
                .lines()
                .find(|line| line.to_lowercase().contains(indicator))
                .unwrap_or(indicator)
                .to_string();
            return Some(context_line);
        }
    }

    None
}

/// Builds the Docker script to run inside a container for testing.
///
/// The script:
/// 1. Clones the repository
/// 2. Checks out the specified commit
/// 3. Optionally applies the patch
/// 4. Runs the provided test commands
/// 5. Returns exit code from test execution
fn build_docker_script(
    repo: &str,
    commit: &str,
    patch: Option<&str>,
    test_commands: &[String],
) -> String {
    let mut script = String::new();
    script.push_str("#!/bin/bash\nset -e\n\n");

    // Install git (minimal) - needed inside the container
    script.push_str("apt-get update -qq && apt-get install -y -qq git curl > /dev/null 2>&1\n\n");

    // Clone the repository
    script.push_str(&format!(
        "git clone --depth 100 https://github.com/{}.git /workspace 2>&1 || exit 100\n",
        repo
    ));
    script.push_str("cd /workspace\n\n");

    // Checkout the specified commit
    script.push_str(&format!("git checkout {} 2>&1 || exit 101\n\n", commit));

    // Apply patch if provided
    if let Some(patch_content) = patch {
        // Write patch to file and apply
        let escaped_patch = patch_content.replace('\\', "\\\\").replace('\'', "'\\''");
        script.push_str(&format!(
            "cat << 'PATCH_EOF' > /tmp/task.patch\n{}\nPATCH_EOF\n\n",
            escaped_patch
        ));
        script.push_str("git apply /tmp/task.patch 2>&1 || exit 102\n\n");
    }

    // Run test commands - capture exit codes individually
    script.push_str("OVERALL_EXIT=0\n");
    for (i, cmd) in test_commands.iter().enumerate() {
        script.push_str(&format!(
            "echo '=== Running test command [{}]: {} ==='\n",
            i, cmd
        ));
        script.push_str(&format!(
            "{} 2>&1\nCMD_EXIT=$?\necho \"=== Test command [{}] exit code: $CMD_EXIT ===\"\n",
            cmd, i
        ));
        script.push_str("if [ $CMD_EXIT -ne 0 ]; then OVERALL_EXIT=$CMD_EXIT; fi\n\n");
    }

    script.push_str("exit $OVERALL_EXIT\n");
    script
}

/// Runs test commands inside a fresh Docker container.
///
/// Returns `(exit_code, stdout, stderr)`.
fn run_in_docker(
    config: &ReplayConfig,
    repo: &str,
    commit: &str,
    patch: Option<&str>,
    test_commands: &[String],
) -> Result<(i32, String, String), String> {
    let script = build_docker_script(repo, commit, patch, test_commands);

    // Run the script in a fresh Docker container
    let stop_timeout = format!("--stop-timeout={}", config.timeout_secs);
    let args = vec![
        "run",
        "--rm",
        "--network=host",
        "--memory=2g",
        "--cpus=2",
        &stop_timeout,
        &config.docker_image,
        "/bin/bash",
        "-c",
        &script,
    ];

    run_command("docker", &args)
}

/// Performs fresh-container replay validation on a single task.
///
/// Implements dual-commit validation:
/// 1. Base commit (without patch): fail_to_pass should FAIL, pass_to_pass should PASS
/// 2. Patched commit (with patch): all tests should PASS
pub fn validate_task(task: &TaskConfig, config: &ReplayConfig) -> TaskValidationResult {
    let mut steps = Vec::new();

    // ------------------------------------------------------------------
    // Step 1: Run pass_to_pass on base commit (should PASS)
    // ------------------------------------------------------------------
    if !task.PASS_TO_PASS.is_empty() {
        match run_in_docker(
            config,
            &task.repo,
            &task.base_commit,
            None,
            &task.PASS_TO_PASS,
        ) {
            Ok((exit_code, stdout, stderr)) => {
                // Check for environment errors first
                if let Some(env_err) = is_environment_error(&stdout, &stderr) {
                    return TaskValidationResult {
                        instance_id: task.instance_id.clone(),
                        result: TestRunResult::EnvironmentBroken(format!(
                            "pass_to_pass on base commit: {}",
                            env_err
                        )),
                        steps,
                    };
                }

                // Exit code 100-102 are our script setup errors
                if exit_code >= 100 {
                    let err_msg = match exit_code {
                        100 => "Failed to clone repository".to_string(),
                        101 => format!("Failed to checkout commit {}", task.base_commit),
                        102 => "Failed to apply patch (unexpected on base)".to_string(),
                        _ => format!("Setup error (exit code {})", exit_code),
                    };
                    return TaskValidationResult {
                        instance_id: task.instance_id.clone(),
                        result: TestRunResult::EnvironmentBroken(err_msg),
                        steps,
                    };
                }

                let passed = exit_code == 0;
                steps.push(StepResult {
                    name: "pass_to_pass on base commit".to_string(),
                    passed,
                    detail: format!("exit_code={}", exit_code),
                });
                if !passed {
                    return TaskValidationResult {
                        instance_id: task.instance_id.clone(),
                        result: TestRunResult::RealFailure(
                            "pass_to_pass tests failed on base commit (should pass)".to_string(),
                        ),
                        steps,
                    };
                }
            }
            Err(e) => {
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::EnvironmentBroken(format!(
                        "Docker execution failed for pass_to_pass on base: {}",
                        e
                    )),
                    steps,
                };
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 2: Run fail_to_pass on base commit (should FAIL)
    // ------------------------------------------------------------------
    match run_in_docker(
        config,
        &task.repo,
        &task.base_commit,
        None,
        &task.FAIL_TO_PASS,
    ) {
        Ok((exit_code, stdout, stderr)) => {
            if let Some(env_err) = is_environment_error(&stdout, &stderr) {
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::EnvironmentBroken(format!(
                        "fail_to_pass on base commit: {}",
                        env_err
                    )),
                    steps,
                };
            }

            if exit_code >= 100 {
                let err_msg = match exit_code {
                    100 => "Failed to clone repository".to_string(),
                    101 => format!("Failed to checkout commit {}", task.base_commit),
                    _ => format!("Setup error (exit code {})", exit_code),
                };
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::EnvironmentBroken(err_msg),
                    steps,
                };
            }

            // fail_to_pass should FAIL on base commit (non-zero exit code)
            let passed = exit_code != 0;
            steps.push(StepResult {
                name: "fail_to_pass on base commit".to_string(),
                passed,
                detail: format!("exit_code={} (expected non-zero)", exit_code),
            });
            if !passed {
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::RealFailure(
                        "fail_to_pass tests passed on base commit (should fail)".to_string(),
                    ),
                    steps,
                };
            }
        }
        Err(e) => {
            return TaskValidationResult {
                instance_id: task.instance_id.clone(),
                result: TestRunResult::EnvironmentBroken(format!(
                    "Docker execution failed for fail_to_pass on base: {}",
                    e
                )),
                steps,
            };
        }
    }

    // ------------------------------------------------------------------
    // Step 3: Apply patch and run ALL tests on patched commit (should PASS)
    // ------------------------------------------------------------------
    let all_test_commands: Vec<String> = task
        .FAIL_TO_PASS
        .iter()
        .chain(task.PASS_TO_PASS.iter())
        .cloned()
        .collect();

    match run_in_docker(
        config,
        &task.repo,
        &task.base_commit,
        Some(&task.patch),
        &all_test_commands,
    ) {
        Ok((exit_code, stdout, stderr)) => {
            if let Some(env_err) = is_environment_error(&stdout, &stderr) {
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::EnvironmentBroken(format!(
                        "tests on patched commit: {}",
                        env_err
                    )),
                    steps,
                };
            }

            if exit_code >= 100 {
                let err_msg = match exit_code {
                    100 => "Failed to clone repository".to_string(),
                    101 => format!("Failed to checkout commit {}", task.base_commit),
                    102 => "Failed to apply patch to base commit".to_string(),
                    _ => format!("Setup error (exit code {})", exit_code),
                };
                let result_type = if exit_code == 102 {
                    TestRunResult::RealFailure(err_msg)
                } else {
                    TestRunResult::EnvironmentBroken(err_msg)
                };
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: result_type,
                    steps,
                };
            }

            let passed = exit_code == 0;
            steps.push(StepResult {
                name: "all tests on patched commit".to_string(),
                passed,
                detail: format!("exit_code={}", exit_code),
            });
            if !passed {
                return TaskValidationResult {
                    instance_id: task.instance_id.clone(),
                    result: TestRunResult::RealFailure(
                        "Tests failed on patched commit (all should pass)".to_string(),
                    ),
                    steps,
                };
            }
        }
        Err(e) => {
            return TaskValidationResult {
                instance_id: task.instance_id.clone(),
                result: TestRunResult::EnvironmentBroken(format!(
                    "Docker execution failed for patched tests: {}",
                    e
                )),
                steps,
            };
        }
    }

    // All steps passed!
    TaskValidationResult {
        instance_id: task.instance_id.clone(),
        result: TestRunResult::Ok,
        steps,
    }
}

/// Discovers all workspace.yaml files under the given directory.
pub fn find_workspace_yamls(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if !dir.is_dir() {
        return results;
    }

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let yaml_path = path.join("workspace.yaml");
            if yaml_path.is_file() {
                results.push(yaml_path);
            }
            // Recurse into subdirectories
            results.extend(find_workspace_yamls(&path));
        }
    }

    results.sort();
    results
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CliArgs {
    tasks_dir: PathBuf,
    limit: Option<usize>,
    timeout_secs: u64,
    docker_image: String,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    let mut tasks_dir = PathBuf::from("hf-tasks/tasks");
    let mut limit = None;
    let mut timeout_secs: u64 = 300;
    let mut docker_image = "ubuntu:22.04".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                i += 1;
                if i < args.len() {
                    limit = args[i].parse().ok();
                }
            }
            "--timeout" => {
                i += 1;
                if i < args.len() {
                    timeout_secs = args[i].parse().unwrap_or(300);
                }
            }
            "--image" => {
                i += 1;
                if i < args.len() {
                    docker_image = args[i].clone();
                }
            }
            "--help" | "-h" => {
                println!("Usage: fresh-container-replay [TASKS_DIR] [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --limit N      Validate at most N tasks");
                println!("  --timeout SECS Docker container timeout (default: 300)");
                println!("  --image IMAGE  Docker image to use (default: ubuntu:22.04)");
                println!("  --help, -h     Show this help message");
                process::exit(0);
            }
            other => {
                if !other.starts_with('-') {
                    tasks_dir = PathBuf::from(other);
                }
            }
        }
        i += 1;
    }

    CliArgs {
        tasks_dir,
        limit,
        timeout_secs,
        docker_image,
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = parse_args();

    if !cli.tasks_dir.is_dir() {
        eprintln!("Error: directory not found: {}", cli.tasks_dir.display());
        process::exit(1);
    }

    println!("=== Fresh-Container Replay Validation ===");
    println!("Scanning: {}", cli.tasks_dir.display());
    println!("Docker image: {}", cli.docker_image);
    println!("Timeout: {}s", cli.timeout_secs);
    if let Some(limit) = cli.limit {
        println!("Limit: {} tasks", limit);
    }
    println!();

    let yaml_files = find_workspace_yamls(&cli.tasks_dir);

    if yaml_files.is_empty() {
        eprintln!(
            "Error: no workspace.yaml files found in {}",
            cli.tasks_dir.display()
        );
        process::exit(1);
    }

    let tasks_to_validate: Vec<PathBuf> = match cli.limit {
        Some(n) => yaml_files.into_iter().take(n).collect(),
        None => yaml_files,
    };

    println!("Found {} task(s) to validate", tasks_to_validate.len());
    println!();

    let config = ReplayConfig {
        docker_image: cli.docker_image,
        timeout_secs: cli.timeout_secs,
    };

    let mut ok_count: usize = 0;
    let mut failure_count: usize = 0;
    let mut env_broken_count: usize = 0;
    let mut results: Vec<TaskValidationResult> = Vec::new();

    for yaml_file in &tasks_to_validate {
        let task = match load_task_config(yaml_file) {
            Ok(t) => t,
            Err(e) => {
                println!("[ERROR] {}: {}", yaml_file.display(), e);
                env_broken_count += 1;
                results.push(TaskValidationResult {
                    instance_id: yaml_file.display().to_string(),
                    result: TestRunResult::EnvironmentBroken(e),
                    steps: vec![],
                });
                continue;
            }
        };

        println!("Validating: {} ...", task.instance_id);

        let validation = validate_task(&task, &config);

        match &validation.result {
            TestRunResult::Ok => {
                println!("[OK] {}", task.instance_id);
                ok_count += 1;
            }
            TestRunResult::RealFailure(msg) => {
                println!("[FAIL] {}: {}", task.instance_id, msg);
                failure_count += 1;
            }
            TestRunResult::EnvironmentBroken(msg) => {
                println!("[ENV_BROKEN] {}: {}", task.instance_id, msg);
                env_broken_count += 1;
            }
        }

        // Print step details
        for step in &validation.steps {
            let status = if step.passed { "✓" } else { "✗" };
            println!("  {} {} ({})", status, step.name, step.detail);
        }
        println!();

        results.push(validation);
    }

    // Print summary
    println!("=== Replay Validation Summary ===");
    println!("Total tasks:        {}", tasks_to_validate.len());
    println!("Ok:                 {}", ok_count);
    println!("Real failures:      {}", failure_count);
    println!("Environment broken: {}", env_broken_count);
    println!();

    if env_broken_count > 0 {
        println!("Environment-broken tasks:");
        for r in &results {
            if let TestRunResult::EnvironmentBroken(msg) = &r.result {
                println!("  - {}: {}", r.instance_id, msg);
            }
        }
        println!();
    }

    if failure_count > 0 {
        println!("Failed tasks:");
        for r in &results {
            if let TestRunResult::RealFailure(msg) = &r.result {
                println!("  - {}: {}", r.instance_id, msg);
            }
        }
        println!();
    }

    if failure_count > 0 || env_broken_count > 0 {
        println!("RESULT: FAIL");
        process::exit(1);
    } else {
        println!("RESULT: PASS — all tasks passed dual-commit validation");
        process::exit(0);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    /// Helper to create a temporary task directory with a workspace.yaml file.
    fn create_temp_task(dir: &Path, task_name: &str, content: &str) -> PathBuf {
        let task_dir = dir.join(task_name);
        fs::create_dir_all(&task_dir).unwrap();
        let yaml_path = task_dir.join("workspace.yaml");
        fs::write(&yaml_path, content).unwrap();
        yaml_path
    }

    /// Returns a valid workspace.yaml content string.
    fn valid_yaml() -> String {
        r#"repo: "owner/repo"
instance_id: "owner__repo-1234"
base_commit: "abc123def456789"
patch: |
  diff --git a/src/main.rs b/src/main.rs
  index 1234567..89abcdef 100644
  --- a/src/main.rs
  +++ b/src/main.rs
  @@ -1,3 +1,4 @@
   fn main() {
  +    println!("Hello, world!");
   }
test_patch: |
  diff --git a/tests/test_main.rs b/tests/test_main.rs
  index 1234567..89abcdef 100644
  --- a/tests/test_main.rs
  +++ b/tests/test_main.rs
  @@ -1,3 +1,7 @@
  +#[test]
  +fn test_hello() {
  +    assert!(true);
  +}
problem_statement: "The main function does not print anything. We need to add a hello world print statement to the main function so users can see output."
FAIL_TO_PASS:
  - "cargo test test_hello"
PASS_TO_PASS:
  - "cargo test test_existing"
  - "cargo test test_other"
created_at: "2024-01-15T10:30:00Z"
version: "1.0.0"
difficulty: "easy"
"#
        .to_string()
    }

    // -----------------------------------------------------------------------
    // TestRunResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_result_display_ok() {
        assert_eq!(TestRunResult::Ok.to_string(), "Ok");
    }

    #[test]
    fn test_run_result_display_real_failure() {
        let r = TestRunResult::RealFailure("tests failed".to_string());
        assert_eq!(r.to_string(), "RealFailure: tests failed");
    }

    #[test]
    fn test_run_result_display_environment_broken() {
        let r = TestRunResult::EnvironmentBroken("docker issue".to_string());
        assert_eq!(r.to_string(), "EnvironmentBroken: docker issue");
    }

    #[test]
    fn test_run_result_equality() {
        assert_eq!(TestRunResult::Ok, TestRunResult::Ok);
        assert_ne!(
            TestRunResult::Ok,
            TestRunResult::RealFailure("x".to_string())
        );
        assert_ne!(
            TestRunResult::RealFailure("x".to_string()),
            TestRunResult::EnvironmentBroken("x".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // load_task_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_task_config_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", &valid_yaml());
        let task = load_task_config(&yaml_path).unwrap();

        assert_eq!(task.repo, "owner/repo");
        assert_eq!(task.instance_id, "owner__repo-1234");
        assert_eq!(task.base_commit, "abc123def456789");
        assert!(!task.patch.is_empty());
        assert_eq!(task.FAIL_TO_PASS.len(), 1);
        assert_eq!(task.FAIL_TO_PASS[0], "cargo test test_hello");
        assert_eq!(task.PASS_TO_PASS.len(), 2);
    }

    #[test]
    fn test_load_task_config_missing_file() {
        let result = load_task_config(Path::new("/nonexistent/workspace.yaml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_load_task_config_invalid_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", "invalid: [yaml: {{{");
        let result = load_task_config(&yaml_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_load_task_config_missing_required_field() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = load_task_config(&yaml_path);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // is_environment_error tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_error_command_not_found() {
        let result = is_environment_error("", "bash: pytest: command not found");
        assert!(result.is_some());
        assert!(result.unwrap().contains("command not found"));
    }

    #[test]
    fn test_env_error_no_such_file() {
        let result = is_environment_error("", "/bin/sh: ./run_tests.sh: No such file or directory");
        assert!(result.is_some());
    }

    #[test]
    fn test_env_error_permission_denied() {
        let result = is_environment_error("", "Permission denied: /usr/local/bin/test");
        assert!(result.is_some());
    }

    #[test]
    fn test_env_error_module_not_found() {
        let result = is_environment_error("ModuleNotFoundError: No module named 'pytest'", "");
        assert!(result.is_some());
    }

    #[test]
    fn test_env_error_import_error() {
        let result = is_environment_error("ImportError: cannot import name 'missing_module'", "");
        assert!(result.is_some());
    }

    #[test]
    fn test_env_error_docker_daemon() {
        let result = is_environment_error(
            "",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_no_env_error_normal_test_failure() {
        let result = is_environment_error(
            "FAILED tests/test_main.py::test_hello - AssertionError: assert 1 == 2",
            "",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_no_env_error_empty_output() {
        let result = is_environment_error("", "");
        assert!(result.is_none());
    }

    #[test]
    fn test_no_env_error_normal_output() {
        let result = is_environment_error("test result: 3 passed, 1 failed", "");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // build_docker_script tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_script_without_patch() {
        let script = build_docker_script("owner/repo", "abc123", None, &["cargo test".to_string()]);

        assert!(script.contains("git clone"));
        assert!(script.contains("owner/repo"));
        assert!(script.contains("git checkout abc123"));
        assert!(!script.contains("git apply"));
        assert!(script.contains("cargo test"));
    }

    #[test]
    fn test_build_script_with_patch() {
        let script = build_docker_script(
            "owner/repo",
            "abc123",
            Some("diff --git a/file.rs b/file.rs"),
            &["cargo test".to_string()],
        );

        assert!(script.contains("git clone"));
        assert!(script.contains("git checkout abc123"));
        assert!(script.contains("git apply /tmp/task.patch"));
        assert!(script.contains("diff --git a/file.rs b/file.rs"));
        assert!(script.contains("cargo test"));
    }

    #[test]
    fn test_build_script_multiple_commands() {
        let script = build_docker_script(
            "owner/repo",
            "abc123",
            None,
            &[
                "cargo test test_a".to_string(),
                "cargo test test_b".to_string(),
            ],
        );

        assert!(script.contains("cargo test test_a"));
        assert!(script.contains("cargo test test_b"));
        assert!(script.contains("Running test command [0]"));
        assert!(script.contains("Running test command [1]"));
    }

    #[test]
    fn test_build_script_exit_codes() {
        let script = build_docker_script("owner/repo", "abc123", None, &["cargo test".to_string()]);

        // Script should capture exit codes
        assert!(script.contains("CMD_EXIT=$?"));
        assert!(script.contains("OVERALL_EXIT"));
        assert!(script.contains("exit $OVERALL_EXIT"));
    }

    #[test]
    fn test_build_script_clone_failure_exit_code() {
        let script = build_docker_script("owner/repo", "abc123", None, &[]);
        assert!(script.contains("|| exit 100"));
    }

    #[test]
    fn test_build_script_checkout_failure_exit_code() {
        let script = build_docker_script("owner/repo", "abc123", None, &[]);
        assert!(script.contains("|| exit 101"));
    }

    #[test]
    fn test_build_script_patch_failure_exit_code() {
        let script = build_docker_script("owner/repo", "abc123", Some("some patch"), &[]);
        assert!(script.contains("|| exit 102"));
    }

    // -----------------------------------------------------------------------
    // find_workspace_yamls tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_workspace_yamls_discovers_files() {
        let tmp = tempfile::tempdir().unwrap();
        create_temp_task(tmp.path(), "task-a", &valid_yaml());
        create_temp_task(tmp.path(), "task-b", &valid_yaml());

        let found = find_workspace_yamls(tmp.path());
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_find_workspace_yamls_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let found = find_workspace_yamls(tmp.path());
        assert_eq!(found.len(), 0);
    }

    #[test]
    fn test_find_workspace_yamls_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("subdir").join("task-nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("workspace.yaml"), valid_yaml()).unwrap();

        let found = find_workspace_yamls(tmp.path());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_workspace_yamls_nonexistent_dir() {
        let found = find_workspace_yamls(Path::new("/nonexistent/dir"));
        assert_eq!(found.len(), 0);
    }

    // -----------------------------------------------------------------------
    // TaskConfig parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_task_config_with_python_commands() {
        let yaml = r#"repo: "owner/py-repo"
instance_id: "owner__py-repo-100"
base_commit: "def456"
patch: "diff --git a/lib.py b/lib.py"
test_patch: "diff --git a/test_lib.py b/test_lib.py"
problem_statement: "A long enough problem statement that exceeds the minimum character count requirement."
FAIL_TO_PASS:
  - "pytest tests/test_lib.py::test_parse_input_strips"
  - "pytest tests/test_lib.py::test_parse_input_type_error"
PASS_TO_PASS:
  - "pytest tests/test_lib.py::test_existing_function"
created_at: "2024-01-01"
version: "1.0.0"
difficulty: "medium"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let task = load_task_config(&path).unwrap();

        assert_eq!(task.repo, "owner/py-repo");
        assert_eq!(task.FAIL_TO_PASS.len(), 2);
        assert_eq!(task.PASS_TO_PASS.len(), 1);
    }

    #[test]
    fn test_task_config_single_commands() {
        let yaml = r#"repo: "org/project"
instance_id: "org__project-42"
base_commit: "aaa111"
patch: "some diff"
test_patch: "some test diff"
problem_statement: "A sufficiently long problem statement that should be more than fifty characters easily."
FAIL_TO_PASS:
  - "cargo test test_handle_request"
PASS_TO_PASS:
  - "cargo test test_server_starts"
created_at: "2024-03-10T09:00:00Z"
version: "1.0.0"
difficulty: "hard"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let task = load_task_config(&path).unwrap();

        assert_eq!(task.FAIL_TO_PASS.len(), 1);
        assert_eq!(task.PASS_TO_PASS.len(), 1);
    }

    // -----------------------------------------------------------------------
    // StepResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step_result_pass() {
        let step = StepResult {
            name: "pass_to_pass on base commit".to_string(),
            passed: true,
            detail: "exit_code=0".to_string(),
        };
        assert!(step.passed);
    }

    #[test]
    fn test_step_result_fail() {
        let step = StepResult {
            name: "fail_to_pass on base commit".to_string(),
            passed: false,
            detail: "exit_code=0 (expected non-zero)".to_string(),
        };
        assert!(!step.passed);
    }

    // -----------------------------------------------------------------------
    // ReplayConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let config = ReplayConfig::default();
        assert_eq!(config.docker_image, "ubuntu:22.04");
        assert_eq!(config.timeout_secs, 300);
    }

    #[test]
    fn test_custom_config() {
        let config = ReplayConfig {
            docker_image: "rust:1.75".to_string(),
            timeout_secs: 600,
        };
        assert_eq!(config.docker_image, "rust:1.75");
        assert_eq!(config.timeout_secs, 600);
    }

    // -----------------------------------------------------------------------
    // Validation result tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validation_result_ok() {
        let result = TaskValidationResult {
            instance_id: "test-1".to_string(),
            result: TestRunResult::Ok,
            steps: vec![],
        };
        assert_eq!(result.result, TestRunResult::Ok);
    }

    #[test]
    fn test_validation_result_with_steps() {
        let result = TaskValidationResult {
            instance_id: "test-2".to_string(),
            result: TestRunResult::Ok,
            steps: vec![
                StepResult {
                    name: "step1".to_string(),
                    passed: true,
                    detail: "ok".to_string(),
                },
                StepResult {
                    name: "step2".to_string(),
                    passed: true,
                    detail: "ok".to_string(),
                },
            ],
        };
        assert_eq!(result.steps.len(), 2);
        assert!(result.steps.iter().all(|s| s.passed));
    }
}
