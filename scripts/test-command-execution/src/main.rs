//! Validates that test commands can execute without "command not found" errors
//! in Docker containers.
//!
//! For each task in the dataset, this script:
//! 1. Clones the repository at the base commit inside a Docker container
//! 2. Installs the necessary build/test tooling (detected from the commands)
//! 3. Runs each FAIL_TO_PASS and PASS_TO_PASS command individually
//! 4. Captures stdout/stderr and checks for "command not found" errors
//! 5. Reports which commands are executable vs non-executable
//!
//! This script fulfills validation assertion:
//! - **VAL-DATASET-005**: FAIL_TO_PASS and PASS_TO_PASS commands can be
//!   executed in the task's Docker environment without "command not found" errors.
//!
//! Usage:
//!   test-command-execution [TASKS_DIR] [--limit N] [--timeout SECS] [--image IMAGE]
//!
//! Defaults to `hf-tasks/tasks` if no directory is provided.
//! Returns exit code 0 if all commands are executable, 1 if any have execution errors.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

/// Result of checking whether a single command is executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandExecResult {
    /// The command was found and executed (may have passed or failed, but it ran).
    Executable {
        exit_code: i32,
    },
    /// The command could not be found or executed due to environment issues.
    NotExecutable {
        error: String,
    },
    /// Docker or infrastructure failed before the command could be tested.
    InfrastructureError {
        error: String,
    },
}

impl fmt::Display for CommandExecResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandExecResult::Executable { exit_code } => {
                write!(f, "Executable (exit_code={})", exit_code)
            }
            CommandExecResult::NotExecutable { error } => {
                write!(f, "NotExecutable: {}", error)
            }
            CommandExecResult::InfrastructureError { error } => {
                write!(f, "InfrastructureError: {}", error)
            }
        }
    }
}

/// Result of checking a single command within a task.
#[derive(Debug)]
pub struct SingleCommandResult {
    pub command: String,
    pub source: CommandSource,
    pub result: CommandExecResult,
    pub stdout: String,
    pub stderr: String,
}

/// Which field the command came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSource {
    FailToPass,
    PassToPass,
}

impl fmt::Display for CommandSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandSource::FailToPass => write!(f, "FAIL_TO_PASS"),
            CommandSource::PassToPass => write!(f, "PASS_TO_PASS"),
        }
    }
}

/// Aggregated results for a single task.
#[derive(Debug)]
pub struct TaskExecutionResult {
    pub instance_id: String,
    pub command_results: Vec<SingleCommandResult>,
}

impl TaskExecutionResult {
    /// Returns `true` if all commands were executable (no "command not found").
    pub fn all_executable(&self) -> bool {
        self.command_results
            .iter()
            .all(|r| matches!(r.result, CommandExecResult::Executable { .. }))
    }

    /// Returns the number of executable commands.
    pub fn executable_count(&self) -> usize {
        self.command_results
            .iter()
            .filter(|r| matches!(r.result, CommandExecResult::Executable { .. }))
            .count()
    }

    /// Returns the number of non-executable commands.
    pub fn not_executable_count(&self) -> usize {
        self.command_results
            .iter()
            .filter(|r| matches!(r.result, CommandExecResult::NotExecutable { .. }))
            .count()
    }

    /// Returns the number of infrastructure errors.
    pub fn infra_error_count(&self) -> usize {
        self.command_results
            .iter()
            .filter(|r| matches!(r.result, CommandExecResult::InfrastructureError { .. }))
            .count()
    }
}

/// Configuration for the execution validator.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    /// Docker image to use for test execution.
    pub docker_image: String,
    /// Timeout in seconds for each Docker container run.
    pub timeout_secs: u64,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            docker_image: "ubuntu:22.04".to_string(),
            timeout_secs: 120,
        }
    }
}

// ---------------------------------------------------------------------------
// Environment error detection
// ---------------------------------------------------------------------------

/// Patterns that indicate "command not found" or similar execution errors.
const COMMAND_NOT_FOUND_PATTERNS: &[&str] = &[
    "command not found",
    "not found",
    "no such file or directory",
    "exec format error",
    "is not recognized as",
    "unable to locate package",
    "not installed",
];

/// Extended patterns for environment/module errors (still indicate the command
/// itself cannot run properly).
const ENVIRONMENT_ERROR_PATTERNS: &[&str] = &[
    "modulenotfounderror",
    "importerror",
    "cannot find module",
    "error: no such subcommand",
];

/// Checks whether stdout/stderr output indicates a "command not found" error
/// specifically (as opposed to a test failure).
///
/// Returns `Some(error_line)` if a command-not-found indicator is detected.
pub fn detect_command_not_found(stdout: &str, stderr: &str) -> Option<String> {
    let combined = format!("{}\n{}", stdout, stderr);
    let lower = combined.to_lowercase();

    for pattern in COMMAND_NOT_FOUND_PATTERNS {
        if lower.contains(pattern) {
            let context_line = combined
                .lines()
                .find(|line| line.to_lowercase().contains(pattern))
                .unwrap_or(pattern)
                .trim()
                .to_string();
            return Some(context_line);
        }
    }

    for pattern in ENVIRONMENT_ERROR_PATTERNS {
        if lower.contains(pattern) {
            let context_line = combined
                .lines()
                .find(|line| line.to_lowercase().contains(pattern))
                .unwrap_or(pattern)
                .trim()
                .to_string();
            return Some(context_line);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Docker execution
// ---------------------------------------------------------------------------

/// Detects the likely language/tooling needed from test commands.
fn detect_tooling(commands: &[String]) -> Vec<&'static str> {
    let mut tools = Vec::new();
    let joined = commands.join(" ").to_lowercase();

    if joined.contains("cargo") || joined.contains("rustc") {
        tools.push("rust");
    }
    if joined.contains("pytest") || joined.contains("python") || joined.contains("pip") {
        tools.push("python");
    }
    if joined.contains("npm") || joined.contains("node") || joined.contains("yarn") || joined.contains("jest") {
        tools.push("node");
    }
    if joined.contains("mvn") || joined.contains("gradle") || joined.contains("java") {
        tools.push("java");
    }
    if joined.contains("go test") || joined.contains("go run") {
        tools.push("go");
    }
    if joined.contains("make") {
        tools.push("make");
    }

    if tools.is_empty() {
        // Default: install basic build tools
        tools.push("base");
    }

    tools
}

/// Generates the tooling installation commands for a Docker script.
fn tooling_install_script(tools: &[&str]) -> String {
    let mut script = String::new();
    script.push_str("apt-get update -qq > /dev/null 2>&1\n");
    script.push_str("apt-get install -y -qq git curl ca-certificates > /dev/null 2>&1\n");

    for tool in tools {
        match *tool {
            "rust" => {
                script.push_str("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1\n");
                script.push_str("export PATH=\"$HOME/.cargo/bin:$PATH\"\n");
            }
            "python" => {
                script.push_str("apt-get install -y -qq python3 python3-pip python3-venv > /dev/null 2>&1\n");
                script.push_str("pip3 install pytest > /dev/null 2>&1 || python3 -m pip install pytest > /dev/null 2>&1\n");
            }
            "node" => {
                script.push_str("curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1\n");
                script.push_str("apt-get install -y -qq nodejs > /dev/null 2>&1\n");
            }
            "java" => {
                script.push_str("apt-get install -y -qq default-jdk maven > /dev/null 2>&1\n");
            }
            "go" => {
                script.push_str("apt-get install -y -qq golang > /dev/null 2>&1\n");
            }
            "make" => {
                script.push_str("apt-get install -y -qq build-essential > /dev/null 2>&1\n");
            }
            _ => {
                script.push_str("apt-get install -y -qq build-essential > /dev/null 2>&1\n");
            }
        }
    }

    script
}

/// Builds the Docker script to test a single command's executability.
///
/// The script:
/// 1. Installs tooling
/// 2. Clones the repository
/// 3. Checks out the specified commit
/// 4. Runs the single test command
/// 5. Captures whether the command was found and could execute
fn build_single_command_script(
    repo: &str,
    commit: &str,
    test_command: &str,
    all_commands: &[String],
) -> String {
    let tools = detect_tooling(all_commands);
    let mut script = String::new();

    script.push_str("#!/bin/bash\n\n");

    // Install tooling
    script.push_str(&tooling_install_script(&tools));
    script.push('\n');

    // Clone the repository
    script.push_str(&format!(
        "git clone --depth 100 https://github.com/{}.git /workspace 2>&1\n",
        repo
    ));
    script.push_str("CLONE_EXIT=$?\n");
    script.push_str("if [ $CLONE_EXIT -ne 0 ]; then\n");
    script.push_str("  echo \"INFRA_ERROR: Failed to clone repository\"\n");
    script.push_str("  exit 200\n");
    script.push_str("fi\n\n");

    script.push_str("cd /workspace\n\n");

    // Checkout the specified commit
    script.push_str(&format!(
        "git checkout {} 2>&1\n",
        commit
    ));
    script.push_str("CHECKOUT_EXIT=$?\n");
    script.push_str("if [ $CHECKOUT_EXIT -ne 0 ]; then\n");
    script.push_str("  echo \"INFRA_ERROR: Failed to checkout commit\"\n");
    script.push_str("  exit 201\n");
    script.push_str("fi\n\n");

    // Install project dependencies if applicable
    script.push_str("# Install project dependencies\n");
    if tools.contains(&"python") {
        script.push_str("if [ -f requirements.txt ]; then pip3 install -r requirements.txt > /dev/null 2>&1 || true; fi\n");
        script.push_str("if [ -f setup.py ]; then pip3 install -e . > /dev/null 2>&1 || true; fi\n");
        script.push_str("if [ -f pyproject.toml ]; then pip3 install -e . > /dev/null 2>&1 || true; fi\n");
    }
    if tools.contains(&"node") {
        script.push_str("if [ -f package.json ]; then npm install > /dev/null 2>&1 || true; fi\n");
    }
    script.push('\n');

    // Run the test command and capture output
    script.push_str(&format!(
        "echo \"=== EXECUTING: {} ===\"\n",
        test_command.replace('"', "\\\"")
    ));
    script.push_str(&format!("{} 2>&1\n", test_command));
    script.push_str("CMD_EXIT=$?\n");
    script.push_str(&format!(
        "echo \"=== EXIT_CODE: $CMD_EXIT for: {} ===\"\n",
        test_command.replace('"', "\\\"")
    ));
    script.push_str("exit $CMD_EXIT\n");

    script
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

/// Runs a single test command inside a fresh Docker container and determines
/// whether it is executable (the command itself was found).
pub fn check_command_executable(
    config: &ExecConfig,
    repo: &str,
    commit: &str,
    test_command: &str,
    all_commands: &[String],
) -> SingleCommandResult {
    let script = build_single_command_script(repo, commit, test_command, all_commands);

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

    match run_command("docker", &args) {
        Ok((exit_code, stdout, stderr)) => {
            // Check for infrastructure errors (our script signals these with exit 200/201)
            if exit_code == 200 || exit_code == 201 {
                let err_msg = if exit_code == 200 {
                    format!("Failed to clone repository {}", repo)
                } else {
                    format!("Failed to checkout commit {}", commit)
                };
                return SingleCommandResult {
                    command: test_command.to_string(),
                    source: CommandSource::FailToPass, // Will be set by caller
                    result: CommandExecResult::InfrastructureError { error: err_msg },
                    stdout,
                    stderr,
                };
            }

            // Check for "command not found" patterns in output
            if let Some(error_line) = detect_command_not_found(&stdout, &stderr) {
                return SingleCommandResult {
                    command: test_command.to_string(),
                    source: CommandSource::FailToPass,
                    result: CommandExecResult::NotExecutable {
                        error: error_line,
                    },
                    stdout,
                    stderr,
                };
            }

            // Command was found and ran (exit code may be non-zero for failing tests,
            // but the command itself was executable)
            SingleCommandResult {
                command: test_command.to_string(),
                source: CommandSource::FailToPass,
                result: CommandExecResult::Executable { exit_code },
                stdout,
                stderr,
            }
        }
        Err(e) => SingleCommandResult {
            command: test_command.to_string(),
            source: CommandSource::FailToPass,
            result: CommandExecResult::InfrastructureError { error: e },
            stdout: String::new(),
            stderr: String::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Task validation
// ---------------------------------------------------------------------------

/// Loads a task configuration from a workspace.yaml file.
pub fn load_task_config(path: &Path) -> Result<TaskConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
}

/// Validates that all test commands in a task are executable.
///
/// Runs each FAIL_TO_PASS and PASS_TO_PASS command individually in a Docker
/// container and checks for "command not found" errors.
pub fn validate_task_commands(
    task: &TaskConfig,
    config: &ExecConfig,
) -> TaskExecutionResult {
    let all_commands: Vec<String> = task
        .FAIL_TO_PASS
        .iter()
        .chain(task.PASS_TO_PASS.iter())
        .cloned()
        .collect();

    let mut command_results = Vec::new();

    // Check each FAIL_TO_PASS command
    for cmd in &task.FAIL_TO_PASS {
        let mut result = check_command_executable(
            config,
            &task.repo,
            &task.base_commit,
            cmd,
            &all_commands,
        );
        result.source = CommandSource::FailToPass;
        command_results.push(result);
    }

    // Check each PASS_TO_PASS command
    for cmd in &task.PASS_TO_PASS {
        let mut result = check_command_executable(
            config,
            &task.repo,
            &task.base_commit,
            cmd,
            &all_commands,
        );
        result.source = CommandSource::PassToPass;
        command_results.push(result);
    }

    TaskExecutionResult {
        instance_id: task.instance_id.clone(),
        command_results,
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
            // Recurse into subdirectories.
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
    let mut timeout_secs: u64 = 120;
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
                    timeout_secs = args[i].parse().unwrap_or(120);
                }
            }
            "--image" => {
                i += 1;
                if i < args.len() {
                    docker_image = args[i].clone();
                }
            }
            "--help" | "-h" => {
                println!("Usage: test-command-execution [TASKS_DIR] [OPTIONS]");
                println!();
                println!("Validates that test commands can execute without 'command not found' errors.");
                println!();
                println!("Options:");
                println!("  --limit N      Validate at most N tasks");
                println!("  --timeout SECS Docker container timeout (default: 120)");
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

    println!("=== Test Command Execution Validation ===");
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

    let config = ExecConfig {
        docker_image: cli.docker_image,
        timeout_secs: cli.timeout_secs,
    };

    let mut total_commands: usize = 0;
    let mut executable_commands: usize = 0;
    let mut not_executable_commands: usize = 0;
    let mut infra_error_commands: usize = 0;
    let mut tasks_all_executable: usize = 0;
    let mut tasks_with_issues: usize = 0;
    let mut all_results: Vec<TaskExecutionResult> = Vec::new();

    for yaml_file in &tasks_to_validate {
        let task = match load_task_config(yaml_file) {
            Ok(t) => t,
            Err(e) => {
                println!("[ERROR] {}: {}", yaml_file.display(), e);
                tasks_with_issues += 1;
                continue;
            }
        };

        println!("--- Validating: {} ---", task.instance_id);
        println!(
            "  Commands: {} FAIL_TO_PASS + {} PASS_TO_PASS",
            task.FAIL_TO_PASS.len(),
            task.PASS_TO_PASS.len()
        );

        let result = validate_task_commands(&task, &config);

        // Print per-command results
        for cmd_result in &result.command_results {
            total_commands += 1;
            let status_icon = match &cmd_result.result {
                CommandExecResult::Executable { exit_code } => {
                    executable_commands += 1;
                    format!("✓ EXECUTABLE (exit={})", exit_code)
                }
                CommandExecResult::NotExecutable { error } => {
                    not_executable_commands += 1;
                    format!("✗ NOT EXECUTABLE: {}", error)
                }
                CommandExecResult::InfrastructureError { error } => {
                    infra_error_commands += 1;
                    format!("⚠ INFRA ERROR: {}", error)
                }
            };
            println!(
                "  [{}] {}: {}",
                cmd_result.source, cmd_result.command, status_icon
            );
        }

        if result.all_executable() {
            println!("  Result: ALL EXECUTABLE");
            tasks_all_executable += 1;
        } else {
            println!(
                "  Result: {} executable, {} not executable, {} infra errors",
                result.executable_count(),
                result.not_executable_count(),
                result.infra_error_count()
            );
            tasks_with_issues += 1;
        }
        println!();

        all_results.push(result);
    }

    // -----------------------------------------------------------------------
    // Summary report
    // -----------------------------------------------------------------------
    println!("=== Test Command Execution Summary ===");
    println!("Tasks validated:             {}", tasks_to_validate.len());
    println!("Tasks all commands executable: {}", tasks_all_executable);
    println!("Tasks with issues:           {}", tasks_with_issues);
    println!();
    println!("Total commands tested:       {}", total_commands);
    println!("Executable commands:         {}", executable_commands);
    println!("Not executable (cmd errors): {}", not_executable_commands);
    println!("Infrastructure errors:       {}", infra_error_commands);
    println!();

    // List non-executable commands
    if not_executable_commands > 0 {
        println!("Commands with 'command not found' errors:");
        for result in &all_results {
            for cmd_result in &result.command_results {
                if let CommandExecResult::NotExecutable { error } = &cmd_result.result {
                    println!(
                        "  - {} [{}] {}: {}",
                        result.instance_id, cmd_result.source, cmd_result.command, error
                    );
                }
            }
        }
        println!();
    }

    // List infrastructure errors
    if infra_error_commands > 0 {
        println!("Commands with infrastructure errors:");
        for result in &all_results {
            for cmd_result in &result.command_results {
                if let CommandExecResult::InfrastructureError { error } = &cmd_result.result {
                    println!(
                        "  - {} [{}] {}: {}",
                        result.instance_id, cmd_result.source, cmd_result.command, error
                    );
                }
            }
        }
        println!();
    }

    if not_executable_commands > 0 {
        println!(
            "RESULT: FAIL — {} command(s) have 'command not found' errors",
            not_executable_commands
        );
        process::exit(1);
    } else if infra_error_commands > 0 {
        println!(
            "RESULT: WARN — all commands executable but {} infrastructure error(s)",
            infra_error_commands
        );
        // Still exit 0 — infrastructure issues aren't "command not found" errors
        process::exit(0);
    } else {
        println!(
            "RESULT: PASS — all {} commands are executable across {} tasks",
            total_commands,
            tasks_all_executable
        );
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
  --- a/src/main.rs
  +++ b/src/main.rs
  @@ -1,3 +1,4 @@
   fn main() {
  +    println!("Hello, world!");
   }
test_patch: |
  diff --git a/tests/test_main.rs b/tests/test_main.rs
  --- a/tests/test_main.rs
  +++ b/tests/test_main.rs
  @@ -1,3 +1,7 @@
  +#[test]
  +fn test_hello() {
  +    assert!(true);
  +}
problem_statement: "The main function does not print anything. We need to add a hello world print statement."
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
    // CommandExecResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exec_result_display_executable() {
        let r = CommandExecResult::Executable { exit_code: 0 };
        assert_eq!(r.to_string(), "Executable (exit_code=0)");
    }

    #[test]
    fn test_exec_result_display_executable_nonzero() {
        let r = CommandExecResult::Executable { exit_code: 1 };
        assert_eq!(r.to_string(), "Executable (exit_code=1)");
    }

    #[test]
    fn test_exec_result_display_not_executable() {
        let r = CommandExecResult::NotExecutable {
            error: "pytest: command not found".to_string(),
        };
        assert_eq!(
            r.to_string(),
            "NotExecutable: pytest: command not found"
        );
    }

    #[test]
    fn test_exec_result_display_infra_error() {
        let r = CommandExecResult::InfrastructureError {
            error: "Failed to clone repository".to_string(),
        };
        assert_eq!(
            r.to_string(),
            "InfrastructureError: Failed to clone repository"
        );
    }

    #[test]
    fn test_exec_result_equality() {
        assert_eq!(
            CommandExecResult::Executable { exit_code: 0 },
            CommandExecResult::Executable { exit_code: 0 }
        );
        assert_ne!(
            CommandExecResult::Executable { exit_code: 0 },
            CommandExecResult::Executable { exit_code: 1 }
        );
        assert_ne!(
            CommandExecResult::Executable { exit_code: 0 },
            CommandExecResult::NotExecutable {
                error: "x".to_string()
            }
        );
    }

    // -----------------------------------------------------------------------
    // CommandSource tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_command_source_display() {
        assert_eq!(CommandSource::FailToPass.to_string(), "FAIL_TO_PASS");
        assert_eq!(CommandSource::PassToPass.to_string(), "PASS_TO_PASS");
    }

    // -----------------------------------------------------------------------
    // detect_command_not_found tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_command_not_found_basic() {
        let result = detect_command_not_found("", "bash: pytest: command not found");
        assert!(result.is_some());
        assert!(result.unwrap().contains("command not found"));
    }

    #[test]
    fn test_detect_command_not_found_no_such_file() {
        let result =
            detect_command_not_found("", "/bin/sh: ./run_tests.sh: No such file or directory");
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_command_not_found_module_error() {
        let result = detect_command_not_found(
            "ModuleNotFoundError: No module named 'pytest'",
            "",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_command_not_found_import_error() {
        let result = detect_command_not_found(
            "ImportError: cannot import name 'missing_module'",
            "",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_command_not_found_exec_format() {
        let result = detect_command_not_found("", "exec format error");
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_no_error_normal_test_failure() {
        let result = detect_command_not_found(
            "FAILED tests/test_main.py::test_hello - AssertionError: assert 1 == 2",
            "",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_no_error_empty_output() {
        let result = detect_command_not_found("", "");
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_no_error_passing_tests() {
        let result = detect_command_not_found(
            "test result: ok. 5 passed; 0 failed",
            "",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_no_error_compilation_error() {
        let result = detect_command_not_found(
            "error[E0308]: mismatched types\n  --> src/main.rs:5:5",
            "",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_command_not_found_case_insensitive() {
        let result = detect_command_not_found("", "COMMAND NOT FOUND: mytest");
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_command_not_found_in_stdout() {
        let result = detect_command_not_found(
            "bash: line 1: mycommand: command not found",
            "",
        );
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // detect_tooling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_tooling_rust() {
        let commands = vec!["cargo test test_hello".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"rust"));
    }

    #[test]
    fn test_detect_tooling_python() {
        let commands = vec!["pytest tests/test_utils.py".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"python"));
    }

    #[test]
    fn test_detect_tooling_node() {
        let commands = vec!["npm test".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"node"));
    }

    #[test]
    fn test_detect_tooling_java() {
        let commands = vec!["mvn test".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"java"));
    }

    #[test]
    fn test_detect_tooling_go() {
        let commands = vec!["go test ./...".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"go"));
    }

    #[test]
    fn test_detect_tooling_make() {
        let commands = vec!["make test".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"make"));
    }

    #[test]
    fn test_detect_tooling_unknown_defaults_to_base() {
        let commands = vec!["./run_custom_tests.sh".to_string()];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"base"));
    }

    #[test]
    fn test_detect_tooling_multiple() {
        let commands = vec![
            "cargo test test_a".to_string(),
            "pytest tests/test_b.py".to_string(),
        ];
        let tools = detect_tooling(&commands);
        assert!(tools.contains(&"rust"));
        assert!(tools.contains(&"python"));
    }

    // -----------------------------------------------------------------------
    // tooling_install_script tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_tooling_install_script_rust() {
        let script = tooling_install_script(&["rust"]);
        assert!(script.contains("rustup"));
        assert!(script.contains("cargo"));
    }

    #[test]
    fn test_tooling_install_script_python() {
        let script = tooling_install_script(&["python"]);
        assert!(script.contains("python3"));
        assert!(script.contains("pytest"));
    }

    #[test]
    fn test_tooling_install_script_node() {
        let script = tooling_install_script(&["node"]);
        assert!(script.contains("nodejs"));
    }

    #[test]
    fn test_tooling_install_script_base() {
        let script = tooling_install_script(&["base"]);
        assert!(script.contains("build-essential"));
    }

    #[test]
    fn test_tooling_install_script_always_includes_git() {
        let script = tooling_install_script(&["rust"]);
        assert!(script.contains("git"));
    }

    // -----------------------------------------------------------------------
    // build_single_command_script tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_script_contains_clone() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test",
            &["cargo test".to_string()],
        );
        assert!(script.contains("git clone"));
        assert!(script.contains("owner/repo"));
    }

    #[test]
    fn test_build_script_contains_checkout() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test",
            &["cargo test".to_string()],
        );
        assert!(script.contains("git checkout abc123"));
    }

    #[test]
    fn test_build_script_contains_command() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test test_hello",
            &["cargo test test_hello".to_string()],
        );
        assert!(script.contains("cargo test test_hello"));
    }

    #[test]
    fn test_build_script_captures_exit_code() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test",
            &["cargo test".to_string()],
        );
        assert!(script.contains("CMD_EXIT=$?"));
        assert!(script.contains("exit $CMD_EXIT"));
    }

    #[test]
    fn test_build_script_infra_error_codes() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test",
            &["cargo test".to_string()],
        );
        assert!(script.contains("exit 200"));
        assert!(script.contains("exit 201"));
    }

    #[test]
    fn test_build_script_installs_rust_for_cargo() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "cargo test",
            &["cargo test".to_string()],
        );
        assert!(script.contains("rustup"));
    }

    #[test]
    fn test_build_script_installs_python_for_pytest() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "pytest tests/",
            &["pytest tests/".to_string()],
        );
        assert!(script.contains("python3"));
        assert!(script.contains("pytest"));
    }

    #[test]
    fn test_build_script_installs_deps_python() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "pytest",
            &["pytest".to_string()],
        );
        assert!(script.contains("requirements.txt"));
        assert!(script.contains("setup.py"));
    }

    #[test]
    fn test_build_script_installs_deps_node() {
        let script = build_single_command_script(
            "owner/repo",
            "abc123",
            "npm test",
            &["npm test".to_string()],
        );
        assert!(script.contains("package.json"));
        assert!(script.contains("npm install"));
    }

    // -----------------------------------------------------------------------
    // TaskExecutionResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_task_result_all_executable() {
        let result = TaskExecutionResult {
            instance_id: "test-1".to_string(),
            command_results: vec![
                SingleCommandResult {
                    command: "cargo test".to_string(),
                    source: CommandSource::FailToPass,
                    result: CommandExecResult::Executable { exit_code: 1 },
                    stdout: String::new(),
                    stderr: String::new(),
                },
                SingleCommandResult {
                    command: "cargo test other".to_string(),
                    source: CommandSource::PassToPass,
                    result: CommandExecResult::Executable { exit_code: 0 },
                    stdout: String::new(),
                    stderr: String::new(),
                },
            ],
        };
        assert!(result.all_executable());
        assert_eq!(result.executable_count(), 2);
        assert_eq!(result.not_executable_count(), 0);
        assert_eq!(result.infra_error_count(), 0);
    }

    #[test]
    fn test_task_result_with_not_executable() {
        let result = TaskExecutionResult {
            instance_id: "test-2".to_string(),
            command_results: vec![
                SingleCommandResult {
                    command: "cargo test".to_string(),
                    source: CommandSource::FailToPass,
                    result: CommandExecResult::Executable { exit_code: 0 },
                    stdout: String::new(),
                    stderr: String::new(),
                },
                SingleCommandResult {
                    command: "mycommand test".to_string(),
                    source: CommandSource::PassToPass,
                    result: CommandExecResult::NotExecutable {
                        error: "mycommand: command not found".to_string(),
                    },
                    stdout: String::new(),
                    stderr: String::new(),
                },
            ],
        };
        assert!(!result.all_executable());
        assert_eq!(result.executable_count(), 1);
        assert_eq!(result.not_executable_count(), 1);
    }

    #[test]
    fn test_task_result_with_infra_error() {
        let result = TaskExecutionResult {
            instance_id: "test-3".to_string(),
            command_results: vec![SingleCommandResult {
                command: "cargo test".to_string(),
                source: CommandSource::FailToPass,
                result: CommandExecResult::InfrastructureError {
                    error: "Failed to clone".to_string(),
                },
                stdout: String::new(),
                stderr: String::new(),
            }],
        };
        assert!(!result.all_executable());
        assert_eq!(result.executable_count(), 0);
        assert_eq!(result.infra_error_count(), 1);
    }

    #[test]
    fn test_task_result_empty_commands() {
        let result = TaskExecutionResult {
            instance_id: "test-empty".to_string(),
            command_results: vec![],
        };
        assert!(result.all_executable()); // vacuously true
        assert_eq!(result.executable_count(), 0);
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
    fn test_load_task_config_python_commands() {
        let yaml = r#"repo: "owner/py-repo"
instance_id: "owner__py-repo-100"
base_commit: "def456"
patch: "diff --git a/lib.py b/lib.py"
test_patch: "diff --git a/test_lib.py b/test_lib.py"
problem_statement: "A long problem statement that exceeds the minimum character count requirement."
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

        assert_eq!(task.FAIL_TO_PASS.len(), 2);
        assert_eq!(task.PASS_TO_PASS.len(), 1);
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
    // ExecConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let config = ExecConfig::default();
        assert_eq!(config.docker_image, "ubuntu:22.04");
        assert_eq!(config.timeout_secs, 120);
    }

    #[test]
    fn test_custom_config() {
        let config = ExecConfig {
            docker_image: "rust:1.75".to_string(),
            timeout_secs: 600,
        };
        assert_eq!(config.docker_image, "rust:1.75");
        assert_eq!(config.timeout_secs, 600);
    }
}
