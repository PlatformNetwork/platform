//! Validates that all workspace.yaml files have non-empty `fail_to_pass` and
//! `pass_to_pass` test commands, and that each command is a valid executable
//! string.
//!
//! This script fulfills validation assertions:
//! - **VAL-DATASET-002**: Every task has non-empty `fail_to_pass` test commands.
//! - **VAL-DATASET-003**: Every task has non-empty `pass_to_pass` test commands.
//!
//! Usage:
//!   validate-test-commands [TASKS_DIR]
//!
//! Defaults to `hf-tasks/tasks` if no directory is provided.
//! Returns exit code 0 if all valid, 1 if any failures.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use serde_yaml::Value;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single validation issue found for a workspace.yaml file.
#[derive(Debug)]
struct Issue {
    field: String,
    message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  [ISSUE] {}: {}", self.field, self.message)
    }
}

/// Aggregated result for a single workspace.yaml file.
#[derive(Debug)]
#[allow(dead_code)]
struct TaskResult {
    path: PathBuf,
    /// The `instance_id` extracted from the file, if available.
    instance_id: Option<String>,
    issues: Vec<Issue>,
}

impl TaskResult {
    fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns a human-readable type name for a YAML value.
fn yaml_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "array",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged",
    }
}

/// Validates that a YAML value is a non-empty array of non-empty,
/// executable-looking strings.
///
/// "Executable-looking" means:
/// - The string is non-empty after trimming.
/// - The string does not consist solely of whitespace.
///
/// Returns a list of [`Issue`]s (empty if everything is fine).
fn validate_test_commands(value: &Option<Value>, field_name: &str) -> Vec<Issue> {
    let mut issues = Vec::new();

    match value {
        None => {
            issues.push(Issue {
                field: field_name.to_string(),
                message: "missing (field not present in file)".to_string(),
            });
        }
        Some(Value::Sequence(seq)) => {
            if seq.is_empty() {
                issues.push(Issue {
                    field: field_name.to_string(),
                    message: "empty array — at least one test command is required".to_string(),
                });
            } else {
                for (i, item) in seq.iter().enumerate() {
                    match item {
                        Value::String(s) => {
                            let trimmed = s.trim();
                            if trimmed.is_empty() {
                                issues.push(Issue {
                                    field: field_name.to_string(),
                                    message: format!(
                                        "command [{}] is an empty/whitespace-only string",
                                        i
                                    ),
                                });
                            }
                        }
                        other => {
                            issues.push(Issue {
                                field: field_name.to_string(),
                                message: format!(
                                    "command [{}] expected string, got {}",
                                    i,
                                    yaml_type_name(other)
                                ),
                            });
                        }
                    }
                }
            }
        }
        Some(Value::Null) => {
            issues.push(Issue {
                field: field_name.to_string(),
                message: "value is null — expected a non-empty array of strings".to_string(),
            });
        }
        Some(other) => {
            issues.push(Issue {
                field: field_name.to_string(),
                message: format!("expected array of strings, got {}", yaml_type_name(other)),
            });
        }
    }

    issues
}

/// Extracts a string field from a parsed YAML mapping.
fn extract_string(root: &Value, key: &str) -> Option<String> {
    root.get(key).and_then(|v| v.as_str()).map(String::from)
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Validates test commands in a single workspace.yaml file.
fn validate_file(path: &Path) -> TaskResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return TaskResult {
                path: path.to_path_buf(),
                instance_id: None,
                issues: vec![Issue {
                    field: "file".to_string(),
                    message: format!("failed to read: {}", e),
                }],
            };
        }
    };

    let root: Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return TaskResult {
                path: path.to_path_buf(),
                instance_id: None,
                issues: vec![Issue {
                    field: "yaml".to_string(),
                    message: format!("failed to parse: {}", e),
                }],
            };
        }
    };

    let instance_id = extract_string(&root, "instance_id");

    // Both field names are checked in their canonical YAML key form.
    // SWE-bench uses UPPER_CASE keys.
    let fail_to_pass = root.get("FAIL_TO_PASS").cloned();
    let pass_to_pass = root.get("PASS_TO_PASS").cloned();

    let mut issues = Vec::new();
    issues.extend(validate_test_commands(&fail_to_pass, "FAIL_TO_PASS"));
    issues.extend(validate_test_commands(&pass_to_pass, "PASS_TO_PASS"));

    TaskResult {
        path: path.to_path_buf(),
        instance_id,
        issues,
    }
}

/// Discovers all workspace.yaml files under the given directory.
fn find_workspace_yamls(dir: &Path) -> Vec<PathBuf> {
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
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    let tasks_dir = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("hf-tasks/tasks")
    };

    if !tasks_dir.is_dir() {
        eprintln!("Error: directory not found: {}", tasks_dir.display());
        process::exit(1);
    }

    println!("=== Test Command Validation ===");
    println!("Scanning: {}", tasks_dir.display());
    println!();

    let yaml_files = find_workspace_yamls(&tasks_dir);

    if yaml_files.is_empty() {
        eprintln!(
            "Error: no workspace.yaml files found in {}",
            tasks_dir.display()
        );
        process::exit(1);
    }

    println!("Found {} workspace.yaml file(s)", yaml_files.len());
    println!();

    let mut pass_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut empty_fail_to_pass: Vec<String> = Vec::new();
    let mut empty_pass_to_pass: Vec<String> = Vec::new();
    let mut bad_format_tasks: Vec<String> = Vec::new();

    for yaml_file in &yaml_files {
        let result = validate_file(yaml_file);

        let task_label = result
            .instance_id
            .clone()
            .unwrap_or_else(|| yaml_file.display().to_string());

        if result.is_valid() {
            println!("[PASS] {}", task_label);
            pass_count += 1;
        } else {
            println!("[FAIL] {}", task_label);
            for issue in &result.issues {
                println!("{}", issue);
            }
            fail_count += 1;

            // Categorise the failure for the summary report.
            for issue in &result.issues {
                if issue.field == "FAIL_TO_PASS" && issue.message.contains("empty array") {
                    empty_fail_to_pass.push(task_label.clone());
                }
                if issue.field == "PASS_TO_PASS" && issue.message.contains("empty array") {
                    empty_pass_to_pass.push(task_label.clone());
                }
                if issue.message.contains("expected string, got")
                    || issue.message.contains("expected array of strings")
                {
                    bad_format_tasks.push(task_label.clone());
                }
            }
        }

        println!();
    }

    // -----------------------------------------------------------------------
    // Summary report
    // -----------------------------------------------------------------------
    println!("=== Test Command Validation Summary ===");
    println!("Total tasks scanned:       {}", yaml_files.len());
    println!("Tasks with valid commands:  {}", pass_count);
    println!("Tasks with issues:         {}", fail_count);
    println!();

    if !empty_fail_to_pass.is_empty() {
        println!(
            "Tasks with empty FAIL_TO_PASS ({}): {}",
            empty_fail_to_pass.len(),
            empty_fail_to_pass.join(", ")
        );
    }

    if !empty_pass_to_pass.is_empty() {
        println!(
            "Tasks with empty PASS_TO_PASS ({}): {}",
            empty_pass_to_pass.len(),
            empty_pass_to_pass.join(", ")
        );
    }

    if !bad_format_tasks.is_empty() {
        let deduped: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            bad_format_tasks
                .into_iter()
                .filter(|t| seen.insert(t.clone()))
                .collect()
        };
        println!(
            "Tasks with bad command format ({}): {}",
            deduped.len(),
            deduped.join(", ")
        );
    }

    println!();

    if fail_count > 0 {
        println!(
            "RESULT: FAIL — {} task(s) have test command issues",
            fail_count
        );
        process::exit(1);
    } else {
        println!("RESULT: PASS — all tasks have valid test commands");
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

    /// Helper to create a temporary task directory with a workspace.yaml file.
    fn create_temp_task(dir: &Path, task_name: &str, content: &str) -> PathBuf {
        let task_dir = dir.join(task_name);
        fs::create_dir_all(&task_dir).unwrap();
        let yaml_path = task_dir.join("workspace.yaml");
        fs::write(&yaml_path, content).unwrap();
        yaml_path
    }

    /// Returns a fully valid workspace.yaml content string.
    fn valid_yaml() -> String {
        r#"repo: "owner/repo"
instance_id: "owner__repo-1234"
base_commit: "abc123def456789"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "A sufficiently long problem statement."
FAIL_TO_PASS:
  - "cargo test test_hello"
PASS_TO_PASS:
  - "cargo test test_existing"
created_at: "2024-01-15T10:30:00Z"
version: "1.0.0"
difficulty: "easy"
"#
        .to_string()
    }

    // ----- validate_test_commands unit tests -----

    #[test]
    fn test_valid_commands() {
        let val = Some(Value::Sequence(vec![
            Value::String("cargo test test_a".into()),
            Value::String("pytest tests/test_b.py".into()),
        ]));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert!(issues.is_empty(), "Expected no issues, got: {:?}", issues);
    }

    #[test]
    fn test_missing_field() {
        let issues = validate_test_commands(&None, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("missing"));
    }

    #[test]
    fn test_empty_array() {
        let val = Some(Value::Sequence(vec![]));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("empty array"));
    }

    #[test]
    fn test_null_value() {
        let val = Some(Value::Null);
        let issues = validate_test_commands(&val, "PASS_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("null"));
    }

    #[test]
    fn test_wrong_type_scalar() {
        let val = Some(Value::String("not an array".into()));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expected array of strings"));
    }

    #[test]
    fn test_wrong_type_number() {
        let val = Some(Value::Number(serde_yaml::Number::from(42)));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expected array of strings"));
    }

    #[test]
    fn test_non_string_element() {
        let val = Some(Value::Sequence(vec![
            Value::Number(serde_yaml::Number::from(123)),
            Value::String("valid cmd".into()),
        ]));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("command [0]"));
        assert!(issues[0].message.contains("expected string"));
    }

    #[test]
    fn test_empty_string_command() {
        let val = Some(Value::Sequence(vec![
            Value::String("".into()),
            Value::String("valid cmd".into()),
        ]));
        let issues = validate_test_commands(&val, "PASS_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("command [0]"));
        assert!(issues[0].message.contains("empty/whitespace-only"));
    }

    #[test]
    fn test_whitespace_only_command() {
        let val = Some(Value::Sequence(vec![Value::String("   \t  ".into())]));
        let issues = validate_test_commands(&val, "PASS_TO_PASS");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("empty/whitespace-only"));
    }

    #[test]
    fn test_multiple_bad_elements() {
        let val = Some(Value::Sequence(vec![
            Value::String("".into()),
            Value::Number(serde_yaml::Number::from(0)),
            Value::String("ok".into()),
            Value::Bool(true),
        ]));
        let issues = validate_test_commands(&val, "FAIL_TO_PASS");
        assert_eq!(issues.len(), 3, "Expected 3 issues, got: {:?}", issues);
    }

    // ----- validate_file integration tests -----

    #[test]
    fn test_validate_file_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", &valid_yaml());
        let result = validate_file(&path);
        assert!(
            result.is_valid(),
            "Expected valid, got: {:?}",
            result.issues
        );
        assert_eq!(result.instance_id.as_deref(), Some("owner__repo-1234"));
    }

    #[test]
    fn test_validate_file_empty_fail_to_pass() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-empty-ftp"
base_commit: "abc123"
patch: "p"
test_patch: "tp"
problem_statement: "desc"
FAIL_TO_PASS: []
PASS_TO_PASS:
  - "cargo test ok"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "FAIL_TO_PASS" && i.message.contains("empty array")));
    }

    #[test]
    fn test_validate_file_empty_pass_to_pass() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-empty-ptp"
base_commit: "abc123"
patch: "p"
test_patch: "tp"
problem_statement: "desc"
FAIL_TO_PASS:
  - "cargo test failing"
PASS_TO_PASS: []
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "PASS_TO_PASS" && i.message.contains("empty array")));
    }

    #[test]
    fn test_validate_file_both_empty() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-both-empty"
base_commit: "abc123"
patch: "p"
test_patch: "tp"
problem_statement: "desc"
FAIL_TO_PASS: []
PASS_TO_PASS: []
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert_eq!(result.issues.len(), 2);
    }

    #[test]
    fn test_validate_file_missing_both_fields() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-missing"
base_commit: "abc123"
patch: "p"
test_patch: "tp"
problem_statement: "desc"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "FAIL_TO_PASS" && i.message.contains("missing")));
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "PASS_TO_PASS" && i.message.contains("missing")));
    }

    #[test]
    fn test_validate_file_bad_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", "key: [unterminated: {bad");
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.field == "yaml"));
    }

    #[test]
    fn test_validate_file_unreadable() {
        let result = validate_file(Path::new("/nonexistent/workspace.yaml"));
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.field == "file"));
    }

    #[test]
    fn test_validate_file_wrong_type_commands() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-wrong-type"
base_commit: "abc123"
patch: "p"
test_patch: "tp"
problem_statement: "desc"
FAIL_TO_PASS: "not an array"
PASS_TO_PASS: 42
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_file(&path);
        assert!(!result.is_valid());
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "FAIL_TO_PASS" && i.message.contains("expected array of strings")));
        assert!(result
            .issues
            .iter()
            .any(|i| i.field == "PASS_TO_PASS" && i.message.contains("expected array of strings")));
    }

    // ----- find_workspace_yamls tests -----

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
        fs::write(nested.join("workspace.yaml"), &valid_yaml()).unwrap();

        let found = find_workspace_yamls(tmp.path());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_workspace_yamls_nonexistent_dir() {
        let found = find_workspace_yamls(Path::new("/nonexistent/dir"));
        assert_eq!(found.len(), 0);
    }
}
