//! Validates workspace.yaml files in hf-tasks/tasks follow the SWE-bench schema.
//!
//! Required fields: repo, instance_id, base_commit, patch, test_patch,
//! problem_statement, FAIL_TO_PASS, PASS_TO_PASS.
//!
//! Optional metadata fields: created_at, version, difficulty.
//!
//! Usage:
//!   validate-workspace-yaml [TASKS_DIR]
//!
//! Defaults to `hf-tasks/tasks` if no directory is provided.
//! Returns exit code 0 if all valid, 1 if any failures.

use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use serde::Deserialize;
use serde_yaml::Value;

/// Represents the expected SWE-bench workspace.yaml schema.
/// All required fields are `Option` so we can detect missing fields
/// and report them individually.
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct WorkspaceYaml {
    repo: Option<Value>,
    instance_id: Option<Value>,
    base_commit: Option<Value>,
    patch: Option<Value>,
    test_patch: Option<Value>,
    problem_statement: Option<Value>,
    FAIL_TO_PASS: Option<Value>,
    PASS_TO_PASS: Option<Value>,
    // Optional metadata fields (VAL-DATASET-008)
    created_at: Option<Value>,
    version: Option<Value>,
    difficulty: Option<Value>,
}

/// A single validation error for a workspace.yaml file.
#[derive(Debug)]
struct ValidationError {
    field: String,
    message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  [FAIL] {}: {}", self.field, self.message)
    }
}

/// Result of validating a single workspace.yaml file.
#[derive(Debug)]
struct ValidationResult {
    path: PathBuf,
    errors: Vec<ValidationError>,
}

impl ValidationResult {
    fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Checks that a YAML value is a non-empty string.
fn validate_string_field(
    value: &Option<Value>,
    field_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    match value {
        None => {
            errors.push(ValidationError {
                field: field_name.to_string(),
                message: "missing required field".to_string(),
            });
        }
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                errors.push(ValidationError {
                    field: field_name.to_string(),
                    message: "field is empty".to_string(),
                });
            }
        }
        Some(other) => {
            errors.push(ValidationError {
                field: field_name.to_string(),
                message: format!("expected string, got {}", yaml_type_name(other)),
            });
        }
    }
}

/// Checks that a YAML value is a non-empty array of strings.
fn validate_string_array_field(
    value: &Option<Value>,
    field_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    match value {
        None => {
            errors.push(ValidationError {
                field: field_name.to_string(),
                message: "missing required field".to_string(),
            });
        }
        Some(Value::Sequence(seq)) => {
            if seq.is_empty() {
                errors.push(ValidationError {
                    field: field_name.to_string(),
                    message: "array is empty".to_string(),
                });
            } else {
                for (i, item) in seq.iter().enumerate() {
                    if !item.is_string() {
                        errors.push(ValidationError {
                            field: field_name.to_string(),
                            message: format!(
                                "element [{}] expected string, got {}",
                                i,
                                yaml_type_name(item)
                            ),
                        });
                    } else if let Value::String(s) = item {
                        if s.trim().is_empty() {
                            errors.push(ValidationError {
                                field: field_name.to_string(),
                                message: format!("element [{}] is an empty string", i),
                            });
                        }
                    }
                }
            }
        }
        Some(other) => {
            errors.push(ValidationError {
                field: field_name.to_string(),
                message: format!("expected array, got {}", yaml_type_name(other)),
            });
        }
    }
}

/// Validates the problem_statement has meaningful content (min 50 chars per VAL-DATASET-007).
fn validate_problem_statement(value: &Option<Value>, errors: &mut Vec<ValidationError>) {
    match value {
        None => {
            errors.push(ValidationError {
                field: "problem_statement".to_string(),
                message: "missing required field".to_string(),
            });
        }
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                errors.push(ValidationError {
                    field: "problem_statement".to_string(),
                    message: "field is empty".to_string(),
                });
            } else if trimmed.len() < 50 {
                errors.push(ValidationError {
                    field: "problem_statement".to_string(),
                    message: format!("too short ({} chars, minimum 50 required)", trimmed.len()),
                });
            }
        }
        Some(other) => {
            errors.push(ValidationError {
                field: "problem_statement".to_string(),
                message: format!("expected string, got {}", yaml_type_name(other)),
            });
        }
    }
}

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

/// Validates a single workspace.yaml file.
fn validate_workspace_yaml(path: &Path) -> ValidationResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return ValidationResult {
                path: path.to_path_buf(),
                errors: vec![ValidationError {
                    field: "file".to_string(),
                    message: format!("failed to read file: {}", e),
                }],
            };
        }
    };

    let workspace: WorkspaceYaml = match serde_yaml::from_str(&content) {
        Ok(w) => w,
        Err(e) => {
            return ValidationResult {
                path: path.to_path_buf(),
                errors: vec![ValidationError {
                    field: "yaml".to_string(),
                    message: format!("failed to parse YAML: {}", e),
                }],
            };
        }
    };

    let mut errors = Vec::new();

    // Validate required string fields
    validate_string_field(&workspace.repo, "repo", &mut errors);
    validate_string_field(&workspace.instance_id, "instance_id", &mut errors);
    validate_string_field(&workspace.base_commit, "base_commit", &mut errors);
    validate_string_field(&workspace.patch, "patch", &mut errors);
    validate_string_field(&workspace.test_patch, "test_patch", &mut errors);

    // Validate problem_statement with min length check
    validate_problem_statement(&workspace.problem_statement, &mut errors);

    // Validate required array fields
    validate_string_array_field(&workspace.FAIL_TO_PASS, "FAIL_TO_PASS", &mut errors);
    validate_string_array_field(&workspace.PASS_TO_PASS, "PASS_TO_PASS", &mut errors);

    // Validate optional metadata fields (VAL-DATASET-008)
    // These fields are required for metadata completeness
    validate_string_field(&workspace.created_at, "created_at", &mut errors);
    validate_string_field(&workspace.version, "version", &mut errors);
    validate_string_field(&workspace.difficulty, "difficulty", &mut errors);

    ValidationResult {
        path: path.to_path_buf(),
        errors,
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
            // Also recurse into subdirectories
            let sub_results = find_workspace_yamls(&path);
            results.extend(sub_results);
        }
    }

    results.sort();
    results
}

/// Checks for duplicate instance_ids across all workspace.yaml files (VAL-DATASET-009).
fn check_duplicate_instance_ids(results: &[ValidationResult]) -> Vec<(String, Vec<PathBuf>)> {
    let mut id_to_paths: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();

    for result in results {
        let content = match fs::read_to_string(&result.path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let parsed: serde_yaml::Value = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(Value::String(id)) = parsed.get("instance_id") {
            id_to_paths
                .entry(id.clone())
                .or_default()
                .push(result.path.clone());
        }
    }

    id_to_paths
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect()
}

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

    println!("=== Workspace YAML Validation ===");
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

    let mut results: Vec<ValidationResult> = Vec::new();
    let mut pass_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut seen_ids = HashSet::new();
    let mut duplicate_ids: Vec<String> = Vec::new();

    for yaml_file in &yaml_files {
        let result = validate_workspace_yaml(yaml_file);

        // Track instance_id duplicates
        let content = fs::read_to_string(yaml_file).ok();
        if let Some(ref c) = content {
            if let Ok(parsed) = serde_yaml::from_str::<serde_yaml::Value>(c) {
                if let Some(Value::String(id)) = parsed.get("instance_id") {
                    if !seen_ids.insert(id.clone()) {
                        duplicate_ids.push(id.clone());
                    }
                }
            }
        }

        if result.is_valid() {
            println!("[PASS] {}", yaml_file.display());
            pass_count += 1;
        } else {
            println!("[FAIL] {}", yaml_file.display());
            for error in &result.errors {
                println!("{}", error);
            }
            fail_count += 1;
        }

        results.push(result);
    }

    // Check for duplicate instance_ids
    let duplicates = check_duplicate_instance_ids(&results);
    if !duplicates.is_empty() {
        println!();
        println!("=== Duplicate Instance IDs ===");
        for (id, paths) in &duplicates {
            println!("  Duplicate instance_id: \"{}\"", id);
            for path in paths {
                println!("    - {}", path.display());
            }
        }
    }

    // Print summary
    println!();
    println!("=== Validation Summary ===");
    println!("Total files: {}", yaml_files.len());
    println!("Passed:      {}", pass_count);
    println!("Failed:      {}", fail_count);

    if !duplicate_ids.is_empty() {
        println!("Duplicate IDs: {}", duplicate_ids.len());
    }

    if fail_count > 0 || !duplicate_ids.is_empty() {
        println!();
        println!("RESULT: FAIL");
        process::exit(1);
    } else {
        println!();
        println!("RESULT: PASS");
        process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper to create a temporary directory with a workspace.yaml file.
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
  +    println!("Hello");
   }
test_patch: |
  diff --git a/tests/test.rs b/tests/test.rs
  +fn test_hello() { assert!(true); }
problem_statement: "The main function does not print anything. We need to add a hello world print statement to the main function so users can see output."
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

    #[test]
    fn test_valid_workspace_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", &valid_yaml());
        let result = validate_workspace_yaml(&yaml_path);
        assert!(
            result.is_valid(),
            "Expected valid, got errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_missing_repo_field() {
        let yaml = r#"instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "repo" && e.message.contains("missing")));
    }

    #[test]
    fn test_missing_multiple_required_fields() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        let missing_fields: Vec<&str> = result
            .errors
            .iter()
            .filter(|e| e.message.contains("missing"))
            .map(|e| e.field.as_str())
            .collect();
        assert!(missing_fields.contains(&"base_commit"));
        assert!(missing_fields.contains(&"patch"));
        assert!(missing_fields.contains(&"test_patch"));
        assert!(missing_fields.contains(&"problem_statement"));
        assert!(missing_fields.contains(&"FAIL_TO_PASS"));
        assert!(missing_fields.contains(&"PASS_TO_PASS"));
    }

    #[test]
    fn test_empty_string_field() {
        let yaml = r#"repo: ""
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "repo" && e.message.contains("empty")));
    }

    #[test]
    fn test_empty_fail_to_pass_array() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS: []
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "FAIL_TO_PASS" && e.message.contains("empty")));
    }

    #[test]
    fn test_empty_pass_to_pass_array() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS: []
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "PASS_TO_PASS" && e.message.contains("empty")));
    }

    #[test]
    fn test_wrong_type_for_string_field() {
        let yaml = r#"repo: 12345
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "repo" && e.message.contains("expected string")));
    }

    #[test]
    fn test_wrong_type_for_array_field() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS: "not an array"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "FAIL_TO_PASS" && e.message.contains("expected array")));
    }

    #[test]
    fn test_non_string_element_in_array() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - 123
  - "valid cmd"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.field == "FAIL_TO_PASS"
            && e.message.contains("element [0]")
            && e.message.contains("expected string")));
    }

    #[test]
    fn test_problem_statement_too_short() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "Too short"
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS:
  - "test cmd"
created_at: "2024-01-01"
version: "1.0"
difficulty: "easy"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "problem_statement" && e.message.contains("too short")));
    }

    #[test]
    fn test_invalid_yaml_syntax() {
        let yaml = "this is: [not: valid: yaml: {{{";
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "yaml" && e.message.contains("failed to parse")));
    }

    #[test]
    fn test_find_workspace_yamls() {
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
    fn test_missing_metadata_fields() {
        let yaml = r#"repo: "owner/repo"
instance_id: "test-1"
base_commit: "abc123"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "This is a sufficiently long problem statement that should pass the minimum length check of fifty characters."
FAIL_TO_PASS:
  - "test cmd"
PASS_TO_PASS:
  - "test cmd"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let yaml_path = create_temp_task(tmp.path(), "task1", yaml);
        let result = validate_workspace_yaml(&yaml_path);
        assert!(!result.is_valid());
        let missing_fields: Vec<&str> = result
            .errors
            .iter()
            .filter(|e| e.message.contains("missing"))
            .map(|e| e.field.as_str())
            .collect();
        assert!(missing_fields.contains(&"created_at"));
        assert!(missing_fields.contains(&"version"));
        assert!(missing_fields.contains(&"difficulty"));
    }

    #[test]
    fn test_duplicate_instance_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml1 = valid_yaml();
        let yaml_path1 = create_temp_task(tmp.path(), "task-a", &yaml1);
        let yaml_path2 = create_temp_task(tmp.path(), "task-b", &yaml1);

        let result1 = validate_workspace_yaml(&yaml_path1);
        let result2 = validate_workspace_yaml(&yaml_path2);

        let duplicates = check_duplicate_instance_ids(&[result1, result2]);
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0].0, "owner__repo-1234");
    }
}
