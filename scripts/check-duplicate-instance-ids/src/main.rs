//! Checks for duplicate `instance_id` values across all `workspace.yaml` files
//! in the dataset.
//!
//! This script fulfills validation assertion:
//! - **VAL-DATASET-009**: All `instance_id`s across the dataset are unique.
//!
//! Usage:
//!   check-duplicate-instance-ids [TASKS_DIR]
//!
//! Defaults to `hf-tasks/tasks` if no directory is provided.
//! Returns exit code 0 if all unique, 1 if any duplicates found.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use serde_yaml::Value;

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Discovers all `workspace.yaml` files under the given directory.
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

/// Extracts the `instance_id` string from a workspace.yaml file.
///
/// Returns `None` if the file cannot be read, parsed, or does not contain
/// a string `instance_id` field.
fn extract_instance_id(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let root: Value = serde_yaml::from_str(&content).ok()?;
    root.get("instance_id")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Collects all instance_ids and groups them by value.
///
/// Returns a map from instance_id to the list of file paths that contain it.
fn collect_instance_ids(files: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    let mut id_to_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();

    for file in files {
        if let Some(id) = extract_instance_id(file) {
            id_to_paths.entry(id).or_default().push(file.clone());
        }
    }

    id_to_paths
}

/// Filters the id map to only entries with more than one path (duplicates).
fn find_duplicates(id_to_paths: &HashMap<String, Vec<PathBuf>>) -> Vec<(&String, &Vec<PathBuf>)> {
    let mut duplicates: Vec<(&String, &Vec<PathBuf>)> = id_to_paths
        .iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();

    // Sort by instance_id for deterministic output.
    duplicates.sort_by_key(|(id, _)| (*id).clone());
    duplicates
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

    println!("=== Duplicate Instance ID Check ===");
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

    let id_to_paths = collect_instance_ids(&yaml_files);
    let total_ids = id_to_paths.len();
    let files_without_id = yaml_files.len() - id_to_paths.values().map(|v| v.len()).sum::<usize>();

    // Report files that could not yield an instance_id.
    if files_without_id > 0 {
        println!(
            "Warning: {} file(s) could not yield an instance_id (missing or unparseable)",
            files_without_id
        );

        for file in &yaml_files {
            if extract_instance_id(file).is_none() {
                println!("  - {}", file.display());
            }
        }
        println!();
    }

    // List all extracted IDs (sorted).
    println!("Extracted {} unique instance_id(s):", total_ids);
    let mut sorted_ids: Vec<&String> = id_to_paths.keys().collect();
    sorted_ids.sort();
    for id in &sorted_ids {
        println!("  {}", id);
    }
    println!();

    // Check for duplicates.
    let duplicates = find_duplicates(&id_to_paths);

    if duplicates.is_empty() {
        println!("=== Duplicate Check Summary ===");
        println!("Total files scanned:  {}", yaml_files.len());
        println!("Unique instance_ids:  {}", total_ids);
        println!("Duplicate IDs found:  0");
        println!();
        println!("RESULT: PASS — all instance_ids are unique");
        process::exit(0);
    } else {
        println!("=== Duplicate Instance IDs Found ===");
        for (id, paths) in &duplicates {
            println!("  Duplicate: \"{}\" (appears {} times)", id, paths.len());
            for path in *paths {
                println!("    - {}", path.display());
            }
        }
        println!();

        println!("=== Duplicate Check Summary ===");
        println!("Total files scanned:  {}", yaml_files.len());
        println!("Unique instance_ids:  {}", total_ids);
        println!("Duplicate IDs found:  {}", duplicates.len());
        println!();
        println!(
            "RESULT: FAIL — {} duplicate instance_id(s) detected",
            duplicates.len()
        );
        process::exit(1);
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

    /// Returns a valid workspace.yaml content string with a given instance_id.
    fn yaml_with_id(instance_id: &str) -> String {
        format!(
            r#"repo: "owner/repo"
instance_id: "{}"
base_commit: "abc123def456789"
patch: "some patch"
test_patch: "some test patch"
problem_statement: "A sufficiently long problem statement for testing purposes here."
FAIL_TO_PASS:
  - "cargo test test_hello"
PASS_TO_PASS:
  - "cargo test test_existing"
created_at: "2024-01-15T10:30:00Z"
version: "1.0.0"
difficulty: "easy"
"#,
            instance_id
        )
    }

    // ----- find_workspace_yamls tests -----

    #[test]
    fn test_find_workspace_yamls_discovers_files() {
        let tmp = tempfile::tempdir().unwrap();
        create_temp_task(tmp.path(), "task-a", &yaml_with_id("id-a"));
        create_temp_task(tmp.path(), "task-b", &yaml_with_id("id-b"));

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
        fs::write(nested.join("workspace.yaml"), &yaml_with_id("nested-id")).unwrap();

        let found = find_workspace_yamls(tmp.path());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_workspace_yamls_nonexistent_dir() {
        let found = find_workspace_yamls(Path::new("/nonexistent/dir"));
        assert_eq!(found.len(), 0);
    }

    // ----- extract_instance_id tests -----

    #[test]
    fn test_extract_instance_id_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", &yaml_with_id("owner__repo-1234"));
        let id = extract_instance_id(&path);
        assert_eq!(id.as_deref(), Some("owner__repo-1234"));
    }

    #[test]
    fn test_extract_instance_id_missing_field() {
        let yaml = r#"repo: "owner/repo"
base_commit: "abc123"
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let id = extract_instance_id(&path);
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_instance_id_non_string() {
        let yaml = r#"repo: "owner/repo"
instance_id: 12345
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", yaml);
        let id = extract_instance_id(&path);
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_instance_id_invalid_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = create_temp_task(tmp.path(), "task1", "not: [valid: {yaml");
        let id = extract_instance_id(&path);
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_instance_id_nonexistent_file() {
        let id = extract_instance_id(Path::new("/nonexistent/workspace.yaml"));
        assert!(id.is_none());
    }

    // ----- collect_instance_ids tests -----

    #[test]
    fn test_collect_unique_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("id-alpha"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("id-beta"));
        let f3 = create_temp_task(tmp.path(), "task-c", &yaml_with_id("id-gamma"));

        let id_map = collect_instance_ids(&[f1, f2, f3]);
        assert_eq!(id_map.len(), 3);
        assert!(id_map.values().all(|paths| paths.len() == 1));
    }

    #[test]
    fn test_collect_with_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("dup-id"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("dup-id"));
        let f3 = create_temp_task(tmp.path(), "task-c", &yaml_with_id("unique-id"));

        let id_map = collect_instance_ids(&[f1, f2, f3]);
        assert_eq!(id_map.len(), 2);
        assert_eq!(id_map["dup-id"].len(), 2);
        assert_eq!(id_map["unique-id"].len(), 1);
    }

    #[test]
    fn test_collect_skips_unparseable() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("good-id"));
        let f2 = create_temp_task(tmp.path(), "task-b", "broken: [yaml: {");

        let id_map = collect_instance_ids(&[f1, f2]);
        assert_eq!(id_map.len(), 1);
        assert!(id_map.contains_key("good-id"));
    }

    #[test]
    fn test_collect_empty_input() {
        let id_map = collect_instance_ids(&[]);
        assert!(id_map.is_empty());
    }

    // ----- find_duplicates tests -----

    #[test]
    fn test_find_duplicates_none() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("id-1"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("id-2"));

        let id_map = collect_instance_ids(&[f1, f2]);
        let dups = find_duplicates(&id_map);
        assert!(dups.is_empty());
    }

    #[test]
    fn test_find_duplicates_one() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("dup-id"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("dup-id"));
        let f3 = create_temp_task(tmp.path(), "task-c", &yaml_with_id("unique-id"));

        let id_map = collect_instance_ids(&[f1, f2, f3]);
        let dups = find_duplicates(&id_map);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].0, "dup-id");
        assert_eq!(dups[0].1.len(), 2);
    }

    #[test]
    fn test_find_duplicates_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("dup-1"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("dup-1"));
        let f3 = create_temp_task(tmp.path(), "task-c", &yaml_with_id("dup-2"));
        let f4 = create_temp_task(tmp.path(), "task-d", &yaml_with_id("dup-2"));
        let f5 = create_temp_task(tmp.path(), "task-e", &yaml_with_id("unique"));

        let id_map = collect_instance_ids(&[f1, f2, f3, f4, f5]);
        let dups = find_duplicates(&id_map);
        assert_eq!(dups.len(), 2);
        // Sorted by id
        assert_eq!(dups[0].0, "dup-1");
        assert_eq!(dups[1].0, "dup-2");
    }

    #[test]
    fn test_find_duplicates_triple() {
        let tmp = tempfile::tempdir().unwrap();
        let f1 = create_temp_task(tmp.path(), "task-a", &yaml_with_id("triple-id"));
        let f2 = create_temp_task(tmp.path(), "task-b", &yaml_with_id("triple-id"));
        let f3 = create_temp_task(tmp.path(), "task-c", &yaml_with_id("triple-id"));

        let id_map = collect_instance_ids(&[f1, f2, f3]);
        let dups = find_duplicates(&id_map);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].0, "triple-id");
        assert_eq!(dups[0].1.len(), 3);
    }

    #[test]
    fn test_find_duplicates_empty_map() {
        let id_map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let dups = find_duplicates(&id_map);
        assert!(dups.is_empty());
    }
}
