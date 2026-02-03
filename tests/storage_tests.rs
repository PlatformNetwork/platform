//! Comprehensive Storage Module Tests
//!
//! Tests for storage operations and data management.

use platform_core::*;
use platform_storage::*;
use tempfile::tempdir;

// ============================================================================
// MAIN STORAGE TESTS
// ============================================================================

mod main_storage {
    use super::*;

    #[test]
    fn test_storage_open() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        assert!(storage.load_state().unwrap().is_none());
    }

    #[test]
    fn test_storage_save_load_state() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        state.increment_block();
        state.epoch = 5;

        storage.save_state(&state).unwrap();

        let loaded = storage.load_state().unwrap().unwrap();
        assert_eq!(loaded.block_height, 1);
        assert_eq!(loaded.epoch, 5);
    }

    #[test]
    fn test_storage_challenge_operations() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let creator = Keypair::generate();
        let challenge = Challenge::new(
            "Test".into(),
            "Description".into(),
            b"code".to_vec(),
            creator.hotkey(),
            ChallengeConfig::default(),
        );

        let id = challenge.id;

        // Save
        storage.save_challenge(&challenge).unwrap();

        // Load
        let loaded = storage.load_challenge(&id).unwrap().unwrap();
        assert_eq!(loaded.name, "Test");

        // List
        let challenges = storage.list_challenges().unwrap();
        assert_eq!(challenges.len(), 1);

        // Delete
        assert!(storage.delete_challenge(&id).unwrap());
        assert!(storage.load_challenge(&id).unwrap().is_none());
    }

    #[test]
    fn test_storage_validator_operations() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));

        // Save
        storage.save_validator(&info).unwrap();

        // Load
        let loaded = storage.load_validator(&kp.hotkey()).unwrap().unwrap();
        assert_eq!(loaded.stake.0, 10_000_000_000);
    }

    #[test]
    fn test_storage_multiple_challenges() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let creator = Keypair::generate();

        for i in 0..5 {
            let challenge = Challenge::new(
                format!("Challenge {}", i),
                format!("Description {}", i),
                format!("code{}", i).into_bytes(),
                creator.hotkey(),
                ChallengeConfig::default(),
            );
            storage.save_challenge(&challenge).unwrap();
        }

        let challenges = storage.list_challenges().unwrap();
        assert_eq!(challenges.len(), 5);
    }

    #[test]
    fn test_storage_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        // Create and save
        {
            let storage = Storage::open(&path).unwrap();
            let sudo = Keypair::generate();
            let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
            storage.save_state(&state).unwrap();
            // Explicit flush before dropping to ensure persistence
            storage.flush().unwrap();
            // Explicitly drop storage to release sled lock before reopening
            drop(storage);
        }

        // Reopen and verify
        {
            let storage = Storage::open(&path).unwrap();
            let loaded = storage.load_state().unwrap();
            assert!(loaded.is_some());
        }
    }
}

// ============================================================================
// STORAGE ERROR TESTS
// ============================================================================

mod storage_errors {
    use super::*;

    #[test]
    fn test_load_nonexistent_state() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        assert!(storage.load_state().unwrap().is_none());
    }

    #[test]
    fn test_load_nonexistent_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let id = ChallengeId::new();
        assert!(storage.load_challenge(&id).unwrap().is_none());
    }

    #[test]
    fn test_load_nonexistent_validator() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let kp = Keypair::generate();
        let loaded = storage.load_validator(&kp.hotkey()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_delete_nonexistent_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let id = ChallengeId::new();
        assert!(!storage.delete_challenge(&id).unwrap());
    }

    #[test]
    fn test_list_challenges_empty() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let challenges = storage.list_challenges().unwrap();
        assert!(challenges.is_empty());
    }
}

// ============================================================================
// DISTRIBUTED STORAGE CONSTANTS TESTS
// ============================================================================

mod distributed_constants {
    use super::*;

    #[test]
    fn test_consensus_threshold() {
        assert_eq!(CONSENSUS_THRESHOLD, 0.50);
    }

    #[test]
    fn test_max_sizes() {
        assert_eq!(MAX_RAW_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_COMPRESSED_SIZE, 5 * 1024 * 1024);
    }

    #[test]
    fn test_max_entries() {
        assert_eq!(MAX_ENTRIES_PER_CATEGORY, 100_000);
    }

    #[test]
    fn test_no_ttl() {
        assert_eq!(NO_TTL, 0);
    }
}

// ============================================================================
// CATEGORY TESTS
// ============================================================================

mod category_tests {
    use super::*;

    #[test]
    fn test_category_variants() {
        let _ = Category::Submission;
        let _ = Category::Agent;
        let _ = Category::Evaluation;
        let _ = Category::Consensus;
        let _ = Category::Log;
        let _ = Category::Index;
        let _ = Category::Meta;
    }

    #[test]
    fn test_category_equality() {
        assert_eq!(Category::Agent, Category::Agent);
        assert_ne!(Category::Agent, Category::Log);
    }
}

// ============================================================================
// WRITE VALIDATION TESTS
// ============================================================================

mod write_validation {
    use super::*;

    #[test]
    fn test_write_validation_result_accept() {
        let result = WriteValidationResult::Accept;
        assert!(matches!(result, WriteValidationResult::Accept));
    }

    #[test]
    fn test_write_validation_result_reject() {
        let result = WriteValidationResult::Reject("reason".to_string());
        if let WriteValidationResult::Reject(reason) = result {
            assert_eq!(reason, "reason");
        } else {
            panic!("Expected Reject");
        }
    }
}

// ============================================================================
// COMPRESSION TESTS
// ============================================================================

mod compression {
    #[test]
    fn test_lz4_compression_roundtrip() {
        let data = b"Hello, World! This is test data that should be compressed.";
        let compressed = lz4_flex::compress_prepend_size(data);
        let decompressed = lz4_flex::decompress_size_prepended(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_lz4_compression_large() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let compressed = lz4_flex::compress_prepend_size(&data);
        let decompressed = lz4_flex::decompress_size_prepended(&compressed).unwrap();
        assert_eq!(data, decompressed);
        // Compression should reduce size for repetitive data
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_lz4_compression_empty() {
        let data: &[u8] = &[];
        let compressed = lz4_flex::compress_prepend_size(data);
        let decompressed = lz4_flex::decompress_size_prepended(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_lz4_compression_random() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let compressed = lz4_flex::compress_prepend_size(&data);
        let decompressed = lz4_flex::decompress_size_prepended(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_empty_storage() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        assert!(storage.load_state().unwrap().is_none());
        assert!(storage.list_challenges().unwrap().is_empty());
    }

    #[test]
    fn test_overwrite_state() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let sudo = Keypair::generate();

        // Save first state
        let mut state1 = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        state1.epoch = 1;
        storage.save_state(&state1).unwrap();

        // Overwrite with second state
        let mut state2 = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        state2.epoch = 2;
        storage.save_state(&state2).unwrap();

        // Verify second state
        let loaded = storage.load_state().unwrap().unwrap();
        assert_eq!(loaded.epoch, 2);
    }

    #[test]
    fn test_large_challenge_code() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let creator = Keypair::generate();
        let large_code = vec![0xAB; 100_000]; // 100KB

        let challenge = Challenge::new(
            "Large".into(),
            "Desc".into(),
            large_code.clone(),
            creator.hotkey(),
            ChallengeConfig::default(),
        );

        storage.save_challenge(&challenge).unwrap();

        let loaded = storage.load_challenge(&challenge.id).unwrap().unwrap();
        assert_eq!(loaded.wasm_code.len(), 100_000);
    }

    #[test]
    fn test_many_validators() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        for i in 0..100 {
            let kp = Keypair::generate();
            let info = ValidatorInfo::new(kp.hotkey(), Stake::new(i * 1_000_000_000));
            storage.save_validator(&info).unwrap();
        }

        // Verify we can save many validators
        // (Storage doesn't have a list_validators method, so we verify by saving)
    }

    #[test]
    fn test_challenge_with_unicode_name() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let creator = Keypair::generate();
        let challenge = Challenge::new(
            "テスト チャレンジ 🚀".into(),
            "Description with émojis 🎉".into(),
            b"code".to_vec(),
            creator.hotkey(),
            ChallengeConfig::default(),
        );

        storage.save_challenge(&challenge).unwrap();

        let loaded = storage.load_challenge(&challenge.id).unwrap().unwrap();
        assert_eq!(loaded.name, "テスト チャレンジ 🚀");
    }
}

// ============================================================================
// STORAGE STATS TESTS
// ============================================================================

mod stats_tests {
    #[test]
    fn test_storage_compression_ratio() {
        let raw_size = 1000usize;
        let compressed_size = 500usize;
        let ratio = compressed_size as f64 / raw_size as f64;
        assert!(ratio > 0.0 && ratio <= 1.0);
    }

    #[test]
    fn test_storage_size_calculation() {
        let entries = [100, 200, 300, 400];
        let total: usize = entries.iter().sum();
        assert_eq!(total, 1000);
    }
}
