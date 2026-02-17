#![no_std]

extern crate alloc;

mod evaluation;
pub mod scoring;
pub mod tasks;
pub mod types;

use platform_challenge_sdk_wasm::{Challenge, EvaluationInput, EvaluationOutput};

pub struct TermChallenge;

impl TermChallenge {
    const fn new() -> Self {
        Self
    }
}

impl Default for TermChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenge for TermChallenge {
    fn name(&self) -> &'static str {
        "term-challenge"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
        evaluation::evaluate(input)
    }

    fn validate(&self, input: EvaluationInput) -> bool {
        evaluation::validate(&input)
    }
}

platform_challenge_sdk_wasm::register_challenge!(TermChallenge, TermChallenge::new());
