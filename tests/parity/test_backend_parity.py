"""Backend parity tests (Task 26): k8s vs Swarm behind the frozen contract.

Drives the fixed broker request sequence and the fixed challenge spec through
both backends with mocked infrastructure, then byte-diffs the normalized
projections. The mutation self-tests prove the diff machinery detects real
semantic differences (it is not vacuously empty).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parity_harness as harness  # noqa: E402


def test_backend_parity_diff_is_empty() -> None:
    result = harness.run_parity()

    assert len(result.guard_proofs) >= 5
    assert result.scenario_attempts == 0
    assert result.diff_lines == []


def test_selftest_memory_mutation_is_detected() -> None:
    base_k8s, _ = harness.build_documents()

    _, mutated_swarm = harness.build_documents(
        mutate_create_argv=harness.mutate_limit_memory
    )

    diff = harness.diff_documents(base_k8s, mutated_swarm)
    assert diff
    assert any("memory_bytes" in line for line in diff)


def test_selftest_env_mutation_is_detected() -> None:
    base_k8s, _ = harness.build_documents()

    _, mutated_swarm = harness.build_documents(
        mutate_create_argv=harness.mutate_env_value
    )

    diff = harness.diff_documents(base_k8s, mutated_swarm)
    assert diff
    assert any("tampered" in line for line in diff)


def test_unmutated_rerun_stays_clean() -> None:
    base_k8s, base_swarm = harness.build_documents()

    rerun_k8s, rerun_swarm = harness.build_documents()

    assert harness.diff_documents(base_k8s, rerun_swarm) == []
    assert harness.diff_documents(rerun_k8s, base_swarm) == []


def test_guards_block_forbidden_side_effects() -> None:
    with harness.forbidden_side_effects() as report:
        proofs = harness.prove_guards_active(report)

    assert len(proofs) >= 5
    assert all(proof.endswith("BLOCKED") for proof in proofs)
    assert len(report.attempts) == len(proofs)
