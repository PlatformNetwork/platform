"""Guard tests for the combined validator runtime image (m5-validator-runtime-image).

A decentralized validator must be able to DISPATCH both challenges from a single
image. That requires two things to stay in lockstep:

1. the in-process dispatch registry exposes exactly the two known slugs
   (``agent-challenge`` and ``prism``) so the per-slug adapters resolve, and
2. platform CI builds + publishes a ``base-validator-runtime`` image (from
   ``docker/Dockerfile.validator-runtime``) that installs ``base`` PLUS both
   challenge dispatch packages and proves both ``validator_dispatch`` modules are
   importable via a build-time smoke check.

These are file-inspection + import guards: a future edit that drops a dispatch
slug, removes the runtime image from CI, breaks the no-deps challenge install
(which would clobber the local ``base``), or deletes the import smoke check fails
loudly here.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from base.validator.agent.challenge_dispatch import (
    DEFAULT_CHALLENGE_EXECUTOR_FACTORIES,
)

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DOCKERFILE_RUNTIME = ROOT / "docker" / "Dockerfile.validator-runtime"

RUNTIME_IMAGE = "base-validator-runtime"
RUNTIME_DOCKERFILE = "docker/Dockerfile.validator-runtime"

AGENT_CHALLENGE_REQ = (
    "agent-challenge @ git+https://github.com/BaseIntelligence/agent-challenge.git"
)
PRISM_REQ = "prism-challenge @ git+https://github.com/BaseIntelligence/prism.git"


def _ci() -> dict:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def _matrix_images(job: dict) -> dict[str, str]:
    """Map ``image -> dockerfile`` for a docker job's build matrix."""
    includes = job["strategy"]["matrix"]["include"]
    return {entry["image"]: entry["dockerfile"] for entry in includes}


# --- Dispatch registry slugs -------------------------------------------------


def test_dispatch_registry_exposes_both_challenge_slugs() -> None:
    # The runtime image only matters because these are the slugs a validator can
    # dispatch in-process; keep the registry and the image in lockstep.
    assert set(DEFAULT_CHALLENGE_EXECUTOR_FACTORIES) == {"agent-challenge", "prism"}


# --- Runtime image build target ---------------------------------------------


def test_ci_builds_and_publishes_validator_runtime_image() -> None:
    ci = _ci()
    build = _matrix_images(ci["jobs"]["docker-build"])
    publish = _matrix_images(ci["jobs"]["docker-publish"])

    assert build.get(RUNTIME_IMAGE) == RUNTIME_DOCKERFILE
    assert publish.get(RUNTIME_IMAGE) == RUNTIME_DOCKERFILE


def test_runtime_image_uses_shared_ghcr_tag_policy() -> None:
    ci = _ci()
    meta_step = next(
        step
        for step in ci["jobs"]["docker-publish"]["steps"]
        if step.get("id") == "meta"
    )
    tags = meta_step["with"]["tags"]
    # Same policy as base/base-master: latest only from main + semver + sha-<sha>.
    assert "type=raw,value=latest,enable=${{ github.ref == 'refs/heads/main' }}" in tags
    assert "type=semver,pattern={{version}}" in tags
    assert "type=sha,prefix=sha-" in tags
    assert "ghcr.io/baseintelligence/${{ matrix.image }}" in meta_step["with"]["images"]


def test_runtime_image_publish_gate_is_pr_safe_and_main_only_latest() -> None:
    ci = _ci()
    publish_if = ci["jobs"]["docker-publish"]["if"]
    # Publishing (incl. the runtime image) never happens on PRs; latest only main.
    assert "github.event_name != 'pull_request'" in publish_if
    assert "refs/heads/main" in publish_if


# --- Dockerfile recipe -------------------------------------------------------


def test_runtime_dockerfile_exists() -> None:
    assert DOCKERFILE_RUNTIME.is_file()


def test_runtime_dockerfile_installs_base_then_both_dispatch_packages_no_deps() -> None:
    text = DOCKERFILE_RUNTIME.read_text(encoding="utf-8")

    # Local base is authoritative (validator extra), installed before the
    # challenge packages.
    assert '".[validator]"' in text

    # Both challenge dispatch packages are installed WITHOUT their deps so their
    # git-pinned `base @ git+...` does not clobber the local base above.
    assert "--no-deps" in text
    assert AGENT_CHALLENGE_REQ in text
    assert PRISM_REQ in text

    base_at = text.index('uv pip install --system -e ".[validator]"')
    no_deps_at = text.index("--no-deps")
    assert base_at < no_deps_at


def test_runtime_dockerfile_adds_leaf_runtime_deps_with_cpu_torch() -> None:
    text = DOCKERFILE_RUNTIME.read_text(encoding="utf-8")

    # CPU torch wheel only (the real GPU re-exec runs in the broker-launched
    # prism-evaluator container, not on the validator host).
    assert "https://download.pytorch.org/whl/cpu" in text
    assert "torch>=2.3" in text

    # agent-challenge leaf deps.
    assert "cryptography" in text
    # prism leaf deps (everything except base/torch).
    for dep in (
        "numpy",
        "langchain-openai",
        "tiktoken",
        "sentencepiece",
        "huggingface_hub",
    ):
        assert dep in text, dep


def test_runtime_dockerfile_is_bittensor_only_no_legacy_substrate_stack() -> None:
    # VAL-CODE-VRT-001: the runtime image must NOT install the legacy
    # substrate-interface/scalecodec stack. Both challenges sign/verify sr25519
    # via bittensor.Keypair (bittensor comes from base[validator]); bittensor 10
    # bundles async-substrate-interface, and the legacy stack conflicts with it
    # (that conflict is what forced the :hotfix-scalecodec pin).
    text = DOCKERFILE_RUNTIME.read_text(encoding="utf-8")
    # Only the executable (non-comment) lines matter: the recipe documents WHY
    # the legacy stack is absent, so comments may name it.
    instructions = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "substrate-interface" not in instructions
    assert "substrateinterface" not in instructions
    assert "scalecodec" not in instructions


def test_runtime_dockerfile_has_import_smoke_check() -> None:
    text = DOCKERFILE_RUNTIME.read_text(encoding="utf-8")
    assert (
        "import base, agent_challenge.validator_dispatch, "
        "prism_challenge.validator_dispatch" in text
    )


def test_runtime_dockerfile_cmd_runs_the_validator_agent() -> None:
    text = DOCKERFILE_RUNTIME.read_text(encoding="utf-8")
    assert '"base", "validator", "agent"' in text
