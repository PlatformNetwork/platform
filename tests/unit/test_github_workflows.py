from __future__ import annotations

from pathlib import Path

import yaml

from base.supervisor.self_update import AvailableRelease

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> dict:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def _step_uses(job: dict) -> set[str]:
    return {step.get("uses", "") for step in job["steps"] if "uses" in step}


def _job_run_text(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_ci_workflow_runs_postgres_orm_integration_gate() -> None:
    workflow = _workflow()
    postgres_orm = workflow["jobs"]["postgres-orm"]

    assert postgres_orm["runs-on"] == "ubuntu-latest"
    assert "continue-on-error" not in postgres_orm
    assert postgres_orm["env"] == {
        "BASE_TEST_DATABASE_URL": (
            "postgresql+asyncpg://base:base@localhost:5432/base_test"
        ),
    }

    service = postgres_orm["services"]["postgres"]
    assert service["image"] == "postgres:16-alpine"
    assert service["env"] == {
        "POSTGRES_USER": "base",
        "POSTGRES_PASSWORD": "base",
        "POSTGRES_DB": "base_test",
    }
    assert service["ports"] == ["5432:5432"]
    assert "pg_isready -U base -d base_test" in service["options"]

    assert _step_uses(postgres_orm) >= {
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "astral-sh/setup-uv@v5",
    }
    assert any(
        step.get("run") == "uv sync --extra dev --extra master"
        for step in postgres_orm["steps"]
    )
    assert any(
        step.get("run") == "uv run pytest tests/integration -m postgres -q"
        for step in postgres_orm["steps"]
    )


def test_ci_workflow_builds_base_images_without_publishing_on_prs() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    docker_build = jobs["docker-build"]

    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request:" in CI_WORKFLOW.read_text(encoding="utf-8")
    assert "compose-validation" not in jobs
    assert "packages" not in docker_build.get("permissions", {})
    assert docker_build["needs"] == [
        "ruff",
        "format",
        "mypy",
        "coverage",
        "production-policy",
        "postgres-orm",
    ]
    assert {
        item["image"] for item in docker_build["strategy"]["matrix"]["include"]
    } == {
        "base",
        "base-master",
        "base-validator-runtime",
    }
    assert _step_uses(docker_build) >= {
        "actions/checkout@v4",
        "docker/setup-buildx-action@v3",
        "docker/build-push-action@v6",
    }
    build_step = next(
        step
        for step in docker_build["steps"]
        if step.get("uses") == "docker/build-push-action@v6"
    )
    assert build_step["with"]["push"] is False


def test_ci_workflow_has_no_compose_or_watchtower_validation() -> None:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8").lower()
    workflow = _workflow()

    assert "compose-validation" not in workflow["jobs"]
    assert "docker compose" not in workflow_text
    assert "compose.yml" not in workflow_text
    assert "compose.dev.yml" not in workflow_text
    assert "compose.watchtower.yml" not in workflow_text
    assert "watchtower" not in workflow_text


def test_ci_workflow_publishes_base_images_to_ghcr_on_trusted_events() -> None:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    workflow = _workflow()
    docker_publish = workflow["jobs"]["docker-publish"]

    assert "workflow_dispatch" in workflow_text
    assert "confirm_publish" in workflow_text
    assert "refs/heads/main" in docker_publish["if"]
    assert "refs/tags/v" in docker_publish["if"]
    assert "pull_request" in docker_publish["if"]
    assert docker_publish["needs"] == ["docker-build", "postgres-orm"]
    assert docker_publish["permissions"] == {
        "contents": "read",
        "packages": "write",
    }
    assert _step_uses(docker_publish) >= {
        "actions/checkout@v4",
        "docker/setup-buildx-action@v3",
        "docker/login-action@v3",
        "docker/metadata-action@v5",
        "docker/build-push-action@v6",
    }

    metadata = next(
        step
        for step in docker_publish["steps"]
        if step.get("uses") == "docker/metadata-action@v5"
    )
    assert metadata["with"]["images"] == "ghcr.io/baseintelligence/${{ matrix.image }}"
    assert "type=ref,event=branch" in metadata["with"]["tags"]
    assert "type=sha,prefix=sha-" in metadata["with"]["tags"]
    assert "type=semver,pattern={{version}}" in metadata["with"]["tags"]
    assert "type=semver,pattern={{raw}}" in metadata["with"]["tags"]
    assert "type=raw,value=latest" in metadata["with"]["tags"]

    publish_step = next(
        step
        for step in docker_publish["steps"]
        if step.get("uses") == "docker/build-push-action@v6"
    )
    assert publish_step["with"]["push"] is True
    assert publish_step["with"]["tags"] == "${{ steps.meta.outputs.tags }}"
    assert publish_step["with"]["labels"] == "${{ steps.meta.outputs.labels }}"


def test_ci_workflow_creates_github_releases_after_tag_image_publish() -> None:
    workflow = _workflow()
    release_job = workflow["jobs"]["github-release"]

    assert release_job["needs"] == ["docker-publish", "postgres-orm"]
    assert release_job["runs-on"] == "ubuntu-latest"
    assert release_job["permissions"] == {"contents": "write"}
    assert "packages" not in release_job["permissions"]
    assert "github.event_name == 'push'" in release_job["if"]
    assert "startsWith(github.ref, 'refs/tags/v')" in release_job["if"]
    assert "workflow_dispatch" not in release_job["if"]
    assert "refs/heads/main" not in release_job["if"]

    release_step = next(
        step
        for step in release_job["steps"]
        if step.get("uses") == "softprops/action-gh-release@v2"
    )
    release_config = release_step["with"]
    release_body = release_config["body"]

    assert release_config["tag_name"] == "${{ github.ref_name }}"
    assert release_config["name"] == "BASE ${{ steps.release.outputs.version }}"
    assert release_config["generate_release_notes"] is True
    assert release_config["append_body"] is True
    assert release_config["draft"] is False
    assert release_config["prerelease"] == "${{ contains(github.ref_name, '-') }}"
    assert release_config["make_latest"] == "${{ !contains(github.ref_name, '-') }}"
    assert "## Container Images" in release_body
    assert (
        "ghcr.io/baseintelligence/base:${{ steps.release.outputs.version }}"
        in release_body
    )
    assert "ghcr.io/baseintelligence/base:${{ github.ref_name }}" in release_body
    assert "ghcr.io/baseintelligence/base:sha-${{ github.sha }}" in release_body
    assert (
        "ghcr.io/baseintelligence/base-master:${{ steps.release.outputs.version }}"
        in release_body
    )
    assert "ghcr.io/baseintelligence/base-master:${{ github.ref_name }}" in release_body
    assert "ghcr.io/baseintelligence/base-master:sha-${{ github.sha }}" in release_body
    assert "Production deployments should pin" in release_body
    assert "docs/versioning.md" in release_body


def test_ci_workflow_publishes_self_update_manifest_on_main() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]

    assert "publish-self-update-manifest" in jobs
    job = jobs["publish-self-update-manifest"]

    # Runs ONLY on a push to main, and ONLY after the images publish.
    assert "github.event_name == 'push'" in job["if"]
    assert "refs/heads/main" in job["if"]
    assert "docker-publish" in job["needs"]

    # Needs write access to push the manifest to the release branch.
    assert job["permissions"]["contents"] == "write"

    scripts = _job_run_text(job)

    # MONOTONIC version: the strictly-increasing run number advances on every
    # merge to main; the commit sha makes the version unique + traceable.
    assert "github.run_number" in scripts
    assert "github.sha" in scripts

    # source_url is the codeload tarball for that exact ref.
    assert "codeload.github.com" in scripts
    assert "tar.gz" in scripts

    # A {version, source_url} JSON manifest ...
    assert "self-update-manifest.json" in scripts
    assert '"version"' in scripts
    assert '"source_url"' in scripts

    # ... published/overwritten at a STABLE url on the dedicated release branch.
    assert "release" in scripts


def test_self_update_manifest_version_is_filesystem_safe() -> None:
    # Mirror the version string the CI step emits (run_number + sha) and prove
    # AvailableRelease.__post_init__ accepts it (no "/", never "." / "..") so the
    # supervisor can stage it as releases/<version>.
    version = "r1234-sha-0123456789abcdef0123456789abcdef01234567"
    release = AvailableRelease(
        version=version, source_url="https://codeload.github.com/x/y/tar.gz/abc"
    )
    assert release.version == version
    assert "/" not in release.version
    assert release.version not in {".", ".."}


def test_ci_workflow_publish_and_release_jobs_need_postgres_orm() -> None:
    workflow = _workflow()
    release_path_jobs = {
        name: job
        for name, job in workflow["jobs"].items()
        if "publish" in name or "release" in name
    }

    assert set(release_path_jobs) == {
        "docker-publish",
        "github-release",
        "publish-self-update-manifest",
    }
    for job in release_path_jobs.values():
        assert "postgres-orm" in job["needs"]
