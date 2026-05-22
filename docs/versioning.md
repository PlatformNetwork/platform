# Versioning Policy

Platform releases start at `3.0.0`. Use Semantic Versioning (`MAJOR.MINOR.PATCH`) for the application, Python package, Helm chart, and release image tags.

## Sources Of Truth

Update these files together for every Platform release:

- `pyproject.toml`: Python package version, without a leading `v`.
- `uv.lock`: editable `platform-network` package entry, without a leading `v`.
- `deploy/helm/platform/Chart.yaml`: chart `version` and quoted `appVersion`.
- `deploy/helm/platform/values.production.example.yaml`: production image tag and digest fixture.
- `.github/workflows/ci.yml`: GHCR tag policy.

For the `3.0.0` release, the Python package version, Helm chart `version`, and Helm `appVersion` are all `3.0.0`. The Git release tag is `v3.0.0`.

## SemVer Rules

- Increment `MAJOR` for breaking public API, CLI, config, environment variable, Helm value/schema, Docker runtime, database migration, deployment, or validator behavior changes.
- Increment `MINOR` for backward-compatible features.
- Increment `PATCH` for backward-compatible fixes.
- Released versions are immutable. If a release is wrong, fix forward with a new version.
- Python package versions must remain PEP 440-compatible, so they do not include the Git tag's leading `v`.

## GitHub And GHCR Tags

Use Git tags with a leading `v`, such as `v3.0.0`, for release events. The GitHub Actions metadata policy publishes canonical GHCR image tags from the tag event using:

```text
type=semver,pattern={{version}}
type=semver,pattern={{raw}}
type=sha,prefix=sha-
```

This means a `v3.0.0` Git tag publishes both the canonical `3.0.0` image tag and the compatibility `v3.0.0` tag, plus a traceable `sha-<commit>` tag. The `latest` tag is published only from `main` and is a mutable development/staging channel.

Pull requests build Docker images with `push: false`. GHCR publication happens only from trusted events: `main`, `v*.*.*` tags, or a manual `workflow_dispatch` where `confirm_publish` is set to `true`.

## Production Image Policy

Production and Kubernetes deployment references must use a SemVer image tag plus a digest:

```text
ghcr.io/platformnetwork/platform:3.0.0@sha256:<64-hex-digest>
```

The digest is the immutable deployment selector. The tag provides human-readable release context. Production policy rejects `latest`, untagged image references, missing digests, and non-SemVer tags.

Mutable tags such as `latest` are allowed only for local, development, and explicitly documented staging flows. The validator installer includes an image-updater CronJob so mutable GHCR tags are repulled after a rollout restart, but production should prefer digest-pinned image references.

## Release Execution Boundary

Do not create Git tags, GitHub releases, GHCR packages, or real-cluster rollouts unless the operator explicitly confirms that external side effect. Local validation, `push: false` Docker builds, and disposable kind tests are safe pre-release checks.
