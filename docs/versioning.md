# Versioning Policy

Platform releases start at `3.0.0`. Use Semantic Versioning (`MAJOR.MINOR.PATCH`) for the application, Python package, Helm chart, and release image tags.

## Sources Of Truth

Update these files together for every Platform release:

- `pyproject.toml`: Python package version, without a leading `v`.
- `uv.lock`: editable `platform-network` package entry, without a leading `v`.
- `deploy/helm/platform/Chart.yaml`: chart `version` and quoted `appVersion`.
- `deploy/helm/platform/values.production.example.yaml`: production image tag and digest fixture.
- `.github/workflows/ci.yml`: GHCR tag policy.

For the `3.0.3` release, the Python package version, Helm chart `version`, and Helm `appVersion` are all `3.0.3`. The Git release tag is `v3.0.3`.

## SemVer Rules

- Increment `MAJOR` for breaking public API, CLI, config, environment variable, Helm value/schema, Docker runtime, database migration, deployment, or validator behavior changes.
- Increment `MINOR` for backward-compatible features.
- Increment `PATCH` for backward-compatible fixes.
- Released versions are immutable. If a release is wrong, fix forward with a new version.
- Python package versions must remain PEP 440-compatible, so they do not include the Git tag's leading `v`.

## GitHub And GHCR Tags

Use Git tags with a leading `v`, such as `v3.0.3`, for release events. The GitHub Actions metadata policy publishes canonical GHCR image tags from the tag event using:

```text
type=semver,pattern={{version}}
type=semver,pattern={{raw}}
type=sha,prefix=sha-
```

This means a `v3.0.3` Git tag publishes both the canonical `3.0.3` image tag and the compatibility `v3.0.3` tag, plus a traceable `sha-<commit>` tag. Branch builds publish a mutable `main` tag, and `main` also publishes `latest`; those mutable tags are the default Kubernetes auto-update channel for first-party Platform workloads.

Pull requests build Docker images with `push: false`. GHCR publication happens only from trusted events: `main`, `v*.*.*` tags, or a manual `workflow_dispatch` where `confirm_publish` is set to `true`.

## GitHub Releases

Pushing a `v*.*.*` tag creates a GitHub Release only after CI validation and both GHCR image publish jobs succeed. Branch pushes and manual `workflow_dispatch` runs can publish images under the trusted-event rules above, but they do not create GitHub Releases.

Release descriptions combine GitHub-generated release notes with a maintained body that lists the published `platform` and `platform-master` GHCR tags: canonical SemVer, compatibility `v` tag, and traceable `sha-<commit>` tag. The body also includes deployment notes that production should pin the SemVer tag plus immutable digest.

Tags containing a hyphen, such as `v3.1.0-rc.1`, are marked as prereleases. Stable tags are marked as the latest GitHub Release.

## Production Image Policy

Pinned production deployment references must use a SemVer image tag plus a digest:

```text
ghcr.io/platformnetwork/platform:3.0.3@sha256:<64-hex-digest>
```

The digest is the immutable deployment selector. The tag provides human-readable release context. Production policy rejects `latest`, untagged image references, missing digests, non-SemVer tags, and mutable auto-update CronJobs.

Mutable tags such as `latest` and `main` are allowed for the default Kubernetes auto-update mode.
In that mode, Helm renders master admin, proxy, broker, config sync, and image-updater resources from `ghcr.io/platformnetwork/platform-master:latest`.
Validator workloads are deployed by an explicit validator release from `ghcr.io/platformnetwork/platform:latest`; validators fetch master-computed weights and perform final Bittensor submission.
The updaters use anonymous GHCR registry digest checks for public packages and patch Deployments to `tag@sha256:<digest>` only when a mutable tag moves. No GHCR pull secret is required while the packages remain public. To roll back or freeze a production deployment, disable `imageAutoUpdate` and pin SemVer plus digest values.

## Release Execution Boundary

Do not create Git tags, GitHub releases, GHCR packages, or real-cluster rollouts unless the operator explicitly confirms that external side effect. Local validation, `push: false` Docker builds, and disposable kind tests are safe pre-release checks.
