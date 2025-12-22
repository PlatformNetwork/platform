#!/bin/bash
# Setup git hooks for platform-chain

REPO_ROOT="$(git rev-parse --show-toplevel)"
git config core.hooksPath "$REPO_ROOT/.githooks"

echo "Git hooks configured:"
echo "  - pre-commit: Runs cargo fmt check, clippy, and cargo check"
echo "  - pre-push: Runs all CI checks (fmt, clippy, check, tests)"
