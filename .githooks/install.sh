#!/bin/bash
# Install git hooks for this repository
# Run this after cloning: ./githooks/install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Copy hooks
cp "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
cp "$SCRIPT_DIR/pre-push" "$HOOKS_DIR/pre-push"

# Make executable
chmod +x "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-push"

echo "Git hooks installed successfully!"
echo ""
echo "Hooks enabled:"
echo "  - pre-commit: Auto-format code"
echo "  - pre-push: Run all CI checks (format, clippy, tests)"
echo ""
echo "To skip hooks temporarily (not recommended):"
echo "  git push --no-verify"
