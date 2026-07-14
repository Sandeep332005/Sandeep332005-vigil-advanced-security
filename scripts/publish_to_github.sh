#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <github-repo-url>"
  echo "Example: $0 https://github.com/Sandeep332005/vigil-advanced-security.git"
  exit 1
fi

repo_url="$1"

if [[ ! "$repo_url" =~ ^https://github\.com/.+/.+(\.git)?$ ]]; then
  echo "Error: expected a GitHub HTTPS repository URL."
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Using repository root: $repo_root"

if git -C "$repo_root" remote get-url origin >/dev/null 2>&1; then
  git -C "$repo_root" remote set-url origin "$repo_url"
  echo "Updated existing origin remote."
else
  git -C "$repo_root" remote add origin "$repo_url"
  echo "Added origin remote."
fi

git -C "$repo_root" branch -M main
git -C "$repo_root" push -u origin main

echo "Publish complete."
