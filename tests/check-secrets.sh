#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Reject common high-confidence signs of real secrets. This is a baseline check,
# not a replacement for a dedicated secret scanner or a manual code review.
if grep -EnRI --exclude='check-secrets.sh' --exclude-dir=.git \
  -e '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' \
  -e 'github_pat_[A-Za-z0-9_]{20,}' \
  -e 'ghp_[A-Za-z0-9]{36}' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'sk-proj-[A-Za-z0-9_-]{20,}' \
  -- README.md vulnmachinesctl.sh LICENSE SECURITY.md .github tests; then
  echo 'Potential secret detected; review before publishing.' >&2
  exit 1
fi
printf 'No common high-confidence secret patterns detected.\n'
