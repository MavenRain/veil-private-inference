#!/usr/bin/env bash
set -euo pipefail
receipt_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$receipt_root"
receipt_python="${VEIL_PYTHON:-$receipt_root/inference/.venv/bin/python}"
receipt_opa="${OPA:-$receipt_root/_build/opa}"
test -x "$receipt_python"
test -x "$receipt_opa"
test -f inference/artifacts/zk/verification_key.json
rm -f inference/artifacts/software-validation.json
node inference/build.mjs
receipt_parent_exit=0
zsh dev/gates.sh > inference/artifacts/parent-gates.log 2>&1 || receipt_parent_exit=$?
cat inference/artifacts/parent-gates.log
npm --prefix inference test
npm --prefix inference run test:zk
OPA="$receipt_opa" npm --prefix inference run test:policy
"$receipt_python" -P inference/deploy/test_gpu_guard.py
"$receipt_python" -P -m unittest veil_privacy.test_fhe veil_privacy.test_federation
receipt_run="$(mktemp -d "${TMPDIR:-/tmp}/veil-release.XXXXXXXX")"
"$receipt_python" -P -m veil_privacy.federation simulate "$receipt_run/federation"
node inference/record-validation.mjs "$receipt_parent_exit" "$receipt_run/federation/workspace/validation.json"
if [ "$receipt_parent_exit" -ne 0 ]; then
  printf 'PRIVATE-INFERENCE-RELEASE-FAIL: parent gates failed; see the recorded validation\n'
  exit "$receipt_parent_exit"
fi
printf 'PRIVATE-INFERENCE-RELEASE-OK\nFederation evidence: %s/federation/workspace/validation.json\n' "$receipt_run"
