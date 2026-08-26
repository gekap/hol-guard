#!/usr/bin/env bash
set -euo pipefail

BASE_REF=${BASE_REF:-origin/release/3.0}
SEED_ROOT=${SEED_ROOT:-/tmp/batch1-native-seed-v3}
REPORT=docs/guard/rust-pretool-authority-bootstrap-report.md

candidates=(
  "feat/rust-safety-kernel-pretool-completion-v2:8f902c06dc57cb7d2973c1a06b6d2483fb5d499c"
  "feat/rust-safety-kernel-pretool-completion:02f31dd99d4ffd2091f17bac971bddcd8ecd7b35"
  "feat/rust-safety-kernel-integration-final:152cddf4c07db198772a8df792bc2aaa54430895"
  "automation/finalize-rust-pretool-authority-20260815:7b5ff3759b23eefa104266be6a679fc3b6fd5eca"
  "automation/shepherd-rust-pretool-authority-20260815:d12a452bb641c3fb8b9a040d7f616a675c9498b4"
  "automation/rust-p1-p2-end-to-end:97a5180646158ec9a7c00d889556f5da01e94a07"
  "feat/rust-p1-p2-native-core:92d0767cbea98e9fbce14f8eaacc3d32131b9864"
  "feat/rust-p1-p2-autonomous:450f4336b10481f6001c450ebf43ea34c0737716"
  "feat/rust-p0-native-core-final-v5:92d0767cbea98e9fbce14f8eaacc3d32131b9864"
  "feat/rust-p0-native-core-final-v4:668b49cca4a20f619a172a12a346a7bac17bfcbc"
  "feat/rust-p0-native-core-final-v3:d8c6dcc32fd77513cf39fc23768511c0b0ab8eef"
  "feat/rust-hardening-foundation:50de681b63958bda3f9f0f5f2ce66a37d8203afc"
  "feat/rust-runtime-foundation:205dfb69c7cb809cf1d9c904cc9736c6f982a9cd"
)

restore_seed() {
  mkdir -p scripts/ci docs/guard
  cp "$SEED_ROOT/scripts/ci/rust_pretool_authority_integration.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/rust_pretool_no_python_gate.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/rust_pretool_no_python_integration.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/remove_python_pretool_runtime.py" scripts/ci/
  cp "$SEED_ROOT/docs/guard/rust-migration-batch-1-tasks.md" docs/guard/
}

validate_candidate() {
  local log_dir=$1
  uv run --no-sync python scripts/ci/remove_python_pretool_runtime.py >"$log_dir/remove-python.log" 2>&1
  mapfile -t changed_py < <(git diff --name-only "$BASE_REF" -- '*.py' | while read -r p; do test -f "$p" && printf '%s\n' "$p"; done)
  if (( ${#changed_py[@]} )); then
    uv run --no-sync ruff format "${changed_py[@]}" >"$log_dir/ruff-format.log" 2>&1
    uv run --no-sync ruff check --fix "${changed_py[@]}" >"$log_dir/ruff-check.log" 2>&1
  fi
  uv run --no-sync python scripts/ci/rust_pretool_no_python_gate.py \
    --root . --json "$log_dir/no-python-source.json" >"$log_dir/no-python-source.log" 2>&1
  cargo fmt --manifest-path rust/Cargo.toml --all >"$log_dir/fmt.log" 2>&1
  cargo fmt --manifest-path rust/Cargo.toml --all --check >>"$log_dir/fmt.log" 2>&1
  cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings >"$log_dir/clippy.log" 2>&1
  cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets >"$log_dir/cargo-test.log" 2>&1
  VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
  HOL_GUARD_BUILD_SHA=$(git rev-parse HEAD) HOL_GUARD_PACKAGE_VERSION="$VERSION" \
    cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime >"$log_dir/build.log" 2>&1
  runtime="$PWD/rust/target/release/hol-guard-runtime"
  "$runtime" self-test --json >"$log_dir/self-test.json" 2>&1
  uv run --no-sync python scripts/ci/rust_pretool_authority_integration.py \
    --runtime "$runtime" --json "$log_dir/pretool.json" >"$log_dir/pretool.log" 2>&1
  uv run --no-sync python scripts/ci/rust_pretool_no_python_integration.py \
    --runtime "$runtime" --json "$log_dir/no-python-runtime.json" >"$log_dir/no-python-runtime.log" 2>&1
  mapfile -t focused < <(find ci/native_runtime tests -type f \( -iname '*pretool*.py' -o -iname '*pre_tool*.py' -o -iname '*native*command*.py' \) | sort)
  if (( ${#focused[@]} )); then
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY="$runtime" \
      uv run --no-sync pytest -q "${focused[@]}" --tb=short >"$log_dir/focused.log" 2>&1
  fi
}

mkdir -p docs/guard
cat >"$REPORT" <<EOF
# Rust PreToolUse Direct-Native Candidate Selection

Base: \`$(git rev-parse "$BASE_REF")\`

Each candidate is reconciled with the current release, obsolete Python live
PreToolUse compatibility code is removed, and the result is accepted only after
source ownership, process tracing, compiled adversarial integration, and Rust
workspace gates pass.

EOF

for entry in "${candidates[@]}"; do
  branch=${entry%%:*}
  sha=${entry##*:}
  safe=${branch//\//-}
  log_dir="/tmp/rust-pretool-direct-v3-$safe"
  rm -rf "$log_dir" && mkdir -p "$log_dir"
  git reset --hard "$BASE_REF" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  restore_seed
  git fetch --no-tags origin "$branch" >/dev/null 2>&1 || git fetch --no-tags origin "$sha" >/dev/null 2>&1 || true
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    printf -- '- %s: unavailable\n' "$branch" >>"$REPORT"
    continue
  fi
  merge_base=$(git merge-base "$BASE_REF" "$sha")
  git diff --binary "$merge_base" "$sha" -- \
    rust \
    src/codex_plugin_scanner/guard \
    ci/native_runtime \
    tests \
    scripts/bench_guard_native_full_path.py \
    scripts/bench_guard_native_release_gate.py \
    >"$log_dir/candidate.patch"
  if [[ ! -s "$log_dir/candidate.patch" ]]; then
    printf -- '- %s: no unique source changes\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! git apply --3way --index "$log_dir/candidate.patch" >"$log_dir/apply.log" 2>&1; then
    printf -- '- %s: patch conflict\n' "$branch" >>"$REPORT"
    continue
  fi
  if validate_candidate "$log_dir"; then
    printf -- '- %s@%s: accepted\n' "$branch" "$sha" >>"$REPORT"
    cat >>"$REPORT" <<EOF

## Accepted candidate

\`$branch@$sha\`

The reconciled candidate passed direct-native source ownership, Python runtime
retirement, process-execution tracing, compiled real-binary adversarial
integration, the complete Rust workspace, and discovered native PreToolUse
integration suites.
EOF
    git add -A
    exit 0
  fi
  printf -- '- %s: rejected by direct-native compiled gates\n' "$branch" >>"$REPORT"
done

git reset --hard "$BASE_REF" >/dev/null
git clean -fdx -e .venv -e rust/target >/dev/null
restore_seed
cat >>"$REPORT" <<'EOF'

## Failure

No historical implementation could be reconciled into a direct-native,
Python-free live PreToolUse path without violating current release gates.
EOF
git add -A
exit 1
