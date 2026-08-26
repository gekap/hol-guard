#!/usr/bin/env bash
set -euo pipefail

BASE_REF=${BASE_REF:-origin/release/3.0}
SEED_ROOT=${SEED_ROOT:-/tmp/batch1-seed}
REPORT=docs/guard/rust-pretool-authority-bootstrap-report.md

candidates=(
  "feat/rust-safety-kernel-pretool-completion-v2:8f902c06dc57cb7d2973c1a06b6d2483fb5d499c"
  "feat/rust-safety-kernel-pretool-completion:02f31dd99d4ffd2091f17bac971bddcd8ecd7b35"
  "feat/rust-safety-kernel-integration-final:152cddf4c07db198772a8df792bc2aaa54430895"
  "automation/rust-p1-p2-end-to-end:97a5180646158ec9a7c00d889556f5da01e94a07"
  "feat/rust-p1-p2-native-core:92d0767cbea98e9fbce14f8eaacc3d32131b9864"
  "feat/rust-p1-p2-autonomous:450f4336b10481f6001c450ebf43ea34c0737716"
)

restore_seed() {
  mkdir -p scripts/ci docs/guard
  cp "$SEED_ROOT/scripts/ci/rust_pretool_authority_integration.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/converge_rust_pretool_authority_v2.py" scripts/ci/
  cp "$SEED_ROOT/docs/guard/rust-migration-batch-1-tasks.md" docs/guard/
}

source_gate() {
  grep -RqsE 'PreToolUse|pre_tool_use|pre-tool' rust/crates
  ! grep -q "from .runtime.command_evaluation import evaluate_command" src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null
  ! grep -q "evaluate_command(" src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null
  ! grep -q "Python remains authoritative" src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null
  if grep -q 'event_name != "PostToolUse"' src/codex_plugin_scanner/guard/daemon/hook_worker.py 2>/dev/null; then
    grep -qE 'PreToolUse|pre_tool' src/codex_plugin_scanner/guard/daemon/hook_worker.py
  fi
}

validate_candidate() {
  local log_dir=$1
  cargo fmt --manifest-path rust/Cargo.toml --all >"$log_dir/fmt.log" 2>&1
  cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings >"$log_dir/clippy.log" 2>&1
  cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets >"$log_dir/cargo-test.log" 2>&1
  VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
  HOL_GUARD_BUILD_SHA=$(git rev-parse HEAD) HOL_GUARD_PACKAGE_VERSION="$VERSION" \
    cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime >"$log_dir/build.log" 2>&1
  rust/target/release/hol-guard-runtime self-test --json >"$log_dir/self-test.json" 2>&1
  uv run --no-sync python scripts/ci/rust_pretool_authority_integration.py \
    --runtime rust/target/release/hol-guard-runtime \
    --json "$log_dir/pretool.json" >"$log_dir/integration.log" 2>&1
}

mkdir -p docs/guard
cat >"$REPORT" <<EOF
# Rust PreToolUse Authority Candidate Selection

Base: \`$(git rev-parse "$BASE_REF")\`

EOF

for entry in "${candidates[@]}"; do
  branch=${entry%%:*}
  sha=${entry##*:}
  safe=${branch//\//-}
  log_dir="/tmp/rust-pretool-candidate-$safe"
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
    scripts/bench_guard_native_release_gate.py \
    scripts/bench_guard_native_full_path.py \
    tests/test_guard_native_runtime.py \
    tests/test_guard_hook_worker.py \
    tests/test_codex_hook_fallback_isolation.py \
    >"$log_dir/candidate.patch"
  if [[ ! -s "$log_dir/candidate.patch" ]]; then
    printf -- '- %s: no unique source changes\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! git apply --3way --index "$log_dir/candidate.patch" >"$log_dir/apply.log" 2>&1; then
    printf -- '- %s: patch conflict\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! source_gate >"$log_dir/source-gate.log" 2>&1; then
    printf -- '- %s: source authority gate failed\n' "$branch" >>"$REPORT"
    continue
  fi
  if validate_candidate "$log_dir"; then
    printf -- '- %s@%s: accepted\n' "$branch" "$sha" >>"$REPORT"
    cat >>"$REPORT" <<EOF

## Accepted candidate

\`$branch@$sha\`

The candidate passed the Rust source authority gate, workspace formatting,
Clippy with warnings denied, workspace tests, release build, runtime self-test,
and compiled real-binary PreToolUse adversarial integration.
EOF
    git add -A
    exit 0
  fi
  printf -- '- %s: compiled integration failed\n' "$branch" >>"$REPORT"
done

git reset --hard "$BASE_REF" >/dev/null
git clean -fdx -e .venv -e rust/target >/dev/null
restore_seed
uv run --no-sync python scripts/ci/converge_rust_pretool_authority_v2.py
cat >"$REPORT" <<'EOF'
# Rust PreToolUse Authority Candidate Selection

No historical candidate passed every current release gate. The deterministic
conservative Rust authority migration was applied.

## Accepted implementation

`scripts/ci/converge_rust_pretool_authority_v2.py`
EOF
git add -A
