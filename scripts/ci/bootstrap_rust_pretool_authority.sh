#!/usr/bin/env bash
set -euo pipefail

BASE_REF=${BASE_REF:-origin/release/3.0}
ORIGINAL_HEAD=$(git rev-parse HEAD)
REPORT=docs/guard/rust-pretool-authority-bootstrap-report.md
mkdir -p "$(dirname "$REPORT")"

candidates=(
  "feat/rust-safety-kernel-pretool-completion-v2:8f902c06dc57cb7d2973c1a06b6d2483fb5d499c"
  "feat/rust-safety-kernel-pretool-completion:02f31dd99d4ffd2091f17bac971bddcd8ecd7b35"
  "feat/rust-safety-kernel-integration-final:152cddf4c07db198772a8df792bc2aaa54430895"
  "automation/rust-p1-p2-end-to-end:97a5180646158ec9a7c00d889556f5da01e94a07"
  "feat/rust-p1-p2-native-core:92d0767cbea98e9fbce14f8eaacc3d32131b9864"
  "feat/rust-p1-p2-autonomous:450f4336b10481f6001c450ebf43ea34c0737716"
)

pathspec=(
  rust
  src/codex_plugin_scanner/guard/native_command_model.py
  src/codex_plugin_scanner/guard/native_runtime.py
  src/codex_plugin_scanner/guard/native_runtime_admission.py
  src/codex_plugin_scanner/guard/native_runtime_resident.py
  src/codex_plugin_scanner/guard/native_runtime_resilience.py
  src/codex_plugin_scanner/guard/daemon/hook_worker.py
  src/codex_plugin_scanner/guard/cli/commands_hook.py
  src/codex_plugin_scanner/guard/cli/commands_hook_runtime_eval.py
  src/codex_plugin_scanner/guard/cli/commands_hook_runtime_review.py
  src/codex_plugin_scanner/guard/cli/commands_hook_runtime_finish.py
  src/codex_plugin_scanner/guard/cli/commands_support_command_activity.py
  ci/native_runtime
  tests/test_guard_native_runtime.py
  tests/test_guard_hook_worker.py
  tests/test_guard_hook_process_deadline_contract.py
)

cat >"$REPORT" <<EOF
# Rust PreToolUse Authority Bootstrap Evidence

Base: \`$(git rev-parse "$BASE_REF")\`

This report records an automated import and real-binary integration verification of previously developed Rust authority candidates. A candidate is accepted only when it compiles, passes Clippy, exposes native PreToolUse authority, removes the Python command evaluator from the native bridge, and passes the compiled-runtime integration probes.

EOF

validate_candidate() {
  local label=$1
  local log_dir=$2

  if ! grep -RqsE 'PreToolUse|pre_tool_use|pre-tool' rust/crates; then
    echo "missing Rust PreToolUse implementation" >"$log_dir/failure"
    return 1
  fi
  if grep -q 'Shadow-only Python bridge' src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null; then
    echo "native command bridge remains shadow-only" >"$log_dir/failure"
    return 1
  fi
  if grep -q 'evaluate_command(' src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null; then
    echo "Python command evaluator remains in native PreToolUse bridge" >"$log_dir/failure"
    return 1
  fi
  if grep -q 'status.mode not in.*shadow.*force' src/codex_plugin_scanner/guard/native_command_model.py 2>/dev/null; then
    echo "native command authority remains mode-gated" >"$log_dir/failure"
    return 1
  fi

  cargo fmt --manifest-path rust/Cargo.toml --all --check >"$log_dir/cargo-fmt.log" 2>&1 || {
    echo "cargo fmt failed" >"$log_dir/failure"; return 1;
  }
  cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings >"$log_dir/cargo-clippy.log" 2>&1 || {
    echo "cargo clippy failed" >"$log_dir/failure"; return 1;
  }
  cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets >"$log_dir/cargo-test.log" 2>&1 || {
    echo "cargo test failed" >"$log_dir/failure"; return 1;
  }

  VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
  HOL_GUARD_BUILD_SHA=$(git rev-parse HEAD) HOL_GUARD_PACKAGE_VERSION="$VERSION" \
    cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime \
    >"$log_dir/cargo-build.log" 2>&1 || {
      echo "native release build failed" >"$log_dir/failure"; return 1;
    }
  local runtime="$PWD/rust/target/release/hol-guard-runtime"
  "$runtime" self-test --json >"$log_dir/self-test.json" 2>"$log_dir/self-test.err" || {
    echo "native self-test failed" >"$log_dir/failure"; return 1;
  }

  HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY="$runtime" \
    uv run --no-sync pytest -q \
      ci/native_runtime/test_command_model_resident.py \
      ci/native_runtime/test_guard_native_runtime_binary.py \
      --tb=short >"$log_dir/integration.log" 2>&1 || {
        echo "compiled native integration tests failed" >"$log_dir/failure"; return 1;
      }

  if [[ -f ci/native_runtime/test_pretool_authority.py ]]; then
    HOL_GUARD_NATIVE_BINARY="$runtime" uv run --no-sync pytest -q \
      ci/native_runtime/test_pretool_authority.py --tb=short \
      >"$log_dir/pretool-integration.log" 2>&1 || {
        echo "native PreToolUse integration test failed" >"$log_dir/failure"; return 1;
      }
  fi

  printf '%s\n' "$label" >"$log_dir/accepted"
  return 0
}

selected=""
for entry in "${candidates[@]}"; do
  branch=${entry%%:*}
  sha=${entry##*:}
  safe=${branch//\//-}
  log_dir="/tmp/rust-authority-$safe"
  rm -rf "$log_dir"
  mkdir -p "$log_dir"

  git reset --hard "$ORIGINAL_HEAD" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  git fetch --no-tags origin "$branch" >/dev/null 2>&1 || git fetch --no-tags origin "$sha" >/dev/null 2>&1 || true
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    printf -- '- %s: unavailable\n' "$branch" >>"$REPORT"
    continue
  fi

  merge_base=$(git merge-base "$BASE_REF" "$sha")
  if ! git diff --binary "$merge_base" "$sha" -- "${pathspec[@]}" >"$log_dir/candidate.patch"; then
    printf -- '- %s: could not create candidate patch\n' "$branch" >>"$REPORT"
    continue
  fi
  if [[ ! -s "$log_dir/candidate.patch" ]]; then
    printf -- '- %s: no unique candidate changes\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! git apply --3way --index "$log_dir/candidate.patch" >"$log_dir/apply.log" 2>&1; then
    printf -- '- %s: patch conflict\n' "$branch" >>"$REPORT"
    continue
  fi

  if validate_candidate "$branch@$sha" "$log_dir"; then
    selected="$branch@$sha"
    printf -- '- %s: accepted\n' "$selected" >>"$REPORT"
    break
  fi
  reason=$(cat "$log_dir/failure" 2>/dev/null || echo validation-failed)
  printf -- '- %s: rejected (%s)\n' "$branch" "$reason" >>"$REPORT"
done

if [[ -z "$selected" ]]; then
  git reset --hard "$ORIGINAL_HEAD" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  echo >>"$REPORT"
  echo "No historical candidate passed the current release/3.0 authority and integration gates." >>"$REPORT"
  git add "$REPORT"
  exit 1
fi

# Keep the current batch evidence and bootstrap machinery while retaining only
# accepted source changes from the candidate patch.
git restore --source="$ORIGINAL_HEAD" -- \
  docs/guard/rust-migration-batch-1-tasks.md \
  .github/workflows/rust-local-toolchain-export.yml \
  .github/workflows/rust-pretool-authority-bootstrap.yml \
  scripts/ci/bootstrap_rust_pretool_authority.sh

cat >>"$REPORT" <<EOF

## Accepted candidate

\`$selected\`

## Verification

- Rust workspace formatting passed.
- Rust workspace Clippy passed with warnings denied.
- Rust workspace tests passed.
- A version-matched release binary was built and passed its self-test.
- Real resident and real-binary native integration probes passed.
- The Python native command bridge contains no Python \`evaluate_command\` call and is not shadow-only or shadow/force gated.
EOF

git add -A
