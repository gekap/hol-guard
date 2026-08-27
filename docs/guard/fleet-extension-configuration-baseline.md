# Fleet Extension Configuration implementation baseline

Status: approved for `release/3.0` implementation only  
Baseline captured: 2026-08-27

## Exact starting points

- HOL Guard Core: `hashgraph-online/hol-guard@784b31eb7b388e23b2a9e8cb4372c1d639049cbe`
- HOL Guard Cloud: `hashgraph-online/points-portal@616f2a08be657cc46aad2bd48216a47181cd840c`

No implementation batch may be based on `main`. Each batch records its actual parent again before it is opened.

## Reconciled current state

The release branches already contain Extension-first Managed Controls, signed policy bundle v2 delivery, staged rollouts, acknowledgement evidence, catalog posture, delegated Package Firewall ownership, local exact-identity Custom Extension continuity, and automatic daemon synchronization. Fleet Extension Configuration extends those systems. It does not introduce a second policy product, a second enforcement engine, or a Cloud dependency for local protection.

The former HOL Guard PR #2522 is closed and superseded by merged `release/3.0` contract and parser work. The Cloud reconciliation PR #5467 was merged to `main`, but this initiative remains release-branch-only.

## Ownership map

| Area | Source of truth | Review owner |
|---|---|---|
| Shared contracts and vectors | `contracts/managed-controls/v2` in both repositories | Core and Cloud maintainers |
| Cloud authoring, assignment, compiler, delivery | `points-portal/src/lib/guard/managed-controls` | Cloud Guard maintainers |
| Cloud persistence | `points-portal/db` | Cloud data maintainers |
| Local parser, binding, apply, recovery | `hol-guard/src/codex_plugin_scanner/guard/managed_controls` | Core Guard maintainers |
| Cloud administration UI | `points-portal/app/guard` | Cloud Guard UI maintainers |
| Local Protection Center | `hol-guard/dashboard` | Core Guard UI maintainers |
| Operations, release, and privacy gates | both `.github/workflows` and `docs/guard` | release owners |

## Paired merge sequence

1. Merge the Cloud side of each 100-task batch to `points-portal/release/3.0`.
2. Rebase the Core side on the latest `hol-guard/release/3.0` and consume the exact shared contract bytes.
3. Require all HOL Guard checks to pass.
4. Merge the Core side.
5. Run the cross-repository drift check and record both merge SHAs.

Cloud CI failures unrelated to the changed area do not block these batches. Review findings, contract drift, tenant-isolation failures, and authority failures always block.

## Completion evidence

Every task is recorded as `FEC-NNN`, implementation paths, tests, review resolution, PR, merge SHA, and verification result. A task is not complete merely because code exists. Evidence must show the intended branch contains the behavior.

## Risk register

| Risk | Required control |
|---|---|
| Portable identity accidentally uploads local paths or commands | Strict allowlist schemas, opaque per-workspace IDs, privacy fixtures |
| Dynamic assignment admits the wrong device | Workspace ownership graph, explicit exclusions, revision-bound selector evidence |
| Cloud weakens a local or required floor | Disable-dominant authority lattice and managed-restrictive validation |
| Partial composite apply exposes mixed authority | Journaled prepare/commit/rollback and exact last-known-good restore |
| Catalog meaning changes under the same target | Semantic fingerprints and publish-time re-simulation |
| Offboarding leaves managed authority behind | Signed tombstones, bounded grace, acknowledgement, and local safe fallback |
| Cross-tenant replay | Workspace, device, runtime session, revision, and digest binding |
