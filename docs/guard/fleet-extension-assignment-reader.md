# Fleet Extension assignment reader

This document records the HOL Guard Core implementation for FEC-201 through FEC-300.

Core parses one strict Managed Control Assignment, evaluates the selector against privacy-safe local catalog evidence, excludes unsupported devices without semantic downgrade, and compiles an exact device-bound projection. Workspace, assignment revision, immutable configuration version, configuration digest, catalog digest, catalog semantic fingerprint, built-in Extension support, exact reviewed Custom Extension binding and target semantics are all authority-bearing.

A missing capability, changed catalog, missing built-in Extension, missing Custom Extension variant, changed Custom Extension semantics, stale revision, workspace mismatch or excluded device fails closed. No discovered executable is promoted to trusted automatically. Raw paths, commands, source, environment values, credentials and secrets are not accepted by the portable assignment or projection reader.

Task evidence:

- FEC-201–230: strict assignment and selector parsing in `fleet_assignment.py`.
- FEC-231–260: heterogeneous fleet admission and stable exclusions in `preview_assignment`.
- FEC-261–285: exact device projection compilation and domain-separated digest binding in `compile_projection`.
- FEC-286–300: capability, tenant, semantic, Custom Extension, stale revision, determinism and privacy regressions in `test_fleet_assignment.py`.
