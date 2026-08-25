# Everyday Mode semantic explanation catalog

HOL Guard Core owns action meaning. This catalog is deterministic, local, and side-effect free. It consumes the executable and argument vector from Core's canonical action pipeline. It does not execute commands, make network requests, or call a language model.

## Initial covered families

- file and folder deletion, including recursive deletion;
- copying, moving, and renaming files;
- ownership and permission changes;
- reads of typed sensitive credential locations;
- outbound web requests, downloads, and uploads;
- remote file transfer;
- package installation, removal, and publication across common package managers.

Every recognized action receives a consequence-first headline, a plain-language summary, a material impact, a recommendation, and safer alternatives. Unknown or unsupported actions remain explicitly limited-confidence and are never inferred safe.

## Privacy and authority

Everyday text uses safe target labels rather than full local paths. Secret-like values are removed before any technical projection is returned. Exact commands are present only when Core retained them and the caller is authorized to see them. Cloud consumers must use the contract's cloud-safe projection.

The catalog is content-addressed through `stable_semantic_catalog_digest()` so caches and compatibility checks can detect semantic changes without using raw action content.
