# Fleet Extension Configuration glossary and copy matrix

| Product copy | Canonical contract value | Meaning |
|---|---|---|
| Allow | `permit` | Allow a matching contextual action when no stronger floor blocks it. |
| Ask for review | `review` | Pause a matching action for authorized review. |
| Deny | `block` | Block a matching contextual action. |
| Observe | `observe` | Record privacy-safe evidence without adding an allow decision. |
| Available | `enabled` | The Extension may participate, subject to required floors and policy. |
| Disabled | `disabled` | The Extension or permission is unavailable. |
| Managed Block | managed restrictive `block` or `disabled` | Non-weakenable fleet restriction. |
| Shared default | `workspace-shared` | Workspace preference that local users may tighten. |
| All team devices | `all-active-devices` | Current and future eligible devices in the workspace. |
| Custom Extension | `guard.custom-extension-definition.v2` | Portable reviewed semantic definition; never a raw local path. |

Prohibited duplicate nouns: fleet profile, extension policy pack, cloud extension engine, synchronized allowlist, and global local identity.
