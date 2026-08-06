# Code-OSS upstream baseline

GuardRails IDE is a fork of Code-OSS, not a reimplementation of an editor shell.

| Field | Value |
| --- | --- |
| Upstream repository | `https://github.com/microsoft/vscode.git` |
| Pinned tag | `1.132.0` |
| Pinned commit | `df53daabb18cd157bdb08c7f01c34df936cf12f4` |
| Import merge | `b0332bac5ed` |
| Fetch date | 2026-08-06 |

The merge preserves both the GuardRails security-kernel history and the upstream
Code-OSS history. Upstream updates must be fetched from `upstream`, merged in a
dedicated commit, validated with the product-configuration and security suites, and
reviewed for new privileged APIs before GuardRails changes resume.

The public extension marketplace is intentionally absent from `product.json`. It will
remain disabled until a curated registry, signed capability manifests, IDE Scanner
artifact identity, and broker conformance coverage exist.
