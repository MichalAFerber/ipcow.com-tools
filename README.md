# ipcow-tools

Privacy-first IP, DNS & email tooling — the reusable, MIT-licensed core behind
[ipcow.com](https://ipcow.com).

- **`packages/tools-core`** — `@ipcow/tools-core`: RFC 8484 DoH client (Quad9), DNS
  record / reverse / SPF / DMARC / DKIM / CAA / MX / MTA-STS / DNSSEC / BIMI lookups, CIDR + IP
  math, RDAP, and AI-crawler-policy checks. Pure, typed, transport-agnostic, **no cross-package
  imports**. See its [README](./packages/tools-core/README.md).
- **`apps/probe`** — `ipcow-probe`: a small per-stack network probe (Go, stdlib + one dependency).

Used in production by **[ipcow.com](https://ipcow.com)** (a separate, private repo) via a git
submodule. Licensed under the [MIT License](./LICENSE).
