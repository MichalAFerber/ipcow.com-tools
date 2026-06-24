# @ipcow/tools-core

Privacy-first IP, DNS & email tool logic — the single source of truth behind the tools at
[ipcow.com](https://ipcow.com). Pure, typed, and transport-agnostic: every function takes a
string in and returns structured data, with no hidden global state and no third-party lookup
APIs. It runs the same in Cloudflare Workers, Node, and the browser.

This package is **MIT-licensed** and intentionally has **no cross-package imports**, so it is
cleanly reusable on its own.

## What's inside

- **DNS over HTTPS (RFC 8484).** A dependency-free DoH client that speaks the `application/dns-message`
  wire format using the GET form. Defaults to **Quad9** (privacy-first, non-profit), with an
  automatic fallback to Cloudflare so one bad upstream doesn't fail a lookup. No big-tech resolvers.
- **DNS lookups.** Record lookups (A, AAAA, MX, TXT, NS, CNAME, SOA, …) and reverse (PTR) lookups,
  built on the DoH client.
- **Email deliverability.** Parsing/inspection for **SPF**, **DMARC**, **DKIM**, **CAA**, and **MX**.
- **IP & CIDR math.** IPv4/IPv6 parsing and normalization, subnet breakdowns (network/broadcast/
  netmask/wildcard/usable-host counts, including RFC 3021 /31 and /32 handling), CIDR ↔ range
  conversion, and special-use address classification (RFC 1918, CGNAT, link-local, documentation, …).
- **RDAP.** The modern WHOIS successor — IP and domain lookups via the community RDAP bootstrap
  (`rdap.org`), which redirects to the authoritative RIR/registry.

All errors are surfaced as a typed `ToolError` with a stable machine-readable code
(`invalid_input`, `not_found`, `timeout`, `upstream_error`, …).

## Use it

This package isn't published to npm — it ships **TypeScript source** directly (`main`/`types` →
`./src/index.ts`). The site at [ipcow.com](https://ipcow.com) consumes it as a **git submodule**
resolved through its pnpm workspace; vendor it the same way elsewhere, or clone and run it standalone:

```bash
git clone https://github.com/MichalAFerber/ipcow.com-tools.git
cd ipcow.com-tools && pnpm install
pnpm -F @ipcow/tools-core test
```

> It's pure ESM TypeScript source, so consume it from a TS/ESM toolchain (Vite, esbuild, tsx,
> Workers, modern Node, …).

## Usage

```ts
import { dohQuery, describeCidr, classifyIp, rdapIp } from '@ipcow/tools-core';

// DNS over HTTPS (defaults to Quad9, falls back to Cloudflare)
const msg = await dohQuery('example.com', 'A');
console.log(msg.answers);

// Subnet math
const net = describeCidr('192.0.2.0/24');
console.log(net.networkAddress, net.broadcastAddress, net.usableHosts); // 192.0.2.0 192.0.2.255 254

// Special-use classification
console.log(classifyIp('10.1.2.3')); // { scope: 'private', description: 'Private-use (RFC 1918)', global: false }

// RDAP (WHOIS successor)
const rir = await rdapIp('1.1.1.1');
console.log(rir.name, rir.country, rir.cidr);
```

## License

[MIT](./LICENSE) © 2026 Michal Ferber.

Part of [ipcow.com](https://ipcow.com) — privacy-first IP, DNS & email tools.
