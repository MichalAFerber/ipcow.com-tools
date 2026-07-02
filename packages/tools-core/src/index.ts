// @ipcow/tools-core — the single source of truth for every ipcow tool.
// Pure, typed, transport-agnostic. Consumed by the web app, the public API, and
// the monitoring engine alike.

export * from './errors';

// IP math
export * from './ip/address';
export * from './ip/cidr';

// DNS
export * from './dns/wire';
export * from './dns/doh';
export * from './dns/records';
export * from './dns/reverse';
export * from './dns/asn';
export * from './dns/dnssec';
export * from './dns/propagation';
export * from './dns/health';

// Email deliverability
export * from './email/spf';
export * from './email/dmarc';
export * from './email/dkim';
export * from './email/caa';
export * from './email/mx';
export * from './email/mtasts';
export * from './email/bimi';
export * from './email/deliverability';

// HTTP
export * from './http/headers';

// AI / crawler policy
export * from './ai/llms';
export * from './ai/robots';

// RDAP (whois successor)
export * from './rdap/client';

// Net helpers (portable — safe on Node + Workers)
export * from './net/client-ip';
export * from './net/short-domains';

// Node-only helpers (SSRF egress guard, GeoLite2 lookup, operational at-rest crypto) live under
// ./node/* and are intentionally NOT re-exported here — import them by subpath so their node: deps
// never enter a Workers/edge bundle.
