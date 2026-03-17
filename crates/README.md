# crates/

Planned shared Rust crates.

Initial expected split:

- `event-schema` — normalized event types and serde models
- `policy-client` — OPA bundle / decision integration
- `audit-store` — append log and integrity helpers
- `runtime-attribution` — session/container attribution helpers
- `collectors-ebpf` — eBPF-facing collector code
- `collectors-fanotify` — fanotify-facing collector code
