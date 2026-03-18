# hostd network domain attribution (minimal strategy)

This note fixes the first usable domain-attribution strategy for the `agent-auditor-hostd` network PoC.

## Goal of P3-4

Produce a provisional domain candidate for outbound `network.connect` events without pretending kernel-space connect observation can prove which hostname the workload intended.

## Current minimal strategy

The hostd network classifier now attributes a domain only when all of the following are true:

1. userspace has a **recent DNS answer cache** entry for a domain
2. the outbound connect destination IP matches one of that answer's IPs **exactly**
3. exactly **one** cached domain matches that destination IP

When those checks pass, the classifier sets:

- `domain_candidate`
- `domain_attribution_source = dns_answer_cache_exact_ip`

When they do not pass, the classifier leaves domain attribution empty.

## Why this strategy first

This keeps the PoC honest:

- the connect event still comes from outbound observe, not from DNS parsing guesses inside the kernel hook
- the attribution rule is deterministic and testable in unprivileged CI
- ambiguous shared-IP cases fail closed to `None` instead of overclaiming a hostname

## Current PoC shape

For the checked-in deterministic preview path, the classifier seeds a tiny recent-answer cache with:

- `example.com -> 93.184.216.34`

That lets the PoC prove the shape end to end while keeping the strategy explicit.

## Explicit constraints

This attribution is intentionally weak and lossy.

### 1. Exact-IP match only

The current strategy does **not** use:

- reverse DNS
- TLS SNI
- HTTP `Host` / `:authority`
- CNAME chain reconstruction
- resolver search-domain expansion

If the exact destination IP is not present in the recent DNS answer cache, no domain is emitted.

### 2. Ambiguous shared IPs return no attribution

Many domains can share the same IP behind CDNs, load balancers, or edge proxies.
If multiple cached domains map to the same destination IP, hostd emits **no** `domain_candidate`.
That is safer than inventing one.

### 3. DNS timing is not proven yet

A cached DNS answer near a connect event does **not** prove the connect used that lookup.
The workload may have:

- reused an old socket destination
- connected via a hard-coded IP
- used a different resolver path
- raced with another process populating the cache

So `domain_candidate` must be treated as an enrichment hint, not ground truth.

### 4. Port does not disambiguate the hostname

The current strategy matches on destination IP only.
Port is preserved in normalized metadata for policy and audit, but it is **not** used to decide the hostname.

### 5. TTL / freshness is still future work

The PoC models a recent-answer cache shape, but it does not yet enforce a real TTL / aging policy.
Future work should bound attribution by observed answer age and resolver context.

## Follow-on work enabled by this step

- P3-5 can evaluate network destination policy against `destination_ip`, `destination_port`, `transport`, and a provisional `domain_candidate`
- P3-6 can surface policy outcomes while preserving whether hostname attribution was present or absent
- P3-8 can document local run steps and operational caveats for the domain-attribution path
