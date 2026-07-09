# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-08

This release is the result of a full-codebase review plus a focused pass on making the client viable in a scaled-out deployment without getting rate limited by upstream registries. **This is a breaking release** - see [Breaking Changes](#breaking-changes) and [Migration Notes](#migration-notes) below. HTTP API consumers are largely unaffected (the JSON gains an additive `lookup_status` field and a new 503 error case); library consumers may need code changes.

### Fixed

**Data correctness**
- **`status` field pollution**: contact address lines (`Registrant/Admin/Tech State/Province`) leaked into the domain `status` list because the parser matched any key containing `"state"`. Since `status` feeds security analysis (transfer locks, holds), nearly every registrar response contaminated downstream tooling with values like `"CA"` and `"REDACTED FOR PRIVACY"`. The parser now matches `status` keys plus only the exact `state` key used by some ccTLD registries (e.g. `.ru`)
- **Referral responses replaced authoritative registry data**: after following a `Registrar WHOIS Server:` referral, only the final response was parsed. Registrar servers frequently return thin or rate-limited responses, silently destroying registry fields (expiry, status, name servers) already in hand. Referral results now backfill missing fields from the registry response - and a referral response that is itself a rate-limit banner is discarded entirely in favor of the registry data
- **RDAP never worked for multi-part TLDs**: IANA's bootstrap registry keys services by top label only (`uk`), while PSL extraction returns the full public suffix (`co.uk`), so every `.co.uk`/`.com.au`/`.co.jp` lookup silently fell back to port-43 WHOIS. Discovery now retries with the last label, restoring the RDAP tier for all multi-part TLDs
- **RDAP domain lookups never extracted admin/tech contacts**: only `registrar`/`registrant` entity roles were handled; `administrative` and `technical` role emails are now extracted
- **Trailing-dot domains broke TLD resolution**: `example.com.` validated but produced the TLD `"com."`, matching nothing in the RDAP bootstrap. Trailing root dots are now stripped during normalization
- **URLs passed domain validation**: `http://example.com` validated (the `addr` crate parses permissive DNS *names*) and was sent verbatim to WHOIS servers. URL syntax (`/ : ? # @`, spaces) is now rejected with a clear error
- IP-shaped garbage (`300.300.300.300`) now returns an invalid-IP error instead of a confusing "Unsupported TLD" error; doubled error prefixes fixed; `whois://` referral scheme stripping is case-insensitive; OpenAPI document version now derives from Cargo.toml instead of being hardcoded

**Security**
- **SSRF gaps in referral handling**: the previous guard passed if *any* resolved address was public (a host resolving to `[public, 127.0.0.1]` could still steer the connection private) and resolved the hostname twice (check, then connect), leaving a DNS-rebinding window. Referral connections now resolve once, filter out private/special addresses, and connect only to the vetted addresses

**Operational**
- **Cache poisoning by rate-limit banners** (the most impactful fix in this release): WHOIS servers signal throttling as ordinary response text (`"Number of allowed queries exceeded"`, `"WHOIS LIMIT EXCEEDED"`, ...). These parsed as empty-but-successful lookups and were **cached for the full TTL**, poisoning the cache with garbage exactly when it should be shielding the upstream server. Responses are now classified (see `LookupStatus` below) and rate-limited responses are never cached
- **Unbounded Prometheus label cardinality**: `whois_requests_total{tld=...}` labeled IP queries with the raw query - one time series per distinct address (catastrophic for IPv6). IP queries now collapse to fixed `ipv4`/`ipv6` labels
- **Hand-built configs could panic or deadlock**: `buffer_pool_size: 0` panicked and `concurrent_whois_queries: 0` deadlocked every query. Service constructors now validate the config and return a clean error
- **Frozen RDAP bootstrap data**: the IANA bootstrap file was fetched once per process lifetime, so long-running services never learned about new TLDs or migrated RDAP endpoints (see bootstrap refresh below)

### Added

- **Lookup outcome classification (`LookupStatus`)**: every response carries a structured outcome - `found`, `not_found`, or `rate_limited` - instead of forcing callers to infer it from raw text:
  - WHOIS responses are classified against known throttle/NXDOMAIN phrases, guarded so a real record that merely *mentions* a trigger phrase still classifies as `found`
  - RDAP 404 is treated as an authoritative "not registered" answer and **short-circuits** - nonexistent domains no longer trigger a wasted WHOIS fallback query
  - RDAP 429 raises a typed `WhoisError::RateLimited` error that is never retried into (HTTP 503 at the API layer)
  - Cache TTLs are status-aware: `found` → `CACHE_TTL_SECONDS`; `not_found` → new `NEGATIVE_CACHE_TTL_SECONDS` (default 300s, `0` disables negative caching); `rate_limited` → never cached
  - New `upstream_rate_limited` metric makes registry throttling visible before it becomes an incident
- **Shared cache tier (`CacheBackend` trait + Redis)**: the cache is now two-tier. L1 remains the in-process moka cache (fast hits, request coalescing); a new `CacheBackend` trait adds an optional shared L2 - with a Redis implementation behind the new `redis-cache` feature - so a fleet of instances presents **one** cache to upstream registries and query volume stays flat as instances scale out:
  - Status-aware TTLs extend to the shared tier; rate-limited responses never reach it, so one throttled instance cannot poison the fleet
  - A backend outage degrades gracefully to per-instance caching - lookups never fail because Redis is down
  - The server binary uses it automatically when built with `--features redis-cache` and `REDIS_URL` is set
  - Custom backends (memcached, a database, ...) implement the same two-method trait
- **RDAP bootstrap refresh**: IANA bootstrap data refreshes every 24 hours (IANA's guidance) instead of freezing at process start. A failed refresh serves stale data and backs off 5 minutes before retrying; a successful refresh clears the discovered-server cache so migrated endpoints actually take effect
- `WhoisClient::new_with_cache_backend()`, `CacheService::with_backend()`, `ParsedWhoisData::fill_missing_from()`, `Config::validate()` (now public)

### Changed

- The HTTP server binary now delegates to the library's `WhoisClient` instead of maintaining its own copy of the RDAP→WHOIS tiering (~150 lines of duplicate logic removed; binary and library can no longer drift apart)
- `WhoisClient` responses now populate `parsing_analysis` (previously always `None` from the client); the HTTP server strips it for non-debug requests
- Zero clippy warnings across all targets and features; `crossbeam` narrowed to `crossbeam-queue`; new `async-trait` dependency
- Test suite grew from 116 to 138 tests, including live-verified fixtures for real registry response formats

### Breaking Changes

1. **`Config` gained a field** - `negative_cache_ttl_seconds: u64`. Struct-literal construction fails to compile until the field is added; `Config::load()` users are unaffected (default 300, env `NEGATIVE_CACHE_TTL_SECONDS`)
2. **`WhoisResponse` gained a field** - `lookup_status: LookupStatus`. Struct literals break; deserializing old JSON is unaffected (`#[serde(default)]` → `found`)
3. **`LookupResult`** (and its `WhoisResult`/`RdapResult` aliases) **gained a field** - `status: LookupStatus`
4. **`WhoisError` gained a variant** - `RateLimited(String)`. Exhaustive `match` statements without a wildcard arm break; maps to HTTP 503
5. **`parsing_analysis` is now populated** by library lookups - strip it before serializing to end users if unwanted (the bundled HTTP server already does)
6. **Stricter input validation** - URLs (`http://example.com`) → `InvalidDomain`; unparseable IP-shaped strings (`300.300.300.300`) → `InvalidIpAddress`; trailing dots are normalized away (`example.com.` → `example.com`, including in the returned `domain` field)
7. **NXDOMAIN behavior changed** - a nonexistent domain is now typically answered by RDAP 404: a *successful* response with `lookup_status: not_found`, `parsed_data: None`, and RDAP JSON (not WHOIS "No match" text) in `raw_data`, with no WHOIS fallback query. Code that grepped `raw_data` for `"No match"` must check `lookup_status` instead
8. **Caching behavior changed** - rate-limited responses are never cached; not-found responses expire after the negative TTL instead of the full TTL
9. **Service constructors validate** - `WhoisService::new`, `RdapService::new`, and `WhoisClient::new_with_config` return `Err` on zero-valued configs instead of panicking or deadlocking later

### Migration Notes

```rust
// 1. Config literals: add the new field
let config = Config {
    // ...existing fields...
    negative_cache_ttl_seconds: 300,
};

// 2. Check outcomes structurally instead of grepping raw text
// Before:
if response.raw_data.contains("No match") { /* not registered */ }
// After:
match response.lookup_status {
    LookupStatus::Found => { /* real record */ }
    LookupStatus::NotFound => { /* not registered */ }
    LookupStatus::RateLimited => { /* unreliable - back off and retry */ }
}

// 3. WhoisError matches: handle the new variant (or add a wildcard)
match err {
    WhoisError::RateLimited(_) => { /* back off */ }
    // ...
    _ => { /* ... */ }
}

// 4. If you serialize WhoisResponse to end users, strip debug output
response.parsing_analysis = None;

// 5. Opt in to the shared cache tier (requires `redis-cache` feature)
let backend = Arc::new(RedisCache::new("redis://127.0.0.1:6379")?);
let client = WhoisClient::new_with_cache_backend(config, backend).await?;
```

## [0.2.1] - 2026-02-10

### Changed
- Updated crates.io metadata to reflect IP address support in description and keywords
- Added `readme = "README.md"` to Cargo.toml for better crates.io presentation

**Note**: This is the same feature set as 0.2.0, published to crates.io with updated metadata.

## [0.2.0] - 2026-02-05

### Added
- **IP address lookup support** for both IPv4 and IPv6 addresses
- **Auto-detection** of domains vs IP addresses with `ValidatedQuery` type
- `ValidatedIpAddress` type for IP address validation and normalization
- **RIR detection** and routing for IP addresses (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- New error types: `InvalidIpAddress`, `UnsupportedIpAddress`
- **Unified API endpoints** - all `/whois/` endpoints now accept both domains and IPs
- Support for 5 Regional Internet Registries (RIRs)
- IPv6 normalization and validation
- Private IP address rejection for security

### Changed
- API endpoints now **auto-detect** query type (domain vs IP) - no separate endpoints needed
- Library `lookup()` method now handles both domains and IPs transparently
- Improved code quality with DRY refactoring (~223 lines of duplication eliminated)
- Consolidated RDAP query methods into generic `query_rdap_resource()`
- Consolidated lookup methods into generic `lookup_internal()`
- Added `MAX_RETRY_ATTEMPTS` constant to eliminate magic numbers
- Updated all documentation for v0.2.0

### Fixed
- Test timing boundary condition in `test_days_since` (date boundary race)
- Cache mutation bug where IP lookups didn't restore original input format
- ParsedWhoisData initialization boilerplate (added helper methods)

### Deprecated
- None

### Removed
- None - **100% backward compatible** with v0.1.0

### Security
- Private IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x) are automatically rejected
- IPv6 special ranges (::1, fe80::, etc.) are automatically rejected
- Enhanced input validation for IP addresses at all API boundaries

### Performance
- Auto-detection overhead: < 1μs per request
- Same caching behavior for both domains and IPs
- Zero performance degradation from v0.1.0

### Migration Notes
**No migration required!** All v0.1.0 code continues to work without changes:
```rust
// This works in both v0.1.0 and v0.2.0
let client = WhoisClient::new().await?;
let result = client.lookup("example.com").await?;
```

**New capabilities** (opt-in):
```rust
// NEW in v0.2.0 - IP address lookups
let ipv4_result = client.lookup("8.8.8.8").await?;
let ipv6_result = client.lookup("2001:4860:4860::8888").await?;
```

## [0.1.0] - 2025-01-26

### Added
- Initial release
- **Domain WHOIS lookup** support via library and HTTP API
- **RDAP-first strategy** with intelligent WHOIS fallback
- **1,194 TLD mappings** auto-generated from IANA bootstrap data
- **Intelligent caching** with configurable TTL and query deduplication
- **Calculated fields** for threat intelligence: `created_ago`, `updated_ago`, `expires_in`
- **Dual-use design**: Import as Rust library or run as HTTP service
- Three-tier lookup system: RDAP → WHOIS → Cache
- Production-ready features:
  - Buffer pooling for network I/O
  - Connection reuse and TCP optimizations
  - Semaphore-based concurrency control
  - Rate limiting (soft limits)
  - Prometheus metrics
  - OpenAPI/Swagger documentation
- Support for common TLDs (.com, .org, .net, etc.)
- WHOIS data parsing with regex patterns
- Domain validation using public suffix list
- Environment-based configuration
- Comprehensive test suite (63 tests)

### Security
- Input validation at all boundaries
- Response size limits to prevent DoS
- Timeout protection
- No command injection risks (no shell execution)
- No SQL injection risks (no database)

[0.2.0]: https://github.com/yourusername/rust-whois/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/rust-whois/releases/tag/v0.1.0
