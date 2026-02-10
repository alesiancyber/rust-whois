# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
