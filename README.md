# Whois Service

A high-performance WHOIS/RDAP lookup service built in Rust for **internal automation** and **library integration**. Designed for cybersecurity pipelines, alert enrichment, and threat intelligence workflows.

## Overview

- **RDAP-first** with automatic WHOIS fallback for universal coverage
- **1,194 TLD mappings** auto-generated from IANA bootstrap data at build time
- **Domain and IP address lookups** (IPv4 and IPv6)
- **Intelligent caching** with configurable TTL (avoids rate limiting)
- **Calculated fields** for threat detection: `created_ago`, `updated_ago`, `expires_in`
- **Dual-use**: Import as a Rust library or run as an HTTP API

## Quick Start

### As HTTP Service

```bash
git clone https://github.com/alesiancyber/rust-whois.git
cd rust-whois
cargo run --release
```

```bash
# Domain lookup
curl "http://localhost:3000/whois/google.com"

# IP address lookup (IPv4)
curl "http://localhost:3000/whois/8.8.8.8"

# IP address lookup (IPv6)
curl "http://localhost:3000/whois/2001:4860:4860::8888"

# Health check
curl "http://localhost:3000/health"
```

### As Library

```toml
[dependencies]
whois-service = "0.2.1"
```

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;

    // Domain lookup
    let domain = client.lookup("example.com").await?;
    println!("Created {} days ago", domain.parsed_data.unwrap().created_ago.unwrap_or(0));

    // IP lookup (auto-detects IPv4 or IPv6)
    let ip_info = client.lookup("8.8.8.8").await?;
    println!("Network: {:?}", ip_info.parsed_data);

    // IPv6 lookup
    let ipv6_info = client.lookup("2001:4860:4860::8888").await?;
    println!("IPv6 Network: {:?}", ipv6_info.parsed_data);

    Ok(())
}
```

📖 See [LIBRARY_USAGE.md](LIBRARY_USAGE.md) for comprehensive examples.

## API Endpoints

All endpoints support **both domains and IP addresses** (auto-detection).

### WHOIS/IP Lookups

| Endpoint | Description |
|----------|-------------|
| `GET /whois?domain={query}` | Query via parameter (domain or IP) |
| `GET /whois/{query}` | Query via path (domain or IP) |
| `GET /whois/debug/{query}` | Include parsing analysis |

**Examples:**
```bash
# Domain lookups
curl "http://localhost:3000/whois/google.com"
curl "http://localhost:3000/whois?domain=example.com"

# IP lookups (same endpoints)
curl "http://localhost:3000/whois/8.8.8.8"
curl "http://localhost:3000/whois/2001:4860:4860::8888"
curl "http://localhost:3000/whois?domain=8.8.8.8"
```

### System

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Service health check |
| `GET /metrics` | Prometheus metrics |
| `GET /docs` | OpenAPI/Swagger UI (with `openapi` feature) |

## Response Format

**Unified response structure** for both domains and IP addresses:

```json
{
  "domain": "example.com",
  "whois_server": "RDAP: https://rdap.verisign.com/com/v1/",
  "parsed_data": {
    "registrar": "Example Registrar",
    "creation_date": "1997-09-15T04:00:00Z",
    "expiration_date": "2028-09-14T04:00:00Z",
    "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
    "status": ["clientTransferProhibited"],
    "created_ago": 10360,
    "expires_in": 961,
    "updated_ago": 45
  },
  "cached": false,
  "query_time_ms": 450
}
```

**Note**: The `domain` field contains either a domain name OR an IP address. For IP lookups, the `parsed_data.registrar` field often contains the network name or organization.

## Performance

| Metric | Value |
|--------|-------|
| Fresh lookup (domain or IP) | 250-900ms |
| Cached lookup | <5ms |
| Throughput | 800+ lookups/min |
| Cache capacity | 10K+ entries |
| Auto-detection overhead | <1μs |

## Configuration

Key environment variables:

```bash
PORT=3000                      # HTTP port
CACHE_TTL_SECONDS=3600         # Cache TTL (1 hour default)
CACHE_MAX_ENTRIES=10000        # Max cached domains
WHOIS_TIMEOUT_SECONDS=30       # Query timeout
CONCURRENT_WHOIS_QUERIES=8     # Parallel query limit
RUST_LOG=whois_service=info    # Log level
```

The service auto-adapts to available system resources (memory, CPU cores).

## Build

```bash
# Development
cargo build

# Release (optimized)
cargo build --release

# Library only (no HTTP server)
cargo build --no-default-features
```

## License

MIT
