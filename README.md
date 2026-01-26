# Whois Service

A high-performance WHOIS/RDAP lookup service built in Rust for **internal automation** and **library integration**. Designed for cybersecurity pipelines, alert enrichment, and threat intelligence workflows.

## Overview

- **RDAP-first** with automatic WHOIS fallback for universal coverage
- **1,194 TLD mappings** auto-generated from IANA bootstrap data at build time
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

# Health check
curl "http://localhost:3000/health"
```

### As Library

```toml
[dependencies]
whois-service = "0.1"
```

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() {
    let client = WhoisClient::new().await;
    let result = client.lookup("example.com").await.unwrap();
    println!("Created {} days ago", result.parsed_data.created_ago.unwrap_or(0));
}
```

📖 See [LIBRARY_USAGE.md](LIBRARY_USAGE.md) for comprehensive examples.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /whois?domain=example.com` | Query via parameter |
| `GET /whois/:domain` | Query via path |
| `GET /whois/debug/:domain` | Include parsing analysis |
| `GET /health` | Service health check |
| `GET /metrics` | Prometheus metrics |
| `GET /docs` | OpenAPI/Swagger UI (with `openapi` feature) |

## Response Format

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
    "expires_in": 961
  },
  "cached": false,
  "query_time_ms": 450
}
```

## Performance

| Metric | Value |
|--------|-------|
| Fresh lookup | 450-900ms |
| Cached lookup | <5ms |
| Throughput | 800+ domains/min |
| Cache capacity | 10K+ domains |

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

## Development Branches

| Branch | Description |
|--------|-------------|
| `main` | Stable release - domain lookups only |
| `dev-ip-lookup` | **Experimental** - adds IPv4/IPv6 address lookups |

### IP Address Support (dev-ip-lookup branch)

The `dev-ip-lookup` branch adds IP address ownership lookups:

```bash
# IPv4
curl "http://localhost:3000/ip/8.8.8.8"

# IPv6  
curl "http://localhost:3000/ip/2001:4860:4860::8888"
```

Returns organization, network range, RIR, and registration details via RDAP (with WHOIS fallback).

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
