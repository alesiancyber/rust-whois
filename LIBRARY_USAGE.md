# Library Usage Guide

This guide shows how to use the whois service as a Rust library in your applications.

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
whois-service = "0.2.1"
tokio = { version = "1.0", features = ["full"] }
```

## 🚀 Basic Usage

### Simple Domain Lookup

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let result = client.lookup("google.com").await?;
    
    println!("Server: {}", result.whois_server);
    println!("Cached: {}", result.cached);
    println!("Query time: {}ms", result.query_time_ms);
    
    if let Some(data) = result.parsed_data {
        println!("Registrar: {:?}", data.registrar);
        println!("Creation date: {:?}", data.creation_date);
        println!("Expiration date: {:?}", data.expiration_date);
        println!("Domain age: {} days", data.created_ago.unwrap_or(0));
        println!("Expires in: {} days", data.expires_in.unwrap_or(0));
        println!("Updated: {} days ago", data.updated_ago.unwrap_or(0));
    }
    
    Ok(())
}
```

### IP Address Lookups (NEW in v0.2.0)

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;

    // IPv4 lookup (auto-detected)
    let ipv4_result = client.lookup("8.8.8.8").await?;
    println!("IPv4 Server: {}", ipv4_result.whois_server);
    if let Some(data) = ipv4_result.parsed_data {
        println!("Network info: {:?}", data.registrar);
    }

    // IPv6 lookup (auto-detected)
    let ipv6_result = client.lookup("2001:4860:4860::8888").await?;
    println!("IPv6 Server: {}", ipv6_result.whois_server);

    Ok(())
}
```

### Auto-Detection (Domains vs IPs)

```rust
use whois_service::{WhoisClient, ValidatedQuery, DetectedQueryType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;

    // Auto-detection example
    let queries = vec!["google.com", "8.8.8.8", "2001:4860:4860::8888"];

    for query in queries {
        // ValidatedQuery auto-detects the type
        let validated = ValidatedQuery::new(query)?;

        match validated.query_type() {
            DetectedQueryType::Domain(_) => println!("{} is a domain", query),
            DetectedQueryType::IpAddress(_) => println!("{} is an IP address", query),
        }

        // lookup() works for both
        let result = client.lookup(query).await?;
        println!("  Server: {}", result.whois_server);
    }

    Ok(())
}
```

### Error Handling

```rust
use whois_service::{WhoisClient, WhoisError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;

    match client.lookup("invalid-domain").await {
        Ok(result) => {
            println!("Success: {} ({}ms)", result.whois_server, result.query_time_ms);
        }
        Err(WhoisError::InvalidDomain(domain)) => {
            println!("Invalid domain: {}", domain);
        }
        Err(WhoisError::InvalidIpAddress(ip)) => {
            println!("Invalid IP address: {}", ip);
        }
        Err(WhoisError::UnsupportedTld(tld)) => {
            println!("Unsupported TLD: {}", tld);
        }
        Err(WhoisError::UnsupportedIpAddress(ip)) => {
            println!("Unsupported IP address (private or reserved): {}", ip);
        }
        Err(WhoisError::Timeout) => {
            println!("Network timeout - try again later");
        }
        Err(e) => {
            println!("Other error: {}", e);
        }
    }

    Ok(())
}
```

## 🔧 Configuration Options

### Custom Configuration

```rust
use whois_service::{WhoisClient, Config};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Config fields are private - use environment variables or Config::load()

    // Option 1: Use environment variables
    std::env::set_var("WHOIS_TIMEOUT_SECONDS", "30");
    std::env::set_var("CACHE_TTL_SECONDS", "3600");
    std::env::set_var("CACHE_MAX_ENTRIES", "10000");

    let config = Arc::new(Config::load()?);
    let client = WhoisClient::new_with_config(config).await?;

    // Option 2: Use default config (recommended)
    let client = WhoisClient::new().await?;
    let result = client.lookup("example.com").await?;

    println!("Result: {:?}", result.parsed_data);
    Ok(())
}
```

### Without Caching

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new_without_cache().await?;
    
    let result = client.lookup("github.com").await?;
    println!("Server: {}", result.whois_server);
    // result.cached will always be false
    
    Ok(())
}
```

### Fresh Lookup (Skip Cache)

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    // This will always query the server, even if cached
    let result = client.lookup_fresh("example.com").await?;
    println!("Fresh lookup: {} ({}ms)", result.whois_server, result.query_time_ms);
    
    Ok(())
}
```

## 🔄 Batch Processing

### Sequential Processing

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let domains = vec!["google.com", "github.com", "rust-lang.org"];
    
    for domain in domains {
        match client.lookup(domain).await {
            Ok(result) => {
                let protocol = if result.whois_server.contains("RDAP") { "RDAP" } else { "WHOIS" };
                println!("✅ {}: {} via {} ({}ms, cached: {})", 
                    domain, result.whois_server, protocol, result.query_time_ms, result.cached);
            }
            Err(e) => {
                println!("❌ {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}
```

### Concurrent Processing

```rust
use whois_service::WhoisClient;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let domains = vec![
        "google.com", "github.com", "rust-lang.org", 
        "stackoverflow.com", "reddit.com"
    ];
    
    let mut join_set = JoinSet::new();
    
    for domain in domains {
        let client_clone = client.clone();
        let domain_owned = domain.to_string();
        
        join_set.spawn(async move {
            let result = client_clone.lookup(&domain_owned).await;
            (domain_owned, result)
        });
    }
    
    while let Some(result) = join_set.join_next().await {
        match result? {
            (domain, Ok(whois_result)) => {
                let protocol = if whois_result.whois_server.contains("RDAP") { "RDAP" } else { "WHOIS" };
                println!("✅ {}: {} via {} ({}ms)", 
                    domain, 
                    whois_result.whois_server,
                    protocol,
                    whois_result.query_time_ms
                );
            }
            (domain, Err(e)) => {
                println!("❌ {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}
```

## 📊 Performance Monitoring

### Timing and Metrics

```rust
use whois_service::WhoisClient;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let start = Instant::now();
    let result = client.lookup("example.com").await?;
    let duration = start.elapsed();
    
    println!("Query completed in: {:?}", duration);
    println!("Server response time: {}ms", result.query_time_ms);
    println!("Cache hit: {}", result.cached);
    
    if let Some(data) = result.parsed_data {
        println!("Name servers: {}", data.name_servers.len());
    }
    
    Ok(())
}
```

### Cache Performance Testing

```rust
use whois_service::WhoisClient;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    let domain = "google.com";
    
    // First lookup (cache miss)
    let start = Instant::now();
    let result1 = client.lookup(domain).await?;
    let fresh_time = start.elapsed();
    
    // Second lookup (cache hit)
    let start = Instant::now();
    let result2 = client.lookup(domain).await?;
    let cached_time = start.elapsed();
    
    println!("Fresh lookup: {:?} (cached: {})", fresh_time, result1.cached);
    println!("Cached lookup: {:?} (cached: {})", cached_time, result2.cached);
    println!("Cache speedup: {:.1}x", 
        fresh_time.as_nanos() as f64 / cached_time.as_nanos() as f64);
    
    Ok(())
}
```

## 🌐 Integration Examples

### With Web Frameworks (Axum)

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use whois_service::WhoisClient;

type AppState = WhoisClient;

async fn lookup_domain(
    State(client): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match client.lookup(&domain).await {
        Ok(result) => Ok(Json(json!({
            "domain": domain,
            "server": result.whois_server,
            "cached": result.cached,
            "data": result.parsed_data
        }))),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let app = Router::new()
        .route("/whois/:domain", get(lookup_domain))
        .with_state(client);
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

## 🔗 API Reference

### WhoisClient Methods

- `WhoisClient::new()` - Create client with default configuration and caching
- `WhoisClient::new_without_cache()` - Create client without caching
- `WhoisClient::new_with_config(config)` - Create client with custom configuration
- `client.lookup(query)` - Lookup domain or IP (auto-detects, uses cache if available)
- `client.lookup_fresh(query)` - Lookup domain or IP (auto-detects, always queries server)

### WhoisResponse Fields

```rust
pub struct WhoisResponse {
    pub domain: String,
    pub whois_server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub cached: bool,
    pub query_time_ms: u64,
}
```

### ParsedWhoisData Fields

```rust
pub struct ParsedWhoisData {
    pub registrar: Option<String>,              // Registrar name (or network name for IPs)
    pub creation_date: Option<String>,          // ISO 8601 date string
    pub expiration_date: Option<String>,        // ISO 8601 date string
    pub updated_date: Option<String>,           // ISO 8601 date string
    pub created_ago: Option<i64>,               // Days since creation
    pub expires_in: Option<i64>,                // Days until expiration
    pub updated_ago: Option<i64>,               // Days since last update
    pub name_servers: Vec<String>,              // Name servers (domains only)
    pub status: Vec<String>,                    // Domain/IP status codes
    pub registrant_email: Option<String>,       // Contact emails
    pub admin_email: Option<String>,
    pub tech_email: Option<String>,
}
```

**Note**: For IP address lookups, `registrar` typically contains the network name or organization.

### Error Types

```rust
pub enum WhoisError {
    InvalidDomain(String),        // Domain validation failed
    InvalidIpAddress(String),     // IP address validation failed (NEW in v0.2.0)
    UnsupportedTld(String),       // TLD not supported
    UnsupportedIpAddress(String), // IP address not supported (private/reserved) (NEW in v0.2.0)
    Timeout,                      // Network timeout
    ResponseTooLarge,             // Response exceeded size limit
    InvalidUtf8,                  // Non-UTF8 response from server
    IoError(tokio::io::Error),
    HttpError(reqwest::Error),
    RegexError(regex::Error),
    ConfigError(config::ConfigError),
    Internal(String),
}
```

## 💡 Tips

1. **Reuse the client**: Create one `WhoisClient` and clone it for concurrent use
2. **Enable caching**: Use `WhoisClient::new()` instead of `new_without_cache()` for better performance
3. **Batch processing**: Use concurrent lookups for multiple domains and IPs
4. **Error handling**: Always handle network timeouts, domain validation, and IP validation errors
5. **Memory management**: The client handles buffer pooling automatically
6. **Auto-detection**: Use `lookup()` for both domains and IPs - it auto-detects the type
7. **IP support**: Private IPs (192.168.x.x, 10.x.x.x, 127.x.x.x, etc.) are rejected automatically

## 🏗 How It Works

The library uses a three-tier lookup system for **both domains and IP addresses**:

1. **RDAP First** - Modern structured JSON responses (faster, 1,194 TLD mappings + 5 RIRs)
2. **WHOIS Fallback** - Traditional protocol for comprehensive coverage
3. **Smart Caching** - In-memory cache for repeated lookups

**Auto-Detection**: Pass any string to `lookup()` - it automatically detects whether it's a domain or IP address and routes to the appropriate service (RIR for IPs, TLD registry for domains).

Your code stays simple - the library handles the complexity automatically! 