# Library Usage Guide

This guide shows how to use the whois service as a Rust library in your applications.

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
whois-service = "0.1.0"
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
        Err(WhoisError::UnsupportedTld(tld)) => {
            println!("Unsupported TLD: {}", tld);
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
    let config = Arc::new(Config {
        whois_timeout_seconds: 30,
        cache_ttl_seconds: 3600,
        cache_max_entries: 10000,
        concurrent_whois_queries: 8,
        ..Default::default()
    });
    
    let client = WhoisClient::new_with_config(config).await?;
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
- `client.lookup(domain)` - Lookup domain (uses cache if available)
- `client.lookup_fresh(domain)` - Lookup domain (always queries server)

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
    pub registrar: Option<String>,
    pub creation_date: Option<chrono::DateTime<chrono::Utc>>,
    pub expiration_date: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_date: Option<chrono::DateTime<chrono::Utc>>,
    pub created_ago: Option<i64>,        // Days since creation
    pub expires_in: Option<i64>,         // Days until expiration  
    pub updated_ago: Option<i64>,        // Days since last update
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub registrant_email: Option<String>,
    pub admin_email: Option<String>,
    pub tech_email: Option<String>,
}
```

### Error Types

```rust
pub enum WhoisError {
    InvalidDomain(String),
    UnsupportedTld(String),
    Timeout,
    IoError(std::io::Error),
    ParseError(String),
}
```

## 💡 Tips

1. **Reuse the client**: Create one `WhoisClient` and clone it for concurrent use
2. **Enable caching**: Use `WhoisClient::new()` instead of `new_without_cache()` for better performance
3. **Batch processing**: Use concurrent lookups for multiple domains
4. **Error handling**: Always handle network timeouts and domain validation errors
5. **Memory management**: The client handles buffer pooling automatically

## 🏗 How It Works

The library uses a three-tier lookup system:

1. **RDAP First** - Modern structured JSON responses (faster, 1,188 TLD mappings)
2. **WHOIS Fallback** - Traditional protocol for comprehensive coverage
3. **Smart Caching** - In-memory cache for repeated lookups

Your code stays simple - the library handles the complexity automatically! 