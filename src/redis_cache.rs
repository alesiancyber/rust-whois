//! Redis-backed shared cache tier (enabled with the `redis-cache` feature)
//!
//! Lets a fleet of service instances share one cache, so upstream WHOIS/RDAP
//! query volume stays flat as instances scale out - the main structural
//! defense against registry rate limiting.

use crate::cache::{BackendError, CacheBackend};
use crate::errors::WhoisError;
use crate::WhoisResponse;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::info;

/// `CacheBackend` implementation backed by Redis.
///
/// - Values are stored as JSON under `whois:<normalized-query>` with per-entry
///   TTLs supplied by the cache layer (status-aware: positive vs negative).
/// - Uses a lazily-initialized [`ConnectionManager`], which multiplexes one
///   connection across all callers and reconnects automatically.
/// - Connection or serialization failures surface as [`BackendError`]s, which
///   the cache layer logs and treats as misses - a Redis outage degrades to
///   per-instance caching instead of breaking lookups.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use whois_service::{Config, RedisCache, WhoisClient};
///
/// let config = Arc::new(Config::load()?);
/// let backend = Arc::new(RedisCache::new("redis://127.0.0.1:6379")?);
/// let client = WhoisClient::new_with_cache_backend(config, backend).await?;
/// # Ok(())
/// # }
/// ```
pub struct RedisCache {
    client: redis::Client,
    connection: OnceCell<ConnectionManager>,
    key_prefix: String,
}

impl RedisCache {
    /// Create a Redis cache backend for the given URL
    /// (e.g. `redis://127.0.0.1:6379` or `rediss://user:pass@host:port/0`).
    ///
    /// The URL is validated here; the connection itself is established lazily
    /// on first use and re-established automatically if it drops.
    pub fn new(url: &str) -> Result<Self, WhoisError> {
        let client = redis::Client::open(url)
            .map_err(|e| WhoisError::Internal(format!("Invalid Redis URL: {}", e)))?;

        Ok(Self {
            client,
            connection: OnceCell::new(),
            key_prefix: "whois:".to_string(),
        })
    }

    /// Override the key prefix (default `whois:`), e.g. to namespace
    /// environments sharing one Redis.
    #[must_use]
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    async fn connection(&self) -> Result<ConnectionManager, BackendError> {
        let manager = self
            .connection
            .get_or_try_init(|| async {
                let manager = self.client.get_connection_manager().await?;
                info!("Connected to Redis cache backend");
                Ok::<_, redis::RedisError>(manager)
            })
            .await?;
        // ConnectionManager is a cheap clonable handle to one multiplexed connection
        Ok(manager.clone())
    }

    fn key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }
}

#[async_trait::async_trait]
impl CacheBackend for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<WhoisResponse>, BackendError> {
        let mut conn = self.connection().await?;
        let value: Option<String> = conn.get(self.key(key)).await?;
        match value {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, response: &WhoisResponse, ttl: Duration) -> Result<(), BackendError> {
        let json = serde_json::to_string(response)?;
        let mut conn = self.connection().await?;
        // The cache layer never passes a zero TTL; clamp defensively anyway
        // since SETEX rejects 0
        let seconds = ttl.as_secs().max(1);
        let _: () = conn.set_ex(self.key(key), json, seconds).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_url_is_rejected() {
        assert!(RedisCache::new("not a url").is_err());
        assert!(RedisCache::new("redis://127.0.0.1:6379").is_ok());
    }

    /// Live round-trip against a real Redis. Ignored by default; run with:
    /// `REDIS_URL=redis://127.0.0.1:6379 cargo test --features redis-cache -- --ignored`
    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_redis_roundtrip() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let cache = RedisCache::new(&url).unwrap().with_key_prefix("whois-test:");

        let response = WhoisResponse {
            domain: "example.com".into(),
            whois_server: "RDAP: test".into(),
            raw_data: "{}".into(),
            parsed_data: None,
            lookup_status: crate::LookupStatus::Found,
            cached: false,
            query_time_ms: 1,
            parsing_analysis: None,
        };

        cache.set("example.com", &response, Duration::from_secs(30)).await.unwrap();
        let hit = cache.get("example.com").await.unwrap().expect("should hit");
        assert_eq!(hit.domain, "example.com");
        assert_eq!(hit.whois_server, "RDAP: test");

        let miss = cache.get("no-such-key.example").await.unwrap();
        assert!(miss.is_none());
    }
}
