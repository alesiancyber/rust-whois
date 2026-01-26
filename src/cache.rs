use crate::{config::Config, WhoisResponse};
use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use tracing::debug;

pub struct CacheService {
    cache: Cache<String, WhoisResponse>,
}

impl CacheService {
    /// Create a new cache service with the given configuration.
    /// 
    /// Note: This cannot fail - moka cache creation is infallible.
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .time_to_live(Duration::from_secs(config.cache_ttl_seconds))
            .build();

        Self { cache }
    }

    /// Get a cached response for a domain.
    /// 
    /// Returns `Some(response)` with `cached=true` if found, `None` otherwise.
    pub async fn get(&self, domain: &str) -> Option<WhoisResponse> {
        let key = Self::normalize_domain(domain);
        
        match self.cache.get(&key).await {
            Some(mut response) => {
                debug!("Cache hit for domain: {}", domain);
                response.cached = true;
                Some(response)
            },
            None => {
                debug!("Cache miss for domain: {}", domain);
                None
            }
        }
    }

    /// Store a response in the cache.
    pub async fn set(&self, domain: &str, response: &WhoisResponse) {
        let key = Self::normalize_domain(domain);
        self.cache.insert(key, response.clone()).await;
        debug!("Cached response for domain: {}", domain);
    }

    /// Normalize domain for consistent cache keys.
    fn normalize_domain(domain: &str) -> String {
        let normalized = domain.trim().to_lowercase();
        
        // Remove trailing dot if present (common in DNS contexts)
        if normalized.ends_with('.') {
            normalized[..normalized.len() - 1].to_string()
        } else {
            normalized
        }
    }
} 