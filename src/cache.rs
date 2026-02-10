use crate::{config::Config, WhoisResponse, errors::WhoisError};
use moka::future::Cache;
use std::{sync::Arc, time::Duration, future::Future};
use tracing::debug;

pub struct CacheService {
    cache: Cache<String, Arc<WhoisResponse>>,
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
            Some(cached_response) => {
                debug!("Cache hit for domain: {}", domain);
                // Create a new response with cached=true
                // This avoids mutating the cached Arc
                Some(WhoisResponse {
                    cached: true,
                    ..(*cached_response).clone()
                })
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
        self.cache.insert(key, Arc::new(response.clone())).await;
        debug!("Cached response for domain: {}", domain);
    }

    /// Get cached response or fetch with automatic deduplication.
    ///
    /// If multiple concurrent requests for the same domain arrive, only ONE
    /// fetch operation will be executed. All other requests will wait for and
    /// share the same result. This prevents thundering herd problems and
    /// reduces load on WHOIS/RDAP servers.
    ///
    /// # Arguments
    /// * `domain` - The domain to lookup
    /// * `fetch_fn` - Async function that performs the actual lookup
    ///
    /// # Returns
    /// WhoisResponse with `cached` field set appropriately
    pub async fn get_or_fetch<F, Fut>(
        &self,
        domain: &str,
        fetch_fn: F,
    ) -> Result<WhoisResponse, WhoisError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<WhoisResponse, WhoisError>>,
    {
        let key = Self::normalize_domain(domain);

        // Check if already cached
        if let Some(cached) = self.cache.get(&key).await {
            debug!("Cache hit for domain: {}", domain);
            return Ok(WhoisResponse {
                cached: true,
                ..(*cached).clone()
            });
        }

        // Not cached - perform fetch
        debug!("Cache miss - executing fetch for domain: {}", domain);
        let mut response = fetch_fn().await?;
        response.cached = false;

        // Store in cache
        self.cache.insert(key, Arc::new(response.clone())).await;

        Ok(response)
    }

    /// Normalize domain for consistent cache keys.
    /// Domain is already lowercased by ValidatedDomain, just handle trailing dot.
    fn normalize_domain(domain: &str) -> String {
        // Remove trailing dot if present (common in DNS contexts)
        // Domain is already trimmed and lowercased by ValidatedDomain
        if let Some(stripped) = domain.strip_suffix('.') {
            stripped.to_string()
        } else {
            domain.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedWhoisData;

    fn create_test_config() -> Arc<Config> {
        Arc::new(Config {
            port: 3000,
            whois_timeout_seconds: 30,
            max_response_size: 1024 * 1024,
            cache_ttl_seconds: 3600,
            cache_max_entries: 100,
            max_referrals: 5,
            discovery_timeout_seconds: 10,
            concurrent_whois_queries: 4,
            buffer_pool_size: 10,
            buffer_size: 4096,
        })
    }

    fn create_test_response(domain: &str) -> WhoisResponse {
        WhoisResponse {
            domain: domain.to_string(),
            whois_server: "whois.test.com".to_string(),
            raw_data: "test data".to_string(),
            parsed_data: Some(ParsedWhoisData {
                registrar: Some("Test Registrar".to_string()),
                creation_date: Some("2020-01-01".to_string()),
                expiration_date: Some("2030-01-01".to_string()),
                updated_date: Some("2024-01-01".to_string()),
                name_servers: vec!["ns1.test.com".to_string()],
                status: vec!["ok".to_string()],
                registrant_name: None,
                registrant_email: None,
                admin_email: None,
                tech_email: None,
                created_ago: Some(1000),
                updated_ago: Some(100),
                expires_in: Some(2000),
            }),
            cached: false,
            query_time_ms: 100,
            parsing_analysis: None,
        }
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let config = create_test_config();
        let cache = CacheService::new(config);
        // Should not panic or error
        drop(cache);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let result = cache.get("example.com").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let response = create_test_response("example.com");
        cache.set("example.com", &response).await;

        let cached = cache.get("example.com").await;
        assert!(cached.is_some());

        let cached = cached.unwrap();
        assert_eq!(cached.domain, "example.com");
        assert_eq!(cached.cached, true);
        assert_eq!(cached.whois_server, "whois.test.com");
    }

    #[tokio::test]
    async fn test_cache_normalization() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        // Store with trailing dot
        let response = create_test_response("example.com.");
        cache.set("example.com.", &response).await;

        // Retrieve without trailing dot (should hit)
        let cached = cache.get("example.com").await;
        assert!(cached.is_some());

        // Retrieve with trailing dot (should also hit)
        let cached = cache.get("example.com.").await;
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_cache_get_or_fetch_miss() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let mut fetch_count = 0;

        let result = cache
            .get_or_fetch("example.com", || async {
                fetch_count += 1;
                Ok(create_test_response("example.com"))
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(fetch_count, 1);

        let response = result.unwrap();
        assert_eq!(response.cached, false);
        assert_eq!(response.domain, "example.com");
    }

    #[tokio::test]
    async fn test_cache_get_or_fetch_hit() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        // Pre-populate cache
        let response = create_test_response("example.com");
        cache.set("example.com", &response).await;

        let mut fetch_count = 0;

        let result = cache
            .get_or_fetch("example.com", || async {
                fetch_count += 1;
                Ok(create_test_response("example.com"))
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(fetch_count, 0); // Should NOT fetch

        let response = result.unwrap();
        assert_eq!(response.cached, true);
    }

    #[tokio::test]
    async fn test_cache_get_or_fetch_error() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let result = cache
            .get_or_fetch("example.com", || async {
                Err(crate::errors::WhoisError::Internal("Test error".to_string()))
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_multiple_domains() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        // Cache multiple domains
        cache.set("example.com", &create_test_response("example.com")).await;
        cache.set("test.com", &create_test_response("test.com")).await;
        cache.set("demo.org", &create_test_response("demo.org")).await;

        // All should be retrievable
        assert!(cache.get("example.com").await.is_some());
        assert!(cache.get("test.com").await.is_some());
        assert!(cache.get("demo.org").await.is_some());

        // Non-existent should miss
        assert!(cache.get("notcached.com").await.is_none());
    }

    #[test]
    fn test_normalize_domain_trailing_dot() {
        assert_eq!(CacheService::normalize_domain("example.com."), "example.com");
        assert_eq!(CacheService::normalize_domain("example.com"), "example.com");
        assert_eq!(CacheService::normalize_domain("test.co.uk."), "test.co.uk");
        assert_eq!(CacheService::normalize_domain("test.co.uk"), "test.co.uk");
    }
} 