use crate::{config::Config, LookupStatus, WhoisResponse, errors::WhoisError};
use moka::future::Cache;
use std::{sync::Arc, time::Duration, future::Future};
use tracing::{debug, warn};

/// Error type for cache backend operations
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Pluggable second-tier cache shared across service instances.
///
/// The in-process moka cache (L1) is always present and provides fast hits
/// plus request coalescing. A `CacheBackend` adds a shared L2 tier - typically
/// Redis - so a fleet of instances presents ONE cache to the upstream
/// registries instead of N cold ones. For rate-limit avoidance this is the
/// single biggest lever: upstream query volume stops scaling with instance
/// count.
///
/// Implementations must be infallible-friendly: backend errors are logged and
/// treated as cache misses, never surfaced to lookup callers.
///
/// `ttl` communicates the status-aware expiry policy (positive vs negative
/// TTL); implementations should honor it. Entries with a zero TTL are never
/// passed to `set`.
#[async_trait::async_trait]
pub trait CacheBackend: Send + Sync {
    /// Fetch a cached response by normalized key, `Ok(None)` on miss.
    async fn get(&self, key: &str) -> Result<Option<WhoisResponse>, BackendError>;

    /// Store a response under the normalized key with the given TTL.
    async fn set(&self, key: &str, response: &WhoisResponse, ttl: Duration) -> Result<(), BackendError>;
}

/// Per-entry cache TTL policy keyed on the lookup outcome:
/// - Found: full configured TTL (registration data changes slowly)
/// - NotFound: short negative TTL (absorbs repeated NXDOMAIN lookups while
///   still noticing new registrations quickly)
/// - RateLimited: not cached (a throttle banner is not data; caching it would
///   poison the cache exactly when it should be shielding the upstream server)
struct StatusExpiry {
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl moka::Expiry<String, Arc<WhoisResponse>> for StatusExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Arc<WhoisResponse>,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        match value.lookup_status {
            LookupStatus::Found => Some(self.positive_ttl),
            LookupStatus::NotFound => Some(self.negative_ttl),
            // Expires immediately: concurrent waiters still share the one
            // in-flight fetch, but nothing persists afterwards
            LookupStatus::RateLimited => Some(Duration::ZERO),
        }
    }
}

pub struct CacheService {
    cache: Cache<String, Arc<WhoisResponse>>,
    /// Optional shared L2 tier (e.g. Redis) consulted on L1 misses and
    /// written through on fetches
    backend: Option<Arc<dyn CacheBackend>>,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl CacheService {
    /// Create a new cache service with the given configuration.
    ///
    /// Note: This cannot fail - moka cache creation is infallible.
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        Self::build(config, None)
    }

    /// Create a cache service with a shared second-tier backend (e.g. Redis).
    ///
    /// L1 (in-process moka) still handles fast hits and request coalescing;
    /// the backend is consulted on L1 misses and written through on fetches,
    /// so all instances sharing the backend share one view of the cache.
    #[must_use]
    pub fn with_backend(config: Arc<Config>, backend: Arc<dyn CacheBackend>) -> Self {
        Self::build(config, Some(backend))
    }

    fn build(config: Arc<Config>, backend: Option<Arc<dyn CacheBackend>>) -> Self {
        let positive_ttl = Duration::from_secs(config.cache_ttl_seconds);
        let negative_ttl = Duration::from_secs(config.negative_cache_ttl_seconds);

        let cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .expire_after(StatusExpiry { positive_ttl, negative_ttl })
            .build();

        Self { cache, backend, positive_ttl, negative_ttl }
    }

    /// TTL a response earns in the shared backend, mirroring `StatusExpiry`.
    /// `None` means "do not store" (rate-limited, or a disabled negative cache).
    fn backend_ttl(&self, response: &WhoisResponse) -> Option<Duration> {
        let ttl = match response.lookup_status {
            LookupStatus::Found => self.positive_ttl,
            LookupStatus::NotFound => self.negative_ttl,
            LookupStatus::RateLimited => return None,
        };
        (!ttl.is_zero()).then_some(ttl)
    }

    /// Consult the L2 backend; errors are logged and degrade to a miss so a
    /// backend outage never breaks lookups.
    async fn backend_get(&self, key: &str) -> Option<WhoisResponse> {
        let backend = self.backend.as_ref()?;
        match backend.get(key).await {
            Ok(hit) => hit,
            Err(e) => {
                warn!("Cache backend get failed for {}: {} - treating as miss", key, e);
                None
            }
        }
    }

    /// Write through to the L2 backend per the status-aware TTL policy.
    async fn backend_set(&self, key: &str, response: &WhoisResponse) {
        let Some(backend) = self.backend.as_ref() else { return };
        let Some(ttl) = self.backend_ttl(response) else { return };
        if let Err(e) = backend.set(key, response, ttl).await {
            warn!("Cache backend set failed for {}: {}", key, e);
        }
    }

    /// Get a cached response for a domain.
    ///
    /// Returns `Some(response)` with `cached=true` if found, `None` otherwise.
    pub async fn get(&self, domain: &str) -> Option<WhoisResponse> {
        let key = Self::normalize_domain(domain);

        if let Some(cached_response) = self.cache.get(&key).await {
            debug!("Cache hit (L1) for domain: {}", domain);
            // Create a new response with cached=true
            // This avoids mutating the cached Arc
            return Some(WhoisResponse {
                cached: true,
                ..(*cached_response).clone()
            });
        }

        if let Some(response) = self.backend_get(&key).await {
            debug!("Cache hit (backend) for domain: {}", domain);
            // Promote to L1. Note: the L1 expiry clock restarts here, so an
            // entry's total lifetime is bounded by backend TTL + L1 TTL.
            self.cache.insert(key, Arc::new(response.clone())).await;
            return Some(WhoisResponse { cached: true, ..response });
        }

        debug!("Cache miss for domain: {}", domain);
        None
    }

    /// Store a response in the cache (both tiers).
    pub async fn set(&self, domain: &str, response: &WhoisResponse) {
        let key = Self::normalize_domain(domain);
        self.cache.insert(key.clone(), Arc::new(response.clone())).await;
        self.backend_set(&key, response).await;
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

        // moka's entry API coalesces concurrent misses for the same key:
        // only one caller runs the init future, the rest wait and share the result.
        let entry = self
            .cache
            .entry(key.clone())
            .or_try_insert_with(async {
                // L1 missed - another instance may have the answer in the
                // shared backend, sparing an upstream query
                if let Some(mut response) = self.backend_get(&key).await {
                    debug!("Cache hit (backend) for domain: {}", domain);
                    response.cached = true;
                    return Ok(Arc::new(response));
                }

                debug!("Cache miss - executing fetch for domain: {}", domain);
                let mut response = fetch_fn().await?;
                response.cached = false;
                self.backend_set(&key, &response).await;
                Ok(Arc::new(response))
            })
            .await
            // moka shares one error across all waiters as Arc<WhoisError>.
            // Unwrap it if we're the only holder, otherwise make a best-effort copy.
            .map_err(|e: Arc<WhoisError>| {
                Arc::try_unwrap(e).unwrap_or_else(|shared| shared.duplicate())
            })?;

        if entry.is_fresh() {
            // This caller (or a coalesced peer) just fetched it
            Ok((*entry.into_value()).clone())
        } else {
            debug!("Cache hit for domain: {}", domain);
            Ok(WhoisResponse {
                cached: true,
                ..(*entry.into_value()).clone()
            })
        }
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
            negative_cache_ttl_seconds: 300,
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
            lookup_status: LookupStatus::Found,
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
        assert!(cached.cached);
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
        assert!(!response.cached);
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
        assert!(response.cached);
    }

    #[tokio::test]
    async fn test_cache_get_or_fetch_deduplicates_concurrent_fetches() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = create_test_config();
        let cache = CacheService::new(config);
        let fetch_count = AtomicUsize::new(0);

        // Fire 10 concurrent lookups for the same key; the fetch sleeps so
        // they all overlap. Exactly one fetch should execute.
        let lookups: Vec<_> = (0..10)
            .map(|_| {
                cache.get_or_fetch("example.com", || async {
                    fetch_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Ok(create_test_response("example.com"))
                })
            })
            .collect();

        let results = futures::future::join_all(lookups).await;

        assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "concurrent misses should coalesce into one fetch");
        for result in results {
            let response = result.expect("all waiters should share the result");
            assert_eq!(response.domain, "example.com");
        }
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

    fn create_test_response_with_status(domain: &str, status: LookupStatus) -> WhoisResponse {
        WhoisResponse {
            lookup_status: status,
            ..create_test_response(domain)
        }
    }

    #[tokio::test]
    async fn test_rate_limited_responses_are_not_cached() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let mut fetch_count = 0;

        // First lookup returns a rate-limited response
        let r = cache
            .get_or_fetch("throttled.com", || async {
                fetch_count += 1;
                Ok(create_test_response_with_status("throttled.com", LookupStatus::RateLimited))
            })
            .await
            .unwrap();
        assert_eq!(r.lookup_status, LookupStatus::RateLimited);

        // Second lookup must fetch again - the throttle banner must not persist
        let r = cache
            .get_or_fetch("throttled.com", || async {
                fetch_count += 1;
                Ok(create_test_response_with_status("throttled.com", LookupStatus::Found))
            })
            .await
            .unwrap();

        assert_eq!(fetch_count, 2, "rate-limited response must not be served from cache");
        assert_eq!(r.lookup_status, LookupStatus::Found);
        assert!(!r.cached);
    }

    #[tokio::test]
    async fn test_not_found_responses_are_cached() {
        let config = create_test_config();
        let cache = CacheService::new(config);

        let mut fetch_count = 0;

        for _ in 0..3 {
            let r = cache
                .get_or_fetch("nosuchdomain.com", || async {
                    fetch_count += 1;
                    Ok(create_test_response_with_status("nosuchdomain.com", LookupStatus::NotFound))
                })
                .await
                .unwrap();
            assert_eq!(r.lookup_status, LookupStatus::NotFound);
        }

        assert_eq!(fetch_count, 1, "NXDOMAIN should be served from the negative cache");
    }

    #[tokio::test]
    async fn test_negative_ttl_is_respected() {
        // Zero negative TTL means NXDOMAIN entries expire immediately
        let mut config = (*create_test_config()).clone();
        config.negative_cache_ttl_seconds = 0;
        let cache = CacheService::new(Arc::new(config));

        let mut fetch_count = 0;
        for _ in 0..2 {
            cache
                .get_or_fetch("nosuchdomain.com", || async {
                    fetch_count += 1;
                    Ok(create_test_response_with_status("nosuchdomain.com", LookupStatus::NotFound))
                })
                .await
                .unwrap();
        }
        assert_eq!(fetch_count, 2, "zero negative TTL must disable negative caching");
    }

    // ===== Two-tier (backend) cache tests =====

    /// In-memory CacheBackend double that records activity
    struct MockBackend {
        store: tokio::sync::Mutex<std::collections::HashMap<String, (WhoisResponse, Duration)>>,
        fail: std::sync::atomic::AtomicBool,
        gets: std::sync::atomic::AtomicUsize,
        sets: std::sync::atomic::AtomicUsize,
    }

    impl MockBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                fail: std::sync::atomic::AtomicBool::new(false),
                gets: std::sync::atomic::AtomicUsize::new(0),
                sets: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl CacheBackend for MockBackend {
        async fn get(&self, key: &str) -> Result<Option<WhoisResponse>, BackendError> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("backend down".into());
            }
            Ok(self.store.lock().await.get(key).map(|(r, _)| r.clone()))
        }

        async fn set(&self, key: &str, response: &WhoisResponse, ttl: Duration) -> Result<(), BackendError> {
            self.sets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("backend down".into());
            }
            self.store.lock().await.insert(key.to_string(), (response.clone(), ttl));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_backend_hit_avoids_fetch() {
        let backend = MockBackend::new();
        // Another instance already cached this domain in the shared tier
        backend.store.lock().await.insert(
            "example.com".to_string(),
            (create_test_response("example.com"), Duration::from_secs(60)),
        );

        let cache = CacheService::with_backend(create_test_config(), backend.clone());

        let mut fetch_count = 0;
        let r = cache
            .get_or_fetch("example.com", || async {
                fetch_count += 1;
                Ok(create_test_response("example.com"))
            })
            .await
            .unwrap();

        assert_eq!(fetch_count, 0, "shared-tier hit must spare the upstream fetch");
        assert!(r.cached, "backend hits report cached=true");

        // Promoted to L1: a second lookup shouldn't touch the backend again
        let gets_before = backend.gets.load(std::sync::atomic::Ordering::SeqCst);
        cache.get_or_fetch("example.com", || async { Ok(create_test_response("example.com")) }).await.unwrap();
        assert_eq!(backend.gets.load(std::sync::atomic::Ordering::SeqCst), gets_before, "L1 should now absorb the hit");
    }

    #[tokio::test]
    async fn test_fetch_writes_through_to_backend() {
        let backend = MockBackend::new();
        let cache = CacheService::with_backend(create_test_config(), backend.clone());

        cache
            .get_or_fetch("example.com", || async { Ok(create_test_response("example.com")) })
            .await
            .unwrap();

        let store = backend.store.lock().await;
        let (stored, ttl) = store.get("example.com").expect("fetch must write through");
        assert_eq!(stored.domain, "example.com");
        assert_eq!(*ttl, Duration::from_secs(3600), "Found entries get the positive TTL");
    }

    #[tokio::test]
    async fn test_rate_limited_is_not_written_to_backend() {
        let backend = MockBackend::new();
        let cache = CacheService::with_backend(create_test_config(), backend.clone());

        cache
            .get_or_fetch("throttled.com", || async {
                Ok(create_test_response_with_status("throttled.com", LookupStatus::RateLimited))
            })
            .await
            .unwrap();

        assert_eq!(backend.sets.load(std::sync::atomic::Ordering::SeqCst), 0, "throttle banners must never reach the shared tier");
        assert!(backend.store.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_not_found_gets_negative_ttl_in_backend() {
        let backend = MockBackend::new();
        let cache = CacheService::with_backend(create_test_config(), backend.clone());

        cache
            .get_or_fetch("nosuchdomain.com", || async {
                Ok(create_test_response_with_status("nosuchdomain.com", LookupStatus::NotFound))
            })
            .await
            .unwrap();

        let store = backend.store.lock().await;
        let (_, ttl) = store.get("nosuchdomain.com").expect("NXDOMAIN should be negative-cached in shared tier");
        assert_eq!(*ttl, Duration::from_secs(300), "NotFound entries get the negative TTL");
    }

    #[tokio::test]
    async fn test_backend_failure_degrades_to_fetch() {
        let backend = MockBackend::new();
        backend.fail.store(true, std::sync::atomic::Ordering::SeqCst);

        let cache = CacheService::with_backend(create_test_config(), backend.clone());

        let mut fetch_count = 0;
        let r = cache
            .get_or_fetch("example.com", || async {
                fetch_count += 1;
                Ok(create_test_response("example.com"))
            })
            .await
            .expect("a backend outage must not fail lookups");

        assert_eq!(fetch_count, 1);
        assert_eq!(r.domain, "example.com");
    }

    #[test]
    fn test_normalize_domain_trailing_dot() {
        assert_eq!(CacheService::normalize_domain("example.com."), "example.com");
        assert_eq!(CacheService::normalize_domain("example.com"), "example.com");
        assert_eq!(CacheService::normalize_domain("test.co.uk."), "test.co.uk");
        assert_eq!(CacheService::normalize_domain("test.co.uk"), "test.co.uk");
    }
} 