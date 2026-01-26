use crate::{config::Config, WhoisResponse};
use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use tracing::debug;

pub struct CacheService {
    cache: Cache<String, WhoisResponse>,
}

impl CacheService {
    pub fn new(config: Arc<Config>) -> Result<Self, String> {
        let cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .time_to_live(Duration::from_secs(config.cache_ttl_seconds))
            .build();

        Ok(Self { cache })
    }

    pub async fn get(&self, domain: &str) -> Result<Option<WhoisResponse>, String> {
        let key = self.normalize_domain(domain);
        
        match self.cache.get(&key).await {
            Some(mut response) => {
                debug!("Cache hit for domain: {}", domain);
                response.cached = true;
                Ok(Some(response))
            },
            None => {
                debug!("Cache miss for domain: {}", domain);
                Ok(None)
            }
        }
    }

    pub async fn set(&self, domain: &str, response: &WhoisResponse) -> Result<(), String> {
        let key = self.normalize_domain(domain);
        self.cache.insert(key, response.clone()).await;
        debug!("Cached response for domain: {}", domain);
        Ok(())
    }

    fn normalize_domain(&self, domain: &str) -> String {
        let normalized = domain.trim().to_lowercase();
        
        // Remove trailing dot if present (common in DNS contexts)
        if normalized.ends_with('.') {
            normalized[..normalized.len() - 1].to_string()
        } else {
            normalized
        }
    }
} 