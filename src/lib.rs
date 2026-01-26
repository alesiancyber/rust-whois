//! # Whois Service Library
//! 
//! A high-performance, production-ready whois lookup library for Rust.
//! 
//! ## Features
//! 
//! - Hybrid TLD discovery: hardcoded mappings for popular TLDs + dynamic discovery
//! - Intelligent whois server detection with fallback strategies
//! - Structured data parsing with calculated fields (age, expiration)
//! - Optional caching with smart domain normalization
//! - Production-ready error handling with graceful degradation
//! - High-performance async implementation with connection pooling
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use whois_service::WhoisClient;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = WhoisClient::new().await?;
//!     let result = client.lookup("google.com").await?;
//!     
//!     println!("Domain: {}", result.domain);
//!     println!("Registrar: {:?}", result.parsed_data.as_ref().and_then(|p| p.registrar.as_ref()));
//!     
//!     Ok(())
//! }
//! ```

pub mod whois;
pub mod rdap;
pub mod cache;
pub mod config;
pub mod errors;
pub mod tld_mappings;
pub mod buffer_pool;
pub mod parser;

// OpenAPI support (optional)
#[cfg(feature = "openapi")]
use utoipa::ToSchema;
#[cfg(feature = "openapi")]
use serde_json::json;

// Re-export main types for easy access
pub use whois::{WhoisService, WhoisResult};
pub use rdap::{RdapService, RdapResult};
pub use cache::CacheService;
pub use config::Config;
pub use errors::WhoisError;



use std::sync::Arc;

/// Parsed whois data structure with calculated fields
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ParsedWhoisData {
    /// Domain registrar name
    #[cfg_attr(feature = "openapi", schema(example = "MarkMonitor Inc."))]
    pub registrar: Option<String>,
    
    /// Domain creation date in ISO 8601 format
    #[cfg_attr(feature = "openapi", schema(example = "1997-09-15T04:00:00Z"))]
    pub creation_date: Option<String>,
    
    /// Domain expiration date in ISO 8601 format
    #[cfg_attr(feature = "openapi", schema(example = "2028-09-14T04:00:00Z"))]
    pub expiration_date: Option<String>,
    
    /// Last update date in ISO 8601 format
    #[cfg_attr(feature = "openapi", schema(example = "2019-09-09T15:39:04Z"))]
    pub updated_date: Option<String>,
    
    /// Domain name servers
    #[cfg_attr(feature = "openapi", schema(example = json!(["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"])))]
    pub name_servers: Vec<String>,
    
    /// Domain status codes (useful for security analysis)
    #[cfg_attr(feature = "openapi", schema(example = json!(["clientDeleteProhibited", "clientTransferProhibited"])))]
    pub status: Vec<String>,
    
    /// Registrant name
    pub registrant_name: Option<String>,
    
    /// Registrant email
    pub registrant_email: Option<String>,
    
    /// Administrative contact email
    pub admin_email: Option<String>,
    
    /// Technical contact email
    pub tech_email: Option<String>,
    
    /// Days since domain creation (threat indicator - newly registered domains are suspicious)
    #[cfg_attr(feature = "openapi", schema(example = 10117))]
    pub created_ago: Option<i64>,
    
    /// Days since last update (activity indicator)
    #[cfg_attr(feature = "openapi", schema(example = 45))]
    pub updated_ago: Option<i64>,
    
    /// Days until expiration (domain monitoring - negative if expired)
    #[cfg_attr(feature = "openapi", schema(example = 1204))]
    pub expires_in: Option<i64>,
}

/// High-level whois client with optional caching
#[derive(Clone)]
pub struct WhoisClient {
    service: Arc<WhoisService>,
    cache: Option<Arc<CacheService>>,
}

impl WhoisClient {
    // === Constructor Methods ===
    
    /// Create a new whois client with default configuration
    pub async fn new() -> Result<Self, WhoisError> {
        let config = Self::load_default_config()?;
        Self::new_with_config(config).await
    }

    /// Create a new whois client with custom configuration
    pub async fn new_with_config(config: Arc<Config>) -> Result<Self, WhoisError> {
        let service = Arc::new(WhoisService::new(config.clone()).await?);
        let cache = Self::initialize_cache(config)?;
        
        Ok(Self { service, cache })
    }

    /// Create a new whois client without caching
    pub async fn new_without_cache() -> Result<Self, WhoisError> {
        let config = Self::load_default_config()?;
        let service = Arc::new(WhoisService::new(config).await?);
        
        Ok(Self { service, cache: None })
    }

    /// Initialize cache - follows SRP
    fn initialize_cache(config: Arc<Config>) -> Result<Option<Arc<CacheService>>, WhoisError> {
        let cache = Some(Arc::new(
            CacheService::new(config)
                .map_err(|e| WhoisError::CacheError(format!("Failed to initialize cache: {}", e)))?
        ));
        Ok(cache)
    }

    // === Public API Methods ===

    /// Perform a whois lookup for the given domain
    /// 
    /// This method will use cache if available, unless `fresh` is true.
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(domain, false).await
    }

    /// Perform a fresh whois lookup, bypassing cache
    pub async fn lookup_fresh(&self, domain: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(domain, true).await
    }

    /// Perform a whois lookup with caching options
    pub async fn lookup_with_options(&self, domain: &str, fresh: bool) -> Result<WhoisResponse, WhoisError> {
        let start_time = std::time::Instant::now();
        let normalized_domain = Self::validate_and_normalize_domain(domain)?;

        // Check cache first (if available and not requesting fresh)
        if !fresh {
            if let Some(cached_result) = self.check_cache(&normalized_domain).await {
                return Ok(cached_result);
            }
        }

        // Perform fresh lookup
        let result = self.service.lookup(&normalized_domain).await?;
        let query_time = start_time.elapsed().as_millis() as u64;
        
        let response = WhoisResponse {
            domain: normalized_domain.clone(),
            whois_server: result.server,
            raw_data: result.raw_data,
            parsed_data: result.parsed_data,
            cached: false,
            query_time_ms: query_time,
            parsing_analysis: None, // No debug info in library mode
        };

        // Cache the result if cache is available
        self.cache_result(&normalized_domain, &response).await;

        Ok(response)
    }

    /// Validate and normalize domain - eliminates DRY violation
    fn validate_and_normalize_domain(domain: &str) -> Result<String, WhoisError> {
        let normalized_domain = domain.trim().to_lowercase();
        
        // Basic domain validation
        if normalized_domain.is_empty() {
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }
        
        if !normalized_domain.contains('.') {
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }

        Ok(normalized_domain)
    }

    /// Check cache - follows SRP
    async fn check_cache(&self, domain: &str) -> Option<WhoisResponse> {
        if let Some(cache) = &self.cache {
            match cache.get(domain).await {
                Ok(Some(cached_result)) => {
                    return Some(cached_result);
                }
                Ok(None) => {
                    // Cache miss, continue to fresh lookup
                }
                Err(e) => {
                    tracing::warn!("Cache read error for {}: {}", domain, e);
                    // Continue to fresh lookup on cache error
                }
            }
        }
        None
    }

    /// Cache result - follows SRP
    async fn cache_result(&self, domain: &str, response: &WhoisResponse) {
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.set(domain, response).await {
                tracing::warn!("Failed to cache result for {}: {}", domain, e);
                // Don't fail the request for cache write errors
            }
        }
    }

    // === Utility Methods ===

    /// Get cache statistics if caching is enabled
    pub fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    // === Private Helper Methods ===

    /// Load default configuration - eliminates DRY violation
    fn load_default_config() -> Result<Arc<Config>, WhoisError> {
        let config = Arc::new(Config::load().map_err(|e| WhoisError::ConfigError(e))?);
        Ok(config)
    }
}

/// Response structure for whois lookups
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WhoisResponse {
    pub domain: String,
    pub whois_server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub cached: bool,
    pub query_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsing_analysis: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_whois_client_creation() {
        let client = WhoisClient::new_without_cache().await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_domain_validation() {
        let client = WhoisClient::new_without_cache().await.unwrap();
        
        // Test empty domain
        let result = client.lookup("").await;
        assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
        
        // Test invalid domain
        let result = client.lookup("invalid").await;
        assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
    }
} 