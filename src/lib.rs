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
pub mod tld;
pub mod dates;


// Re-export main types for easy access
pub use whois::{WhoisService, WhoisResult};
pub use rdap::{RdapService, RdapResult};
pub use cache::CacheService;
pub use config::Config;
pub use errors::WhoisError;
pub use tld::extract_tld;
pub use dates::{parse_date, calculate_date_fields};



use std::sync::Arc;

/// Validated and normalized domain name.
/// 
/// Ensures domain conforms to RFC 1035 / RFC 5891 requirements:
/// - Total length <= 253 characters
/// - Contains at least one dot (TLD required)
/// - No consecutive dots or leading/trailing dots
/// - Each label is 1-63 characters
/// - Labels don't start or end with hyphens
/// - Only alphanumeric characters and hyphens allowed
#[derive(Debug, Clone)]
pub struct ValidatedDomain(pub String);

impl ValidatedDomain {
    /// Validate and normalize a domain name per RFC 1035 / RFC 5891
    pub fn new(domain: impl Into<String>) -> Result<Self, WhoisError> {
        let domain = domain.into().trim().to_lowercase();
        
        // Check for empty domain
        if domain.is_empty() {
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }
        
        // RFC 1035: Total domain length max 253 characters
        if domain.len() > 253 {
            return Err(WhoisError::InvalidDomain("Domain name too long".to_string()));
        }
        
        // Must have at least one dot (TLD required)
        if !domain.contains('.') {
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        // Check for invalid dot patterns
        if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        // Validate each label
        for label in domain.split('.') {
            Self::validate_label(label)?;
        }
        
        Ok(ValidatedDomain(domain))
    }
    
    /// Validate a single domain label per RFC 1035
    fn validate_label(label: &str) -> Result<(), WhoisError> {
        // RFC 1035: Labels must be 1-63 characters
        if label.is_empty() || label.len() > 63 {
            return Err(WhoisError::InvalidDomain(
                format!("Label '{}' has invalid length (must be 1-63 chars)", label)
            ));
        }
        
        // RFC 1035: Labels cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(WhoisError::InvalidDomain(
                format!("Label '{}' cannot start or end with hyphen", label)
            ));
        }
        
        // RFC 1035: Labels can only contain alphanumeric and hyphens
        // Exception: Allow punycode (xn--) for internationalized domain names
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err(WhoisError::InvalidDomain(
                    format!("Invalid character '{}' in domain", ch)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Get the validated domain string
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for ValidatedDomain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidatedDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
        let cache = Self::initialize_cache(config);
        
        Ok(Self { service, cache })
    }

    /// Create a new whois client without caching
    pub async fn new_without_cache() -> Result<Self, WhoisError> {
        let config = Self::load_default_config()?;
        let service = Arc::new(WhoisService::new(config).await?);
        
        Ok(Self { service, cache: None })
    }

    /// Initialize cache
    fn initialize_cache(config: Arc<Config>) -> Option<Arc<CacheService>> {
        Some(Arc::new(CacheService::new(config)))
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
        
        // Use shared ValidatedDomain for consistent validation
        let validated = ValidatedDomain::new(domain)?;
        let domain_str = validated.as_str();

        // Check cache first (if available and not requesting fresh)
        if !fresh {
            if let Some(cached_result) = self.check_cache(domain_str).await {
                return Ok(cached_result);
            }
        }

        // Perform fresh lookup
        let result = self.service.lookup(domain_str).await?;
        let query_time = start_time.elapsed().as_millis() as u64;
        
        let response = WhoisResponse {
            domain: validated.into_inner(),
            whois_server: result.server,
            raw_data: result.raw_data,
            parsed_data: result.parsed_data,
            cached: false,
            query_time_ms: query_time,
            parsing_analysis: None, // No debug info in library mode
        };

        // Cache the result if cache is available
        self.cache_result(&response.domain, &response).await;

        Ok(response)
    }

    /// Check cache for a cached response
    async fn check_cache(&self, domain: &str) -> Option<WhoisResponse> {
        if let Some(cache) = &self.cache {
            // get() returns Option directly - cache operations are infallible
            return cache.get(domain).await;
        }
        None
    }

    /// Cache result for future lookups
    async fn cache_result(&self, domain: &str, response: &WhoisResponse) {
        if let Some(cache) = &self.cache {
            // set() is infallible - in-memory cache operations don't fail
            cache.set(domain, response).await;
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