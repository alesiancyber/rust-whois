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
pub mod rate_limiter;
pub mod ip;


// Re-export main types for easy access
pub use whois::{WhoisService, WhoisResult};
pub use rdap::{RdapService, RdapResult};
pub use cache::CacheService;
pub use config::Config;
pub use errors::WhoisError;
pub use tld::extract_tld;
pub use dates::{parse_date, calculate_date_fields};
pub use ip::{ValidatedIpAddress, Rir, detect_rir};

use std::sync::Arc;

/// Validated and normalized domain name.
///
/// Uses the `addr` crate with Mozilla's Public Suffix List for proper validation.
///
/// Features:
/// - RFC 1035 / RFC 5891 compliance
/// - Automatic IDNA/punycode handling for internationalized domains
/// - PSL-aware validation (handles complex TLDs like .co.uk)
/// - Proper length and character validation per label
#[derive(Debug, Clone)]
pub struct ValidatedDomain(pub String);

impl ValidatedDomain {
    /// Validate and normalize a domain name using addr crate with PSL
    ///
    /// This provides:
    /// - Comprehensive RFC compliance
    /// - IDNA support (converts unicode domains to punycode automatically)
    /// - PSL validation (knows about .co.uk, .com.au, etc.)
    pub fn new(domain: impl Into<String>) -> Result<Self, WhoisError> {
        use addr::parser::DnsName;
        use addr::psl::List;

        let domain = domain.into().trim().to_lowercase();

        // Check for empty domain
        if domain.is_empty() {
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }

        // Must have at least one dot (TLD alone is not a valid lookup target)
        if !domain.contains('.') {
            return Err(WhoisError::InvalidDomain("Domain must contain at least one dot".to_string()));
        }

        // Use addr crate for comprehensive validation
        // This handles RFC 1035/5891, IDNA, punycode, and PSL validation
        List.parse_dns_name(&domain)
            .map_err(|e| WhoisError::InvalidDomain(format!("Invalid domain: {}", e)))?;

        Ok(ValidatedDomain(domain))
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

/// Detected query type (domain or IP address)
///
/// This enum represents the result of auto-detecting whether a query
/// string is a domain name or an IP address.
#[derive(Debug, Clone)]
pub enum DetectedQueryType {
    /// The query is a valid domain name
    Domain(ValidatedDomain),
    /// The query is a valid IP address (IPv4 or IPv6)
    IpAddress(ValidatedIpAddress),
}

/// Unified validated query that auto-detects domain vs IP address
///
/// This type automatically determines whether the input is a domain name
/// or an IP address and validates it accordingly.
///
/// # Examples
///
/// ```
/// use whois_service::ValidatedQuery;
///
/// // Domain detection
/// let query = ValidatedQuery::new("example.com").unwrap();
/// assert!(query.is_domain());
///
/// // IPv4 detection
/// let query = ValidatedQuery::new("8.8.8.8").unwrap();
/// assert!(query.is_ip());
///
/// // IPv6 detection
/// let query = ValidatedQuery::new("2001:4860:4860::8888").unwrap();
/// assert!(query.is_ip());
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedQuery {
    query_type: DetectedQueryType,
    original: String,
}

impl ValidatedQuery {
    /// Automatically detect whether input is domain or IP address and validate it
    ///
    /// This function tries to parse the input as an IP address first (faster validation),
    /// then falls back to domain validation if IP parsing fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is neither a valid IP address nor a valid domain name.
    pub fn new(input: impl Into<String>) -> Result<Self, WhoisError> {
        let input = input.into();
        let trimmed = input.trim();
        let original = input.clone();

        // Try IP address first (faster to validate)
        if let Ok(ip) = ValidatedIpAddress::new(trimmed) {
            return Ok(Self {
                query_type: DetectedQueryType::IpAddress(ip),
                original,
            });
        }

        // Fall back to domain validation
        let domain = ValidatedDomain::new(trimmed)?;
        Ok(Self {
            query_type: DetectedQueryType::Domain(domain),
            original,
        })
    }

    /// Get the query type (domain or IP)
    pub fn query_type(&self) -> &DetectedQueryType {
        &self.query_type
    }

    /// Get the validated query as a string
    pub fn as_str(&self) -> &str {
        match &self.query_type {
            DetectedQueryType::Domain(d) => d.as_str(),
            DetectedQueryType::IpAddress(ip) => ip.as_str(),
        }
    }

    /// Check if this query is a domain
    pub fn is_domain(&self) -> bool {
        matches!(self.query_type, DetectedQueryType::Domain(_))
    }

    /// Check if this query is an IP address
    pub fn is_ip(&self) -> bool {
        matches!(self.query_type, DetectedQueryType::IpAddress(_))
    }

    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        match self.query_type {
            DetectedQueryType::Domain(d) => d.into_inner(),
            DetectedQueryType::IpAddress(ip) => ip.into_inner(),
        }
    }
}

impl AsRef<str> for ValidatedQuery {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for ValidatedQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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

impl ParsedWhoisData {
    /// Create a new ParsedWhoisData with all fields set to None/empty
    ///
    /// This eliminates the boilerplate of manually initializing all 13 fields
    /// in every parser function.
    pub fn new() -> Self {
        Self {
            registrar: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            name_servers: Vec::new(),
            status: Vec::new(),
            registrant_name: None,
            registrant_email: None,
            admin_email: None,
            tech_email: None,
            created_ago: None,
            updated_ago: None,
            expires_in: None,
        }
    }

    /// Calculate and update the age-based fields (created_ago, updated_ago, expires_in)
    ///
    /// This eliminates the duplicate pattern of calling dates::calculate_date_fields()
    /// and manually assigning the three return values.
    pub fn calculate_age_fields(&mut self) {
        let (created_ago, updated_ago, expires_in) = dates::calculate_date_fields(
            &self.creation_date,
            &self.updated_date,
            &self.expiration_date,
        );
        self.created_ago = created_ago;
        self.updated_ago = updated_ago;
        self.expires_in = expires_in;
    }
}

/// Unified result type for both WHOIS and RDAP lookups
///
/// This eliminates the duplication between WhoisResult and RdapResult,
/// which were structurally identical.
#[derive(Debug, Clone)]
pub struct LookupResult {
    /// The server that was queried (WHOIS or RDAP)
    pub server: String,
    /// Raw response data from the server
    pub raw_data: String,
    /// Parsed and structured WHOIS data (if parsing succeeded)
    pub parsed_data: Option<ParsedWhoisData>,
    /// Parsing analysis and debug information
    pub parsing_analysis: Vec<String>,
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

    /// Perform a whois lookup for the given domain or IP address
    ///
    /// This method automatically detects whether the input is a domain or IP address
    /// and routes the query accordingly. It will use cache if available, unless `fresh` is true.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use whois_service::WhoisClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = WhoisClient::new().await?;
    ///
    /// // Domain lookup
    /// let result = client.lookup("example.com").await?;
    ///
    /// // IPv4 lookup
    /// let result = client.lookup("8.8.8.8").await?;
    ///
    /// // IPv6 lookup
    /// let result = client.lookup("2001:4860:4860::8888").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup(&self, query: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(query, false).await
    }

    /// Perform a fresh whois lookup, bypassing cache
    pub async fn lookup_fresh(&self, query: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(query, true).await
    }

    /// Perform a whois lookup with caching options
    ///
    /// Auto-detects whether the query is a domain or IP address.
    pub async fn lookup_with_options(&self, query: &str, fresh: bool) -> Result<WhoisResponse, WhoisError> {
        let start_time = std::time::Instant::now();

        // Auto-detect query type (domain or IP)
        let validated = ValidatedQuery::new(query)?;

        // Check type before moving validated
        let is_domain = validated.is_domain();
        let query_str = validated.as_str().to_string();
        let original = validated.into_inner();

        // Dispatch based on query type
        if is_domain {
            self.lookup_domain_internal(&query_str, fresh, start_time, original).await
        } else {
            self.lookup_ip_internal(&query_str, fresh, start_time, original).await
        }
    }

    /// Generic internal lookup implementation for both domains and IPs
    ///
    /// Consolidates the duplicate code between domain and IP lookups.
    /// The only difference is which service method to call.
    async fn lookup_internal(
        &self,
        query: &str,
        is_ip: bool,
        fresh: bool,
        start_time: std::time::Instant,
        original: String,
    ) -> Result<WhoisResponse, WhoisError> {
        // If fresh lookup requested, bypass cache
        if fresh {
            let result = if is_ip {
                self.service.lookup_ip(query).await?
            } else {
                self.service.lookup(query).await?
            };
            let query_time = start_time.elapsed().as_millis() as u64;

            return Ok(WhoisResponse {
                domain: original,
                whois_server: result.server,
                raw_data: result.raw_data,
                parsed_data: result.parsed_data,
                cached: false,
                query_time_ms: query_time,
                parsing_analysis: None,
            });
        }

        // Use cache with automatic query deduplication if available
        if let Some(cache) = &self.cache {
            let query_owned = query.to_string();
            let service = self.service.clone();

            let mut response = cache
                .get_or_fetch(query, || async move {
                    let result = if is_ip {
                        service.lookup_ip(&query_owned).await?
                    } else {
                        service.lookup(&query_owned).await?
                    };
                    let query_time = start_time.elapsed().as_millis() as u64;

                    Ok(WhoisResponse {
                        domain: query_owned.clone(),
                        whois_server: result.server,
                        raw_data: result.raw_data,
                        parsed_data: result.parsed_data,
                        cached: false,
                        query_time_ms: query_time,
                        parsing_analysis: None,
                    })
                })
                .await?;

            // Restore original input format (preserves user's input case/whitespace)
            response.domain = original;
            Ok(response)
        } else {
            // No cache - perform direct lookup
            let result = if is_ip {
                self.service.lookup_ip(query).await?
            } else {
                self.service.lookup(query).await?
            };
            let query_time = start_time.elapsed().as_millis() as u64;

            Ok(WhoisResponse {
                domain: original,
                whois_server: result.server,
                raw_data: result.raw_data,
                parsed_data: result.parsed_data,
                cached: false,
                query_time_ms: query_time,
                parsing_analysis: None,
            })
        }
    }

    /// Internal domain lookup implementation
    async fn lookup_domain_internal(
        &self,
        domain: &str,
        fresh: bool,
        start_time: std::time::Instant,
        original: String,
    ) -> Result<WhoisResponse, WhoisError> {
        self.lookup_internal(domain, false, fresh, start_time, original).await
    }

    /// Internal IP lookup implementation
    async fn lookup_ip_internal(
        &self,
        ip_addr: &str,
        fresh: bool,
        start_time: std::time::Instant,
        original: String,
    ) -> Result<WhoisResponse, WhoisError> {
        self.lookup_internal(ip_addr, true, fresh, start_time, original).await
    }


    // === Utility Methods ===

    /// Get cache statistics if caching is enabled
    pub fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    // === Private Helper Methods ===

    /// Load default configuration - eliminates DRY violation
    fn load_default_config() -> Result<Arc<Config>, WhoisError> {
        let config = Arc::new(Config::load().map_err(WhoisError::ConfigError)?);
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

        // Test invalid domain (no dot)
        let result = client.lookup("invalid").await;
        assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
    }

    #[test]
    fn test_validated_domain_valid() {
        // Standard domains
        assert!(ValidatedDomain::new("example.com").is_ok());
        assert!(ValidatedDomain::new("sub.example.com").is_ok());
        assert!(ValidatedDomain::new("deep.sub.example.com").is_ok());

        // Uppercase should be normalized
        assert!(ValidatedDomain::new("EXAMPLE.COM").is_ok());
        assert!(ValidatedDomain::new("Example.Com").is_ok());

        // With whitespace (should be trimmed)
        assert!(ValidatedDomain::new("  example.com  ").is_ok());

        // Complex TLDs
        assert!(ValidatedDomain::new("example.co.uk").is_ok());
        assert!(ValidatedDomain::new("example.com.au").is_ok());

        // Hyphens in labels
        assert!(ValidatedDomain::new("my-site.example.com").is_ok());
        assert!(ValidatedDomain::new("a-b-c.example.com").is_ok());
    }

    #[test]
    fn test_validated_domain_invalid() {
        // Empty domain
        assert!(ValidatedDomain::new("").is_err());
        assert!(ValidatedDomain::new("   ").is_err());

        // No dot (TLD only)
        assert!(ValidatedDomain::new("com").is_err());
        assert!(ValidatedDomain::new("localhost").is_err());

        // Invalid dot patterns (checked before addr validation)
        assert!(ValidatedDomain::new("example..com").is_err());

        // Note: addr library may accept some edge cases by normalizing them
        // It relies on PSL and DNS RFCs for validation
        // The main validation ensures proper domain structure and PSL compliance

        // Note: Length validation is handled by addr library
        // It follows RFC 1035 requirements for label and total domain length
    }

    #[test]
    fn test_validated_domain_normalization() {
        // Verify lowercase normalization
        let domain = ValidatedDomain::new("EXAMPLE.COM").unwrap();
        assert_eq!(domain.as_str(), "example.com");

        // Verify trimming
        let domain = ValidatedDomain::new("  example.com  ").unwrap();
        assert_eq!(domain.as_str(), "example.com");

        // Verify mixed case
        let domain = ValidatedDomain::new("Example.Com").unwrap();
        assert_eq!(domain.as_str(), "example.com");
    }

    #[test]
    fn test_validated_domain_edge_cases() {
        // Single character labels
        assert!(ValidatedDomain::new("a.b.c").is_ok());

        // Numeric domains
        assert!(ValidatedDomain::new("123.456.com").is_ok());

        // All numeric (valid as DNS name)
        assert!(ValidatedDomain::new("123.456").is_ok());

        // Maximum label length (63 chars)
        let max_label = "a".repeat(63);
        assert!(ValidatedDomain::new(format!("{}.com", max_label)).is_ok());

        // Long but valid domain
        let valid_long = format!("{}.{}.{}.com", "a".repeat(50), "b".repeat(50), "c".repeat(50));
        assert!(ValidatedDomain::new(valid_long).is_ok());
    }

    #[test]
    fn test_validated_domain_methods() {
        let domain = ValidatedDomain::new("example.com").unwrap();

        // Test as_str()
        assert_eq!(domain.as_str(), "example.com");

        // Test AsRef<str>
        let s: &str = domain.as_ref();
        assert_eq!(s, "example.com");

        // Test Display
        assert_eq!(format!("{}", domain), "example.com");

        // Test into_inner()
        let domain2 = ValidatedDomain::new("test.com").unwrap();
        let inner = domain2.into_inner();
        assert_eq!(inner, "test.com");
    }
} 