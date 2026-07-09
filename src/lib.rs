//! # Whois Service Library
//! 
//! A high-performance, production-ready whois lookup library for Rust.
//! 
//! ## Features
//! 
//! - Dynamic TLD discovery: IANA root/bootstrap data with a self-healing runtime cache
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
pub mod buffer_pool;
pub mod parser;
pub mod tld;
pub mod dates;
pub mod rate_limiter;
pub mod ip;
#[cfg(feature = "redis-cache")]
pub mod redis_cache;


// Re-export main types for easy access
pub use whois::{WhoisService, WhoisResult};
pub use rdap::{RdapService, RdapResult};
pub use cache::{CacheService, CacheBackend, BackendError};
#[cfg(feature = "redis-cache")]
pub use redis_cache::RedisCache;
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

        // Normalize: trim, lowercase, and drop the trailing root dot ("example.com.")
        // so downstream TLD extraction and server caches see one canonical form
        let domain = domain.into().trim().trim_end_matches('.').to_lowercase();

        // Check for empty domain
        if domain.is_empty() {
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }

        // Must have at least one dot (TLD alone is not a valid lookup target)
        if !domain.contains('.') {
            return Err(WhoisError::InvalidDomain("Domain must contain at least one dot".to_string()));
        }

        // Reject URL-ish syntax explicitly. The addr crate parses DNS *names*,
        // which permit almost any byte in a label, so "http://example.com"
        // would otherwise validate and be sent verbatim to WHOIS servers.
        if domain.contains(['/', ':', '?', '#', '@', ' ']) {
            return Err(WhoisError::InvalidDomain(format!(
                "Domain contains URL syntax or invalid characters: {} (pass a bare hostname)", domain
            )));
        }

        // Use addr crate for comprehensive validation
        // This handles RFC 1035/5891, IDNA, punycode, and PSL validation
        List.parse_dns_name(&domain)
            .map_err(|e| WhoisError::InvalidDomain(format!("{} ({})", domain, e)))?;

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

        // Try IP address first (faster to validate)
        if let Ok(ip) = ValidatedIpAddress::new(trimmed) {
            return Ok(Self {
                query_type: DetectedQueryType::IpAddress(ip),
            });
        }

        // Inputs that look like IP addresses but failed to parse (e.g.
        // "300.300.300.300", "2001:db8::12345") should surface an invalid-IP
        // error instead of falling through to a confusing domain/TLD failure
        let looks_like_ipv4 = trimmed.contains('.')
            && trimmed.chars().all(|c| c.is_ascii_digit() || c == '.');
        let looks_like_ipv6 = trimmed.contains(':')
            && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
        if looks_like_ipv4 || looks_like_ipv6 {
            return Err(WhoisError::InvalidIpAddress(trimmed.to_string()));
        }

        // Fall back to domain validation
        let domain = ValidatedDomain::new(trimmed)?;
        Ok(Self {
            query_type: DetectedQueryType::Domain(domain),
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

/// Outcome classification of a lookup response
///
/// WHOIS servers signal "domain does not exist" and "you are being throttled"
/// as ordinary response text, and RDAP signals them as HTTP 404/429. This enum
/// surfaces that outcome as structured data so callers (and the cache) don't
/// treat throttle banners or NXDOMAIN responses as real registration records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum LookupStatus {
    /// A registration record was returned
    #[default]
    Found,
    /// The queried object is not registered / does not exist
    NotFound,
    /// The upstream server refused the query due to rate limiting or quota
    RateLimited,
}

/// Parsed whois data structure with calculated fields
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
        Self::default()
    }

    /// Fill any empty fields from another parse result.
    ///
    /// Used when a registrar referral response turns out thinner than the
    /// registry response already in hand (rate-limited or empty registrar
    /// WHOIS servers are common) - referral data wins, registry data fills gaps.
    pub fn fill_missing_from(&mut self, fallback: &ParsedWhoisData) {
        macro_rules! fill_option {
            ($($field:ident),+) => {
                $(if self.$field.is_none() {
                    self.$field = fallback.$field.clone();
                })+
            };
        }
        fill_option!(
            registrar, creation_date, expiration_date, updated_date,
            registrant_name, registrant_email, admin_email, tech_email,
            created_ago, updated_ago, expires_in
        );
        if self.name_servers.is_empty() {
            self.name_servers = fallback.name_servers.clone();
        }
        if self.status.is_empty() {
            self.status = fallback.status.clone();
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
    /// Classified outcome (found / not found / rate limited)
    pub status: LookupStatus,
}

/// High-level lookup client with optional caching
///
/// Uses a three-tier lookup strategy for both domains and IP addresses:
/// 1. RDAP first (modern, structured JSON)
/// 2. WHOIS fallback (legacy but comprehensive)
/// 3. Optional in-memory caching with request deduplication
#[derive(Clone)]
pub struct WhoisClient {
    service: Arc<WhoisService>,
    rdap: Arc<RdapService>,
    cache: Option<Arc<CacheService>>,
}

/// Cache configuration for `WhoisClient::build`
enum CacheMode {
    /// In-process moka cache only (or disabled entirely)
    InProcess { enabled: bool },
    /// In-process cache backed by a shared second tier (e.g. Redis)
    Tiered(Arc<dyn cache::CacheBackend>),
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
        Self::build(config, CacheMode::InProcess { enabled: true }).await
    }

    /// Create a new whois client without caching
    pub async fn new_without_cache() -> Result<Self, WhoisError> {
        Self::build(Self::load_default_config()?, CacheMode::InProcess { enabled: false }).await
    }

    /// Create a client whose cache has a shared second tier (e.g. Redis).
    ///
    /// The in-process cache still provides fast hits and request coalescing;
    /// the backend is consulted on local misses and written through on
    /// fetches, so every instance sharing it shares one cache - upstream
    /// query volume stays flat as instances scale out.
    pub async fn new_with_cache_backend(
        config: Arc<Config>,
        backend: Arc<dyn cache::CacheBackend>,
    ) -> Result<Self, WhoisError> {
        Self::build(config, CacheMode::Tiered(backend)).await
    }

    /// Shared constructor for all client variants
    async fn build(config: Arc<Config>, cache_mode: CacheMode) -> Result<Self, WhoisError> {
        let service = Arc::new(WhoisService::new(config.clone()).await?);
        let rdap = Arc::new(RdapService::new(config.clone()).await?);
        let cache = match cache_mode {
            CacheMode::InProcess { enabled: false } => None,
            CacheMode::InProcess { enabled: true } => Some(Arc::new(CacheService::new(config))),
            CacheMode::Tiered(backend) => Some(Arc::new(CacheService::with_backend(config, backend))),
        };

        Ok(Self { service, rdap, cache })
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

        // Auto-detect query type (domain or IP) and normalize
        let validated = ValidatedQuery::new(query)?;
        let is_ip = validated.is_ip();
        let query = validated.into_inner();

        self.lookup_internal(&query, is_ip, fresh, start_time).await
    }

    /// Perform an RDAP-first lookup with WHOIS fallback
    ///
    /// The returned server is prefixed with "RDAP: " or "WHOIS: " so callers
    /// can tell which protocol answered.
    async fn lookup_with_fallback(&self, query: &str, is_ip: bool) -> Result<LookupResult, WhoisError> {
        // Tier 1: RDAP (modern, structured JSON)
        let rdap_result = if is_ip {
            self.rdap.lookup_ip(query).await
        } else {
            self.rdap.lookup(query).await
        };

        match rdap_result {
            // An Ok(NotFound) short-circuits here too: the registry's RDAP 404
            // is authoritative, so a WHOIS fallback query would be wasted load
            Ok(mut result) => {
                result.server = format!("RDAP: {}", result.server);
                return Ok(result);
            }
            Err(e) => {
                tracing::debug!("RDAP lookup failed for {}: {} - falling back to WHOIS", query, e);
            }
        }

        // Tier 2: WHOIS (legacy but comprehensive)
        let mut result = if is_ip {
            self.service.lookup_ip(query).await?
        } else {
            self.service.lookup(query).await?
        };
        result.server = format!("WHOIS: {}", result.server);
        Ok(result)
    }

    /// Perform a lookup and package it as a WhoisResponse
    async fn fetch_response(
        &self,
        query: &str,
        is_ip: bool,
        start_time: std::time::Instant,
    ) -> Result<WhoisResponse, WhoisError> {
        let result = self.lookup_with_fallback(query, is_ip).await?;
        let query_time = start_time.elapsed().as_millis() as u64;

        Ok(WhoisResponse {
            domain: query.to_string(),
            whois_server: result.server,
            raw_data: result.raw_data,
            parsed_data: result.parsed_data,
            lookup_status: result.status,
            cached: false,
            query_time_ms: query_time,
            parsing_analysis: Some(result.parsing_analysis),
        })
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
    ) -> Result<WhoisResponse, WhoisError> {
        // If fresh lookup requested, bypass cache
        if fresh {
            return self.fetch_response(query, is_ip, start_time).await;
        }

        // Use cache with automatic query deduplication if available
        if let Some(cache) = &self.cache {
            let query_owned = query.to_string();
            let client = self.clone();

            let mut response = cache
                .get_or_fetch(query, || async move {
                    client.fetch_response(&query_owned, is_ip, start_time).await
                })
                .await?;

            // A cache hit stores the original fetch's duration - report this
            // request's actual (near-instant) latency instead
            if response.cached {
                response.query_time_ms = start_time.elapsed().as_millis() as u64;
            }
            Ok(response)
        } else {
            // No cache - perform direct lookup
            self.fetch_response(query, is_ip, start_time).await
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
    /// Classified outcome: "found", "not_found" (domain is not registered),
    /// or "rate_limited" (upstream throttled the query - data is unreliable)
    #[serde(default)]
    pub lookup_status: LookupStatus,
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

        // URL syntax must be rejected (addr's DNS-name parsing would accept it)
        assert!(ValidatedDomain::new("http://example.com").is_err());
        assert!(ValidatedDomain::new("example.com/path").is_err());
        assert!(ValidatedDomain::new("example.com:443").is_err());
        assert!(ValidatedDomain::new("user@example.com").is_err());

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

        // Verify trailing root dot is stripped (DNS-equivalent form)
        let domain = ValidatedDomain::new("example.com.").unwrap();
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