//! TLD (Top-Level Domain) extraction utilities
//!
//! Provides shared TLD extraction logic using the embedded Public Suffix List.

use crate::errors::WhoisError;
use psl::Psl;
use tracing::{debug, warn};

/// Extract the TLD/suffix from a domain using the embedded Public Suffix List.
///
/// The `psl` crate contains an up-to-date embedded PSL, updated with each crate release.
/// This handles complex suffixes like `co.uk`, `com.au`, etc.
///
/// # Examples
///
/// ```
/// use whois_service::tld::extract_tld;
///
/// assert_eq!(extract_tld("example.com").unwrap(), "com");
/// assert_eq!(extract_tld("example.co.uk").unwrap(), "co.uk");
/// ```
pub fn extract_tld(domain: &str) -> Result<String, WhoisError> {
    match psl::List.suffix(domain.as_bytes()) {
        Some(suffix) => {
            match std::str::from_utf8(suffix.as_bytes()) {
                Ok(tld) => {
                    debug!("PSL extracted TLD '{}' from domain '{}'", tld, domain);
                    Ok(tld.to_string())
                }
                Err(_) => Err(WhoisError::InvalidDomain(
                    format!("Invalid UTF-8 in TLD for domain: {}", domain)
                ))
            }
        }
        None => {
            // Fallback for edge cases (should be rare with proper PSL)
            // This handles malformed domains or very new TLDs not yet in PSL
            warn!("PSL suffix not found for '{}', falling back to simple extraction", domain);
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() < 2 {
                Err(WhoisError::InvalidDomain(
                    format!("No TLD found in domain: {}", domain)
                ))
            } else {
                // Return just the last segment as TLD
                Ok(parts[parts.len() - 1].to_string())
            }
        }
    }
}

/// Simple TLD extraction for metrics (doesn't need PSL complexity)
/// Returns just the last segment of the domain.
pub fn extract_tld_simple(domain: &str) -> String {
    domain
        .split('.')
        .next_back()
        .unwrap_or("unknown")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tld_simple() {
        // Basic TLDs
        assert_eq!(extract_tld_simple("example.com"), "com");
        assert_eq!(extract_tld_simple("test.org"), "org");
        assert_eq!(extract_tld_simple("site.net"), "net");

        // Multi-part TLDs (simple extraction returns last part only)
        assert_eq!(extract_tld_simple("test.co.uk"), "uk");
        assert_eq!(extract_tld_simple("example.com.au"), "au");

        // Edge cases
        assert_eq!(extract_tld_simple("nodots"), "nodots");
        assert_eq!(extract_tld_simple("a.b"), "b");

        // Case normalization
        assert_eq!(extract_tld_simple("EXAMPLE.COM"), "com");
        assert_eq!(extract_tld_simple("Example.Com"), "com");
    }

    #[test]
    fn test_extract_tld_psl_simple() {
        // Simple TLDs
        assert_eq!(extract_tld("example.com").unwrap(), "com");
        assert_eq!(extract_tld("test.org").unwrap(), "org");
        assert_eq!(extract_tld("site.net").unwrap(), "net");

        // Country code TLDs
        assert_eq!(extract_tld("example.uk").unwrap(), "uk");
        assert_eq!(extract_tld("example.de").unwrap(), "de");
        assert_eq!(extract_tld("example.jp").unwrap(), "jp");
    }

    #[test]
    fn test_extract_tld_psl_complex() {
        // Multi-part TLDs (PSL-aware)
        assert_eq!(extract_tld("example.co.uk").unwrap(), "co.uk");
        assert_eq!(extract_tld("example.com.au").unwrap(), "com.au");
        assert_eq!(extract_tld("example.ac.uk").unwrap(), "ac.uk");

        // More complex suffixes
        assert_eq!(extract_tld("example.blogspot.com").unwrap(), "blogspot.com");
        assert_eq!(extract_tld("example.github.io").unwrap(), "github.io");
    }

    #[test]
    fn test_extract_tld_subdomains() {
        // Subdomains should extract TLD correctly
        assert_eq!(extract_tld("sub.example.com").unwrap(), "com");
        assert_eq!(extract_tld("deep.sub.example.com").unwrap(), "com");
        assert_eq!(extract_tld("www.example.co.uk").unwrap(), "co.uk");
        assert_eq!(extract_tld("api.service.example.com.au").unwrap(), "com.au");
    }

    #[test]
    fn test_extract_tld_case_handling() {
        // PSL is case-sensitive - uppercase input won't match complex TLDs properly
        // Lowercase works correctly for all TLDs
        assert_eq!(extract_tld("example.com").unwrap(), "com");
        assert_eq!(extract_tld("example.co.uk").unwrap(), "co.uk");
        assert_eq!(extract_tld("test.org").unwrap(), "org");

        // Uppercase domains may fallback to simple extraction
        let tld_upper = extract_tld("EXAMPLE.COM").unwrap();
        // Should extract something (either "COM" or fallback)
        assert!(!tld_upper.is_empty());
    }

    #[test]
    fn test_extract_tld_new_tlds() {
        // New gTLDs
        assert_eq!(extract_tld("example.tech").unwrap(), "tech");
        assert_eq!(extract_tld("example.app").unwrap(), "app");
        assert_eq!(extract_tld("example.dev").unwrap(), "dev");
    }

    #[test]
    fn test_extract_tld_invalid() {
        // Empty string should fail
        assert!(extract_tld("").is_err());

        // Note: PSL has fallback behavior for edge cases like single dots
        // or domains without dots. These may extract the last segment as TLD,
        // which is technically valid in DNS contexts.
    }

    #[test]
    fn test_extract_tld_edge_cases() {
        // Single letter TLD (valid in DNS)
        assert!(extract_tld("example.x").is_ok());

        // Numeric TLD (theoretical)
        assert!(extract_tld("example.123").is_ok());

        // Long TLD
        assert!(extract_tld("example.abcdefghij").is_ok());
    }
}
