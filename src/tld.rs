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
        .last()
        .unwrap_or("unknown")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tld_simple() {
        assert_eq!(extract_tld_simple("example.com"), "com");
        assert_eq!(extract_tld_simple("test.co.uk"), "uk");
        assert_eq!(extract_tld_simple("nodots"), "nodots");
    }

    #[test]
    fn test_extract_tld_psl() {
        // These should use PSL for accurate extraction
        assert!(extract_tld("example.com").is_ok());
        assert!(extract_tld("test.co.uk").is_ok());
    }
}
