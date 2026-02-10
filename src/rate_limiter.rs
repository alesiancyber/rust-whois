use governor::{Quota, RateLimiter as GovernorLimiter, DefaultDirectRateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::warn;

/// Internal rate limiter for protecting against accidental abuse
///
/// This is designed for internal APIs to prevent:
/// - Buggy services spamming fresh queries
/// - Accidental loops in internal tools
/// - Getting blacklisted by external WHOIS servers
///
/// Uses soft limits with warnings rather than hard blocks.
pub struct RateLimiter {
    /// Rate limiter for fresh (cache-bypass) queries
    /// More restrictive since these hit external servers
    fresh_limiter: Arc<DefaultDirectRateLimiter>,

    /// Rate limiter for debug endpoint queries
    /// Very restrictive since debug always bypasses cache
    debug_limiter: Arc<DefaultDirectRateLimiter>,
}

/// Error type for rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfigError(String);

impl std::fmt::Display for RateLimiterConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rate limiter configuration error: {}", self.0)
    }
}

impl std::error::Error for RateLimiterConfigError {}

impl RateLimiter {
    /// Create a new rate limiter with default quotas for internal protection
    ///
    /// Default limits (per hour):
    /// - Fresh queries: 1000/hour (prevents cache bypass abuse)
    /// - Debug queries: 100/hour (debug is expensive)
    pub fn new() -> Self {
        Self {
            // 1000 fresh queries per hour = ~16/minute
            // These unwraps are safe because we're using non-zero constants
            fresh_limiter: Arc::new(GovernorLimiter::direct(
                Quota::per_hour(NonZeroU32::new(1000).unwrap())
            )),
            // 100 debug queries per hour = ~1-2/minute
            debug_limiter: Arc::new(GovernorLimiter::direct(
                Quota::per_hour(NonZeroU32::new(100).unwrap())
            )),
        }
    }

    /// Create a rate limiter with custom quotas
    ///
    /// Returns an error if either quota is zero.
    ///
    /// # Arguments
    /// * `fresh_per_hour` - Max fresh queries per hour (must be > 0)
    /// * `debug_per_hour` - Max debug queries per hour (must be > 0)
    ///
    /// # Example
    /// ```
    /// use whois_service::rate_limiter::RateLimiter;
    ///
    /// let limiter = RateLimiter::with_quotas(500, 50).unwrap();
    /// ```
    pub fn with_quotas(fresh_per_hour: u32, debug_per_hour: u32) -> Result<Self, RateLimiterConfigError> {
        let fresh_quota = NonZeroU32::new(fresh_per_hour)
            .ok_or_else(|| RateLimiterConfigError(
                "fresh_per_hour must be greater than 0".to_string()
            ))?;

        let debug_quota = NonZeroU32::new(debug_per_hour)
            .ok_or_else(|| RateLimiterConfigError(
                "debug_per_hour must be greater than 0".to_string()
            ))?;

        Ok(Self {
            fresh_limiter: Arc::new(GovernorLimiter::direct(Quota::per_hour(fresh_quota))),
            debug_limiter: Arc::new(GovernorLimiter::direct(Quota::per_hour(debug_quota))),
        })
    }

    /// Check fresh query rate limit
    ///
    /// Logs warning if rate limit exceeded but doesn't block (soft limit).
    /// Returns true if rate limit exceeded (for metrics).
    pub fn check_fresh_query(&self, domain: &str) -> bool {
        match self.fresh_limiter.check() {
            Ok(_) => false, // Within rate limit
            Err(_) => {
                warn!(
                    domain = domain,
                    "Fresh query rate limit exceeded - possible internal service bug or misconfiguration"
                );
                true // Rate limit exceeded
            }
        }
    }

    /// Check debug query rate limit
    ///
    /// Logs warning if rate limit exceeded but doesn't block (soft limit).
    /// Returns true if rate limit exceeded (for metrics).
    pub fn check_debug_query(&self, domain: &str) -> bool {
        match self.debug_limiter.check() {
            Ok(_) => false, // Within rate limit
            Err(_) => {
                warn!(
                    domain = domain,
                    "Debug query rate limit exceeded - debug endpoint is being overused"
                );
                true // Rate limit exceeded
            }
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_normal_usage() {
        let limiter = RateLimiter::with_quotas(10, 5).unwrap();

        // Should allow first few queries
        assert!(!limiter.check_fresh_query("test.com"));
        assert!(!limiter.check_fresh_query("test.com"));
        assert!(!limiter.check_debug_query("test.com"));
    }

    #[test]
    fn test_rate_limiter_rejects_zero_quota() {
        // Should fail with zero fresh quota
        assert!(RateLimiter::with_quotas(0, 100).is_err());

        // Should fail with zero debug quota
        assert!(RateLimiter::with_quotas(100, 0).is_err());

        // Should fail with both zero
        assert!(RateLimiter::with_quotas(0, 0).is_err());
    }

    #[test]
    fn test_rate_limiter_accepts_valid_quotas() {
        // Should succeed with valid quotas
        assert!(RateLimiter::with_quotas(1, 1).is_ok());
        assert!(RateLimiter::with_quotas(1000, 100).is_ok());
    }
}
