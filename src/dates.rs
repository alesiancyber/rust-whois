//! Date parsing and calculation utilities
//!
//! Provides shared date handling for WHOIS and RDAP responses.

use chrono::{DateTime, NaiveDateTime, Utc};
use tracing::debug;

/// Parse various date formats commonly found in WHOIS/RDAP data.
///
/// Supports:
/// - ISO 8601 / RFC 3339 formats (with timezone)
/// - Common WHOIS date formats (various separators)
/// - Date-only formats (assumes midnight UTC)
pub fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    let date_str = date_str.trim();
    
    // Try RFC 3339 first (most common for RDAP)
    if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
        return Some(dt.with_timezone(&Utc));
    }
    
    // DateTime formats (with time component)
    const DATETIME_FORMATS: &[&str] = &[
        "%Y-%m-%dT%H:%M:%S%.fZ",           // 2025-05-18T13:36:06.0Z (ISO 8601)
        "%Y-%m-%dT%H:%M:%S%z",             // 2025-05-18T13:36:06+0000
        "%Y-%m-%d %H:%M:%S",               // 2025-05-18 13:36:06
    ];
    
    // Date-only formats (no time component)
    const DATE_FORMATS: &[&str] = &[
        "%Y-%m-%d",                        // 2025-05-18 (ISO 8601)
        "%d-%b-%Y",                        // 18-May-2025
        "%d %b %Y",                        // 18 May 2025
        "%Y/%m/%d",                        // 2025/05/18
        "%m/%d/%Y",                        // 05/18/2025
        "%d.%m.%Y",                        // 18.05.2025
    ];

    // Try parsing with timezone
    for format in DATETIME_FORMATS {
        if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    // Try parsing as naive datetime and assume UTC
    for format in DATETIME_FORMATS {
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(date_str, format) {
            return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }
    }

    // Try parsing as date-only and assume midnight UTC
    for format in DATE_FORMATS {
        if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
            if let Some(naive_dt) = naive_date.and_hms_opt(0, 0, 0) {
                return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
            }
        }
    }

    debug!("Failed to parse date: {}", date_str);
    None
}

/// Calculate days since a date (negative if in future)
pub fn days_since(date: &DateTime<Utc>) -> i64 {
    (Utc::now() - *date).num_days()
}

/// Calculate days until a date (negative if in past)
pub fn days_until(date: &DateTime<Utc>) -> i64 {
    (*date - Utc::now()).num_days()
}

/// Calculate relative date fields for parsed data
/// 
/// Updates `created_ago`, `updated_ago`, and `expires_in` fields
/// based on the corresponding date strings.
pub fn calculate_date_fields(
    creation_date: &Option<String>,
    updated_date: &Option<String>,
    expiration_date: &Option<String>,
) -> (Option<i64>, Option<i64>, Option<i64>) {
    let created_ago = creation_date
        .as_ref()
        .and_then(|d| parse_date(d))
        .map(|dt| days_since(&dt));
    
    let updated_ago = updated_date
        .as_ref()
        .and_then(|d| parse_date(d))
        .map(|dt| days_since(&dt));
    
    let expires_in = expiration_date
        .as_ref()
        .and_then(|d| parse_date(d))
        .map(|dt| days_until(&dt));
    
    (created_ago, updated_ago, expires_in)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc3339() {
        let result = parse_date("2024-01-15T10:30:00Z");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_iso_date() {
        let result = parse_date("2024-01-15");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_whois_format() {
        let result = parse_date("15-Jan-2024");
        assert!(result.is_some());
    }
}
