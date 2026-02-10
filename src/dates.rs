//! Date parsing and calculation utilities
//!
//! Provides shared date handling for WHOIS and RDAP responses.
//!
//! Uses the `dateparser` crate for comprehensive format support with
//! chrono fallback for WHOIS-specific formats.

use chrono::{DateTime, NaiveDate, Utc};

/// Parse various date formats commonly found in WHOIS/RDAP data.
///
/// Primary parsing via `dateparser` crate which handles:
/// - ISO 8601: "2024-01-15T10:30:00Z"
/// - RFC 3339: "2024-01-15T10:30:00+00:00"
/// - RFC 2822: "Mon, 15 Jan 2024 10:30:00 +0000"
/// - Unix timestamps: "1705317000"
/// - Common formats: "2024/01/15", "01/15/2024"
/// - PostgreSQL: "2024-01-15 10:30:00.123456"
///
/// Fallback to chrono for WHOIS-specific formats:
/// - "15-Jan-2024" (dd-Mmm-yyyy)
/// - "15 Jan 2024" (dd Mmm yyyy)
/// - "18.05.2025" (dd.mm.yyyy)
pub fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    let date_str = date_str.trim();

    // Try dateparser first (handles most formats)
    if let Ok(dt) = dateparser::parse(date_str) {
        return Some(dt);
    }

    // Fallback to chrono for WHOIS-specific formats that dateparser might miss
    const WHOIS_DATE_FORMATS: &[&str] = &[
        "%d-%b-%Y",      // 15-Jan-2024 (common in WHOIS)
        "%d %b %Y",      // 15 Jan 2024
        "%d.%m.%Y",      // 18.05.2025
        "%Y.%m.%d",      // 2025.05.18
    ];

    for format in WHOIS_DATE_FORMATS {
        if let Ok(naive_date) = NaiveDate::parse_from_str(date_str, format) {
            if let Some(naive_dt) = naive_date.and_hms_opt(0, 0, 0) {
                return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
            }
        }
    }

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

        // With timezone offset
        let result = parse_date("2024-01-15T10:30:00+00:00");
        assert!(result.is_some());

        let result = parse_date("2024-01-15T10:30:00-05:00");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_iso_date() {
        let result = parse_date("2024-01-15");
        assert!(result.is_some());

        // ISO with time and Z
        let result = parse_date("2024-01-15T10:30:00Z");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_whois_format() {
        // dd-Mmm-yyyy format (common in WHOIS)
        let result = parse_date("15-Jan-2024");
        assert!(result.is_some());

        let result = parse_date("01-Dec-2023");
        assert!(result.is_some());

        let result = parse_date("31-Mar-2025");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_various_formats() {
        // dd Mmm yyyy (space separated)
        assert!(parse_date("15 Jan 2024").is_some());

        // dd.mm.yyyy (European format)
        assert!(parse_date("15.01.2024").is_some());

        // yyyy.mm.dd
        assert!(parse_date("2024.01.15").is_some());

        // Slash formats (handled by dateparser)
        assert!(parse_date("2024/01/15").is_some());
        assert!(parse_date("01/15/2024").is_some());

        // With full month name
        assert!(parse_date("15 January 2024").is_some());
        assert!(parse_date("January 15, 2024").is_some());
    }

    #[test]
    fn test_parse_with_time() {
        // ISO 8601 with fractional seconds
        assert!(parse_date("2024-01-15T10:30:00.123Z").is_some());
        assert!(parse_date("2024-01-15T10:30:00.123456Z").is_some());

        // Space-separated datetime
        assert!(parse_date("2024-01-15 10:30:00").is_some());
    }

    #[test]
    fn test_parse_edge_cases() {
        // Leap year
        assert!(parse_date("2024-02-29").is_some());

        // End of year
        assert!(parse_date("2024-12-31").is_some());

        // Start of year
        assert!(parse_date("2024-01-01").is_some());

        // With leading/trailing whitespace
        assert!(parse_date("  2024-01-15  ").is_some());
        assert!(parse_date("\t2024-01-15\n").is_some());
    }

    #[test]
    fn test_parse_unix_timestamp() {
        // Unix timestamps (handled by dateparser)
        assert!(parse_date("1705317000").is_some());
        // Note: "0" alone may not parse as a timestamp in all contexts
        // It could be ambiguous. Use explicit formats for epoch.
    }

    #[test]
    fn test_parse_invalid_dates() {
        // Invalid formats
        assert!(parse_date("not-a-date").is_none());
        assert!(parse_date("").is_none());
        assert!(parse_date("   ").is_none());

        // Invalid dates
        assert!(parse_date("2024-02-30").is_none()); // Feb 30 doesn't exist
        assert!(parse_date("2024-13-01").is_none()); // Month 13 doesn't exist
        assert!(parse_date("2024-00-01").is_none()); // Month 0 doesn't exist

        // Non-leap year Feb 29
        assert!(parse_date("2023-02-29").is_none());
    }

    #[test]
    fn test_days_since() {
        // Date in the past
        let past_date = Utc::now() - chrono::Duration::days(10);
        let days = days_since(&past_date);
        assert_eq!(days, 10);

        // Date in the future (negative)
        let future_date = Utc::now() + chrono::Duration::days(5);
        let days = days_since(&future_date);
        // Allow for day boundary race conditions
        assert!(days >= -5 && days <= -4);

        // Today
        let today = Utc::now();
        let days = days_since(&today);
        assert_eq!(days, 0);
    }

    #[test]
    fn test_days_until() {
        // Date in the future
        let future_date = Utc::now() + chrono::Duration::days(10);
        let days = days_until(&future_date);
        // Allow for day boundary race conditions (9-10 days is acceptable)
        assert!(days >= 9 && days <= 10);

        // Date in the past (negative)
        let past_date = Utc::now() - chrono::Duration::days(5);
        let days = days_until(&past_date);
        // Allow for day boundary race conditions
        assert!(days >= -5 && days <= -4);

        // Today
        let today = Utc::now();
        let days = days_until(&today);
        assert_eq!(days, 0);
    }

    #[test]
    fn test_calculate_date_fields() {
        let creation = Some("2020-01-01T00:00:00Z".to_string());
        let updated = Some("2023-06-15T00:00:00Z".to_string());
        let expiration = Some("2030-12-31T00:00:00Z".to_string());

        let (created_ago, updated_ago, expires_in) = calculate_date_fields(&creation, &updated, &expiration);

        // Should all be Some
        assert!(created_ago.is_some());
        assert!(updated_ago.is_some());
        assert!(expires_in.is_some());

        // Created should be positive (in the past)
        assert!(created_ago.unwrap() > 0);

        // Expires should be positive (in the future)
        assert!(expires_in.unwrap() > 0);
    }

    #[test]
    fn test_calculate_date_fields_with_none() {
        let (created_ago, updated_ago, expires_in) = calculate_date_fields(&None, &None, &None);

        assert!(created_ago.is_none());
        assert!(updated_ago.is_none());
        assert!(expires_in.is_none());
    }

    #[test]
    fn test_calculate_date_fields_invalid_dates() {
        let invalid = Some("not-a-date".to_string());

        let (created_ago, updated_ago, expires_in) = calculate_date_fields(&invalid, &invalid, &invalid);

        // Should all be None for invalid dates
        assert!(created_ago.is_none());
        assert!(updated_ago.is_none());
        assert!(expires_in.is_none());
    }
}
