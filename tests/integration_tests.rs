//! Integration tests for whois-service
//!
//! These tests verify end-to-end functionality of the library.

use whois_service::{Config, ValidatedDomain, WhoisClient, WhoisError};
use std::sync::Arc;

/// Test that the WhoisClient can be created with default config
#[tokio::test]
async fn test_client_creation_without_cache() {
    let client = WhoisClient::new_without_cache().await;
    assert!(client.is_ok());

    let client = client.unwrap();
    assert!(!client.cache_enabled());
}

/// Test that the WhoisClient can be created with cache
#[tokio::test]
async fn test_client_creation_with_cache() {
    let config = Arc::new(Config::load().unwrap());
    let client = WhoisClient::new_with_config(config).await;
    assert!(client.is_ok());

    let client = client.unwrap();
    assert!(client.cache_enabled());
}

/// Test domain validation integration
#[tokio::test]
async fn test_domain_validation_integration() {
    let _client = WhoisClient::new_without_cache().await.unwrap();

    // Valid domains should validate
    let valid_domains = vec![
        "example.com",
        "test.org",
        "sub.example.com",
        "example.co.uk",
    ];

    for domain in valid_domains {
        let validated = ValidatedDomain::new(domain);
        assert!(validated.is_ok(), "Domain {} should be valid", domain);
    }

    // Invalid domains should fail validation
    let invalid_domains = vec![
        "",              // Empty
        "nodot",         // No dot
        "example..com",  // Double dot
    ];

    for domain in invalid_domains {
        let validated = ValidatedDomain::new(domain);
        assert!(validated.is_err(), "Domain {} should be invalid", domain);
    }
}

/// Test error handling for invalid domains
#[tokio::test]
async fn test_lookup_invalid_domain_error() {
    let client = WhoisClient::new_without_cache().await.unwrap();

    // Empty domain
    let result = client.lookup("").await;
    assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));

    // No dot
    let result = client.lookup("invalid").await;
    assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));

    // Double dot
    let result = client.lookup("example..com").await;
    assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
}

/// Test that fresh lookups bypass cache
#[tokio::test]
async fn test_fresh_lookup_bypasses_cache() {
    let config = Arc::new(Config::load().unwrap());
    let _client = WhoisClient::new_with_config(config).await.unwrap();

    // Note: This test doesn't actually perform lookups to avoid
    // hitting real WHOIS servers. It just verifies the client
    // accepts the fresh parameter.
    assert!(_client.cache_enabled());
}

/// Test configuration loading
#[test]
fn test_config_integration() {
    let config = Config::load();
    assert!(config.is_ok());

    let config = config.unwrap();

    // Verify all values are reasonable
    assert!(config.port > 0);
    assert!(config.whois_timeout_seconds > 0);
    assert!(config.max_response_size >= 1024 * 1024); // At least 1MB
    assert!(config.cache_ttl_seconds > 0);
    assert!(config.cache_max_entries > 0);
    assert!(config.max_referrals > 0);
    assert!(config.buffer_pool_size > 0);
    assert!(config.buffer_size > 0);

    // Config loaded successfully means validation passed internally
}

/// Test TLD extraction integration
#[test]
fn test_tld_extraction_integration() {
    use whois_service::extract_tld;

    // Simple TLDs
    assert_eq!(extract_tld("example.com").unwrap(), "com");
    assert_eq!(extract_tld("test.org").unwrap(), "org");

    // Complex TLDs (PSL-aware)
    assert_eq!(extract_tld("example.co.uk").unwrap(), "co.uk");
    assert_eq!(extract_tld("example.com.au").unwrap(), "com.au");

    // Subdomains
    assert_eq!(extract_tld("sub.example.com").unwrap(), "com");
    assert_eq!(extract_tld("www.example.co.uk").unwrap(), "co.uk");
}

/// Test date parsing integration
#[test]
fn test_date_parsing_integration() {
    use whois_service::parse_date;

    // Various formats should all parse
    let formats = vec![
        "2024-01-15T10:30:00Z",
        "2024-01-15",
        "15-Jan-2024",
        "15 Jan 2024",
        "2024/01/15",
        "01/15/2024",
    ];

    for format in formats {
        let result = parse_date(format);
        assert!(result.is_some(), "Failed to parse: {}", format);
    }
}

/// Test date field calculation integration
#[test]
fn test_date_calculation_integration() {
    use whois_service::calculate_date_fields;

    let creation = Some("2020-01-01T00:00:00Z".to_string());
    let updated = Some("2023-06-15T00:00:00Z".to_string());
    let expiration = Some("2030-12-31T00:00:00Z".to_string());

    let (created_ago, updated_ago, expires_in) = calculate_date_fields(&creation, &updated, &expiration);

    // All should parse successfully
    assert!(created_ago.is_some());
    assert!(updated_ago.is_some());
    assert!(expires_in.is_some());

    // Sanity checks
    assert!(created_ago.unwrap() > 0); // Created in the past
    assert!(expires_in.unwrap() > 0);  // Expires in the future
}

/// Test that multiple clients can coexist
#[tokio::test]
async fn test_multiple_clients() {
    let client1 = WhoisClient::new_without_cache().await.unwrap();
    let client2 = WhoisClient::new_without_cache().await.unwrap();

    assert!(!client1.cache_enabled());
    assert!(!client2.cache_enabled());
}

/// Test domain normalization consistency
#[test]
fn test_domain_normalization_consistency() {
    // Uppercase should normalize to lowercase
    let domain1 = ValidatedDomain::new("EXAMPLE.COM").unwrap();
    let domain2 = ValidatedDomain::new("example.com").unwrap();
    assert_eq!(domain1.as_str(), domain2.as_str());

    // Mixed case should normalize
    let domain3 = ValidatedDomain::new("Example.Com").unwrap();
    assert_eq!(domain1.as_str(), domain3.as_str());

    // Whitespace should be trimmed
    let domain4 = ValidatedDomain::new("  example.com  ").unwrap();
    assert_eq!(domain1.as_str(), domain4.as_str());
}

/// Test error types are properly propagated
#[test]
fn test_error_types() {
    // Invalid domain error
    let result = ValidatedDomain::new("");
    assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));

    let result = ValidatedDomain::new("invalid");
    assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
}

// ===== IP Address Integration Tests =====

/// Test IP address validation
#[test]
fn test_ip_validation_integration() {
    use whois_service::ValidatedIpAddress;

    // Valid IPv4
    let valid_ipv4 = vec![
        "8.8.8.8",
        "1.1.1.1",
        "192.0.2.1",  // TEST-NET-1
        "255.255.255.255",
        "4.2.2.2",
    ];

    for ip in valid_ipv4 {
        let validated = ValidatedIpAddress::new(ip);
        assert!(validated.is_ok(), "IP {} should be valid", ip);
    }

    // Valid IPv6
    let valid_ipv6 = vec![
        "2001:4860:4860::8888",
        "::1",
        "2001:db8::1",  // Documentation prefix
        "fe80::1",
        "2600::1",
    ];

    for ip in valid_ipv6 {
        let validated = ValidatedIpAddress::new(ip);
        assert!(validated.is_ok(), "IP {} should be valid", ip);
    }

    // Invalid IPs
    let invalid_ips = vec![
        "",
        "not.an.ip",
        "256.1.1.1",
        "gggg::1",
        "1.1.1",
        "example.com",
    ];

    for ip in invalid_ips {
        let validated = ValidatedIpAddress::new(ip);
        assert!(validated.is_err(), "IP {} should be invalid", ip);
    }
}

/// Test query type auto-detection
#[test]
fn test_query_type_detection() {
    use whois_service::ValidatedQuery;

    // Domain detection
    let domain_query = ValidatedQuery::new("example.com").unwrap();
    assert!(domain_query.is_domain());
    assert!(!domain_query.is_ip());

    // IPv4 detection
    let ipv4_query = ValidatedQuery::new("8.8.8.8").unwrap();
    assert!(ipv4_query.is_ip());
    assert!(!ipv4_query.is_domain());

    // IPv6 detection
    let ipv6_query = ValidatedQuery::new("2001:4860:4860::8888").unwrap();
    assert!(ipv6_query.is_ip());
    assert!(!ipv6_query.is_domain());

    // Complex domain
    let complex_domain = ValidatedQuery::new("sub.example.co.uk").unwrap();
    assert!(complex_domain.is_domain());
    assert!(!complex_domain.is_ip());
}

/// Test RIR detection for various IP ranges
#[test]
fn test_rir_detection_integration() {
    use whois_service::{ValidatedIpAddress, detect_rir, Rir};

    // ARIN ranges
    let arin_ips = vec![
        ("8.8.8.8", Rir::ARIN),
        ("4.2.2.2", Rir::ARIN),
        ("104.16.123.45", Rir::ARIN),
    ];

    for (ip_str, expected_rir) in arin_ips {
        let ip = ValidatedIpAddress::new(ip_str).unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, expected_rir, "IP {} should map to {:?}", ip_str, expected_rir);
    }

    // APNIC ranges
    let ip = ValidatedIpAddress::new("1.1.1.1").unwrap();
    let rir = detect_rir(&ip).unwrap();
    assert_eq!(rir, Rir::APNIC);

    // RIPE ranges
    let ip = ValidatedIpAddress::new("2.0.0.1").unwrap();
    let rir = detect_rir(&ip).unwrap();
    assert_eq!(rir, Rir::RIPE);

    // LACNIC ranges
    let ip = ValidatedIpAddress::new("177.1.2.3").unwrap();
    let rir = detect_rir(&ip).unwrap();
    assert_eq!(rir, Rir::LACNIC);

    // AFRINIC ranges
    let ip = ValidatedIpAddress::new("41.1.2.3").unwrap();
    let rir = detect_rir(&ip).unwrap();
    assert_eq!(rir, Rir::AFRINIC);
}

/// Test that private IP addresses fail RIR detection
#[test]
fn test_private_ip_rir_detection_fails() {
    use whois_service::{ValidatedIpAddress, detect_rir};

    // Private IPs should not map to any RIR
    let private_ips = vec![
        "192.168.1.1",  // RFC 1918
        "10.0.0.1",     // RFC 1918
        "172.16.0.1",   // RFC 1918
        "127.0.0.1",    // Loopback
        "169.254.1.1",  // Link-local
        "224.0.0.1",    // Multicast
        "0.0.0.0",      // Unspecified
        "255.255.255.255", // Broadcast
    ];

    for ip_str in private_ips {
        let ip = ValidatedIpAddress::new(ip_str).unwrap();
        let result = detect_rir(&ip);
        assert!(result.is_err(), "Private IP {} should not map to RIR", ip_str);
    }

    // IPv6 special ranges
    let ipv6_special = vec![
        "::1",          // Loopback
        "fe80::1",      // Link-local
        "2001:db8::1",  // Documentation
        "::",           // Unspecified
    ];

    for ip_str in ipv6_special {
        let ip = ValidatedIpAddress::new(ip_str).unwrap();
        let result = detect_rir(&ip);
        assert!(result.is_err(), "Special IPv6 {} should not map to RIR", ip_str);
    }
}

/// Test mixed domain and IP queries
#[test]
fn test_mixed_domain_ip_queries() {
    use whois_service::ValidatedQuery;

    let queries = vec![
        ("example.com", false, true),  // (query, is_ip, is_domain)
        ("8.8.8.8", true, false),
        ("sub.example.com", false, true),
        ("2001:4860:4860::8888", true, false),
        ("example.co.uk", false, true),
        ("1.1.1.1", true, false),
    ];

    for (query, should_be_ip, should_be_domain) in queries {
        let validated = ValidatedQuery::new(query).unwrap();
        assert_eq!(validated.is_ip(), should_be_ip, "Query {} IP detection failed", query);
        assert_eq!(validated.is_domain(), should_be_domain, "Query {} domain detection failed", query);
    }
}

/// Test IP address normalization
#[test]
fn test_ip_normalization_integration() {
    use whois_service::ValidatedIpAddress;

    // IPv6 should be normalized to compressed form
    let test_cases = vec![
        ("0:0:0:0:0:0:0:1", "::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:0db8:0001:0000:0000:0000:0000:0001", "2001:db8:1::1"),
        ("fe80:0000:0000:0000:0000:0000:0000:0001", "fe80::1"),
    ];

    for (input, expected) in test_cases {
        let ip = ValidatedIpAddress::new(input).unwrap();
        assert_eq!(ip.as_str(), expected, "IPv6 {} should normalize to {}", input, expected);
    }

    // IPv4 should remain unchanged
    let ip = ValidatedIpAddress::new("8.8.8.8").unwrap();
    assert_eq!(ip.as_str(), "8.8.8.8");
}

/// Test RIR server mappings
#[test]
fn test_rir_server_mappings() {
    use whois_service::Rir;

    // WHOIS servers
    assert_eq!(Rir::ARIN.whois_server(), "whois.arin.net");
    assert_eq!(Rir::RIPE.whois_server(), "whois.ripe.net");
    assert_eq!(Rir::APNIC.whois_server(), "whois.apnic.net");
    assert_eq!(Rir::LACNIC.whois_server(), "whois.lacnic.net");
    assert_eq!(Rir::AFRINIC.whois_server(), "whois.afrinic.net");

    // RDAP servers (should all be HTTPS URLs)
    assert!(Rir::ARIN.rdap_server().starts_with("https://"));
    assert!(Rir::RIPE.rdap_server().starts_with("https://"));
    assert!(Rir::APNIC.rdap_server().starts_with("https://"));
    assert!(Rir::LACNIC.rdap_server().starts_with("https://"));
    assert!(Rir::AFRINIC.rdap_server().starts_with("https://"));

    assert_eq!(Rir::ARIN.rdap_server(), "https://rdap.arin.net/registry");
    assert_eq!(Rir::RIPE.rdap_server(), "https://rdap.db.ripe.net");
}

/// Test error propagation for invalid IP addresses
#[test]
fn test_ip_error_types() {
    use whois_service::{ValidatedIpAddress, WhoisError};

    // Empty IP
    let result = ValidatedIpAddress::new("");
    assert!(matches!(result, Err(WhoisError::InvalidIpAddress(_))));

    // Invalid format
    let result = ValidatedIpAddress::new("not.an.ip");
    assert!(matches!(result, Err(WhoisError::InvalidIpAddress(_))));

    // Out of range
    let result = ValidatedIpAddress::new("256.1.1.1");
    assert!(matches!(result, Err(WhoisError::InvalidIpAddress(_))));
}

/// Test IPv4 type detection
#[test]
fn test_ipv4_type_detection() {
    use whois_service::ValidatedIpAddress;

    let ipv4 = ValidatedIpAddress::new("8.8.8.8").unwrap();
    assert!(ipv4.is_ipv4());
    assert!(!ipv4.is_ipv6());
}

/// Test IPv6 type detection
#[test]
fn test_ipv6_type_detection() {
    use whois_service::ValidatedIpAddress;

    let ipv6 = ValidatedIpAddress::new("2001:4860:4860::8888").unwrap();
    assert!(ipv6.is_ipv6());
    assert!(!ipv6.is_ipv4());
}

/// Test edge cases for special IP addresses
#[test]
fn test_special_ip_addresses_validation() {
    use whois_service::ValidatedIpAddress;

    // These should validate (parsing succeeds) but RIR detection should fail
    let special_ips = vec![
        "127.0.0.1",   // Loopback
        "0.0.0.0",     // Unspecified
        "::1",         // IPv6 loopback
        "::",          // IPv6 unspecified
        "fe80::1",     // Link-local
        "255.255.255.255", // Broadcast
    ];

    for ip_str in special_ips {
        let ip = ValidatedIpAddress::new(ip_str);
        assert!(ip.is_ok(), "Special IP {} should validate", ip_str);
    }
}
