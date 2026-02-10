//! IP address validation and RIR (Regional Internet Registry) detection
//!
//! This module provides IP address validation for both IPv4 and IPv6, and determines
//! which Regional Internet Registry (RIR) is responsible for a given IP address.
//!
//! The five RIRs are:
//! - ARIN: North America
//! - RIPE NCC: Europe, Middle East, Central Asia
//! - APNIC: Asia-Pacific
//! - LACNIC: Latin America and Caribbean
//! - AFRINIC: Africa

use crate::errors::WhoisError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// Validated IP address (IPv4 or IPv6)
///
/// This type ensures that IP addresses are properly validated and normalized
/// before being used in WHOIS/RDAP lookups.
///
/// # Examples
///
/// ```
/// use whois_service::ValidatedIpAddress;
///
/// // IPv4
/// let ip = ValidatedIpAddress::new("8.8.8.8").unwrap();
/// assert_eq!(ip.as_str(), "8.8.8.8");
///
/// // IPv6 (automatically normalized)
/// let ip = ValidatedIpAddress::new("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
/// assert_eq!(ip.as_str(), "2001:db8::1");
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedIpAddress {
    addr: IpAddr,
    normalized: String,
}

impl ValidatedIpAddress {
    /// Create a new validated IP address
    ///
    /// Validates and normalizes the IP address. IPv6 addresses are normalized
    /// to their canonical form (e.g., `::1` instead of `0:0:0:0:0:0:0:1`).
    ///
    /// # Errors
    ///
    /// Returns `WhoisError::InvalidIpAddress` if the input is not a valid IPv4 or IPv6 address.
    pub fn new(ip: impl Into<String>) -> Result<Self, WhoisError> {
        let ip_str = ip.into().trim().to_string();

        // Parse using std::net::IpAddr (handles both IPv4 and IPv6)
        let addr: IpAddr = ip_str.parse()
            .map_err(|_| WhoisError::InvalidIpAddress(
                format!("Invalid IP address: {}", ip_str)
            ))?;

        // Normalize to canonical form
        let normalized = addr.to_string();

        debug!("Validated IP address: {} -> {}", ip_str, normalized);

        Ok(Self { addr, normalized })
    }

    /// Get the validated IP address as a string
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        self.normalized
    }

    /// Get the underlying IpAddr
    pub fn addr(&self) -> &IpAddr {
        &self.addr
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }
}

impl AsRef<str> for ValidatedIpAddress {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Display for ValidatedIpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

/// Regional Internet Registry
///
/// The five RIRs responsible for IP address allocation worldwide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rir {
    /// American Registry for Internet Numbers (North America)
    ARIN,
    /// Réseaux IP Européens Network Coordination Centre (Europe, Middle East, Central Asia)
    RIPE,
    /// Asia-Pacific Network Information Centre
    APNIC,
    /// Latin America and Caribbean Network Information Centre
    LACNIC,
    /// African Network Information Centre
    AFRINIC,
}

impl Rir {
    /// Get the WHOIS server for this RIR
    pub fn whois_server(&self) -> &'static str {
        match self {
            Rir::ARIN => "whois.arin.net",
            Rir::RIPE => "whois.ripe.net",
            Rir::APNIC => "whois.apnic.net",
            Rir::LACNIC => "whois.lacnic.net",
            Rir::AFRINIC => "whois.afrinic.net",
        }
    }

    /// Get the RDAP server for this RIR
    pub fn rdap_server(&self) -> &'static str {
        match self {
            Rir::ARIN => "https://rdap.arin.net/registry",
            Rir::RIPE => "https://rdap.db.ripe.net",
            Rir::APNIC => "https://rdap.apnic.net",
            Rir::LACNIC => "https://rdap.lacnic.net",
            Rir::AFRINIC => "https://rdap.afrinic.net/rdap",
        }
    }
}

/// IPv4 address range
#[derive(Debug, Clone)]
struct Ipv4Range {
    start: u32,
    end: u32,
}

/// IPv6 address range
#[derive(Debug, Clone)]
struct Ipv6Range {
    start: u128,
    end: u128,
}

impl Ipv4Range {
    fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }
}

impl Ipv6Range {
    fn contains(&self, ip: u128) -> bool {
        ip >= self.start && ip <= self.end
    }
}

/// Convert IPv4 address to u32
fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

/// Convert IPv6 address to u128
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

/// Create an IPv4 range from two addresses
fn ipv4_range(start: &str, end: &str) -> Ipv4Range {
    let start_addr: Ipv4Addr = start.parse().expect("Invalid start IPv4");
    let end_addr: Ipv4Addr = end.parse().expect("Invalid end IPv4");

    Ipv4Range {
        start: ipv4_to_u32(start_addr),
        end: ipv4_to_u32(end_addr),
    }
}

/// Create an IPv6 range from two addresses
fn ipv6_range(start: &str, end: &str) -> Ipv6Range {
    let start_addr: Ipv6Addr = start.parse().expect("Invalid start IPv6");
    let end_addr: Ipv6Addr = end.parse().expect("Invalid end IPv6");

    Ipv6Range {
        start: ipv6_to_u128(start_addr),
        end: ipv6_to_u128(end_addr),
    }
}

/// RIR IP range database
///
/// Contains hardcoded IP range allocations for fast RIR detection.
/// This is a simplified database with major allocations. In production,
/// this would be updated periodically from IANA registry data.
struct RirDatabase {
    ipv4_ranges: Vec<(Ipv4Range, Rir)>,
    ipv6_ranges: Vec<(Ipv6Range, Rir)>,
}

impl RirDatabase {
    fn new() -> Self {
        // Initialize with major RIR allocations
        // Source: IANA IPv4 and IPv6 registries
        // Note: This is a representative sample. A production system would include
        // the complete registry and update it periodically.

        let ipv4_ranges = vec![
            // ARIN (North America) - Major allocations
            (ipv4_range("3.0.0.0", "3.255.255.255"), Rir::ARIN),
            (ipv4_range("4.0.0.0", "4.255.255.255"), Rir::ARIN),
            (ipv4_range("6.0.0.0", "6.255.255.255"), Rir::ARIN),
            (ipv4_range("7.0.0.0", "7.255.255.255"), Rir::ARIN),
            (ipv4_range("8.0.0.0", "8.255.255.255"), Rir::ARIN),
            (ipv4_range("9.0.0.0", "9.255.255.255"), Rir::ARIN),
            (ipv4_range("11.0.0.0", "11.255.255.255"), Rir::ARIN),
            (ipv4_range("12.0.0.0", "12.255.255.255"), Rir::ARIN),
            (ipv4_range("13.0.0.0", "13.255.255.255"), Rir::ARIN),
            (ipv4_range("15.0.0.0", "15.255.255.255"), Rir::ARIN),
            (ipv4_range("16.0.0.0", "16.255.255.255"), Rir::ARIN),
            (ipv4_range("17.0.0.0", "17.255.255.255"), Rir::ARIN),
            (ipv4_range("18.0.0.0", "18.255.255.255"), Rir::ARIN),
            (ipv4_range("19.0.0.0", "19.255.255.255"), Rir::ARIN),
            (ipv4_range("20.0.0.0", "20.255.255.255"), Rir::ARIN),
            (ipv4_range("23.0.0.0", "23.255.255.255"), Rir::ARIN),
            (ipv4_range("24.0.0.0", "24.255.255.255"), Rir::ARIN),
            (ipv4_range("32.0.0.0", "32.255.255.255"), Rir::ARIN),
            (ipv4_range("33.0.0.0", "33.255.255.255"), Rir::ARIN),
            (ipv4_range("34.0.0.0", "34.255.255.255"), Rir::ARIN),
            (ipv4_range("35.0.0.0", "35.255.255.255"), Rir::ARIN),
            (ipv4_range("40.0.0.0", "40.255.255.255"), Rir::ARIN),
            (ipv4_range("44.0.0.0", "44.255.255.255"), Rir::ARIN),
            (ipv4_range("47.0.0.0", "47.255.255.255"), Rir::ARIN),
            (ipv4_range("48.0.0.0", "48.255.255.255"), Rir::ARIN),
            (ipv4_range("50.0.0.0", "50.255.255.255"), Rir::ARIN),
            (ipv4_range("52.0.0.0", "52.255.255.255"), Rir::ARIN),
            (ipv4_range("54.0.0.0", "54.255.255.255"), Rir::ARIN),
            (ipv4_range("55.0.0.0", "55.255.255.255"), Rir::ARIN),
            (ipv4_range("56.0.0.0", "56.255.255.255"), Rir::ARIN),
            (ipv4_range("63.0.0.0", "63.255.255.255"), Rir::ARIN),
            (ipv4_range("64.0.0.0", "64.255.255.255"), Rir::ARIN),
            (ipv4_range("65.0.0.0", "65.255.255.255"), Rir::ARIN),
            (ipv4_range("66.0.0.0", "66.255.255.255"), Rir::ARIN),
            (ipv4_range("67.0.0.0", "67.255.255.255"), Rir::ARIN),
            (ipv4_range("68.0.0.0", "68.255.255.255"), Rir::ARIN),
            (ipv4_range("69.0.0.0", "69.255.255.255"), Rir::ARIN),
            (ipv4_range("70.0.0.0", "70.255.255.255"), Rir::ARIN),
            (ipv4_range("71.0.0.0", "71.255.255.255"), Rir::ARIN),
            (ipv4_range("72.0.0.0", "72.255.255.255"), Rir::ARIN),
            (ipv4_range("73.0.0.0", "73.255.255.255"), Rir::ARIN),
            (ipv4_range("74.0.0.0", "74.255.255.255"), Rir::ARIN),
            (ipv4_range("75.0.0.0", "75.255.255.255"), Rir::ARIN),
            (ipv4_range("76.0.0.0", "76.255.255.255"), Rir::ARIN),
            (ipv4_range("96.0.0.0", "96.255.255.255"), Rir::ARIN),
            (ipv4_range("97.0.0.0", "97.255.255.255"), Rir::ARIN),
            (ipv4_range("98.0.0.0", "98.255.255.255"), Rir::ARIN),
            (ipv4_range("99.0.0.0", "99.255.255.255"), Rir::ARIN),
            (ipv4_range("100.0.0.0", "100.63.255.255"), Rir::ARIN),
            (ipv4_range("104.0.0.0", "104.255.255.255"), Rir::ARIN),
            (ipv4_range("107.0.0.0", "107.255.255.255"), Rir::ARIN),
            (ipv4_range("108.0.0.0", "108.255.255.255"), Rir::ARIN),

            // RIPE NCC (Europe, Middle East, Central Asia) - Major allocations
            (ipv4_range("2.0.0.0", "2.255.255.255"), Rir::RIPE),
            (ipv4_range("5.0.0.0", "5.255.255.255"), Rir::RIPE),
            (ipv4_range("25.0.0.0", "25.255.255.255"), Rir::RIPE),
            (ipv4_range("31.0.0.0", "31.255.255.255"), Rir::RIPE),
            (ipv4_range("37.0.0.0", "37.255.255.255"), Rir::RIPE),
            (ipv4_range("46.0.0.0", "46.255.255.255"), Rir::RIPE),
            (ipv4_range("51.0.0.0", "51.255.255.255"), Rir::RIPE),
            (ipv4_range("53.0.0.0", "53.255.255.255"), Rir::RIPE),
            (ipv4_range("62.0.0.0", "62.255.255.255"), Rir::RIPE),
            (ipv4_range("77.0.0.0", "77.255.255.255"), Rir::RIPE),
            (ipv4_range("78.0.0.0", "78.255.255.255"), Rir::RIPE),
            (ipv4_range("79.0.0.0", "79.255.255.255"), Rir::RIPE),
            (ipv4_range("80.0.0.0", "80.255.255.255"), Rir::RIPE),
            (ipv4_range("81.0.0.0", "81.255.255.255"), Rir::RIPE),
            (ipv4_range("82.0.0.0", "82.255.255.255"), Rir::RIPE),
            (ipv4_range("83.0.0.0", "83.255.255.255"), Rir::RIPE),
            (ipv4_range("84.0.0.0", "84.255.255.255"), Rir::RIPE),
            (ipv4_range("85.0.0.0", "85.255.255.255"), Rir::RIPE),
            (ipv4_range("86.0.0.0", "86.255.255.255"), Rir::RIPE),
            (ipv4_range("87.0.0.0", "87.255.255.255"), Rir::RIPE),
            (ipv4_range("88.0.0.0", "88.255.255.255"), Rir::RIPE),
            (ipv4_range("89.0.0.0", "89.255.255.255"), Rir::RIPE),
            (ipv4_range("90.0.0.0", "90.255.255.255"), Rir::RIPE),
            (ipv4_range("91.0.0.0", "91.255.255.255"), Rir::RIPE),
            (ipv4_range("92.0.0.0", "92.255.255.255"), Rir::RIPE),
            (ipv4_range("93.0.0.0", "93.255.255.255"), Rir::RIPE),
            (ipv4_range("94.0.0.0", "94.255.255.255"), Rir::RIPE),
            (ipv4_range("95.0.0.0", "95.255.255.255"), Rir::RIPE),
            (ipv4_range("109.0.0.0", "109.255.255.255"), Rir::RIPE),
            (ipv4_range("176.0.0.0", "176.255.255.255"), Rir::RIPE),
            (ipv4_range("178.0.0.0", "178.255.255.255"), Rir::RIPE),
            (ipv4_range("185.0.0.0", "185.255.255.255"), Rir::RIPE),
            (ipv4_range("188.0.0.0", "188.255.255.255"), Rir::RIPE),
            (ipv4_range("193.0.0.0", "193.255.255.255"), Rir::RIPE),
            (ipv4_range("194.0.0.0", "194.255.255.255"), Rir::RIPE),
            (ipv4_range("195.0.0.0", "195.255.255.255"), Rir::RIPE),
            (ipv4_range("212.0.0.0", "212.255.255.255"), Rir::RIPE),
            (ipv4_range("213.0.0.0", "213.255.255.255"), Rir::RIPE),
            (ipv4_range("217.0.0.0", "217.255.255.255"), Rir::RIPE),

            // APNIC (Asia-Pacific) - Major allocations
            (ipv4_range("1.0.0.0", "1.255.255.255"), Rir::APNIC),
            (ipv4_range("14.0.0.0", "14.255.255.255"), Rir::APNIC),
            (ipv4_range("27.0.0.0", "27.255.255.255"), Rir::APNIC),
            (ipv4_range("36.0.0.0", "36.255.255.255"), Rir::APNIC),
            (ipv4_range("39.0.0.0", "39.255.255.255"), Rir::APNIC),
            (ipv4_range("42.0.0.0", "42.255.255.255"), Rir::APNIC),
            (ipv4_range("43.0.0.0", "43.255.255.255"), Rir::APNIC),
            (ipv4_range("49.0.0.0", "49.255.255.255"), Rir::APNIC),
            (ipv4_range("58.0.0.0", "58.255.255.255"), Rir::APNIC),
            (ipv4_range("59.0.0.0", "59.255.255.255"), Rir::APNIC),
            (ipv4_range("60.0.0.0", "60.255.255.255"), Rir::APNIC),
            (ipv4_range("61.0.0.0", "61.255.255.255"), Rir::APNIC),
            (ipv4_range("101.0.0.0", "101.255.255.255"), Rir::APNIC),
            (ipv4_range("103.0.0.0", "103.255.255.255"), Rir::APNIC),
            (ipv4_range("106.0.0.0", "106.255.255.255"), Rir::APNIC),
            (ipv4_range("110.0.0.0", "110.255.255.255"), Rir::APNIC),
            (ipv4_range("111.0.0.0", "111.255.255.255"), Rir::APNIC),
            (ipv4_range("112.0.0.0", "112.255.255.255"), Rir::APNIC),
            (ipv4_range("113.0.0.0", "113.255.255.255"), Rir::APNIC),
            (ipv4_range("114.0.0.0", "114.255.255.255"), Rir::APNIC),
            (ipv4_range("115.0.0.0", "115.255.255.255"), Rir::APNIC),
            (ipv4_range("116.0.0.0", "116.255.255.255"), Rir::APNIC),
            (ipv4_range("117.0.0.0", "117.255.255.255"), Rir::APNIC),
            (ipv4_range("118.0.0.0", "118.255.255.255"), Rir::APNIC),
            (ipv4_range("119.0.0.0", "119.255.255.255"), Rir::APNIC),
            (ipv4_range("120.0.0.0", "120.255.255.255"), Rir::APNIC),
            (ipv4_range("121.0.0.0", "121.255.255.255"), Rir::APNIC),
            (ipv4_range("122.0.0.0", "122.255.255.255"), Rir::APNIC),
            (ipv4_range("123.0.0.0", "123.255.255.255"), Rir::APNIC),
            (ipv4_range("124.0.0.0", "124.255.255.255"), Rir::APNIC),
            (ipv4_range("125.0.0.0", "125.255.255.255"), Rir::APNIC),
            (ipv4_range("126.0.0.0", "126.255.255.255"), Rir::APNIC),
            (ipv4_range("133.0.0.0", "133.255.255.255"), Rir::APNIC),
            (ipv4_range("150.0.0.0", "150.255.255.255"), Rir::APNIC),
            (ipv4_range("153.0.0.0", "153.255.255.255"), Rir::APNIC),
            (ipv4_range("163.0.0.0", "163.255.255.255"), Rir::APNIC),
            (ipv4_range("202.0.0.0", "202.255.255.255"), Rir::APNIC),
            (ipv4_range("203.0.0.0", "203.255.255.255"), Rir::APNIC),
            (ipv4_range("210.0.0.0", "210.255.255.255"), Rir::APNIC),
            (ipv4_range("211.0.0.0", "211.255.255.255"), Rir::APNIC),
            (ipv4_range("218.0.0.0", "218.255.255.255"), Rir::APNIC),
            (ipv4_range("219.0.0.0", "219.255.255.255"), Rir::APNIC),
            (ipv4_range("220.0.0.0", "220.255.255.255"), Rir::APNIC),
            (ipv4_range("221.0.0.0", "221.255.255.255"), Rir::APNIC),
            (ipv4_range("222.0.0.0", "222.255.255.255"), Rir::APNIC),
            (ipv4_range("223.0.0.0", "223.255.255.255"), Rir::APNIC),

            // LACNIC (Latin America and Caribbean) - Major allocations
            (ipv4_range("177.0.0.0", "177.255.255.255"), Rir::LACNIC),
            (ipv4_range("179.0.0.0", "179.255.255.255"), Rir::LACNIC),
            (ipv4_range("181.0.0.0", "181.255.255.255"), Rir::LACNIC),
            (ipv4_range("186.0.0.0", "186.255.255.255"), Rir::LACNIC),
            (ipv4_range("187.0.0.0", "187.255.255.255"), Rir::LACNIC),
            (ipv4_range("189.0.0.0", "189.255.255.255"), Rir::LACNIC),
            (ipv4_range("190.0.0.0", "190.255.255.255"), Rir::LACNIC),
            (ipv4_range("191.0.0.0", "191.255.255.255"), Rir::LACNIC),
            (ipv4_range("200.0.0.0", "200.255.255.255"), Rir::LACNIC),
            (ipv4_range("201.0.0.0", "201.255.255.255"), Rir::LACNIC),

            // AFRINIC (Africa) - Major allocations
            (ipv4_range("41.0.0.0", "41.255.255.255"), Rir::AFRINIC),
            (ipv4_range("102.0.0.0", "102.255.255.255"), Rir::AFRINIC),
            (ipv4_range("105.0.0.0", "105.255.255.255"), Rir::AFRINIC),
            (ipv4_range("154.0.0.0", "154.255.255.255"), Rir::AFRINIC),
            (ipv4_range("196.0.0.0", "196.255.255.255"), Rir::AFRINIC),
            (ipv4_range("197.0.0.0", "197.255.255.255"), Rir::AFRINIC),
        ];

        let ipv6_ranges = vec![
            // ARIN IPv6 allocations
            (ipv6_range("2001:400::", "2001:7ff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::ARIN),
            (ipv6_range("2600::", "26ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::ARIN),
            (ipv6_range("2610::", "261f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::ARIN),
            (ipv6_range("2620::", "262f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::ARIN),

            // RIPE IPv6 allocations
            (ipv6_range("2001:600::", "2001:7ff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::RIPE),
            (ipv6_range("2a00::", "2aff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::RIPE),

            // APNIC IPv6 allocations
            (ipv6_range("2001:200::", "2001:3ff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::APNIC),
            (ipv6_range("2400::", "24ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::APNIC),
            (ipv6_range("2001:c00::", "2001:dff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::APNIC),

            // LACNIC IPv6 allocations
            (ipv6_range("2800::", "28ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::LACNIC),
            (ipv6_range("2801::", "2801:1ff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::LACNIC),

            // AFRINIC IPv6 allocations
            (ipv6_range("2001:4200::", "2001:43ff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::AFRINIC),
            (ipv6_range("2c00::", "2cff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Rir::AFRINIC),
        ];

        Self {
            ipv4_ranges,
            ipv6_ranges,
        }
    }

    /// Detect which RIR is responsible for the given IP address
    fn detect_rir(&self, ip: &IpAddr) -> Option<Rir> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_num = ipv4_to_u32(*ipv4);

                // Linear search (good enough for ~100 ranges, O(n) but n is small)
                // Future optimization: binary search on sorted ranges
                for (range, rir) in &self.ipv4_ranges {
                    if range.contains(ip_num) {
                        return Some(rir.clone());
                    }
                }
                None
            }
            IpAddr::V6(ipv6) => {
                let ip_num = ipv6_to_u128(*ipv6);

                for (range, rir) in &self.ipv6_ranges {
                    if range.contains(ip_num) {
                        return Some(rir.clone());
                    }
                }
                None
            }
        }
    }
}

/// Detect which RIR (Regional Internet Registry) is responsible for an IP address
///
/// This function determines which of the five RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
/// is responsible for the given IP address based on allocation data.
///
/// # Errors
///
/// Returns `WhoisError::UnsupportedIpAddress` if:
/// - The IP is in a private range (RFC 1918, RFC 4193)
/// - The IP is in a special-use range (loopback, link-local, etc.)
/// - The IP is not allocated to any known RIR
///
/// # Examples
///
/// ```
/// use whois_service::{ValidatedIpAddress, detect_rir, Rir};
///
/// // Google DNS (ARIN)
/// let ip = ValidatedIpAddress::new("8.8.8.8").unwrap();
/// let rir = detect_rir(&ip).unwrap();
/// assert_eq!(rir, Rir::ARIN);
/// ```
pub fn detect_rir(ip: &ValidatedIpAddress) -> Result<Rir, WhoisError> {
    use once_cell::sync::Lazy;

    static RIR_DB: Lazy<RirDatabase> = Lazy::new(RirDatabase::new);

    // Check for private/special IP ranges first
    if is_private_or_special(ip.addr()) {
        return Err(WhoisError::UnsupportedIpAddress(
            format!("IP address {} is in a private or special-use range", ip.as_str())
        ));
    }

    // Look up in RIR database
    RIR_DB.detect_rir(ip.addr())
        .ok_or_else(|| WhoisError::UnsupportedIpAddress(
            format!("Could not determine RIR for IP: {}", ip.as_str())
        ))
}

/// Check if an IP address is in a private or special-use range
fn is_private_or_special(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            // RFC 1918 private ranges
            ipv4.is_private() ||
            // Loopback
            ipv4.is_loopback() ||
            // Link-local
            ipv4.is_link_local() ||
            // Documentation ranges (RFC 5737)
            ipv4.is_documentation() ||
            // Broadcast
            ipv4.is_broadcast() ||
            // Multicast
            ipv4.is_multicast() ||
            // Unspecified
            ipv4.is_unspecified() ||
            // Shared address space (RFC 6598) - 100.64.0.0/10
            (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(ipv6) => {
            // RFC 4193 unique local addresses
            // Loopback
            ipv6.is_loopback() ||
            // Multicast
            ipv6.is_multicast() ||
            // Unspecified
            ipv6.is_unspecified() ||
            // Unique local (fc00::/7)
            (ipv6.segments()[0] & 0xfe00) == 0xfc00 ||
            // Link-local (fe80::/10)
            (ipv6.segments()[0] & 0xffc0) == 0xfe80 ||
            // Documentation (2001:db8::/32)
            (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== IP Validation Tests =====

    #[test]
    fn test_valid_ipv4() {
        assert!(ValidatedIpAddress::new("8.8.8.8").is_ok());
        assert!(ValidatedIpAddress::new("1.1.1.1").is_ok());
        assert!(ValidatedIpAddress::new("255.255.255.255").is_ok());
        assert!(ValidatedIpAddress::new("0.0.0.0").is_ok());
        assert!(ValidatedIpAddress::new("192.0.2.1").is_ok());  // TEST-NET-1
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(ValidatedIpAddress::new("2001:4860:4860::8888").is_ok());
        assert!(ValidatedIpAddress::new("::1").is_ok());
        assert!(ValidatedIpAddress::new("fe80::1").is_ok());
        assert!(ValidatedIpAddress::new("2001:db8::1").is_ok());
        assert!(ValidatedIpAddress::new("::").is_ok());  // All zeros
        assert!(ValidatedIpAddress::new("2a00:1450:4001:814::200e").is_ok());
    }

    #[test]
    fn test_invalid_ip() {
        assert!(ValidatedIpAddress::new("").is_err());
        assert!(ValidatedIpAddress::new("not.an.ip").is_err());
        assert!(ValidatedIpAddress::new("256.1.1.1").is_err());  // Out of range
        assert!(ValidatedIpAddress::new("1.1.1").is_err());  // Incomplete
        assert!(ValidatedIpAddress::new("1.1.1.1.1").is_err());  // Too many octets
        assert!(ValidatedIpAddress::new("gggg::1").is_err());  // Invalid hex
        assert!(ValidatedIpAddress::new("::gggg").is_err());
    }

    #[test]
    fn test_ip_normalization() {
        // IPv6 normalization - compressed form
        let ip1 = ValidatedIpAddress::new("0:0:0:0:0:0:0:1").unwrap();
        assert_eq!(ip1.as_str(), "::1");

        let ip2 = ValidatedIpAddress::new("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(ip2.as_str(), "2001:db8::1");

        let ip3 = ValidatedIpAddress::new("2001:0db8:0001:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(ip3.as_str(), "2001:db8:1::1");

        // IPv4 normalization (no change expected)
        let ip4 = ValidatedIpAddress::new("8.8.8.8").unwrap();
        assert_eq!(ip4.as_str(), "8.8.8.8");

        let ip5 = ValidatedIpAddress::new("192.0.2.1").unwrap();
        assert_eq!(ip5.as_str(), "192.0.2.1");
    }

    #[test]
    fn test_ip_type_detection() {
        let ipv4 = ValidatedIpAddress::new("8.8.8.8").unwrap();
        assert!(ipv4.is_ipv4());
        assert!(!ipv4.is_ipv6());

        let ipv6 = ValidatedIpAddress::new("::1").unwrap();
        assert!(ipv6.is_ipv6());
        assert!(!ipv6.is_ipv4());

        let ipv6_2 = ValidatedIpAddress::new("2001:4860:4860::8888").unwrap();
        assert!(ipv6_2.is_ipv6());
        assert!(!ipv6_2.is_ipv4());
    }

    #[test]
    fn test_ip_methods() {
        let ip = ValidatedIpAddress::new("8.8.8.8").unwrap();

        // Test as_str()
        assert_eq!(ip.as_str(), "8.8.8.8");

        // Test AsRef<str>
        let s: &str = ip.as_ref();
        assert_eq!(s, "8.8.8.8");

        // Test Display
        assert_eq!(format!("{}", ip), "8.8.8.8");

        // Test into_inner()
        let ip2 = ValidatedIpAddress::new("1.1.1.1").unwrap();
        let inner = ip2.into_inner();
        assert_eq!(inner, "1.1.1.1");
    }

    // ===== RIR Detection Tests =====

    #[test]
    fn test_rir_detection_arin() {
        // Google DNS (ARIN - 8.0.0.0/8)
        let ip = ValidatedIpAddress::new("8.8.8.8").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::ARIN);

        // Cloudflare (ARIN - varies by region, but 104.0.0.0/8 is ARIN)
        let ip = ValidatedIpAddress::new("104.16.123.45").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::ARIN);

        // Level 3 (ARIN - 4.0.0.0/8)
        let ip = ValidatedIpAddress::new("4.2.2.2").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::ARIN);
    }

    #[test]
    fn test_rir_detection_ripe() {
        // Example RIPE range (2.0.0.0/8)
        let ip = ValidatedIpAddress::new("2.0.0.1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::RIPE);

        // Another RIPE range (5.0.0.0/8)
        let ip = ValidatedIpAddress::new("5.5.5.5").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::RIPE);

        // European range (80.0.0.0/8)
        let ip = ValidatedIpAddress::new("80.80.80.80").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::RIPE);
    }

    #[test]
    fn test_rir_detection_apnic() {
        // Cloudflare DNS (APNIC - 1.0.0.0/8)
        let ip = ValidatedIpAddress::new("1.1.1.1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::APNIC);

        // Example APNIC range (27.0.0.0/8)
        let ip = ValidatedIpAddress::new("27.0.0.1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::APNIC);

        // Chinese range (58.0.0.0/8)
        let ip = ValidatedIpAddress::new("58.1.2.3").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::APNIC);
    }

    #[test]
    fn test_rir_detection_lacnic() {
        // Brazilian range (177.0.0.0/8)
        let ip = ValidatedIpAddress::new("177.1.2.3").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::LACNIC);

        // Another LACNIC range (200.0.0.0/8)
        let ip = ValidatedIpAddress::new("200.1.2.3").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::LACNIC);
    }

    #[test]
    fn test_rir_detection_afrinic() {
        // South African range (41.0.0.0/8)
        let ip = ValidatedIpAddress::new("41.1.2.3").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::AFRINIC);

        // Another AFRINIC range (102.0.0.0/8)
        let ip = ValidatedIpAddress::new("102.1.2.3").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::AFRINIC);
    }

    #[test]
    fn test_rir_detection_ipv6() {
        // Google IPv6 (ARIN - 2600::/12)
        let ip = ValidatedIpAddress::new("2600::1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::ARIN);

        // RIPE IPv6 (2a00::/12)
        let ip = ValidatedIpAddress::new("2a00::1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::RIPE);

        // APNIC IPv6 (2400::/12)
        let ip = ValidatedIpAddress::new("2400::1").unwrap();
        let rir = detect_rir(&ip).unwrap();
        assert_eq!(rir, Rir::APNIC);
    }

    #[test]
    fn test_rir_detection_private_ranges() {
        // Private IP ranges should fail (RFC 1918)
        let ip = ValidatedIpAddress::new("192.168.1.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("10.0.0.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("172.16.0.1").unwrap();
        assert!(detect_rir(&ip).is_err());
    }

    #[test]
    fn test_rir_detection_special_ranges() {
        // Loopback
        let ip = ValidatedIpAddress::new("127.0.0.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("::1").unwrap();
        assert!(detect_rir(&ip).is_err());

        // Link-local
        let ip = ValidatedIpAddress::new("169.254.1.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("fe80::1").unwrap();
        assert!(detect_rir(&ip).is_err());

        // Documentation range
        let ip = ValidatedIpAddress::new("192.0.2.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("2001:db8::1").unwrap();
        assert!(detect_rir(&ip).is_err());

        // Multicast
        let ip = ValidatedIpAddress::new("224.0.0.1").unwrap();
        assert!(detect_rir(&ip).is_err());

        // Broadcast
        let ip = ValidatedIpAddress::new("255.255.255.255").unwrap();
        assert!(detect_rir(&ip).is_err());

        // Unspecified
        let ip = ValidatedIpAddress::new("0.0.0.0").unwrap();
        assert!(detect_rir(&ip).is_err());

        let ip = ValidatedIpAddress::new("::").unwrap();
        assert!(detect_rir(&ip).is_err());
    }

    #[test]
    fn test_rir_servers() {
        assert_eq!(Rir::ARIN.whois_server(), "whois.arin.net");
        assert_eq!(Rir::RIPE.whois_server(), "whois.ripe.net");
        assert_eq!(Rir::APNIC.whois_server(), "whois.apnic.net");
        assert_eq!(Rir::LACNIC.whois_server(), "whois.lacnic.net");
        assert_eq!(Rir::AFRINIC.whois_server(), "whois.afrinic.net");

        assert_eq!(Rir::ARIN.rdap_server(), "https://rdap.arin.net/registry");
        assert_eq!(Rir::RIPE.rdap_server(), "https://rdap.db.ripe.net");
        assert_eq!(Rir::APNIC.rdap_server(), "https://rdap.apnic.net");
        assert_eq!(Rir::LACNIC.rdap_server(), "https://rdap.lacnic.net");
        assert_eq!(Rir::AFRINIC.rdap_server(), "https://rdap.afrinic.net/rdap");
    }

    #[test]
    fn test_is_private_or_special() {
        // Private ranges
        assert!(is_private_or_special(&IpAddr::V4("192.168.1.1".parse().unwrap())));
        assert!(is_private_or_special(&IpAddr::V4("10.0.0.1".parse().unwrap())));
        assert!(is_private_or_special(&IpAddr::V4("172.16.0.1".parse().unwrap())));

        // Loopback
        assert!(is_private_or_special(&IpAddr::V4("127.0.0.1".parse().unwrap())));
        assert!(is_private_or_special(&IpAddr::V6("::1".parse().unwrap())));

        // Link-local
        assert!(is_private_or_special(&IpAddr::V4("169.254.1.1".parse().unwrap())));
        assert!(is_private_or_special(&IpAddr::V6("fe80::1".parse().unwrap())));

        // Shared address space (100.64.0.0/10)
        assert!(is_private_or_special(&IpAddr::V4("100.64.0.1".parse().unwrap())));
        assert!(is_private_or_special(&IpAddr::V4("100.127.255.254".parse().unwrap())));

        // Public IPs should not be special
        assert!(!is_private_or_special(&IpAddr::V4("8.8.8.8".parse().unwrap())));
        assert!(!is_private_or_special(&IpAddr::V4("1.1.1.1".parse().unwrap())));
        assert!(!is_private_or_special(&IpAddr::V6("2600::1".parse().unwrap())));
    }
}
