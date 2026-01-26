//! IP Address WHOIS/RDAP Support
//!
//! Provides lookup functionality for IP addresses (IPv4 and IPv6) using:
//! - RDAP via IANA bootstrap (ipv4.json / ipv6.json)
//! - WHOIS via Regional Internet Registries (RIRs)

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Regional Internet Registry information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rir {
    /// American Registry for Internet Numbers (North America)
    Arin,
    /// Réseaux IP Européens Network Coordination Centre (Europe, Middle East, Central Asia)
    Ripe,
    /// Asia-Pacific Network Information Centre
    Apnic,
    /// Latin America and Caribbean Network Information Centre
    Lacnic,
    /// African Network Information Centre
    Afrinic,
}

impl Rir {
    /// Get the WHOIS server for this RIR
    pub fn whois_server(&self) -> &'static str {
        match self {
            Rir::Arin => "whois.arin.net",
            Rir::Ripe => "whois.ripe.net",
            Rir::Apnic => "whois.apnic.net",
            Rir::Lacnic => "whois.lacnic.net",
            Rir::Afrinic => "whois.afrinic.net",
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Rir::Arin => "ARIN",
            Rir::Ripe => "RIPE NCC",
            Rir::Apnic => "APNIC",
            Rir::Lacnic => "LACNIC",
            Rir::Afrinic => "AFRINIC",
        }
    }
}

/// Parsed IP WHOIS/RDAP data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ParsedIpData {
    /// IP address or CIDR range queried
    #[cfg_attr(feature = "openapi", schema(example = "8.8.8.0/24"))]
    pub range: Option<String>,
    
    /// Network name
    #[cfg_attr(feature = "openapi", schema(example = "LVLT-GOGL-8-8-8"))]
    pub net_name: Option<String>,
    
    /// Network handle/ID
    #[cfg_attr(feature = "openapi", schema(example = "NET-8-8-8-0-1"))]
    pub net_handle: Option<String>,
    
    /// Organization name
    #[cfg_attr(feature = "openapi", schema(example = "Google LLC"))]
    pub organization: Option<String>,
    
    /// Country code
    #[cfg_attr(feature = "openapi", schema(example = "US"))]
    pub country: Option<String>,
    
    /// Regional Internet Registry
    #[cfg_attr(feature = "openapi", schema(example = "ARIN"))]
    pub rir: Option<String>,
    
    /// Registration date
    pub registration_date: Option<String>,
    
    /// Last updated date
    pub updated_date: Option<String>,
    
    /// Abuse contact email
    #[cfg_attr(feature = "openapi", schema(example = "network-abuse@google.com"))]
    pub abuse_email: Option<String>,
    
    /// Description/comments
    pub description: Option<String>,
    
    /// CIDR notation
    #[cfg_attr(feature = "openapi", schema(example = "8.8.8.0/24"))]
    pub cidr: Option<String>,
    
    /// Start address of the range
    pub start_address: Option<String>,
    
    /// End address of the range
    pub end_address: Option<String>,
    
    /// AS Number if available
    #[cfg_attr(feature = "openapi", schema(example = "AS15169"))]
    pub asn: Option<String>,
}

/// Represents either a domain or an IP address for lookup
#[derive(Debug, Clone)]
pub enum LookupTarget {
    /// Domain name (e.g., "google.com")
    Domain(String),
    /// IP address (IPv4 or IPv6)
    Ip(IpAddr),
}

impl LookupTarget {
    /// Parse a string into either a domain or IP address
    pub fn parse(input: &str) -> Self {
        let input = input.trim();
        
        // Try parsing as IP address first
        if let Ok(ip) = input.parse::<IpAddr>() {
            return LookupTarget::Ip(ip);
        }
        
        // Otherwise treat as domain
        LookupTarget::Domain(input.to_lowercase())
    }
    
    /// Check if this is an IP address
    pub fn is_ip(&self) -> bool {
        matches!(self, LookupTarget::Ip(_))
    }
    
    /// Check if this is a domain
    pub fn is_domain(&self) -> bool {
        matches!(self, LookupTarget::Domain(_))
    }
    
    /// Get as string representation
    pub fn as_str(&self) -> String {
        match self {
            LookupTarget::Domain(d) => d.clone(),
            LookupTarget::Ip(ip) => ip.to_string(),
        }
    }
}

/// IP WHOIS response parser
pub struct IpParser;

impl IpParser {
    /// Parse raw WHOIS data for an IP address
    pub fn parse_whois_data(raw_data: &str) -> ParsedIpData {
        let mut parsed = ParsedIpData::default();
        
        for line in raw_data.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
                continue;
            }
            
            // Try to parse key-value pairs
            if let Some((key, value)) = Self::parse_line(line) {
                Self::apply_field(&mut parsed, &key.to_lowercase(), value);
            }
        }
        
        parsed
    }
    
    /// Parse a single line into key-value pair
    fn parse_line(line: &str) -> Option<(&str, &str)> {
        // Handle "Key: Value" format
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();
            if !key.is_empty() && !value.is_empty() {
                return Some((key, value));
            }
        }
        None
    }
    
    /// Apply a parsed field to the result
    fn apply_field(parsed: &mut ParsedIpData, key: &str, value: &str) {
        match key {
            // Network range identifiers
            "netrange" | "inetnum" | "inet6num" => {
                parsed.range = Some(value.to_string());
            }
            "cidr" | "route" | "route6" => {
                parsed.cidr = Some(value.to_string());
            }
            "netname" | "network-name" => {
                parsed.net_name = Some(value.to_string());
            }
            "nethandle" | "nic-hdl" => {
                parsed.net_handle = Some(value.to_string());
            }
            
            // Organization
            "orgname" | "org-name" | "organisation" | "organization" => {
                parsed.organization = Some(value.to_string());
            }
            "country" => {
                parsed.country = Some(value.to_uppercase());
            }
            
            // Dates
            "regdate" | "created" => {
                parsed.registration_date = Some(value.to_string());
            }
            "updated" | "last-modified" | "changed" => {
                if parsed.updated_date.is_none() {
                    parsed.updated_date = Some(value.to_string());
                }
            }
            
            // Abuse contact
            "abuse-mailbox" | "orgabuseemail" => {
                parsed.abuse_email = Some(value.to_string());
            }
            
            // Description
            "descr" | "comment" | "nettype" => {
                if parsed.description.is_none() {
                    parsed.description = Some(value.to_string());
                }
            }
            
            // ASN
            "originas" | "origin" | "asn" => {
                parsed.asn = Some(value.to_string());
            }
            
            _ => {} // Ignore unknown fields
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lookup_target_parsing() {
        // IPv4
        assert!(matches!(LookupTarget::parse("8.8.8.8"), LookupTarget::Ip(_)));
        assert!(matches!(LookupTarget::parse("192.168.1.1"), LookupTarget::Ip(_)));
        
        // IPv6
        assert!(matches!(LookupTarget::parse("2001:4860:4860::8888"), LookupTarget::Ip(_)));
        assert!(matches!(LookupTarget::parse("::1"), LookupTarget::Ip(_)));
        
        // Domains
        assert!(matches!(LookupTarget::parse("google.com"), LookupTarget::Domain(_)));
        assert!(matches!(LookupTarget::parse("example.org"), LookupTarget::Domain(_)));
        
        // Edge cases
        assert!(matches!(LookupTarget::parse("  8.8.8.8  "), LookupTarget::Ip(_)));
        assert!(matches!(LookupTarget::parse("GOOGLE.COM"), LookupTarget::Domain(d) if d == "google.com"));
    }
    
    #[test]
    fn test_rir_servers() {
        assert_eq!(Rir::Arin.whois_server(), "whois.arin.net");
        assert_eq!(Rir::Ripe.whois_server(), "whois.ripe.net");
        assert_eq!(Rir::Apnic.whois_server(), "whois.apnic.net");
        assert_eq!(Rir::Lacnic.whois_server(), "whois.lacnic.net");
        assert_eq!(Rir::Afrinic.whois_server(), "whois.afrinic.net");
    }
    
    #[test]
    fn test_ip_parser() {
        let sample = r#"
# ARIN WHOIS data
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        LVLT-GOGL-8-8-8
NetHandle:      NET-8-8-8-0-1
OrgName:        Google LLC
Country:        US
RegDate:        2014-03-14
Updated:        2014-03-14
"#;
        
        let parsed = IpParser::parse_whois_data(sample);
        assert_eq!(parsed.range.as_deref(), Some("8.8.8.0 - 8.8.8.255"));
        assert_eq!(parsed.cidr.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(parsed.net_name.as_deref(), Some("LVLT-GOGL-8-8-8"));
        assert_eq!(parsed.organization.as_deref(), Some("Google LLC"));
        assert_eq!(parsed.country.as_deref(), Some("US"));
    }
}
