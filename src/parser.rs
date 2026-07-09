use crate::{LookupStatus, ParsedWhoisData};

/// Phrases WHOIS servers use to say "you are being throttled".
///
/// Matched case-insensitively against the raw response, and only when the
/// parse found no substantive record data (see [`WhoisParser::classify_response`]),
/// so a quota notice appended to a full record never masks real data.
const RATE_LIMIT_PATTERNS: &[&str] = &[
    "rate limit",
    "ratelimit",
    "quota exceeded",
    "exceeded your quota",
    "lookup quota",
    "number of allowed queries exceeded",
    "exceeded the maximum",
    "maximum number of queries",
    "whois limit exceeded",
    "too many requests",
    "excessive quer",       // "excessive queries" / "excessive querying"
    "request limit reached",
    "access denied",        // RIPE %ERROR:201, ARIN ACL blocks
    "connection limit",
];

/// Phrases WHOIS servers use to say "this object is not registered".
const NOT_FOUND_PATTERNS: &[&str] = &[
    "no match",             // Verisign: 'No match for "FOO.COM"'
    "not found",            // PIR/.org: "Domain not found."
    "no data found",
    "no entries found",     // RIPE-style
    "no object found",
    "object does not exist",
    "nothing found",
    "not registered",
    "no information available",
    "status: available",    // some ccTLDs report availability instead
    "status: free",         // DENIC/.de
    "is available for registration",
];

/// Stateless WHOIS response parser
///
/// All methods are associated functions since parsing is pure computation.
/// No instance is needed - use `WhoisParser::parse_whois_data(data)` directly.
pub struct WhoisParser;

impl WhoisParser {
    /// Classify a WHOIS response as found / not found / rate limited.
    ///
    /// WHOIS has no status codes: throttling and NXDOMAIN both arrive as
    /// ordinary text in a successful TCP exchange. Left unclassified, a
    /// throttle banner parses to an empty record and gets cached as a
    /// "successful" lookup - poisoning the cache exactly when it should be
    /// shielding the upstream server.
    ///
    /// Pattern matches only apply when the parse found no substantive record
    /// data (no registrar, no creation date, no name servers). A real record
    /// that merely *mentions* "not found" or carries an appended quota notice
    /// still classifies as Found.
    pub fn classify_response(raw_data: &str, parsed: &ParsedWhoisData) -> LookupStatus {
        let has_record_data = parsed.registrar.is_some()
            || parsed.creation_date.is_some()
            || !parsed.name_servers.is_empty();
        if has_record_data {
            return LookupStatus::Found;
        }

        let lower = raw_data.to_lowercase();

        // Rate limiting first: a throttle message must not read as NXDOMAIN
        if RATE_LIMIT_PATTERNS.iter().any(|p| lower.contains(p)) {
            return LookupStatus::RateLimited;
        }

        if NOT_FOUND_PATTERNS.iter().any(|p| lower.contains(p)) {
            return LookupStatus::NotFound;
        }

        LookupStatus::Found
    }

    /// Parse raw WHOIS data into structured fields
    pub fn parse_whois_data(data: &str) -> ParsedWhoisData {
        let mut parsed = ParsedWhoisData::new();

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') || line.starts_with(">>>") {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                
                if value.is_empty() {
                    continue;
                }

                // Match field patterns more intelligently (order matters - most specific first)
                match key.as_str() {
                    // Expiration date patterns (check first to catch "Registrar Registration Expiration Date")
                    k if (k.contains("expir") || k.contains("expires"))
                        && parsed.expiration_date.is_none() => {
                            parsed.expiration_date = Some(value.to_string());
                        },
                    
                    // Creation date patterns
                    k if (k.contains("creation") || k.contains("created") || k == "registered")
                        && parsed.creation_date.is_none() => {
                            parsed.creation_date = Some(value.to_string());
                        },
                    
                    // Updated date patterns
                    k if (k.contains("updated") || k.contains("modified") || k.contains("last updated"))
                        && parsed.updated_date.is_none() => {
                            parsed.updated_date = Some(value.to_string());
                        },
                    
                    // Registrar patterns (after date patterns to avoid conflicts)
                    k if k.contains("registrar") && !k.contains("whois") && !k.contains("url") && !k.contains("abuse") && !k.contains("expir") && !k.contains("registration")
                        && parsed.registrar.is_none() => {
                            parsed.registrar = Some(value.to_string());
                        },
                    
                    // Name server patterns
                    k if k.contains("name server") || k == "nserver" || k == "ns" => {
                        // Extract just the hostname, ignore IP addresses
                        let server = value.split_whitespace().next().unwrap_or(value);
                        if !parsed.name_servers.contains(&server.to_string()) {
                            parsed.name_servers.push(server.to_string());
                        }
                    },
                    
                    // Status patterns. Match "state" only as an exact key (used by
                    // some ccTLD registries, e.g. .ru) - a substring match would also
                    // capture contact address lines like "Registrant State/Province"
                    k if (k.contains("status") || k == "state")
                        && !parsed.status.contains(&value.to_string()) => {
                            parsed.status.push(value.to_string());
                        },
                    
                    // Registrant name patterns
                    k if k.starts_with("registrant") && (k.contains("name") || k.contains("organization") || k.contains("org") || k == "registrant")
                        && parsed.registrant_name.is_none() && !value.to_lowercase().contains("select request") => {
                            parsed.registrant_name = Some(value.to_string());
                        },
                    
                    // Email patterns (value must look like an email, not a
                    // redacted-notice or a registry contact handle)
                    k if k.contains("registrant") && k.contains("email")
                        && parsed.registrant_email.is_none() && value.contains('@') && !value.to_lowercase().contains("select request") => {
                            parsed.registrant_email = Some(value.to_string());
                        },
                    k if k.contains("admin") && k.contains("email")
                        && parsed.admin_email.is_none() && value.contains('@') && !value.to_lowercase().contains("select request") => {
                            parsed.admin_email = Some(value.to_string());
                        },
                    k if k.contains("tech") && k.contains("email")
                        && parsed.tech_email.is_none() && value.contains('@') && !value.to_lowercase().contains("select request") => {
                            parsed.tech_email = Some(value.to_string());
                        },
                    
                    _ => {} // Ignore unrecognized fields
                }
            }
        }

        // Calculate date-based fields using shared date utilities
        parsed.calculate_age_fields();

        parsed
    }

    /// Parse WHOIS data and return detailed analysis for debugging
    pub fn parse_whois_data_with_analysis(data: &str) -> (ParsedWhoisData, Vec<String>) {
        let mut analysis = Vec::new();
        
        // Parse the data
        let parsed = Self::parse_whois_data(data);
        
        // Analyze what was found
        analysis.push("=== PARSING ANALYSIS ===".to_string());
        analysis.push(format!("✓ Registrar: {}", parsed.registrar.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("✓ Creation Date: {}", parsed.creation_date.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("✓ Expiration Date: {}", parsed.expiration_date.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("✓ Updated Date: {}", parsed.updated_date.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("✓ Registrant Name: {}", parsed.registrant_name.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("✓ Name Servers: {} found", parsed.name_servers.len()));
        analysis.push(format!("✓ Status: {} found", parsed.status.len()));
        
        // Show lines that might contain registrant info
        analysis.push("\n=== LINES CONTAINING 'REGISTRANT' ===".to_string());
        for (i, line) in data.lines().enumerate() {
            if line.to_lowercase().contains("registrant") {
                analysis.push(format!("Line {}: {}", i + 1, line.trim()));
            }
        }
        
        // Show lines that might contain expiry info
        analysis.push("\n=== LINES CONTAINING 'EXPIR' ===".to_string());
        for (i, line) in data.lines().enumerate() {
            if line.to_lowercase().contains("expir") {
                analysis.push(format!("Line {}: {}", i + 1, line.trim()));
            }
        }
        
        (parsed, analysis)
    }

    /// Parse IP WHOIS data with analysis
    ///
    /// IP WHOIS responses have different field names than domain WHOIS:
    /// - NetRange, CIDR, NetName (network info)
    /// - OrgName, OrgTechEmail (organization info)
    /// - Updated, Created dates (no expiration for IPs)
    pub fn parse_ip_whois_data_with_analysis(data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        analysis.push("=== IP WHOIS PARSING ANALYSIS ===".to_string());

        // Use new() helper to eliminate boilerplate
        let mut parsed = ParsedWhoisData::new();

        // NetName is a terse fallback (e.g. "LVLT-ORG-8-8"); a proper
        // organization name may appear later in the response and should win
        let mut org_from_netname = false;

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                if value.is_empty() {
                    continue;
                }

                // IP WHOIS-specific field matching
                match key.as_str() {
                    // Organization name (use as "registrar" for consistency);
                    // overrides a netname-derived value
                    "orgname" | "org-name" | "owner" | "organization"
                        if (parsed.registrar.is_none() || org_from_netname) => {
                            parsed.registrar = Some(value.to_string());
                            org_from_netname = false;
                            analysis.push(format!("✓ Organization: {}", value));
                        },

                    // Network name - fallback when no organization is present
                    "netname"
                        if parsed.registrar.is_none() => {
                            parsed.registrar = Some(value.to_string());
                            org_from_netname = true;
                            analysis.push(format!("✓ Network Name: {}", value));
                        },

                    // Dates
                    "updated" | "lastupdated" | "changed" | "last-modified"
                        if parsed.updated_date.is_none() => {
                            parsed.updated_date = Some(value.to_string());
                            analysis.push(format!("✓ Updated Date: {}", value));
                        },
                    "created" | "regdate" | "registration"
                        if parsed.creation_date.is_none() => {
                            parsed.creation_date = Some(value.to_string());
                            analysis.push(format!("✓ Created Date: {}", value));
                        },

                    // Contact emails - the value must contain '@'. Keys like
                    // "tech-c"/"abuse-c" carry RIR contact handles (e.g. "ABC123-RIPE"),
                    // not addresses, and must not be stored as emails.
                    k if (k.contains("orgtechemail") || k.contains("tech-c") || k.contains("technical"))
                        && parsed.tech_email.is_none() && value.contains('@') => {
                            parsed.tech_email = Some(value.to_string());
                            analysis.push(format!("✓ Tech Email: {}", value));
                        },
                    k if (k.contains("orgabuseemail") || k.contains("abuse-c") || k.contains("abuse"))
                        && parsed.admin_email.is_none() && value.contains('@') => {
                            parsed.admin_email = Some(value.to_string());
                            analysis.push(format!("✓ Abuse Email: {}", value));
                        },
                    k if (k.contains("orgemail") || k.contains("e-mail") || k.contains("email"))
                        && parsed.registrant_email.is_none() && value.contains('@') => {
                            parsed.registrant_email = Some(value.to_string());
                            analysis.push(format!("✓ Contact Email: {}", value));
                        },

                    // Status
                    "status" | "nettype"
                        if !parsed.status.contains(&value.to_string()) => {
                            parsed.status.push(value.to_string());
                            analysis.push(format!("✓ Status: {}", value));
                        },

                    // Network range info (log for analysis, not stored in ParsedWhoisData)
                    "netrange" | "inetnum" | "cidr" => {
                        analysis.push(format!("✓ Network Range: {}", value));
                    },

                    _ => {} // Ignore unrecognized fields
                }
            }
        }

        // Calculate date-based fields
        parsed.calculate_age_fields();

        // Summary analysis
        analysis.push("\n=== SUMMARY ===".to_string());
        analysis.push(format!("Organization: {}", parsed.registrar.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("Created: {}", parsed.creation_date.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("Updated: {}", parsed.updated_date.as_deref().unwrap_or("NOT FOUND")));
        analysis.push(format!("Status entries: {}", parsed.status.len()));
        analysis.push(format!("Contact emails found: {}",
            [&parsed.registrant_email, &parsed.admin_email, &parsed.tech_email]
                .iter()
                .filter(|e| e.is_some())
                .count()
        ));

        (Some(parsed), analysis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verisign-style .com registry response
    const VERISIGN_STYLE: &str = "\
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
>>> Last update of whois database: 2026-07-08T00:00:00Z <<<";

    /// Registrar-style response with contact details
    const REGISTRAR_STYLE: &str = "\
Domain Name: example.io
Registrar: Sav.com, LLC
Registrar Registration Expiration Date: 2026-11-26T19:28:34Z
Creation Date: 2019-11-26T19:28:34Z
Updated Date: 2025-10-30T00:32:24Z
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Privacy Protect, LLC
Registrant State/Province: FL
Registrant Email: Please select Request Email Form at https://example.test
Admin State/Province: REDACTED FOR PRIVACY
Admin Email: admin@example.io
Tech State/Province: WA
Tech Email: tech@example.io
Domain Status: clientTransferProhibited
Name Server: bonnie.ns.cloudflare.com
Name Server: kanye.ns.cloudflare.com
Name Server: bonnie.ns.cloudflare.com";

    /// RIPE-style IP response (contact handles, not emails)
    const RIPE_STYLE: &str = "\
% This is the RIPE Database query service.
inetnum:        130.89.0.0 - 130.89.255.255
netname:        UTNET
descr:          University of Twente
country:        NL
admin-c:        ITBE1-RIPE
tech-c:         ITBE1-RIPE
abuse-c:        ITBE1-RIPE
status:         LEGACY
last-modified:  2020-10-14T09:41:24Z
% Abuse contact for '130.89.0.0 - 130.89.255.255' is 'abuse@utwente.nl'";

    /// ARIN-style IP response (real org emails)
    const ARIN_STYLE: &str = "\
NetRange:       8.0.0.0 - 8.127.255.255
CIDR:           8.0.0.0/9
NetName:        LVLT-ORG-8-8
NetType:        Direct Allocation
Organization:   Level 3 Parent, LLC (LPL-141)
RegDate:        1992-12-01
Updated:        2018-04-23
OrgAbuseEmail:  abuse@level3.com
OrgTechEmail:   ipaddressing@level3.com";

    #[test]
    fn test_parse_verisign_style() {
        let parsed = WhoisParser::parse_whois_data(VERISIGN_STYLE);

        assert_eq!(parsed.registrar.as_deref(), Some("RESERVED-Internet Assigned Numbers Authority"));
        assert_eq!(parsed.creation_date.as_deref(), Some("1995-08-14T04:00:00Z"));
        assert_eq!(parsed.expiration_date.as_deref(), Some("2026-08-13T04:00:00Z"));
        assert_eq!(parsed.updated_date.as_deref(), Some("2024-08-14T07:01:34Z"));
        assert_eq!(parsed.name_servers, vec!["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]);
        assert_eq!(parsed.status.len(), 2);
        // Calculated fields should be populated from the parsed dates
        assert!(parsed.created_ago.unwrap() > 0);
    }

    #[test]
    fn test_parse_registrar_style() {
        let parsed = WhoisParser::parse_whois_data(REGISTRAR_STYLE);

        assert_eq!(parsed.registrar.as_deref(), Some("Sav.com, LLC"));
        // "Registrar Registration Expiration Date" must land in expiration, not registrar
        assert_eq!(parsed.expiration_date.as_deref(), Some("2026-11-26T19:28:34Z"));
        // Redacted registrant email ("Please select Request Email Form...") must be dropped
        assert_eq!(parsed.registrant_email, None);
        assert_eq!(parsed.admin_email.as_deref(), Some("admin@example.io"));
        assert_eq!(parsed.tech_email.as_deref(), Some("tech@example.io"));
        assert_eq!(parsed.registrant_name.as_deref(), Some("REDACTED FOR PRIVACY"));
        // Duplicate nameserver lines are deduplicated
        assert_eq!(parsed.name_servers.len(), 2);
        // Contact "State/Province" lines must not leak into domain status
        assert_eq!(parsed.status, vec!["clientTransferProhibited"]);
    }

    #[test]
    fn test_exact_state_key_is_status() {
        // Some ccTLD registries (e.g. .ru) report status under a bare "state" key
        let parsed = WhoisParser::parse_whois_data("state: REGISTERED, DELEGATED, VERIFIED");
        assert_eq!(parsed.status, vec!["REGISTERED, DELEGATED, VERIFIED"]);
    }

    #[test]
    fn test_parse_ip_ripe_style_handles_are_not_emails() {
        let (parsed, _) = WhoisParser::parse_ip_whois_data_with_analysis(RIPE_STYLE);
        let parsed = parsed.unwrap();

        assert_eq!(parsed.registrar.as_deref(), Some("UTNET"));
        assert_eq!(parsed.updated_date.as_deref(), Some("2020-10-14T09:41:24Z"));
        // tech-c / abuse-c hold RIR handles (ITBE1-RIPE), not email addresses
        assert_eq!(parsed.tech_email, None);
        assert_eq!(parsed.admin_email, None);
        assert!(parsed.status.contains(&"LEGACY".to_string()));
    }

    #[test]
    fn test_parse_ip_arin_style() {
        let (parsed, _) = WhoisParser::parse_ip_whois_data_with_analysis(ARIN_STYLE);
        let parsed = parsed.unwrap();

        assert_eq!(parsed.registrar.as_deref(), Some("Level 3 Parent, LLC (LPL-141)"));
        assert_eq!(parsed.creation_date.as_deref(), Some("1992-12-01"));
        assert_eq!(parsed.updated_date.as_deref(), Some("2018-04-23"));
        assert_eq!(parsed.tech_email.as_deref(), Some("ipaddressing@level3.com"));
        assert_eq!(parsed.admin_email.as_deref(), Some("abuse@level3.com"));
        assert!(parsed.status.contains(&"Direct Allocation".to_string()));
    }

    #[test]
    fn test_parse_ignores_comments_and_empty_values() {
        let data = "% comment line\n# another comment\nRegistrar:\nRegistrar: Real Registrar Inc.";
        let parsed = WhoisParser::parse_whois_data(data);
        // Empty value skipped, first non-empty wins
        assert_eq!(parsed.registrar.as_deref(), Some("Real Registrar Inc."));
    }

    #[test]
    fn test_parse_empty_input() {
        let parsed = WhoisParser::parse_whois_data("");
        assert_eq!(parsed.registrar, None);
        assert!(parsed.name_servers.is_empty());
        assert!(parsed.status.is_empty());
    }

    #[test]
    fn test_parse_no_match_response() {
        let parsed = WhoisParser::parse_whois_data("No match for domain \"NOSUCHDOMAIN.COM\".\n>>> Last update of whois database: 2026-07-08T00:00:00Z <<<");
        assert_eq!(parsed.registrar, None);
        assert_eq!(parsed.creation_date, None);
    }

    fn classify(raw: &str) -> LookupStatus {
        let parsed = WhoisParser::parse_whois_data(raw);
        WhoisParser::classify_response(raw, &parsed)
    }

    #[test]
    fn test_classify_not_found() {
        // Verisign
        assert_eq!(classify("No match for \"NOSUCHDOMAIN.COM\".\n>>> Last update of whois database: 2026-07-08T00:00:00Z <<<"), LookupStatus::NotFound);
        // PIR / .org
        assert_eq!(classify("Domain not found."), LookupStatus::NotFound);
        // DENIC / .de
        assert_eq!(classify("Domain: nosuchdomain.de\nStatus: free"), LookupStatus::NotFound);
        // RIPE-style
        assert_eq!(classify("%ERROR:101: no entries found\n% No entries found in source RIPE."), LookupStatus::NotFound);
    }

    #[test]
    fn test_classify_rate_limited() {
        assert_eq!(classify("You have exceeded your quota of queries."), LookupStatus::RateLimited);
        assert_eq!(classify("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS"), LookupStatus::RateLimited);
        assert_eq!(classify("Number of allowed queries exceeded."), LookupStatus::RateLimited);
        assert_eq!(classify("%ERROR:201: access denied for 203.0.113.5"), LookupStatus::RateLimited);
        assert_eq!(classify("Rate limit exceeded. Try again later."), LookupStatus::RateLimited);
    }

    #[test]
    fn test_classify_rate_limit_wins_over_not_found_wording() {
        // Throttle messages sometimes contain phrasing that could read as NXDOMAIN
        assert_eq!(
            classify("Query rate limit exceeded; no data found for your request."),
            LookupStatus::RateLimited
        );
    }

    #[test]
    fn test_classify_real_record_is_found() {
        // Full records classify as Found even if they mention trigger phrases
        assert_eq!(classify(VERISIGN_STYLE), LookupStatus::Found);
        assert_eq!(classify(REGISTRAR_STYLE), LookupStatus::Found);
        // Record with an appended quota notice still counts as Found
        let with_notice = format!("{}\n%% Queries exceeding the maximum may be throttled.", ARIN_STYLE);
        let (parsed, _) = WhoisParser::parse_ip_whois_data_with_analysis(&with_notice);
        assert_eq!(
            WhoisParser::classify_response(&with_notice, &parsed.unwrap()),
            LookupStatus::Found
        );
    }

    #[test]
    fn test_classify_empty_or_ambiguous_is_found() {
        // No patterns and no data - stay conservative, report Found
        assert_eq!(classify(""), LookupStatus::Found);
        assert_eq!(classify("% some banner text only"), LookupStatus::Found);
    }

    #[test]
    fn test_nameserver_strips_ip_annotations() {
        // Some registries append IPs after the hostname
        let parsed = WhoisParser::parse_whois_data("nserver: ns1.example.de 192.0.2.1 2001:db8::1");
        assert_eq!(parsed.name_servers, vec!["ns1.example.de"]);
    }
} 