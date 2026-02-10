use crate::ParsedWhoisData;

/// Stateless WHOIS response parser
/// 
/// All methods are associated functions since parsing is pure computation.
/// No instance is needed - use `WhoisParser::parse_whois_data(data)` directly.
pub struct WhoisParser;

impl WhoisParser {
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
                    k if k.contains("expir") || k.contains("expires") => {
                        if parsed.expiration_date.is_none() {
                            parsed.expiration_date = Some(value.to_string());
                        }
                    },
                    
                    // Creation date patterns
                    k if k.contains("creation") || k.contains("created") || k == "registered" => {
                        if parsed.creation_date.is_none() {
                            parsed.creation_date = Some(value.to_string());
                        }
                    },
                    
                    // Updated date patterns
                    k if k.contains("updated") || k.contains("modified") || k.contains("last updated") => {
                        if parsed.updated_date.is_none() {
                            parsed.updated_date = Some(value.to_string());
                        }
                    },
                    
                    // Registrar patterns (after date patterns to avoid conflicts)
                    k if k.contains("registrar") && !k.contains("whois") && !k.contains("url") && !k.contains("abuse") && !k.contains("expir") && !k.contains("registration") => {
                        if parsed.registrar.is_none() {
                            parsed.registrar = Some(value.to_string());
                        }
                    },
                    
                    // Name server patterns
                    k if k.contains("name server") || k == "nserver" || k == "ns" => {
                        // Extract just the hostname, ignore IP addresses
                        let server = value.split_whitespace().next().unwrap_or(value);
                        if !parsed.name_servers.contains(&server.to_string()) {
                            parsed.name_servers.push(server.to_string());
                        }
                    },
                    
                    // Status patterns
                    k if k.contains("status") || k.contains("state") => {
                        if !parsed.status.contains(&value.to_string()) {
                            parsed.status.push(value.to_string());
                        }
                    },
                    
                    // Registrant name patterns
                    k if k.starts_with("registrant") && (k.contains("name") || k.contains("organization") || k.contains("org") || k == "registrant") => {
                        if parsed.registrant_name.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.registrant_name = Some(value.to_string());
                        }
                    },
                    
                    // Email patterns
                    k if k.contains("registrant") && k.contains("email") => {
                        if parsed.registrant_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.registrant_email = Some(value.to_string());
                        }
                    },
                    k if k.contains("admin") && k.contains("email") => {
                        if parsed.admin_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.admin_email = Some(value.to_string());
                        }
                    },
                    k if k.contains("tech") && k.contains("email") => {
                        if parsed.tech_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.tech_email = Some(value.to_string());
                        }
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
                    // Organization/Network name (use as "registrar" for consistency)
                    "orgname" | "org-name" | "netname" | "owner" | "organization" => {
                        if parsed.registrar.is_none() {
                            parsed.registrar = Some(value.to_string());
                            analysis.push(format!("✓ Organization: {}", value));
                        }
                    },

                    // Dates
                    "updated" | "lastupdated" | "changed" | "last-modified" => {
                        if parsed.updated_date.is_none() {
                            parsed.updated_date = Some(value.to_string());
                            analysis.push(format!("✓ Updated Date: {}", value));
                        }
                    },
                    "created" | "regdate" | "registration" => {
                        if parsed.creation_date.is_none() {
                            parsed.creation_date = Some(value.to_string());
                            analysis.push(format!("✓ Created Date: {}", value));
                        }
                    },

                    // Contact emails
                    k if k.contains("orgtechemail") || k.contains("tech-c") || k.contains("technical") => {
                        if parsed.tech_email.is_none() {
                            parsed.tech_email = Some(value.to_string());
                            analysis.push(format!("✓ Tech Email: {}", value));
                        }
                    },
                    k if k.contains("orgabuseemail") || k.contains("abuse-c") || k.contains("abuse") => {
                        if parsed.admin_email.is_none() {
                            parsed.admin_email = Some(value.to_string());
                            analysis.push(format!("✓ Abuse Email: {}", value));
                        }
                    },
                    k if k.contains("orgemail") || k.contains("e-mail") || k.contains("email") => {
                        if parsed.registrant_email.is_none() {
                            parsed.registrant_email = Some(value.to_string());
                            analysis.push(format!("✓ Contact Email: {}", value));
                        }
                    },

                    // Status
                    "status" | "nettype" => {
                        if !parsed.status.contains(&value.to_string()) {
                            parsed.status.push(value.to_string());
                            analysis.push(format!("✓ Status: {}", value));
                        }
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