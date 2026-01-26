use crate::{ParsedWhoisData, dates};

/// Stateless WHOIS response parser
/// 
/// All methods are associated functions since parsing is pure computation.
/// No instance is needed - use `WhoisParser::parse_whois_data(data)` directly.
pub struct WhoisParser;

impl WhoisParser {
    /// Parse raw WHOIS data into structured fields
    pub fn parse_whois_data(data: &str) -> ParsedWhoisData {
        let mut parsed = ParsedWhoisData {
            registrar: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            name_servers: Vec::new(),
            status: Vec::new(),
            registrant_name: None,
            registrant_email: None,
            admin_email: None,
            tech_email: None,
            created_ago: None,
            updated_ago: None,
            expires_in: None,
        };

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
        let (created_ago, updated_ago, expires_in) = dates::calculate_date_fields(
            &parsed.creation_date,
            &parsed.updated_date,
            &parsed.expiration_date,
        );
        parsed.created_ago = created_ago;
        parsed.updated_ago = updated_ago;
        parsed.expires_in = expires_in;

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
} 