use crate::ParsedWhoisData;
use chrono::{DateTime, Utc, NaiveDateTime};
use tracing::debug;

pub struct WhoisParser;

impl WhoisParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_whois_data(&self, data: &str) -> Option<ParsedWhoisData> {
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

        // Calculate date-based fields
        let now = Utc::now();
        
        // Calculate created_ago (days since creation)
        if let Some(ref creation_date) = parsed.creation_date {
            if let Some(created_dt) = self.parse_date(creation_date) {
                let days_ago = (now - created_dt).num_days();
                parsed.created_ago = Some(days_ago);
            }
        }
        
        // Calculate updated_ago (days since last update)
        if let Some(ref updated_date) = parsed.updated_date {
            if let Some(updated_dt) = self.parse_date(updated_date) {
                let days_ago = (now - updated_dt).num_days();
                parsed.updated_ago = Some(days_ago);
            }
        }
        
        // Calculate expires_in (days until expiration, negative if expired)
        if let Some(ref expiration_date) = parsed.expiration_date {
            if let Some(expires_dt) = self.parse_date(expiration_date) {
                let days_until = (expires_dt - now).num_days();
                parsed.expires_in = Some(days_until);
            }
        }

        Some(parsed)
    }

    pub fn parse_whois_data_with_analysis(&self, data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        
        // Parse the data
        let parsed_data = self.parse_whois_data(data);
        
        // Analyze what was found
        analysis.push("=== PARSING ANALYSIS ===".to_string());
        
        if let Some(ref parsed) = parsed_data {
            analysis.push(format!("✓ Registrar: {}", parsed.registrar.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Creation Date: {}", parsed.creation_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Expiration Date: {}", parsed.expiration_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Updated Date: {}", parsed.updated_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Registrant Name: {}", parsed.registrant_name.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Name Servers: {} found", parsed.name_servers.len()));
            analysis.push(format!("✓ Status: {} found", parsed.status.len()));
        }
        
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
        
        (parsed_data, analysis)
    }

    /// Parse various date formats commonly found in whois data
    fn parse_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        let date_str = date_str.trim();
        
        // Common whois date formats to try
        let formats = [
            "%Y-%m-%dT%H:%M:%S%.fZ",           // 2025-05-18T13:36:06.0Z
            "%Y-%m-%dT%H:%M:%S%z",             // 2025-05-18T13:36:06+0000
            "%Y-%m-%d %H:%M:%S",               // 2025-05-18 13:36:06
            "%Y-%m-%d",                        // 2025-05-18
            "%d-%b-%Y",                        // 18-May-2025
            "%d %b %Y",                        // 18 May 2025
            "%Y/%m/%d",                        // 2025/05/18
            "%m/%d/%Y",                        // 05/18/2025
            "%d.%m.%Y",                        // 18.05.2025
        ];

        // Try parsing with timezone first
        for format in &formats {
            if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
                return Some(dt.with_timezone(&Utc));
            }
        }

        // Try parsing as naive datetime and assume UTC
        for format in &formats {
            if let Ok(naive_dt) = NaiveDateTime::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
            }
        }

        // Try parsing just the date part and assume midnight UTC
        let date_only_formats = [
            "%Y-%m-%d",
            "%d-%b-%Y", 
            "%d %b %Y",
            "%Y/%m/%d",
            "%m/%d/%Y",
            "%d.%m.%Y",
        ];

        for format in &date_only_formats {
            if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
                if let Some(naive_dt) = naive_date.and_hms_opt(0, 0, 0) {
                    return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
                }
            }
        }

        debug!("Failed to parse date: {}", date_str);
        None
    }
} 