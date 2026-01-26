//! RDAP (Registration Data Access Protocol) Service
//! 
//! Modern successor to WHOIS providing structured JSON responses.
//! RFC 7480-7484 compliant implementation with hybrid discovery.

use crate::{
    config::Config,
    errors::WhoisError,
    ParsedWhoisData,
};
use once_cell::sync::{Lazy, OnceCell};
use publicsuffix::{List, Psl};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use url::Url;

// Global PSL instance - shared across all service instances
static PSL: Lazy<Option<List>> = Lazy::new(|| {
    match List::new() {
        list => Some(list),
    }
});

// RDAP Bootstrap Service URL for dynamic discovery
const RDAP_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

// Include the auto-generated RDAP mappings from build script
include!(concat!(env!("OUT_DIR"), "/rdap_mappings.rs"));

pub struct RdapService {
    client: reqwest::Client,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    bootstrap_cache: OnceCell<RdapBootstrap>,
    query_semaphore: Arc<Semaphore>,
    discovery_semaphore: Arc<Semaphore>,
}

pub struct RdapResult {
    pub server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub parsing_analysis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapBootstrap {
    services: Vec<RdapBootstrapEntry>,
    #[serde(rename = "publicationDate")]
    publication_date: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapBootstrapEntry {
    #[serde(rename = "0")]
    tlds: Vec<String>,
    #[serde(rename = "1")]
    servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapDomainResponse {
    #[serde(rename = "objectClassName")]
    object_class_name: Option<String>,
    handle: Option<String>,
    #[serde(rename = "ldhName")]
    ldh_name: Option<String>,
    #[serde(rename = "nameservers")]
    name_servers: Option<Vec<RdapNameserver>>,
    events: Option<Vec<RdapEvent>>,
    entities: Option<Vec<RdapEntity>>,
    status: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapNameserver {
    #[serde(rename = "objectClassName")]
    object_class_name: Option<String>,
    #[serde(rename = "ldhName")]
    ldh_name: Option<String>,
    #[serde(rename = "unicodeName")]
    unicode_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: Option<String>,
    #[serde(rename = "eventDate")]
    event_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapEntity {
    #[serde(rename = "objectClassName")]
    object_class_name: Option<String>,
    handle: Option<String>,
    roles: Option<Vec<String>>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
}

impl RdapService {
    pub async fn new(config: Arc<Config>) -> Result<Self, WhoisError> {
        // Create HTTP client with appropriate timeouts and settings
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.whois_timeout_seconds))
            .user_agent("whois-service/0.1.0 (RDAP client)")
            .gzip(true)
            .build()
            .map_err(|e| WhoisError::HttpError(e))?;

        let service = Self {
            client,
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            bootstrap_cache: OnceCell::new(),
            query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
        };

        info!("RdapService initialized with hybrid discovery (hardcoded + bootstrap)");
        info!("Generated RDAP servers: {} entries", GENERATED_RDAP_SERVERS.len());
        
        Ok(service)
    }

    /// Perform RDAP lookup for a domain
    /// Returns structured data that doesn't require parsing
    pub async fn lookup(&self, domain: &str) -> Result<RdapResult, WhoisError> {
        let domain = domain.trim().to_lowercase();
        
        // Basic validation - assume domain is pre-parsed and valid
        if domain.is_empty() || !domain.contains('.') {
            return Err(WhoisError::InvalidDomain(domain));
        }
        
        // Extract TLD from the domain using global PSL
        let tld = self.extract_tld(&domain)?;
        
        // Find appropriate RDAP server (hybrid: hardcoded + bootstrap discovery)
        let rdap_server = self.find_rdap_server(&tld).await?;
        
        // Perform RDAP query
        let raw_data = self.query_rdap_server(&rdap_server, &domain).await?;
        
        // Parse RDAP JSON response into our standard format
        let (parsed_data, parsing_analysis) = self.parse_rdap_response(&raw_data);
        
        Ok(RdapResult {
            server: rdap_server,
            raw_data,
            parsed_data,
            parsing_analysis,
        })
    }

    /// Extract TLD from domain using global PSL for accurate parsing
    fn extract_tld(&self, domain: &str) -> Result<String, WhoisError> {
        // Parse the domain using the global public suffix list
        match PSL.as_ref() {
            Some(psl) => {
                match psl.domain(domain.as_bytes()) {
                    Some(parsed_domain) => {
                        // Get the public suffix (effective TLD)
                        let suffix = parsed_domain.suffix();
                        match std::str::from_utf8(suffix.as_bytes()) {
                            Ok(tld) => Ok(tld.to_string()),
                            Err(_) => Err(WhoisError::InvalidDomain(format!("Invalid UTF-8 in TLD for domain: {}", domain)))
                        }
                    },
                    None => {
                        // Fallback to simple extraction if PSL parsing fails
                        warn!("Public suffix parsing failed for {}, using fallback", domain);
                        let parts: Vec<&str> = domain.split('.').collect();
                        if parts.is_empty() {
                            Err(WhoisError::InvalidDomain(format!("No TLD found in domain: {}", domain)))
                        } else {
                            Ok(parts[parts.len() - 1].to_string())
                        }
                    }
                }
            },
            None => {
                // Fallback to simple extraction if PSL is not initialized
                warn!("Public suffix list is not initialized, using fallback");
                let parts: Vec<&str> = domain.split('.').collect();
                if parts.is_empty() {
                    Err(WhoisError::InvalidDomain(format!("No TLD found in domain: {}", domain)))
                } else {
                    Ok(parts[parts.len() - 1].to_string())
                }
            }
        }
    }

    async fn find_rdap_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check cache first
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                debug!("Using cached RDAP server for {}: {}", tld, server);
                return Ok(server.clone());
            }
        }

        // Check generated RDAP mappings first (instant lookup for popular TLDs)
        if let Some(server) = GENERATED_RDAP_SERVERS.get(tld) {
            info!("Using generated RDAP server for {}: {}", tld, server);
            return Ok(server.to_string());
        }

        // Dynamic discovery using IANA bootstrap service
        if let Some(server) = self.discover_rdap_server_bootstrap(tld).await {
            // Cache the discovered server
            {
                let mut servers = self.tld_servers.write().await;
                servers.insert(tld.to_string(), server.clone());
            }
            return Ok(server);
        }

        Err(WhoisError::UnsupportedTld(format!("No RDAP server found for TLD: {}", tld)))
    }

    async fn discover_rdap_server_bootstrap(&self, tld: &str) -> Option<String> {
        debug!("Discovering RDAP server for TLD via bootstrap: {}", tld);

        // Check if we have cached bootstrap data
        let needs_refresh = {
            self.bootstrap_cache.get().is_none()
        };

        // Fetch bootstrap data if needed
        if needs_refresh {
            if let Err(e) = self.fetch_bootstrap_data().await {
                warn!("Failed to fetch RDAP bootstrap data: {}", e);
                return None;
            }
        }

        // Search bootstrap data for the TLD
        let bootstrap = match self.bootstrap_cache.get() {
            Some(data) => data,
            None => return None,
        };
        
        for service in &bootstrap.services {
            if service.tlds.contains(&tld.to_string()) {
                if let Some(server) = service.servers.first() {
                    info!("Discovered RDAP server via bootstrap for {}: {}", tld, server);
                    return Some(server.clone());
                }
            }
        }

        warn!("Could not discover RDAP server for TLD: {}", tld);
        None
    }

    async fn fetch_bootstrap_data(&self) -> Result<(), WhoisError> {
        debug!("Fetching RDAP bootstrap data from IANA");

        let _permit = self.discovery_semaphore.acquire().await
            .map_err(|_| WhoisError::Internal("Semaphore acquisition failed".to_string()))?;

        let response = self.client
            .get(RDAP_BOOTSTRAP_URL)
            .send()
            .await
            .map_err(|e| WhoisError::HttpError(e))?;

        if !response.status().is_success() {
            return Err(WhoisError::Internal(format!("Bootstrap fetch failed with status: {}", response.status())));
        }

        let bootstrap_data: RdapBootstrap = response
            .json()
            .await
            .map_err(|e| WhoisError::HttpError(e))?;

        // Cache the bootstrap data
        self.bootstrap_cache.set(bootstrap_data).expect("Bootstrap cache should only be set once");

        info!("Successfully fetched and cached RDAP bootstrap data");
        Ok(())
    }

    async fn query_rdap_server(&self, server: &str, domain: &str) -> Result<String, WhoisError> {
        let _permit = self.query_semaphore.acquire().await
            .map_err(|_| WhoisError::Internal("Semaphore acquisition failed".to_string()))?;

        // Construct RDAP URL using proper URL parsing for security
        let base_url = Url::parse(server)
            .map_err(|e| WhoisError::Internal(format!("Invalid RDAP server URL '{}': {}", server, e)))?;
        
        let url = base_url.join(&format!("domain/{}", domain))
            .map_err(|e| WhoisError::Internal(format!("Failed to construct RDAP URL: {}", e)))?;

        debug!("Querying RDAP server: {}", url);

        let response = self.client
            .get(url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
            .map_err(|e| WhoisError::HttpError(e))?;

        if !response.status().is_success() {
            return Err(WhoisError::Internal(format!("RDAP query failed with status: {}", response.status())));
        }

        let raw_data = response
            .text()
            .await
            .map_err(|e| WhoisError::HttpError(e))?;

        debug!("RDAP response length: {} bytes", raw_data.len());
        Ok(raw_data)
    }

    fn parse_rdap_response(&self, raw_data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        analysis.push("=== RDAP PARSING ANALYSIS ===".to_string());

        // Parse JSON response
        let rdap_response: Result<RdapDomainResponse, _> = serde_json::from_str(raw_data);
        
        match rdap_response {
            Ok(rdap) => {
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

                // Extract name servers
                if let Some(ref nameservers) = rdap.name_servers {
                    for ns in nameservers {
                        if let Some(ref name) = ns.ldh_name {
                            parsed.name_servers.push(name.clone());
                        }
                    }
                }

                // Extract status information
                if let Some(ref status) = rdap.status {
                    parsed.status = status.clone();
                }

                // Extract events (creation, expiration, last update)
                if let Some(ref events) = rdap.events {
                    for event in events {
                        if let (Some(ref action), Some(ref date)) = (&event.event_action, &event.event_date) {
                            match action.as_str() {
                                "registration" => parsed.creation_date = Some(date.clone()),
                                "expiration" => parsed.expiration_date = Some(date.clone()),
                                "last changed" | "last update of RDAP database" => {
                                    if parsed.updated_date.is_none() {
                                        parsed.updated_date = Some(date.clone());
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }

                // Extract registrar and contact information from entities
                if let Some(ref entities) = rdap.entities {
                    for entity in entities {
                        if let Some(ref roles) = entity.roles {
                            if roles.contains(&"registrar".to_string()) {
                                // Extract registrar name from vCard if available
                                if let Some(ref vcard) = entity.vcard_array {
                                    if let Some(registrar_name) = self.extract_registrar_from_vcard(vcard) {
                                        parsed.registrar = Some(registrar_name);
                                    }
                                }
                            }
                            
                            if roles.contains(&"registrant".to_string()) {
                                if let Some(ref vcard) = entity.vcard_array {
                                    if let Some(name) = self.extract_name_from_vcard(vcard) {
                                        parsed.registrant_name = Some(name);
                                    }
                                    if let Some(email) = self.extract_email_from_vcard(vcard) {
                                        parsed.registrant_email = Some(email);
                                    }
                                }
                            }
                        }
                    }
                }

                // Calculate date-based fields using the same logic as WHOIS parser
                self.calculate_date_fields(&mut parsed);

                analysis.push(format!("✓ RDAP JSON parsed successfully"));
                analysis.push(format!("✓ Registrar: {}", parsed.registrar.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("✓ Creation Date: {}", parsed.creation_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("✓ Expiration Date: {}", parsed.expiration_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("✓ Name Servers: {} found", parsed.name_servers.len()));
                analysis.push(format!("✓ Status: {} found", parsed.status.len()));

                (Some(parsed), analysis)
            }
            Err(e) => {
                analysis.push(format!("❌ Failed to parse RDAP JSON: {}", e));
                analysis.push("Raw response (first 500 chars):".to_string());
                analysis.push(raw_data.chars().take(500).collect::<String>());
                (None, analysis)
            }
        }
    }

    fn calculate_date_fields(&self, parsed: &mut ParsedWhoisData) {
        let now = chrono::Utc::now();
        
        // Calculate created_ago (days since creation)
        if let Some(ref creation_date) = parsed.creation_date {
            if let Some(created_dt) = self.parse_iso_date(creation_date) {
                let days_ago = (now - created_dt).num_days();
                parsed.created_ago = Some(days_ago);
            }
        }
        
        // Calculate updated_ago (days since last update)
        if let Some(ref updated_date) = parsed.updated_date {
            if let Some(updated_dt) = self.parse_iso_date(updated_date) {
                let days_ago = (now - updated_dt).num_days();
                parsed.updated_ago = Some(days_ago);
            }
        }
        
        // Calculate expires_in (days until expiration, negative if expired)
        if let Some(ref expiration_date) = parsed.expiration_date {
            if let Some(expires_dt) = self.parse_iso_date(expiration_date) {
                let days_until = (expires_dt - now).num_days();
                parsed.expires_in = Some(days_until);
            }
        }
    }

    fn parse_iso_date(&self, date_str: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        // RDAP dates are typically ISO 8601 format
        chrono::DateTime::parse_from_rfc3339(date_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .ok()
    }

    fn extract_registrar_from_vcard(&self, _vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        None
    }

    fn extract_name_from_vcard(&self, _vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        None
    }

    fn extract_email_from_vcard(&self, _vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        None
    }
} 