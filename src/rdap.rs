//! RDAP (Registration Data Access Protocol) Service
//! 
//! Modern successor to WHOIS providing structured JSON responses.
//! RFC 7480-7484 compliant implementation with hybrid discovery.

use crate::{
    config::Config,
    errors::WhoisError,
    ParsedWhoisData,
    tld::extract_tld,
    dates,
};
use once_cell::sync::Lazy;  // Used by include!(rdap_mappings.rs)
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{OnceCell, Semaphore};
use tracing::{debug, info, warn};
use url::Url;

// RDAP Bootstrap Service URL for dynamic discovery
const RDAP_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

// Include the auto-generated RDAP mappings from build script
include!(concat!(env!("OUT_DIR"), "/rdap_mappings.rs"));

pub struct RdapService {
    config: Arc<Config>,
    client: reqwest::Client,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    /// Bootstrap cache using tokio::sync::OnceCell for proper async initialization
    /// get_or_try_init prevents concurrent fetches - only one thread fetches, others wait
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

#[derive(Debug, Clone, Deserialize)]
struct RdapBootstrap {
    services: Vec<RdapBootstrapEntry>,
    #[serde(rename = "publicationDate")]
    #[allow(dead_code)]
    publication_date: Option<String>,
    #[allow(dead_code)]
    version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RdapBootstrapEntry {
    #[serde(rename = "0")]
    tlds: Vec<String>,
    #[serde(rename = "1")]
    servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RdapDomainResponse {
    #[serde(rename = "nameservers")]
    name_servers: Option<Vec<RdapNameserver>>,
    events: Option<Vec<RdapEvent>>,
    entities: Option<Vec<RdapEntity>>,
    status: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RdapNameserver {
    #[serde(rename = "ldhName")]
    ldh_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: Option<String>,
    #[serde(rename = "eventDate")]
    event_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RdapEntity {
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
            config: config.clone(),
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
        
        // Extract TLD from the domain using shared PSL-based extraction
        let tld = extract_tld(&domain)?;
        
        // Find appropriate RDAP server (hybrid: hardcoded + bootstrap discovery)
        let rdap_server = self.find_rdap_server(&tld).await?;
        
        // Perform RDAP query
        let raw_data = self.query_rdap_server(&rdap_server, &domain).await?;
        
        // Parse RDAP JSON response into our standard format
        let (parsed_data, parsing_analysis) = Self::parse_rdap_response(&raw_data);
        
        Ok(RdapResult {
            server: rdap_server,
            raw_data,
            parsed_data,
            parsing_analysis,
        })
    }

    async fn find_rdap_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check generated RDAP mappings first (instant lookup, no lock needed)
        if let Some(server) = GENERATED_RDAP_SERVERS.get(tld) {
            debug!("Using generated RDAP server for {}: {}", tld, server);
            return Ok(server.to_string());
        }

        // Check cache for dynamically discovered servers
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                debug!("Using cached RDAP server for {}: {}", tld, server);
                return Ok(server.clone());
            }
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

        // Use get_or_try_init to safely handle concurrent initialization
        // This prevents race conditions and panics from double-initialization
        let bootstrap = match self.get_or_fetch_bootstrap().await {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to fetch RDAP bootstrap data: {}", e);
                return None;
            }
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

    /// Safely get or fetch bootstrap data using tokio's get_or_try_init
    /// Only one thread fetches, others wait - prevents concurrent HTTP requests
    async fn get_or_fetch_bootstrap(&self) -> Result<&RdapBootstrap, WhoisError> {
        self.bootstrap_cache
            .get_or_try_init(|| self.fetch_bootstrap_data())
            .await
    }

    async fn fetch_bootstrap_data(&self) -> Result<RdapBootstrap, WhoisError> {
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

        info!("Successfully fetched RDAP bootstrap data");
        Ok(bootstrap_data)
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

        // Check content-length header before downloading (if available)
        if let Some(content_length) = response.content_length() {
            if content_length as usize > self.config.max_response_size {
                return Err(WhoisError::ResponseTooLarge);
            }
        }

        let raw_data = response
            .text()
            .await
            .map_err(|e| WhoisError::HttpError(e))?;

        // Check actual size (content-length might be missing or wrong)
        if raw_data.len() > self.config.max_response_size {
            return Err(WhoisError::ResponseTooLarge);
        }

        debug!("RDAP response length: {} bytes", raw_data.len());
        Ok(raw_data)
    }

    fn parse_rdap_response(raw_data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
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
                                    if let Some(registrar_name) = Self::extract_registrar_from_vcard(vcard) {
                                        parsed.registrar = Some(registrar_name);
                                    }
                                }
                            }
                            
                            if roles.contains(&"registrant".to_string()) {
                                if let Some(ref vcard) = entity.vcard_array {
                                    if let Some(name) = Self::extract_name_from_vcard(vcard) {
                                        parsed.registrant_name = Some(name);
                                    }
                                    if let Some(email) = Self::extract_email_from_vcard(vcard) {
                                        parsed.registrant_email = Some(email);
                                    }
                                }
                            }
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

    fn extract_registrar_from_vcard(_vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        debug!("vCard registrar extraction not yet implemented");
        None
    }

    fn extract_name_from_vcard(_vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        debug!("vCard name extraction not yet implemented");
        None
    }

    fn extract_email_from_vcard(_vcard: &serde_json::Value) -> Option<String> {
        // vCard arrays in RDAP are complex - this is a simplified extraction
        // TODO: Implement proper vCard parsing if needed
        debug!("vCard email extraction not yet implemented");
        None
    }
} 