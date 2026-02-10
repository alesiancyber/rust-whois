//! RDAP (Registration Data Access Protocol) Service
//! 
//! Modern successor to WHOIS providing structured JSON responses.
//! RFC 7480-7484 compliant implementation with hybrid discovery.

use crate::{
    config::Config,
    errors::WhoisError,
    ParsedWhoisData,
    tld::extract_tld,
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

/// Maximum retry attempts for transient failures
/// Uses exponential backoff: immediate, +1s, +2s
const MAX_RETRY_ATTEMPTS: usize = 3;

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

/// Type alias for RDAP lookup results
///
/// Uses the unified LookupResult structure to eliminate duplication
/// with WHOIS results. Maintains backward compatibility.
pub type RdapResult = crate::LookupResult;

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
            .map_err(WhoisError::HttpError)?;

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
    /// Assumes domain is already validated and normalized by ValidatedDomain
    pub async fn lookup(&self, domain: &str) -> Result<RdapResult, WhoisError> {
        // Domain is already validated and normalized by ValidatedDomain - no need to re-check

        // Extract TLD from the domain using shared PSL-based extraction
        let tld = extract_tld(domain)?;
        
        // Find appropriate RDAP server (hybrid: hardcoded + bootstrap discovery)
        let rdap_server = self.find_rdap_server(&tld).await?;
        
        // Perform RDAP query
        let raw_data = self.query_rdap_server(&rdap_server, domain).await?;
        
        // Parse RDAP JSON response into our standard format
        let (parsed_data, parsing_analysis) = Self::parse_rdap_response(&raw_data);
        
        Ok(RdapResult {
            server: rdap_server,
            raw_data,
            parsed_data,
            parsing_analysis,
        })
    }

    /// Perform RDAP lookup for an IP address (IPv4 or IPv6)
    ///
    /// RDAP provides better structured data for IPs than traditional WHOIS.
    /// Assumes IP is already validated.
    ///
    /// # Arguments
    ///
    /// * `ip_addr` - Validated IP address string
    ///
    /// # Returns
    ///
    /// RdapResult containing server info, raw JSON data, and parsed fields
    pub async fn lookup_ip(&self, ip_addr: &str) -> Result<RdapResult, WhoisError> {
        use crate::ip::{ValidatedIpAddress, detect_rir};

        // Validate IP and detect RIR
        let validated_ip = ValidatedIpAddress::new(ip_addr)?;
        let rir = detect_rir(&validated_ip)?;

        // Get RDAP server for this RIR
        let rdap_server = rir.rdap_server();

        debug!("Using RIR RDAP server for IP {}: {} ({})", ip_addr, rdap_server, format!("{:?}", rir));

        // Perform RDAP query for IP
        let raw_data = self.query_rdap_server_ip(rdap_server, ip_addr).await?;

        // Parse RDAP JSON response for IP
        let (parsed_data, parsing_analysis) = Self::parse_rdap_ip_response(&raw_data);

        Ok(RdapResult {
            server: rdap_server.to_string(),
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
            // Cache the discovered server using double-checked locking pattern
            {
                let mut servers = self.tld_servers.write().await;
                // Check again in case another thread just inserted it (avoids duplicate work)
                if !servers.contains_key(tld) {
                    servers.insert(tld.to_string(), server.clone());
                }
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
            .map_err(WhoisError::HttpError)?;

        if !response.status().is_success() {
            return Err(WhoisError::Internal(format!("Bootstrap fetch failed with status: {}", response.status())));
        }

        let bootstrap_data: RdapBootstrap = response
            .json()
            .await
            .map_err(WhoisError::HttpError)?;

        info!("Successfully fetched RDAP bootstrap data");
        Ok(bootstrap_data)
    }

    /// Generic RDAP query method for both domains and IPs
    ///
    /// Consolidates duplicate code between domain and IP queries.
    /// The only differences are the URL path segment and debug messages.
    async fn query_rdap_resource(&self, server: &str, resource_type: &str, query: &str) -> Result<String, WhoisError> {
        use backon::{ExponentialBuilder, Retryable};

        let _permit = self.query_semaphore.acquire().await
            .map_err(|_| WhoisError::Internal("Semaphore acquisition failed".to_string()))?;

        // Construct RDAP URL with proper percent-encoding for security
        let mut url = Url::parse(server)
            .map_err(|e| WhoisError::Internal(format!("Invalid RDAP server URL '{}': {}", server, e)))?;

        // Use path_segments_mut for automatic URL encoding
        url.path_segments_mut()
            .map_err(|_| WhoisError::Internal("Cannot construct RDAP URL (base URL cannot be a base)".to_string()))?
            .push(resource_type)
            .push(query);

        debug!("Querying RDAP server for {}: {}", resource_type, url);

        // Retry transient HTTP errors with exponential backoff
        // Max 3 attempts: immediate, +1s, +2s
        let raw_data = (|| async {
            let response = self.client
                .get(url.clone())
                .header("Accept", "application/rdap+json, application/json")
                .send()
                .await
                .map_err(WhoisError::HttpError)?;

            if !response.status().is_success() {
                return Err(WhoisError::Internal(format!("RDAP {} query failed with status: {}", resource_type, response.status())));
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
                .map_err(WhoisError::HttpError)?;

            // Check actual size (content-length might be missing or wrong)
            if raw_data.len() > self.config.max_response_size {
                return Err(WhoisError::ResponseTooLarge);
            }

            Ok(raw_data)
        })
        .retry(&ExponentialBuilder::default().with_max_times(MAX_RETRY_ATTEMPTS))
        .when(|e: &WhoisError| {
            // Retry only on transient network errors, not on client errors
            matches!(e, WhoisError::Timeout | WhoisError::HttpError(_))
        })
        .await?;

        debug!("RDAP {} response length: {} bytes", resource_type, raw_data.len());
        Ok(raw_data)
    }

    async fn query_rdap_server(&self, server: &str, domain: &str) -> Result<String, WhoisError> {
        self.query_rdap_resource(server, "domain", domain).await
    }

    /// Query RDAP server for IP address information
    async fn query_rdap_server_ip(&self, server: &str, ip: &str) -> Result<String, WhoisError> {
        self.query_rdap_resource(server, "ip", ip).await
    }

    fn parse_rdap_response(raw_data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        analysis.push("=== RDAP PARSING ANALYSIS ===".to_string());

        // Parse JSON response
        let rdap_response: Result<RdapDomainResponse, _> = serde_json::from_str(raw_data);
        
        match rdap_response {
            Ok(rdap) => {
                let mut parsed = ParsedWhoisData::new();

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
                parsed.calculate_age_fields();

                analysis.push("✓ RDAP JSON parsed successfully".to_string());
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

    /// Parse RDAP IP response (different structure than domain responses)
    ///
    /// IP RDAP responses have different fields:
    /// - startAddress, endAddress (IP range)
    /// - cidr0_cidrs (CIDR notation)
    /// - name (network name)
    /// - type (allocation type)
    /// - entities (organizations, contacts)
    fn parse_rdap_ip_response(raw_data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        analysis.push("=== RDAP IP PARSING ANALYSIS ===".to_string());

        // Parse as generic JSON (IP RDAP structure differs from domain RDAP)
        let rdap_response: Result<serde_json::Value, _> = serde_json::from_str(raw_data);

        match rdap_response {
            Ok(json) => {
                let mut parsed = ParsedWhoisData::new();

                // Extract network name (use as "registrar" for consistency)
                if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                    parsed.registrar = Some(name.to_string());
                    analysis.push(format!("✓ Network Name: {}", name));
                }

                // Extract CIDR blocks
                if let Some(cidr_array) = json.get("cidr0_cidrs").and_then(|v| v.as_array()) {
                    for cidr in cidr_array {
                        if let Some(cidr_str) = cidr.get("v4prefix").or_else(|| cidr.get("v6prefix")).and_then(|v| v.as_str()) {
                            analysis.push(format!("✓ CIDR: {}", cidr_str));
                        }
                    }
                }

                // Extract IP range
                if let (Some(start), Some(end)) = (
                    json.get("startAddress").and_then(|v| v.as_str()),
                    json.get("endAddress").and_then(|v| v.as_str())
                ) {
                    analysis.push(format!("✓ IP Range: {} - {}", start, end));
                }

                // Extract status
                if let Some(status) = json.get("status").and_then(|v| v.as_array()) {
                    parsed.status = status.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect();
                    analysis.push(format!("✓ Status: {} entries", parsed.status.len()));
                }

                // Extract events (registration, last update)
                if let Some(events) = json.get("events").and_then(|v| v.as_array()) {
                    for event in events {
                        if let (Some(action), Some(date)) = (
                            event.get("eventAction").and_then(|v| v.as_str()),
                            event.get("eventDate").and_then(|v| v.as_str())
                        ) {
                            match action {
                                "registration" => {
                                    parsed.creation_date = Some(date.to_string());
                                    analysis.push(format!("✓ Registration Date: {}", date));
                                },
                                "last changed" | "last update of RDAP database" => {
                                    if parsed.updated_date.is_none() {
                                        parsed.updated_date = Some(date.to_string());
                                        analysis.push(format!("✓ Last Updated: {}", date));
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }

                // Extract entities (organizations, contacts)
                if let Some(entities) = json.get("entities").and_then(|v| v.as_array()) {
                    for entity in entities {
                        // Extract organization name from vCard
                        if let Some(vcard) = entity.get("vcardArray") {
                            if let Some(name) = Self::extract_name_from_vcard(vcard) {
                                if parsed.registrant_name.is_none() {
                                    parsed.registrant_name = Some(name.clone());
                                    analysis.push(format!("✓ Organization: {}", name));
                                }
                            }
                            if let Some(email) = Self::extract_email_from_vcard(vcard) {
                                // Determine role from entity roles
                                if let Some(roles) = entity.get("roles").and_then(|v| v.as_array()) {
                                    let role_strings: Vec<String> = roles.iter()
                                        .filter_map(|r| r.as_str().map(|s| s.to_string()))
                                        .collect();

                                    if role_strings.contains(&"technical".to_string()) && parsed.tech_email.is_none() {
                                        parsed.tech_email = Some(email.clone());
                                        analysis.push(format!("✓ Tech Email: {}", email));
                                    } else if role_strings.contains(&"abuse".to_string()) && parsed.admin_email.is_none() {
                                        parsed.admin_email = Some(email.clone());
                                        analysis.push(format!("✓ Abuse Email: {}", email));
                                    } else if parsed.registrant_email.is_none() {
                                        parsed.registrant_email = Some(email);
                                    }
                                }
                            }
                        }
                    }
                }

                // Calculate date-based fields
                parsed.calculate_age_fields();

                analysis.push("\n=== SUMMARY ===".to_string());
                analysis.push(format!("Network/Organization: {}", parsed.registrar.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("Created: {}", parsed.creation_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("Updated: {}", parsed.updated_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
                analysis.push(format!("Status entries: {}", parsed.status.len()));

                (Some(parsed), analysis)
            }
            Err(e) => {
                analysis.push(format!("❌ Failed to parse RDAP IP JSON: {}", e));
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