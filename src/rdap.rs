//! RDAP (Registration Data Access Protocol) Service
//! 
//! Modern successor to WHOIS providing structured JSON responses.
//! RFC 7480-7484 compliant implementation with dynamic IANA bootstrap discovery.

use crate::{
    config::Config,
    errors::WhoisError,
    LookupStatus,
    ParsedWhoisData,
    tld::extract_tld,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};
use url::Url;

// RDAP Bootstrap Service URL for dynamic discovery
const RDAP_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

/// Maximum retries for transient failures (up to 4 attempts total)
/// Uses exponential backoff between attempts: +1s, +2s, +4s
const MAX_RETRY_ATTEMPTS: usize = 3;

/// How long fetched IANA bootstrap data stays fresh. IANA republishes the
/// registry as TLDs are added and RDAP endpoints move; a long-running service
/// must not freeze its view at process start. IANA's guidance is daily.
const BOOTSTRAP_REFRESH_SECS: u64 = 24 * 60 * 60;

/// Minimum wait between refetch attempts after a failure, so a broken network
/// or IANA outage doesn't add a fetch attempt to every lookup. Stale data
/// keeps being served in the meantime.
const BOOTSTRAP_RETRY_SECS: u64 = 300;

/// IANA bootstrap data plus the bookkeeping needed to refresh it
#[derive(Default)]
struct BootstrapState {
    data: Option<Arc<RdapBootstrap>>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

/// What to do about the bootstrap data on this access (pure decision,
/// extracted for testability)
#[derive(Debug, PartialEq, Eq)]
enum BootstrapAction {
    /// Data is fresh - use it
    UseCached,
    /// Missing or stale, and no recent failed attempt - fetch now
    Fetch,
    /// Stale but a refetch failed recently - keep serving stale data
    ServeStale,
    /// No data and a fetch failed recently - fail fast until retry window opens
    Unavailable,
}

impl BootstrapState {
    fn decide(&self, refresh_after: Duration, retry_after: Duration) -> BootstrapAction {
        let fresh = self.fetched_at.is_some_and(|t| t.elapsed() < refresh_after);
        if self.data.is_some() && fresh {
            return BootstrapAction::UseCached;
        }

        let attempted_recently = self.last_attempt.is_some_and(|t| t.elapsed() < retry_after);
        match (attempted_recently, self.data.is_some()) {
            (false, _) => BootstrapAction::Fetch,
            (true, true) => BootstrapAction::ServeStale,
            (true, false) => BootstrapAction::Unavailable,
        }
    }
}

pub struct RdapService {
    config: Arc<Config>,
    client: reqwest::Client,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    /// IANA bootstrap data with periodic refresh. A Mutex is fine here:
    /// it's only consulted on TLD discovery misses, which the tld_servers
    /// cache makes rare, and holding it across the initial fetch doubles as
    /// single-flight coalescing.
    bootstrap: Mutex<BootstrapState>,
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
        // Reject hand-built configs with zero values (would deadlock the semaphores)
        config.validate()?;

        // Create HTTP client with appropriate timeouts and settings
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.whois_timeout_seconds))
            .user_agent(concat!("whois-service/", env!("CARGO_PKG_VERSION"), " (RDAP client)"))
            .gzip(true)
            .build()
            .map_err(WhoisError::HttpError)?;

        let service = Self {
            config: config.clone(),
            client,
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            bootstrap: Mutex::new(BootstrapState::default()),
            query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
        };

        info!("RdapService initialized with dynamic discovery (IANA bootstrap + runtime cache)");

        Ok(service)
    }

    /// Perform RDAP lookup for a domain
    /// Returns structured data that doesn't require parsing
    /// Assumes domain is already validated and normalized by ValidatedDomain
    pub async fn lookup(&self, domain: &str) -> Result<RdapResult, WhoisError> {
        // Domain is already validated and normalized by ValidatedDomain - no need to re-check

        // Extract TLD from the domain using shared PSL-based extraction
        let tld = extract_tld(domain)?;
        
        // Find appropriate RDAP server (cached or discovered via IANA bootstrap)
        let rdap_server = self.find_rdap_server(&tld).await?;
        
        // Perform RDAP query
        let (raw_data, status) = self.query_rdap_server(&rdap_server, domain).await?;

        // A 404 is an authoritative "not registered" - no record to parse
        if status == LookupStatus::NotFound {
            return Ok(RdapResult {
                server: rdap_server,
                raw_data,
                parsed_data: None,
                parsing_analysis: vec![format!("Domain {} is not registered (RDAP 404)", domain)],
                status,
            });
        }

        // Parse RDAP JSON response into our standard format
        let (parsed_data, parsing_analysis) = Self::parse_rdap_response(&raw_data);

        Ok(RdapResult {
            server: rdap_server,
            raw_data,
            parsed_data,
            parsing_analysis,
            status,
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
        let (raw_data, status) = self.query_rdap_server_ip(rdap_server, ip_addr).await?;

        // A 404 is an authoritative "no such registration" - no record to parse
        if status == LookupStatus::NotFound {
            return Ok(RdapResult {
                server: rdap_server.to_string(),
                raw_data,
                parsed_data: None,
                parsing_analysis: vec![format!("IP {} has no registration record (RDAP 404)", ip_addr)],
                status,
            });
        }

        // Parse RDAP JSON response for IP
        let (parsed_data, parsing_analysis) = Self::parse_rdap_ip_response(&raw_data);

        Ok(RdapResult {
            server: rdap_server.to_string(),
            raw_data,
            parsed_data,
            parsing_analysis,
            status,
        })
    }

    async fn find_rdap_server(&self, tld: &str) -> Result<String, WhoisError> {
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
        
        let lookup = |candidate: &str| {
            bootstrap
                .services
                .iter()
                .find(|service| service.tlds.iter().any(|t| t == candidate))
                .and_then(|service| service.servers.first().cloned())
        };

        // The IANA bootstrap registry keys services by top label only ("uk"),
        // while PSL extraction returns the full public suffix ("co.uk").
        // Fall back to the last label so multi-part TLDs still reach RDAP.
        let server = lookup(tld).or_else(|| {
            let last_label = tld.rsplit('.').next()?;
            if last_label == tld {
                return None;
            }
            debug!("Bootstrap has no entry for '{}', retrying with '{}'", tld, last_label);
            lookup(last_label)
        });

        match server {
            Some(server) => {
                info!("Discovered RDAP server via bootstrap for {}: {}", tld, server);
                Some(server)
            }
            None => {
                warn!("Could not discover RDAP server for TLD: {}", tld);
                None
            }
        }
    }

    /// Get bootstrap data, fetching or refreshing it as needed.
    ///
    /// - Data older than [`BOOTSTRAP_REFRESH_SECS`] is refetched, so new TLDs
    ///   and migrated RDAP endpoints are picked up by long-running services.
    /// - A failed refresh keeps serving the stale data and backs off for
    ///   [`BOOTSTRAP_RETRY_SECS`] before trying again.
    /// - The Mutex makes concurrent fetches single-flight.
    async fn get_or_fetch_bootstrap(&self) -> Result<Arc<RdapBootstrap>, WhoisError> {
        let mut state = self.bootstrap.lock().await;

        match state.decide(
            Duration::from_secs(BOOTSTRAP_REFRESH_SECS),
            Duration::from_secs(BOOTSTRAP_RETRY_SECS),
        ) {
            BootstrapAction::UseCached | BootstrapAction::ServeStale => {
                Ok(state.data.as_ref().expect("decide() guarantees data").clone())
            }
            BootstrapAction::Unavailable => Err(WhoisError::Internal(
                "RDAP bootstrap data unavailable, retry pending".to_string(),
            )),
            BootstrapAction::Fetch => {
                let is_refresh = state.data.is_some();
                state.last_attempt = Some(Instant::now());

                match self.fetch_bootstrap_data().await {
                    Ok(data) => {
                        let data = Arc::new(data);
                        state.data = Some(data.clone());
                        state.fetched_at = Some(Instant::now());
                        drop(state);

                        if is_refresh {
                            // Discovered-server entries were derived from the old
                            // bootstrap; drop them so migrated endpoints take effect
                            self.tld_servers.write().await.clear();
                            info!("RDAP bootstrap refreshed; cleared discovered-server cache");
                        }
                        Ok(data)
                    }
                    Err(e) => match &state.data {
                        Some(stale) => {
                            warn!("RDAP bootstrap refresh failed ({}); serving stale data", e);
                            Ok(stale.clone())
                        }
                        None => Err(e),
                    },
                }
            }
        }
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
    ///
    /// RDAP's HTTP layer carries lookup semantics: 404 means the object is
    /// not registered (an answer, not a failure - returned as NotFound), and
    /// 429 means the server is throttling us (returned as a RateLimited error
    /// so callers can fall back or back off; never retried here).
    async fn query_rdap_resource(&self, server: &str, resource_type: &str, query: &str) -> Result<(String, LookupStatus), WhoisError> {
        use backon::{ExponentialBuilder, Retryable};

        let _permit = self.query_semaphore.acquire().await
            .map_err(|_| WhoisError::Internal("Semaphore acquisition failed".to_string()))?;

        // Construct RDAP URL with proper percent-encoding for security
        let mut url = Url::parse(server)
            .map_err(|e| WhoisError::Internal(format!("Invalid RDAP server URL '{}': {}", server, e)))?;

        // Use path_segments_mut for automatic URL encoding
        url.path_segments_mut()
            .map_err(|_| WhoisError::Internal("Cannot construct RDAP URL (base URL cannot be a base)".to_string()))?
            .pop_if_empty()
            .push(resource_type)
            .push(query);

        debug!("Querying RDAP server for {}: {}", resource_type, url);

        // Retry transient HTTP errors with exponential backoff
        // (up to 4 attempts total: immediate, then +1s, +2s, +4s)
        let (raw_data, status) = (|| async {
            let response = self.client
                .get(url.clone())
                .header("Accept", "application/rdap+json, application/json")
                .send()
                .await
                .map_err(WhoisError::HttpError)?;

            let http_status = response.status();

            // 404 is a definitive "not registered" answer from the registry
            if http_status == reqwest::StatusCode::NOT_FOUND {
                let body = response.text().await.unwrap_or_default();
                return Ok((body, LookupStatus::NotFound));
            }

            // 429 means we're being throttled - surface it, don't retry into it
            if http_status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(WhoisError::RateLimited(format!(
                    "RDAP server returned 429 for {} query", resource_type
                )));
            }

            if !http_status.is_success() {
                return Err(WhoisError::Internal(format!("RDAP {} query failed with status: {}", resource_type, http_status)));
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

            Ok((raw_data, LookupStatus::Found))
        })
        .retry(&ExponentialBuilder::default().with_max_times(MAX_RETRY_ATTEMPTS))
        .when(|e: &WhoisError| {
            // Retry only on transient network errors - not client errors,
            // and especially not rate limiting
            matches!(e, WhoisError::Timeout | WhoisError::HttpError(_))
        })
        .await?;

        debug!("RDAP {} response length: {} bytes", resource_type, raw_data.len());
        Ok((raw_data, status))
    }

    async fn query_rdap_server(&self, server: &str, domain: &str) -> Result<(String, LookupStatus), WhoisError> {
        self.query_rdap_resource(server, "domain", domain).await
    }

    /// Query RDAP server for IP address information
    async fn query_rdap_server_ip(&self, server: &str, ip: &str) -> Result<(String, LookupStatus), WhoisError> {
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
                                "last changed" | "last update of RDAP database"
                                    if parsed.updated_date.is_none() => {
                                        parsed.updated_date = Some(date.clone());
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

                            if roles.contains(&"administrative".to_string()) {
                                if let Some(ref vcard) = entity.vcard_array {
                                    if parsed.admin_email.is_none() {
                                        parsed.admin_email = Self::extract_email_from_vcard(vcard);
                                    }
                                }
                            }

                            if roles.contains(&"technical".to_string()) {
                                if let Some(ref vcard) = entity.vcard_array {
                                    if parsed.tech_email.is_none() {
                                        parsed.tech_email = Self::extract_email_from_vcard(vcard);
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
                                "last changed" | "last update of RDAP database"
                                    if parsed.updated_date.is_none() => {
                                        parsed.updated_date = Some(date.to_string());
                                        analysis.push(format!("✓ Last Updated: {}", date));
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

    /// Extract the first value of a jCard property (RFC 7095)
    ///
    /// RDAP vcardArray format: `["vcard", [[name, params, type, value], ...]]`
    /// e.g. `["vcard", [["fn", {}, "text", "MarkMonitor Inc."], ...]]`
    ///
    /// Values are usually strings, but structured properties (like "org" or "adr")
    /// can be arrays of strings - those are joined with spaces.
    fn extract_vcard_property(vcard: &serde_json::Value, property: &str) -> Option<String> {
        let entries = vcard.as_array()?.get(1)?.as_array()?;

        for entry in entries {
            let Some(fields) = entry.as_array() else { continue };
            let Some(name) = fields.first().and_then(|v| v.as_str()) else { continue };
            if !name.eq_ignore_ascii_case(property) {
                continue;
            }

            match fields.get(3) {
                Some(serde_json::Value::String(s)) if !s.trim().is_empty() => {
                    return Some(s.trim().to_string());
                }
                Some(serde_json::Value::Array(parts)) => {
                    let joined = parts
                        .iter()
                        .filter_map(|p| p.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !joined.is_empty() {
                        return Some(joined);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn extract_registrar_from_vcard(vcard: &serde_json::Value) -> Option<String> {
        // Registrar entities carry their name in "fn" (formatted name) or "org"
        Self::extract_vcard_property(vcard, "fn")
            .or_else(|| Self::extract_vcard_property(vcard, "org"))
    }

    fn extract_name_from_vcard(vcard: &serde_json::Value) -> Option<String> {
        Self::extract_vcard_property(vcard, "fn")
            .or_else(|| Self::extract_vcard_property(vcard, "org"))
    }

    fn extract_email_from_vcard(vcard: &serde_json::Value) -> Option<String> {
        Self::extract_vcard_property(vcard, "email")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_bootstrap() -> Arc<RdapBootstrap> {
        Arc::new(RdapBootstrap {
            services: vec![],
            publication_date: None,
            version: None,
        })
    }

    const HOUR: Duration = Duration::from_secs(3600);
    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn test_bootstrap_decide_fresh_data_is_used() {
        let state = BootstrapState {
            data: Some(empty_bootstrap()),
            fetched_at: Some(Instant::now()),
            last_attempt: Some(Instant::now()),
        };
        assert_eq!(state.decide(HOUR, MINUTE), BootstrapAction::UseCached);
    }

    #[test]
    fn test_bootstrap_decide_cold_start_fetches() {
        let state = BootstrapState::default();
        assert_eq!(state.decide(HOUR, MINUTE), BootstrapAction::Fetch);
    }

    #[test]
    fn test_bootstrap_decide_stale_data_refreshes() {
        // refresh_after of zero makes any data stale; no recent attempt
        let state = BootstrapState {
            data: Some(empty_bootstrap()),
            fetched_at: Some(Instant::now()),
            last_attempt: None,
        };
        assert_eq!(state.decide(Duration::ZERO, MINUTE), BootstrapAction::Fetch);
    }

    #[test]
    fn test_bootstrap_decide_failed_refresh_serves_stale() {
        // Stale data + recent failed attempt -> keep serving stale, don't hammer IANA
        let state = BootstrapState {
            data: Some(empty_bootstrap()),
            fetched_at: Some(Instant::now()),
            last_attempt: Some(Instant::now()),
        };
        assert_eq!(state.decide(Duration::ZERO, MINUTE), BootstrapAction::ServeStale);
    }

    #[test]
    fn test_bootstrap_decide_no_data_recent_failure_is_unavailable() {
        let state = BootstrapState {
            data: None,
            fetched_at: None,
            last_attempt: Some(Instant::now()),
        };
        assert_eq!(state.decide(HOUR, MINUTE), BootstrapAction::Unavailable);
    }

    #[test]
    fn test_bootstrap_decide_retry_window_reopens() {
        // Attempt outside the retry window -> fetch again even with no data
        let state = BootstrapState {
            data: None,
            fetched_at: None,
            last_attempt: Some(Instant::now()),
        };
        assert_eq!(state.decide(HOUR, Duration::ZERO), BootstrapAction::Fetch);
    }

    fn sample_vcard() -> serde_json::Value {
        serde_json::json!([
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "MarkMonitor Inc."],
                ["org", {}, "text", "MarkMonitor"],
                ["adr", {}, "text", ["", "", "3540 E Longwing Ln", "Meridian", "ID", "83646", "US"]],
                ["email", {}, "text", "abusecomplaints@markmonitor.com"]
            ]
        ])
    }

    #[test]
    fn test_extract_vcard_fn() {
        let vcard = sample_vcard();
        assert_eq!(
            RdapService::extract_registrar_from_vcard(&vcard),
            Some("MarkMonitor Inc.".to_string())
        );
        assert_eq!(
            RdapService::extract_name_from_vcard(&vcard),
            Some("MarkMonitor Inc.".to_string())
        );
    }

    #[test]
    fn test_extract_vcard_email() {
        let vcard = sample_vcard();
        assert_eq!(
            RdapService::extract_email_from_vcard(&vcard),
            Some("abusecomplaints@markmonitor.com".to_string())
        );
    }

    #[test]
    fn test_extract_vcard_org_fallback() {
        // No "fn" property - should fall back to "org"
        let vcard = serde_json::json!([
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["org", {}, "text", "Example Org"]
            ]
        ]);
        assert_eq!(
            RdapService::extract_registrar_from_vcard(&vcard),
            Some("Example Org".to_string())
        );
    }

    #[test]
    fn test_extract_vcard_structured_value() {
        // Structured (array) values are joined
        let vcard = serde_json::json!([
            "vcard",
            [["org", {}, "text", ["Example Corp", "Security Division"]]]
        ]);
        assert_eq!(
            RdapService::extract_name_from_vcard(&vcard),
            Some("Example Corp Security Division".to_string())
        );
    }

    #[test]
    fn test_extract_vcard_malformed() {
        // Malformed inputs return None instead of panicking
        assert_eq!(RdapService::extract_email_from_vcard(&serde_json::json!(null)), None);
        assert_eq!(RdapService::extract_email_from_vcard(&serde_json::json!("vcard")), None);
        assert_eq!(RdapService::extract_email_from_vcard(&serde_json::json!(["vcard"])), None);
        assert_eq!(RdapService::extract_email_from_vcard(&serde_json::json!(["vcard", []])), None);
        assert_eq!(
            RdapService::extract_email_from_vcard(&serde_json::json!(["vcard", [["email", {}]]])),
            None
        );
    }

    #[test]
    fn test_parse_rdap_response_with_registrar() {
        let raw = serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"}
            ],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]
            }],
            "nameservers": [
                {"ldhName": "NS1.EXAMPLE.COM"},
                {"ldhName": "NS2.EXAMPLE.COM"}
            ]
        })
        .to_string();

        let (parsed, _analysis) = RdapService::parse_rdap_response(&raw);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.registrar, Some("MarkMonitor Inc.".to_string()));
        assert_eq!(parsed.creation_date, Some("1997-09-15T04:00:00Z".to_string()));
        assert_eq!(parsed.expiration_date, Some("2028-09-14T04:00:00Z".to_string()));
        assert_eq!(parsed.name_servers.len(), 2);
        assert_eq!(parsed.status, vec!["client transfer prohibited".to_string()]);
    }
} 