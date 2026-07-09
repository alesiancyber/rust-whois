use crate::{
    config::Config,
    errors::WhoisError,
    buffer_pool::{BufferPool, PooledBuffer},
    parser::WhoisParser,
    tld::extract_tld,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};
use tracing::{debug, info, warn};

// Standard whois protocol port
const WHOIS_PORT: u16 = 43;

/// Maximum timeout for server discovery/connectivity tests (seconds)
/// Kept short since we're just testing if a server is reachable
const MAX_DISCOVERY_TIMEOUT_SECS: u64 = 10;

/// Multiplier for total read timeout vs individual read timeout
/// Prevents slow-loris attacks while allowing legitimate slow connections
const TOTAL_TIMEOUT_MULTIPLIER: u64 = 2;

/// Maximum retries for transient failures (up to 4 attempts total)
/// Uses exponential backoff between attempts: +1s, +2s, +4s
const MAX_RETRY_ATTEMPTS: usize = 3;

/// Total time budget for a referral query (seconds)
///
/// Referral queries are best-effort enrichment - the authoritative registry
/// response is already in hand. Registrars sometimes publish dead whois hosts
/// (e.g. .io registrars pointing at unreachable servers); without a tight cap,
/// connect timeouts and retries against such hosts stall the entire request
/// past the HTTP layer's 60s timeout, turning a good lookup into a 408.
const REFERRAL_TIMEOUT_SECS: u64 = 10;

/// Root WHOIS servers for TLD discovery (IANA is authoritative)
const ROOT_WHOIS_SERVERS: &[&str] = &["whois.iana.org"];

pub struct WhoisService {
    config: Arc<Config>,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    domain_query_semaphore: Arc<Semaphore>,  // For actual domain lookups
    discovery_semaphore: Arc<Semaphore>,     // For TLD discovery (higher limit)
    buffer_pool: BufferPool,  // Reusable buffers for network I/O
}

/// Type alias for WHOIS lookup results
///
/// Uses the unified LookupResult structure to eliminate duplication
/// with RDAP results. Maintains backward compatibility.
pub type WhoisResult = crate::LookupResult;

impl WhoisService {
    pub async fn new(config: Arc<Config>) -> Result<Self, WhoisError> {
        // Reject hand-built configs with zero values (would panic the buffer
        // pool allocation or deadlock the semaphores)
        config.validate()?;

        let service = Self {
            config: config.clone(),
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            domain_query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
            buffer_pool: Arc::new(crossbeam_queue::ArrayQueue::new(config.buffer_pool_size)),
        };

        info!("WhoisService initialized with dynamic TLD discovery (IANA root + runtime cache)");
        info!("Buffer pool: {} buffers of {} bytes each", config.buffer_pool_size, config.buffer_size);

        Ok(service)
    }

    /// Perform whois lookup for a domain
    /// Assumes domain is already validated and normalized by ValidatedDomain
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        // Domain is already normalized by ValidatedDomain - no need to lowercase again

        // Extract TLD from the domain using shared PSL-based extraction
        let tld = extract_tld(domain)?;

        // Find appropriate whois server (cached or dynamically discovered)
        let whois_server = self.find_whois_server(&tld).await?;

        // Perform whois query; if the cached server has died or moved,
        // purge it, rediscover, and retry once (self-healing cache)
        let (whois_server, raw_data) = match self.raw_whois_query(&whois_server, domain).await {
            Ok(data) => (whois_server, data),
            Err(e) => {
                warn!("Whois server {} failed for .{}: {} - rediscovering", whois_server, tld, e);
                self.rediscover_and_retry(&tld, &whois_server, domain, e).await?
            }
        };

        // Check for referrals and follow them
        let (mut server, mut data) = self.follow_referrals(&whois_server, &raw_data, domain).await?;

        // Parse the whois data with detailed analysis
        let (mut parsed_data, mut parsing_analysis) = WhoisParser::parse_whois_data_with_analysis(&data);
        let mut status = WhoisParser::classify_response(&data, &parsed_data);

        if server != whois_server {
            if status == crate::LookupStatus::RateLimited {
                // The referral server throttled us but the authoritative
                // registry response is already in hand - use it instead
                let (registry_parsed, registry_analysis) = WhoisParser::parse_whois_data_with_analysis(&raw_data);
                let registry_status = WhoisParser::classify_response(&raw_data, &registry_parsed);
                if registry_status != crate::LookupStatus::RateLimited {
                    warn!("Referral server {} rate-limited query for {} - using registry response from {}", server, domain, whois_server);
                    parsing_analysis = registry_analysis;
                    parsing_analysis.push(format!("Referral server {} was rate-limited; kept registry response", server));
                    parsed_data = registry_parsed;
                    status = registry_status;
                    server = whois_server;
                    data = raw_data;
                }
            } else {
                // Referrals are enrichment: a thin registrar response must not
                // lose fields the registry already provided
                let registry_parsed = WhoisParser::parse_whois_data(&raw_data);
                parsed_data.fill_missing_from(&registry_parsed);
                parsing_analysis.push(format!("Backfilled missing fields from registry response ({})", whois_server));
            }
        }

        Ok(WhoisResult {
            server,
            raw_data: data,
            parsed_data: Some(parsed_data),
            parsing_analysis,
            status,
        })
    }

    /// Perform whois lookup for an IP address (IPv4 or IPv6)
    ///
    /// Assumes IP is already validated. Detects the appropriate RIR
    /// (Regional Internet Registry) and queries their WHOIS server.
    ///
    /// # Arguments
    ///
    /// * `ip_addr` - Validated IP address string
    ///
    /// # Returns
    ///
    /// WhoisResult containing server info, raw data, and parsed fields
    pub async fn lookup_ip(&self, ip_addr: &str) -> Result<WhoisResult, WhoisError> {
        use crate::ip::{ValidatedIpAddress, detect_rir};

        // Validate IP and detect RIR
        let validated_ip = ValidatedIpAddress::new(ip_addr)?;
        let rir = detect_rir(&validated_ip)?;

        // Get WHOIS server for this RIR
        let whois_server = rir.whois_server();

        debug!("Using RIR whois server for IP {}: {} ({})", ip_addr, whois_server, format!("{:?}", rir));

        // Perform whois query
        let raw_data = self.raw_whois_query(whois_server, ip_addr).await?;

        // Follow referrals: when the local RIR table misses (or an IP was transferred),
        // the queried RIR responds with a ReferralServer line pointing at the
        // authoritative RIR (e.g. ARIN -> whois.ripe.net)
        let (final_server, final_data) = self.follow_referrals(whois_server, &raw_data, ip_addr).await?;

        // Parse IP-specific whois data
        let (mut parsed_data, mut parsing_analysis) = WhoisParser::parse_ip_whois_data_with_analysis(&final_data);

        // Same enrichment rule as domains: never lose fields the first RIR provided
        if final_server != whois_server {
            if let (Some(parsed), (Some(initial_parsed), _)) = (
                parsed_data.as_mut(),
                WhoisParser::parse_ip_whois_data_with_analysis(&raw_data),
            ) {
                parsed.fill_missing_from(&initial_parsed);
                parsing_analysis.push(format!("Backfilled missing fields from initial RIR response ({})", whois_server));
            }
        }

        let status = match &parsed_data {
            Some(parsed) => WhoisParser::classify_response(&final_data, parsed),
            None => crate::LookupStatus::Found,
        };

        Ok(WhoisResult {
            server: final_server,
            raw_data: final_data,
            parsed_data,
            parsing_analysis,
            status,
        })
    }

    async fn find_whois_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check cache for previously discovered servers
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                debug!("Using cached whois server for {}: {}", tld, server);
                return Ok(server.clone());
            }
        }

        // Dynamic discovery (IANA root referral, then common naming patterns)
        if let Some(server) = self.discover_whois_server_dynamic(tld).await {
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

        Err(WhoisError::UnsupportedTld(tld.to_string()))
    }

    /// Self-heal a failed TLD server: purge the cache entry, rediscover, retry once
    ///
    /// Registries move their whois servers over time; a cached (or previously
    /// discovered) server that stops answering must not permanently break the TLD.
    /// Returns the original error when rediscovery finds nothing new.
    async fn rediscover_and_retry(
        &self,
        tld: &str,
        failed_server: &str,
        domain: &str,
        original_error: WhoisError,
    ) -> Result<(String, String), WhoisError> {
        self.tld_servers.write().await.remove(tld);

        match self.discover_whois_server_dynamic(tld).await {
            Some(server) if server != failed_server => {
                info!("Rediscovered whois server for .{}: {} (was {})", tld, server, failed_server);
                let data = self.raw_whois_query(&server, domain).await?;
                self.tld_servers.write().await.insert(tld.to_string(), server.clone());
                Ok((server, data))
            }
            _ => Err(original_error),
        }
    }

    async fn discover_whois_server_dynamic(&self, tld: &str) -> Option<String> {
        debug!("Dynamically discovering whois server for TLD: {}", tld);

        // Strategy 1: Query root whois servers for referrals (most reliable and fast)
        if let Some(server) = self.query_root_servers_for_tld(tld).await {
            debug!("Found whois server from root query: {}", server);
            // Just test connectivity, don't validate with fake domains
            if self.test_whois_server(&server).await {
                info!("Discovered whois server via root query for {}: {}", tld, server);
                return Some(server);
            }
        }

        // Strategy 2: Try common patterns with connectivity testing only
        let patterns = Self::generate_whois_patterns(tld);
        for pattern in patterns {
            debug!("Testing pattern server: {}", pattern);
            if self.test_whois_server(&pattern).await {
                info!("Discovered whois server via pattern for {}: {}", tld, pattern);
                return Some(pattern);
            }
        }

        warn!("Could not discover whois server for TLD: {}", tld);
        None
    }

    fn generate_whois_patterns(tld: &str) -> Vec<String> {
        // Intelligent pattern generation based on TLD characteristics
        let mut patterns = Vec::new();
        
        // Most reliable patterns first
        patterns.push(format!("whois.nic.{}", tld));
        
        // Country-specific patterns (for ccTLDs)
        if tld.len() == 2 {
            patterns.push(format!("whois.{}", tld));
            patterns.push(format!("whois.domain.{}", tld));
            patterns.push(format!("whois.registry.{}", tld));
            patterns.push(format!("whois.dns.{}", tld));
        } else {
            // gTLD patterns
            patterns.push(format!("whois.{}", tld));
            patterns.push(format!("whois.registry.{}", tld));
        }
        
        patterns
    }

    async fn query_root_servers_for_tld(&self, tld: &str) -> Option<String> {
        use futures::future::join_all;

        // Query all root servers in parallel for faster discovery
        let queries: Vec<_> = Self::get_root_servers()
            .iter()
            .map(|&root_server| {
                let tld = tld.to_string();
                async move {
                    debug!("Querying root server {} for TLD: {}", root_server, tld);

                    match self.discovery_whois_query(root_server, &tld).await {
                        Ok(response) => {
                            debug!("Root server {} response length: {} bytes", root_server, response.len());
                            Self::parse_root_server_response(&response)
                        }
                        Err(e) => {
                            debug!("Failed to query root server {}: {}", root_server, e);
                            None
                        }
                    }
                }
            })
            .collect();

        // Wait for all queries to complete in parallel
        let results = join_all(queries).await;

        // Return the first successful result
        results.into_iter().find_map(|result| result)
    }

    fn parse_root_server_response(response: &str) -> Option<String> {
        // Parse the response line by line to find referral
        for line in response.lines() {
            let line = line.trim();
            
            // Check for various whois server line formats
            if let Some(server) = Self::extract_server_from_line(line) {
                return Some(server);
            }
        }
        
        // Fallback: try key-value parsing for other referral formats
        if let Some(server) = Self::extract_whois_server(response) {
            debug!("Found referral server via key-value parsing: {}", server);
            return Some(server);
        }
        
        None
    }

    fn extract_server_from_line(line: &str) -> Option<String> {
        let line_lower = line.to_lowercase();
        
        // Look for "whois:" lines (IANA format)
        if line_lower.starts_with("whois:") {
            return Self::extract_server_after_colon(line, "whois server");
        }
        
        // Look for "refer:" lines (alternative format)
        if line_lower.starts_with("refer:") {
            return Self::extract_server_after_colon(line, "refer server");
        }
        
        // Look for "whois server:" lines (alternative format)
        if line_lower.contains("whois server:") {
            return Self::extract_server_after_colon(line, "whois server");
        }
        
        None
    }

    fn extract_server_after_colon(line: &str, server_type: &str) -> Option<String> {
        if let Some(server) = line.split(':').nth(1) {
            let server = server.trim().to_string();
            
            // Reject empty servers - this allows fallback to pattern generation
            if server.is_empty() {
                debug!("Found empty {} field, will try pattern generation", server_type);
                return None;
            }
            
            debug!("Found {}: {}", server_type, server);
            return Some(server);
        }
        None
    }

    fn get_root_servers() -> &'static [&'static str] {
        ROOT_WHOIS_SERVERS
    }

    async fn test_whois_server(&self, server: &str) -> bool {
        match timeout(
            Duration::from_secs(self.config.discovery_timeout_seconds.min(MAX_DISCOVERY_TIMEOUT_SECS)), 
            TcpStream::connect((server, WHOIS_PORT))
        ).await {
            Ok(Ok(_)) => {
                debug!("Successfully connected to whois server: {}", server);
                true
            },
            Ok(Err(e)) => {
                debug!("Failed to connect to whois server {}: {}", server, e);
                false
            },
            Err(_) => {
                debug!("Timeout connecting to whois server: {}", server);
                false
            }
        }
    }

    async fn raw_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        self.whois_query_with_semaphore(server, query, &self.domain_query_semaphore, "Semaphore error").await
    }

    async fn discovery_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        self.whois_query_with_semaphore(server, query, &self.discovery_semaphore, "Discovery semaphore error").await
    }

    /// Best-effort query against a referral server: single attempt, tight
    /// time budget, no retries.
    ///
    /// A dead referral host fails fast here and the caller falls back to the
    /// registry data it already has, instead of timing out the whole request.
    ///
    /// Referral hostnames come from untrusted remote responses, so hosts that
    /// resolve only to private/special addresses are refused - a malicious
    /// response must not steer queries at internal infrastructure.
    async fn referral_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        let _permit = self.domain_query_semaphore.acquire().await
            .map_err(|_| WhoisError::Internal("Semaphore error".to_string()))?;

        let budget = Duration::from_secs(self.config.whois_timeout_seconds.min(REFERRAL_TIMEOUT_SECS));
        timeout(budget, async {
            let mut stream = self.connect_to_referral_server(server).await?;
            self.send_query(&mut stream, query).await?;
            self.read_whois_response(&mut stream).await
        })
        .await?
    }

    /// Resolve a referral hostname, keep only public addresses, and connect to those.
    ///
    /// Resolving once and connecting by vetted address (never re-resolving by
    /// hostname) closes the DNS-rebinding window and ignores private records
    /// mixed into an otherwise-public answer.
    async fn connect_to_referral_server(&self, server: &str) -> Result<TcpStream, WhoisError> {
        let public_addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((server, WHOIS_PORT))
            .await?
            .filter(|addr| !crate::ip::is_private_or_special(&addr.ip()))
            .collect();

        if public_addrs.is_empty() {
            warn!("Refusing referral to {}: resolves only to private/special addresses", server);
            return Err(WhoisError::Internal(format!(
                "Referral server {} resolves to private address space", server
            )));
        }

        let stream = timeout(
            Duration::from_secs(self.config.whois_timeout_seconds),
            TcpStream::connect(&public_addrs[..])
        ).await??;

        if let Err(e) = stream.set_nodelay(true) {
            debug!("Failed to set TCP_NODELAY: {}", e);
        }

        Ok(stream)
    }

    async fn whois_query_with_semaphore(
        &self, 
        server: &str, 
        query: &str, 
        semaphore: &Semaphore, 
        error_msg: &str
    ) -> Result<String, WhoisError> {
        // Acquire semaphore permit to limit concurrent queries
        let _permit = semaphore.acquire().await.map_err(|_| WhoisError::Internal(error_msg.to_string()))?;
        
        self.execute_whois_query(server, query).await
    }

    async fn execute_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        use backon::{ExponentialBuilder, Retryable};

        // Retry transient network errors with exponential backoff
        // (up to 4 attempts total: immediate, then +1s, +2s, +4s)
        let result = (|| async {
            let mut stream = self.connect_to_whois_server(server).await?;
            self.send_query(&mut stream, query).await?;
            self.read_whois_response(&mut stream).await
        })
        .retry(&ExponentialBuilder::default().with_max_times(MAX_RETRY_ATTEMPTS))
        .when(|e: &WhoisError| {
            // Retry only on transient network errors
            matches!(e, WhoisError::Timeout | WhoisError::IoError(_))
        })
        .await?;

        Ok(result)
    }

    async fn connect_to_whois_server(&self, server: &str) -> Result<TcpStream, WhoisError> {
        let stream = timeout(
            Duration::from_secs(self.config.whois_timeout_seconds),
            TcpStream::connect((server, WHOIS_PORT))
        ).await??;

        // Optimize TCP performance
        if let Err(e) = stream.set_nodelay(true) {
            debug!("Failed to set TCP_NODELAY: {}", e);
        }

        Ok(stream)
    }

    async fn send_query(&self, stream: &mut TcpStream, query: &str) -> Result<(), WhoisError> {
        let query_line = format!("{}\r\n", query);
        stream.write_all(query_line.as_bytes()).await?;
        Ok(())
    }

    async fn read_whois_response(&self, stream: &mut TcpStream) -> Result<String, WhoisError> {
        // Get RAII buffer from pool - automatically returns on drop
        // Uses DerefMut for ergonomic access via &mut *buffer
        let mut buffer = PooledBuffer::new(self.buffer_pool.clone(), self.config.buffer_size);

        // Read response with total timeout to prevent slow-loris attacks
        // (individual read timeouts could be bypassed by sending 1 byte per timeout period)
        let mut response = Vec::new();
        let read_start = std::time::Instant::now();
        let total_timeout = Duration::from_secs(self.config.whois_timeout_seconds * TOTAL_TIMEOUT_MULTIPLIER);
        
        loop {
            // Check total elapsed time
            if read_start.elapsed() > total_timeout {
                warn!("Total read timeout exceeded for whois response");
                return Err(WhoisError::Timeout);
            }
            
            match timeout(
                Duration::from_secs(self.config.whois_timeout_seconds),
                stream.read(&mut buffer)
            ).await? {
                Ok(0) => break, // EOF
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    if response.len() > self.config.max_response_size {
                        return Err(WhoisError::ResponseTooLarge);
                    }
                }
                Err(e) => {
                    return Err(WhoisError::IoError(e));
                }
            }
        }

        // Buffer automatically returns to pool when pooled_buffer goes out of scope
        String::from_utf8(response).map_err(|_| WhoisError::InvalidUtf8)
    }

    async fn follow_referrals(&self, initial_server: &str, initial_data: &str, domain: &str) -> Result<(String, String), WhoisError> {
        let mut current_server = initial_server.to_string();
        let mut current_data = initial_data.to_string();
        let mut referral_count = 0;
        let max_referrals = self.config.max_referrals;

        // Track every server already queried to prevent referral loops
        // (A -> B -> A ping-pong would otherwise run until max_referrals)
        let mut visited: std::collections::HashSet<String> =
            std::collections::HashSet::from([current_server.clone()]);

        while referral_count < max_referrals {
            if let Some(referral_server) = Self::extract_whois_server(&current_data) {
                if visited.insert(referral_server.clone()) {
                    debug!("Following referral from {} to {}", current_server, referral_server);

                    match self.referral_whois_query(&referral_server, domain).await {
                        Ok(new_data) => {
                            current_server = referral_server;
                            current_data = new_data;
                            referral_count += 1;
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to query referral server {}: {}", referral_server, e);
                            break;
                        }
                    }
                }
            }
            break;
        }

        Ok((current_server, current_data))
    }

    fn extract_whois_server(data: &str) -> Option<String> {
        for line in data.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                let is_referral_key = (key.contains("whois") && key.contains("server"))
                    || key == "refer"
                    || key == "referralserver";

                if is_referral_key {
                    // Keep scanning on invalid values - a later line may hold a usable referral
                    if let Some(server) = Self::sanitize_referral_value(value) {
                        return Some(server);
                    }
                }
            }
        }
        None
    }

    /// Validate and normalize a referral server value into a bare hostname
    ///
    /// Registries frequently emit empty referral fields ("Registrar WHOIS Server:")
    /// or URL-style values ("whois://whois.ripe.net", ARIN's ReferralServer format).
    /// Returns None for anything that can't be queried on port 43, so callers skip
    /// it instead of burning retries on a doomed connection.
    fn sanitize_referral_value(value: &str) -> Option<String> {
        if value.is_empty() {
            return None;
        }

        let lower = value.to_lowercase();

        // rwhois:// referrals use a different protocol/port - not queryable here
        if lower.starts_with("rwhois://") {
            return None;
        }

        // Strip whois:// scheme, any casing (ARIN ReferralServer format)
        let host = if lower.starts_with("whois://") {
            &value["whois://".len()..]
        } else {
            value
        };

        // Strip standard port suffix and trailing slash
        let host = host.strip_suffix('/').unwrap_or(host);
        let host = host.strip_suffix(":43").unwrap_or(host);

        // Reject anything that isn't a plain hostname (embedded URLs,
        // non-standard ports, comments with spaces, etc.)
        if host.is_empty() || host.contains([':', '/', ' ']) {
            return None;
        }

        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_referral_plain_hostname() {
        assert_eq!(
            WhoisService::sanitize_referral_value("whois.markmonitor.com"),
            Some("whois.markmonitor.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_referral_empty_value() {
        // Registries commonly emit "Registrar WHOIS Server:" with no value
        assert_eq!(WhoisService::sanitize_referral_value(""), None);
    }

    #[test]
    fn test_sanitize_referral_whois_scheme() {
        // ARIN ReferralServer format
        assert_eq!(
            WhoisService::sanitize_referral_value("whois://whois.ripe.net"),
            Some("whois.ripe.net".to_string())
        );
        assert_eq!(
            WhoisService::sanitize_referral_value("whois://whois.ripe.net:43"),
            Some("whois.ripe.net".to_string())
        );
    }

    #[test]
    fn test_sanitize_referral_rejects_unqueryable() {
        // rwhois uses a different protocol/port
        assert_eq!(
            WhoisService::sanitize_referral_value("rwhois://rwhois.example.net:4321"),
            None
        );
        // Non-standard port
        assert_eq!(WhoisService::sanitize_referral_value("whois.example.com:4343"), None);
        // URLs are not hostnames
        assert_eq!(WhoisService::sanitize_referral_value("http://whois.example.com"), None);
        // Free text
        assert_eq!(WhoisService::sanitize_referral_value("not a hostname"), None);
    }

    #[test]
    fn test_extract_whois_server_standard_formats() {
        let verisign_style = "Domain Name: EXAMPLE.COM\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com";
        assert_eq!(
            WhoisService::extract_whois_server(verisign_style),
            Some("whois.markmonitor.com".to_string())
        );

        let iana_style = "refer:        whois.verisign-grs.com\ndomain:       COM";
        assert_eq!(
            WhoisService::extract_whois_server(iana_style),
            Some("whois.verisign-grs.com".to_string())
        );

        let arin_style = "NetRange: 2.0.0.0 - 2.255.255.255\nReferralServer: whois://whois.ripe.net";
        assert_eq!(
            WhoisService::extract_whois_server(arin_style),
            Some("whois.ripe.net".to_string())
        );
    }

    #[test]
    fn test_extract_whois_server_skips_empty_and_continues() {
        // Empty referral field must not shadow a valid one later in the response
        let data = "Registrar WHOIS Server:\nRegistrar URL: http://example.com\nWhois Server: whois.example-registrar.com";
        assert_eq!(
            WhoisService::extract_whois_server(data),
            Some("whois.example-registrar.com".to_string())
        );
    }

    #[test]
    fn test_extract_whois_server_none_when_absent() {
        let data = "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server:\nStatus: ok";
        assert_eq!(WhoisService::extract_whois_server(data), None);
    }
} 