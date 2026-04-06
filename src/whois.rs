use crate::{
    config::Config,
    errors::WhoisError,
    tld_mappings::HARDCODED_TLD_SERVERS,
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

/// Maximum retry attempts for transient failures
/// Uses exponential backoff: immediate, +1s, +2s
const MAX_RETRY_ATTEMPTS: usize = 3;

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
        let service = Self {
            config: config.clone(),
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            domain_query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
            buffer_pool: Arc::new(crossbeam::queue::ArrayQueue::new(config.buffer_pool_size)),
        };

        info!("WhoisService initialized with hybrid TLD discovery (hardcoded + dynamic)");
        info!("Buffer pool: {} buffers of {} bytes each", config.buffer_pool_size, config.buffer_size);
        info!("Hardcoded TLD mappings: {} entries", HARDCODED_TLD_SERVERS.len());
        
        Ok(service)
    }

    /// Perform whois lookup for a domain
    /// Assumes domain is already validated and normalized by ValidatedDomain
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        // Domain is already normalized by ValidatedDomain - no need to lowercase again

        // Extract TLD from the domain using shared PSL-based extraction
        let tld = extract_tld(domain)?;
        
        // Find appropriate whois server (hybrid: hardcoded + dynamic discovery)
        let whois_server = self.find_whois_server(&tld).await?;
        
        // Perform whois query
        let raw_data = self.raw_whois_query(&whois_server, domain).await?;

        // Check for referrals and follow them
        let (final_server, final_data) = self.follow_referrals(&whois_server, &raw_data, domain).await?;
        
        // Parse the whois data with detailed analysis
        let (parsed_data, parsing_analysis) = WhoisParser::parse_whois_data_with_analysis(&final_data);
        
        Ok(WhoisResult {
            server: final_server,
            raw_data: final_data,
            parsed_data: Some(parsed_data),
            parsing_analysis,
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

        // Perform whois query (IP queries typically don't need referral following)
        let raw_data = self.raw_whois_query(whois_server, ip_addr).await?;

        // Parse IP-specific whois data
        let (parsed_data, parsing_analysis) = WhoisParser::parse_ip_whois_data_with_analysis(&raw_data);

        Ok(WhoisResult {
            server: whois_server.to_string(),
            raw_data,
            parsed_data,
            parsing_analysis,
        })
    }

    async fn find_whois_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check hardcoded TLD mappings first (instant lookup, no lock needed)
        if let Some(server) = HARDCODED_TLD_SERVERS.get(tld) {
            debug!("Using hardcoded whois server for {}: {}", tld, server);
            return Ok(server.to_string());
        }

        // Check cache for dynamically discovered servers
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                debug!("Using cached whois server for {}: {}", tld, server);
                return Ok(server.clone());
            }
        }

        // Dynamic discovery for uncommon/new TLDs
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
        // Max 3 attempts: immediate, +1s, +2s
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
        let mut buffer = PooledBuffer::new(
            self.buffer_pool.clone(), 
            self.config.buffer_size, 
            self.config.buffer_pool_size
        );

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

        while referral_count < max_referrals {
            if let Some(referral_server) = Self::extract_whois_server(&current_data) {
                if referral_server != current_server {
                    if self.test_whois_server(&referral_server).await {
                        debug!("Following referral from {} to {}", current_server, referral_server);
                    
                        match self.raw_whois_query(&referral_server, domain).await {
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
                    } else {
                        warn!("Referral server liveness test failed. Skipping {}", referral_server);
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
                
                if (key.contains("whois") && key.contains("server")) || key == "refer" {
                    return Some(value.to_string());
                }
            }
        }
        None
    }
} 