use crate::{
    config::Config, 
    errors::WhoisError, 
    ParsedWhoisData,
    tld_mappings::HARDCODED_TLD_SERVERS,
    buffer_pool::{BufferPool, PooledBuffer},
    parser::WhoisParser,
};
use once_cell::sync::Lazy;
use publicsuffix::{List, Psl};
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

// Global PSL instance - shared across all service instances
static PSL: Lazy<List> = Lazy::new(|| List::new());

// Standard whois protocol port
const WHOIS_PORT: u16 = 43;

pub struct WhoisService {
    config: Arc<Config>,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    domain_query_semaphore: Arc<Semaphore>,  // For actual domain lookups
    discovery_semaphore: Arc<Semaphore>,     // For TLD discovery (higher limit)
    buffer_pool: BufferPool,  // Reusable buffers for network I/O
    parser: WhoisParser,      // Whois data parser
}

pub struct WhoisResult {
    pub server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub parsing_analysis: Vec<String>,
}

impl WhoisService {
    pub async fn new(config: Arc<Config>) -> Result<Self, WhoisError> {
        let service = Self {
            config: config.clone(),
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            domain_query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
            buffer_pool: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(config.buffer_pool_size))),
            parser: WhoisParser::new(),
        };

        info!("WhoisService initialized with hybrid TLD discovery (hardcoded + dynamic)");
        info!("Buffer pool: {} buffers of {} bytes each", config.buffer_pool_size, config.buffer_size);
        info!("Hardcoded TLD mappings: {} entries", HARDCODED_TLD_SERVERS.len());
        
        Ok(service)
    }

    /// Perform whois lookup for a domain
    /// Assumes domain is already validated and properly formatted (e.g., "example.com")
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        let domain = domain.trim().to_lowercase();
        
        // Basic validation - assume domain is pre-parsed and valid
        if domain.is_empty() || !domain.contains('.') {
            return Err(WhoisError::InvalidDomain(domain));
        }
        
        // Extract TLD from the domain using global PSL
        let tld = self.extract_tld(&domain)?;
        
        // Find appropriate whois server (hybrid: hardcoded + dynamic discovery)
        let whois_server = self.find_whois_server(&tld).await?;
        
        // Perform whois query
        let raw_data = self.raw_whois_query(&whois_server, &domain).await?;
        
        // Check for referrals and follow them
        let (final_server, final_data) = self.follow_referrals(&whois_server, &raw_data, &domain).await?;
        
        // Parse the whois data with detailed analysis
        let (parsed_data, parsing_analysis) = self.parser.parse_whois_data_with_analysis(&final_data);
        
        Ok(WhoisResult {
            server: final_server,
            raw_data: final_data,
            parsed_data,
            parsing_analysis,
        })
    }

    /// Extract TLD from domain using global PSL for accurate parsing
    fn extract_tld(&self, domain: &str) -> Result<String, WhoisError> {
        // Parse the domain using the global public suffix list
        match PSL.domain(domain.as_bytes()) {
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
    }

    async fn find_whois_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check cache first
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                debug!("Using cached whois server for {}: {}", tld, server);
                return Ok(server.clone());
            }
        }

        // Check hardcoded TLD mappings first (instant lookup for popular TLDs)
        if let Some(server) = HARDCODED_TLD_SERVERS.get(tld) {
            info!("Using hardcoded whois server for {}: {}", tld, server);
            return Ok(server.to_string());
        }

        // Dynamic discovery for uncommon/new TLDs
        if let Some(server) = self.discover_whois_server_dynamic(tld).await {
            // Cache the discovered server
            {
                let mut servers = self.tld_servers.write().await;
                servers.insert(tld.to_string(), server.clone());
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
        let patterns = self.generate_whois_patterns(tld);
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

    fn generate_whois_patterns(&self, tld: &str) -> Vec<String> {
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
        let root_servers = self.get_root_servers();

        for root_server in &root_servers {
            debug!("Querying root server {} for TLD: {}", root_server, tld);
            
            match self.discovery_whois_query(root_server, tld).await {
                Ok(response) => {
                    debug!("Root server {} response length: {} bytes", root_server, response.len());
                    
                    if let Some(server) = self.parse_root_server_response(&response) {
                        return Some(server);
                    }
                    
                    debug!("No referral found in response from {}", root_server);
                }
                Err(e) => {
                    debug!("Failed to query root server {}: {}", root_server, e);
                }
            }
        }

        None
    }

    fn parse_root_server_response(&self, response: &str) -> Option<String> {
        // Parse the response line by line to find referral
        for line in response.lines() {
            let line = line.trim();
            
            // Check for various whois server line formats
            if let Some(server) = self.extract_server_from_line(line) {
                return Some(server);
            }
        }
        
        // Fallback: try the regex approach
        if let Some(server) = self.extract_whois_server(response) {
            debug!("Found referral server via regex: {}", server);
            return Some(server);
        }
        
        None
    }

    fn extract_server_from_line(&self, line: &str) -> Option<String> {
        let line_lower = line.to_lowercase();
        
        // Look for "whois:" lines (IANA format)
        if line_lower.starts_with("whois:") {
            return self.extract_server_after_colon(line, "whois server");
        }
        
        // Look for "refer:" lines (alternative format)
        if line_lower.starts_with("refer:") {
            return self.extract_server_after_colon(line, "refer server");
        }
        
        // Look for "whois server:" lines (alternative format)
        if line_lower.contains("whois server:") {
            return self.extract_server_after_colon(line, "whois server");
        }
        
        None
    }

    fn extract_server_after_colon(&self, line: &str, server_type: &str) -> Option<String> {
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

    fn get_root_servers(&self) -> Vec<String> {
        // Root whois servers - IANA is the authoritative source
        vec![
            "whois.iana.org".to_string(),
        ]
    }

    async fn test_whois_server(&self, server: &str) -> bool {
        match timeout(
            Duration::from_secs(self.config.discovery_timeout_seconds.min(10)), 
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
        let mut stream = self.connect_to_whois_server(server).await?;
        self.send_query(&mut stream, query).await?;
        self.read_whois_response(&mut stream).await
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
        let mut pooled_buffer = PooledBuffer::new(
            self.buffer_pool.clone(), 
            self.config.buffer_size, 
            self.config.buffer_pool_size
        );
        let buffer = pooled_buffer.as_mut();

        // Read response
        let mut response = Vec::new();
        
        loop {
            match timeout(
                Duration::from_secs(self.config.whois_timeout_seconds),
                stream.read(buffer)
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
            if let Some(referral_server) = self.extract_whois_server(&current_data) {
                if referral_server != current_server {
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
                }
            }
            break;
        }

        Ok((current_server, current_data))
    }

    fn extract_whois_server(&self, data: &str) -> Option<String> {
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