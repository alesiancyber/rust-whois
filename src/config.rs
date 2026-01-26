use serde::{Deserialize, Serialize};

/// Application configuration loaded from environment variables with intelligent defaults.
/// 
/// All fields are serializable for debugging/logging purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub whois_timeout_seconds: u64,
    pub max_response_size: usize,
    pub cache_ttl_seconds: u64,
    pub cache_max_entries: u64,
    pub max_referrals: usize,
    pub discovery_timeout_seconds: u64,
    pub concurrent_whois_queries: usize,
    /// Maximum number of buffers in the pool
    pub buffer_pool_size: usize,
    /// Size of each buffer in bytes
    pub buffer_size: usize,
}

impl Config {
    pub fn load() -> Result<Self, config::ConfigError> {
        // Get system information for intelligent defaults
        let system_info = Self::detect_system_capabilities();
        
        let mut settings = config::Config::builder()
            .set_default("port", Self::get_default_port())?
            .set_default("whois_timeout_seconds", system_info.default_timeout)?
            .set_default("max_response_size", system_info.max_response_size as i64)?
            .set_default("cache_ttl_seconds", system_info.cache_ttl)?
            .set_default("cache_max_entries", system_info.cache_max_entries)?
            .set_default("max_referrals", system_info.max_referrals as i64)?
            .set_default("discovery_timeout_seconds", system_info.discovery_timeout)?
            .set_default("concurrent_whois_queries", system_info.concurrent_whois_queries as i64)?
            .set_default("buffer_pool_size", system_info.buffer_pool_size as i64)?
            .set_default("buffer_size", system_info.buffer_size as i64)?;

        // Override with environment variables if present
        settings = Self::apply_env_overrides(settings)?;

        let config: Config = settings.build()?.try_deserialize()?;
        
        // Validate configuration values
        config.validate()?;
        
        Ok(config)
    }

    /// Validate configuration values to catch invalid settings early
    fn validate(&self) -> Result<(), config::ConfigError> {
        if self.port == 0 {
            return Err(config::ConfigError::Message("port cannot be 0".into()));
        }
        if self.whois_timeout_seconds == 0 {
            return Err(config::ConfigError::Message("whois_timeout_seconds cannot be 0".into()));
        }
        if self.buffer_size == 0 {
            return Err(config::ConfigError::Message("buffer_size cannot be 0".into()));
        }
        if self.buffer_pool_size == 0 {
            return Err(config::ConfigError::Message("buffer_pool_size cannot be 0".into()));
        }
        if self.max_response_size == 0 {
            return Err(config::ConfigError::Message("max_response_size cannot be 0".into()));
        }
        if self.concurrent_whois_queries == 0 {
            return Err(config::ConfigError::Message("concurrent_whois_queries cannot be 0".into()));
        }
        Ok(())
    }

    fn detect_system_capabilities() -> SystemCapabilities {
        let available_memory = Self::get_available_memory();
        let cpu_cores = Self::get_cpu_cores();
        let is_production = Self::is_production_environment();

        SystemCapabilities {
            default_timeout: if is_production { 30 } else { 15 },
            max_response_size: Self::calculate_max_response_size(available_memory),
            cache_ttl: if is_production { 3600 } else { 1800 }, // 1 hour prod, 30 min dev
            cache_max_entries: Self::calculate_cache_size(available_memory),
            max_referrals: if is_production { 10 } else { 5 },
            discovery_timeout: if is_production { 20 } else { 10 },
            concurrent_whois_queries: cpu_cores.min(8), // Cap at 8 for network sanity
            buffer_pool_size: Self::calculate_buffer_pool_size(available_memory),
            buffer_size: Self::calculate_buffer_size(available_memory),
        }
    }

    fn get_available_memory() -> u64 {
        // Try to detect available memory
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemAvailable:") {
                        if let Some(kb) = line.split_whitespace().nth(1) {
                            if let Ok(kb_val) = kb.parse::<u64>() {
                                return kb_val * 1024; // Convert to bytes
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Use sysctl for macOS
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.memsize").output() {
                if let Ok(mem_str) = String::from_utf8(output.stdout) {
                    if let Ok(mem_bytes) = mem_str.trim().parse::<u64>() {
                        return mem_bytes;
                    }
                }
            }
        }

        // Default fallback: assume 4GB
        4 * 1024 * 1024 * 1024
    }

    fn get_cpu_cores() -> usize {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4) // Default to 4 cores
    }

    fn is_production_environment() -> bool {
        std::env::var("ENVIRONMENT")
            .or_else(|_| std::env::var("ENV"))
            .map(|env| env.to_lowercase() == "production" || env.to_lowercase() == "prod")
            .unwrap_or(false)
    }

    fn calculate_max_response_size(available_memory: u64) -> usize {
        // Use 0.1% of available memory, capped between 1MB and 10MB
        let calculated = (available_memory as f64 * 0.001) as usize;
        calculated.max(1024 * 1024).min(10 * 1024 * 1024)
    }

    fn calculate_cache_size(available_memory: u64) -> u64 {
        // Use 1% of available memory for cache, with reasonable bounds
        let gb = available_memory / (1024 * 1024 * 1024);
        match gb {
            0..=2 => 1000,      // Low memory: 1K entries
            3..=8 => 5000,      // Medium memory: 5K entries
            9..=16 => 10000,    // High memory: 10K entries
            _ => 25000,         // Very high memory: 25K entries
        }
    }

    fn calculate_buffer_pool_size(available_memory: u64) -> usize {
        // Buffer pool size based on available memory
        let gb = available_memory / (1024 * 1024 * 1024);
        match gb {
            0..=2 => 10,        // Low memory: 10 buffers
            3..=8 => 50,        // Medium memory: 50 buffers
            9..=16 => 100,      // High memory: 100 buffers
            _ => 200,           // Very high memory: 200 buffers
        }
    }

    fn calculate_buffer_size(available_memory: u64) -> usize {
        // Buffer size based on available memory, optimized for network I/O
        let gb = available_memory / (1024 * 1024 * 1024);
        match gb {
            0..=2 => 4096,      // Low memory: 4KB buffers
            3..=8 => 8192,      // Medium memory: 8KB buffers
            9..=16 => 16384,    // High memory: 16KB buffers
            _ => 32768,         // Very high memory: 32KB buffers
        }
    }

    fn get_default_port() -> u16 {
        // Check common environment variables for port
        std::env::var("PORT")
            .or_else(|_| std::env::var("HTTP_PORT"))
            .or_else(|_| std::env::var("SERVER_PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000)
    }

    fn apply_env_overrides(mut settings: config::ConfigBuilder<config::builder::DefaultState>) -> Result<config::ConfigBuilder<config::builder::DefaultState>, config::ConfigError> {
        // Apply all possible environment variable overrides
        let env_mappings = [
            ("PORT", "port"),
            ("WHOIS_TIMEOUT_SECONDS", "whois_timeout_seconds"),
            ("WHOIS_TIMEOUT", "whois_timeout_seconds"),
            ("MAX_RESPONSE_SIZE", "max_response_size"),
            ("CACHE_TTL_SECONDS", "cache_ttl_seconds"),
            ("CACHE_TTL", "cache_ttl_seconds"),
            ("CACHE_MAX_ENTRIES", "cache_max_entries"),
            ("CACHE_SIZE", "cache_max_entries"),
            ("MAX_REFERRALS", "max_referrals"),
            ("DISCOVERY_TIMEOUT_SECONDS", "discovery_timeout_seconds"),
            ("DISCOVERY_TIMEOUT", "discovery_timeout_seconds"),
            ("CONCURRENT_WHOIS_QUERIES", "concurrent_whois_queries"),
            ("BUFFER_POOL_SIZE", "buffer_pool_size"),
            ("BUFFER_SIZE", "buffer_size"),
        ];

        for (env_var, config_key) in env_mappings {
            if let Ok(value) = std::env::var(env_var) {
                settings = settings.set_override(config_key, value)?;
            }
        }

        Ok(settings)
    }
}

struct SystemCapabilities {
    default_timeout: u64,
    max_response_size: usize,
    cache_ttl: u64,
    cache_max_entries: u64,
    max_referrals: usize,
    discovery_timeout: u64,
    concurrent_whois_queries: usize,
    buffer_pool_size: usize,
    buffer_size: usize,
} 