use axum::{
    extract::{Query, State, FromRequestParts},
    response::Json,
    routing::{get, post},
    Router,
    http::request::Parts,
};

#[cfg(feature = "openapi")]
use utoipa::{OpenApi, ToSchema};
#[cfg(feature = "openapi")]
use utoipa_swagger_ui::SwaggerUi;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::{info, warn};

// Constants to eliminate magic numbers
const CACHE_WRITE_TIMEOUT_SECS: u64 = 5;

// Import from the library instead of local modules
use whois_service::{
    whois::WhoisService,
    rdap::RdapService,
    cache::CacheService,
    config::Config,
    errors::WhoisError,
    WhoisResponse,  // Use the library's WhoisResponse
    ParsedWhoisData, // Import for OpenAPI schema
};

// Import metrics module locally (API-only)
mod metrics;

#[cfg(feature = "openapi")]
#[derive(OpenApi)]
#[openapi(
    paths(
        whois_lookup,
        whois_lookup_path,
        whois_debug,
        whois_debug_path,
        health_check
    ),
    components(schemas(HealthResponse, WhoisResponse, ParsedWhoisData)),
    tags(
        (name = "whois", description = "Domain whois lookup operations"),
        (name = "system", description = "System health and monitoring")
    ),
    info(
        title = "Whois Service API",
        version = "0.1.0",
        description = "High-performance whois lookup service with RDAP support for cybersecurity applications. Features RDAP-first lookup with intelligent fallback to traditional whois.",
        contact(
            name = "Whois Service Support",
            email = "support@example.com"
        ),
        license(
            name = "MIT OR Apache-2.0"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Development server"),
        (url = "https://api.example.com", description = "Production server")
    )
)]
struct ApiDoc;

#[derive(Clone)]
pub struct AppState {
    whois_service: Arc<WhoisService>,
    rdap_service: Arc<RdapService>,
    cache_service: Arc<CacheService>,
    config: Arc<Config>,
}

// Domain validation extractor
#[derive(Debug, Clone)]
pub struct ValidatedDomain(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for ValidatedDomain
where
    S: Send + Sync,
{
    type Rejection = WhoisError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract domain from path parameters
        let domain = Self::extract_domain_from_path(parts.uri.path())?;
        Self::validate_domain(domain)
    }
}

impl ValidatedDomain {
    // Separate concern: path extraction
    fn extract_domain_from_path(path: &str) -> Result<String, WhoisError> {
        // Handle /whois/debug/:domain
        if let Some(domain_part) = path.strip_prefix("/whois/debug/") {
            let domain = domain_part.split('/').next().unwrap_or("").to_string();
            if !domain.is_empty() {
                return Ok(domain);
            }
        }
        
        // Handle /whois/:domain
        if let Some(domain_part) = path.strip_prefix("/whois/") {
            let domain = domain_part.split('/').next().unwrap_or("").to_string();
            if !domain.is_empty() {
                return Ok(domain);
            }
        }
        
        Err(WhoisError::InvalidDomain("Domain not found in path".to_string()))
    }

    // Separate concern: domain validation
    pub fn validate_domain(domain: String) -> Result<Self, WhoisError> {
        let domain = domain.trim().to_lowercase();
        
        if domain.is_empty() {
            metrics::increment_errors("invalid_domain");
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }
        
        if domain.len() > 253 {
            metrics::increment_errors("domain_too_long");
            return Err(WhoisError::InvalidDomain("Domain name too long".to_string()));
        }
        
        if !domain.contains('.') {
            metrics::increment_errors("invalid_domain_format");
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        // Add more sophisticated validation
        if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
            metrics::increment_errors("invalid_domain_format");
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        Ok(ValidatedDomain(domain))
    }
    
    pub(crate) fn from_query_params(params: &WhoisQuery) -> Result<Self, WhoisError> {
        Self::validate_domain(params.domain.clone())
    }
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
struct WhoisQuery {
    /// Domain name to lookup (e.g., "example.com")
    /// Must be a valid, pre-parsed domain name
    #[cfg_attr(feature = "openapi", param(example = "google.com"))]
    domain: String,
    #[serde(default)]
    /// Skip cache if true
    #[cfg_attr(feature = "openapi", param(default = false))]
    fresh: bool,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
struct HealthResponse {
    #[cfg_attr(feature = "openapi", schema(example = "healthy"))]
    status: String,
    #[cfg_attr(feature = "openapi", schema(example = "0.1.0"))]
    version: String,
    #[cfg_attr(feature = "openapi", schema(example = 3600))]
    uptime_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "whois_service=info,tower_http=debug".into()),
        )
        .init();

    // Load configuration
    let config = Arc::new(Config::load()?);
    info!("Configuration loaded successfully");

    // Initialize services
    let whois_service = Arc::new(WhoisService::new(config.clone()).await?);
    let rdap_service = Arc::new(RdapService::new(config.clone()).await?);
    let cache_service = Arc::new(CacheService::new(config.clone())?);  // Handle cache initialization error

    // Initialize metrics
    metrics::init_metrics();

    let app_state = AppState {
        whois_service,
        rdap_service,
        cache_service,
        config: config.clone(),
    };

    // Build the application
    let mut app = Router::new()
        .route("/whois", get(whois_lookup))
        .route("/whois", post(whois_lookup_post))
        .route("/whois/:domain", get(whois_lookup_path))  // Path-based route for easier testing
        .route("/whois/debug", get(whois_debug))
        .route("/whois/debug/:domain", get(whois_debug_path))  // Path-based debug route
        .route("/health", get(health_check))
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(app_state);

    // Add OpenAPI documentation if feature is enabled
    #[cfg(feature = "openapi")]
    {
        app = app.merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }

    // Apply middleware layers AFTER all routes are added (including OpenAPI routes)
    let app = app.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .layer(CorsLayer::permissive())
            .into_inner(),
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    
    info!("Whois service listening on {}", addr);
    info!("Health check: http://{}/health", addr);
    info!("Metrics: http://{}/metrics", addr);
    #[cfg(feature = "openapi")]
    info!("API Documentation: http://{}/docs", addr);
    info!("API expects pre-parsed domain names (e.g., 'example.com')");

    // Graceful shutdown handling
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Received shutdown signal, gracefully shutting down...");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

// Three-tier lookup: RDAP -> WHOIS -> (Command-line skipped for now)
async fn three_tier_lookup(
    state: &AppState,
    domain: &str,
) -> Result<(String, String, Option<whois_service::ParsedWhoisData>, Vec<String>), WhoisError> {
    // Tier 1: Try RDAP first (modern, structured JSON)
    match state.rdap_service.lookup(domain).await {
        Ok(rdap_result) => {
            info!("✓ RDAP lookup successful for {}", domain);
            return Ok((
                format!("RDAP: {}", rdap_result.server), 
                rdap_result.raw_data,
                rdap_result.parsed_data,
                rdap_result.parsing_analysis,
            ));
        }
        Err(e) => {
            info!("⚠ RDAP lookup failed for {}: {} - falling back to WHOIS", domain, e);
        }
    }

    // Tier 2: Fallback to WHOIS (legacy but comprehensive)
    match state.whois_service.lookup(domain).await {
        Ok(whois_result) => {
            info!("✓ WHOIS lookup successful for {}", domain);
            Ok((
                format!("WHOIS: {}", whois_result.server),
                whois_result.raw_data,
                whois_result.parsed_data,  
                whois_result.parsing_analysis,
            ))
        }
        Err(e) => {
            warn!("❌ Both RDAP and WHOIS lookups failed for {}", domain);
            Err(e)
        }
    }
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/whois",
    params(WhoisQuery),
    responses(
        (status = 200, description = "Whois lookup successful", body = WhoisResponse),
        (status = 400, description = "Invalid domain"),
        (status = 500, description = "Internal server error")
    ),
    tag = "whois"
))]
async fn whois_lookup(
    Query(params): Query<WhoisQuery>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let start_time = std::time::Instant::now();
    
    // Validate domain using centralized validation
    let validated_domain = ValidatedDomain::from_query_params(&params)?;
    let domain = validated_domain.0;
    
    // Increment request counter
    metrics::increment_requests(&domain);

    // Check cache first (unless fresh is requested)
    if !params.fresh {
        if let Some(cached_result) = check_cache(&state.cache_service, &domain).await {
            metrics::increment_cache_hits();
            return Ok(Json(cached_result));
        }
    }

    // Perform three-tier lookup
    let result = three_tier_lookup(&state, &domain).await?;
    
    let query_time = start_time.elapsed().as_millis() as u64;
    
    let response = build_whois_response(domain.clone(), result, query_time, false);

    // Cache the result (with error handling)
    handle_cache_write(&state.cache_service, &domain, &response).await;
    
    metrics::record_query_time(query_time);
    metrics::increment_cache_misses();

    Ok(Json(response))
}

// Helper function to handle cache writes - follows SRP
async fn handle_cache_write(cache_service: &CacheService, domain: &str, response: &WhoisResponse) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(CACHE_WRITE_TIMEOUT_SECS),
        cache_service.set(domain, response)
    ).await {
        Ok(Ok(())) => {
            // Cache write successful
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to cache result for {}: {}", domain, e);
            metrics::increment_errors("cache_write_error");
        }
        Err(_) => {
            tracing::warn!("Cache write timeout for {}", domain);
            metrics::increment_errors("cache_write_timeout");
        }
    }
}

// Helper function to build WhoisResponse - eliminates DRY violation
fn build_whois_response(
    domain: String,
    result: (String, String, Option<whois_service::ParsedWhoisData>, Vec<String>),
    query_time: u64,
    include_debug: bool,
) -> WhoisResponse {
    WhoisResponse {
        domain,
        whois_server: result.0,
        raw_data: result.1,
        parsed_data: result.2,
        cached: false,
        query_time_ms: query_time,
        parsing_analysis: if include_debug { Some(result.3) } else { None },
    }
}

async fn whois_lookup_post(
    State(state): State<AppState>,
    Json(payload): Json<WhoisQuery>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    whois_lookup(Query(payload), State(state)).await
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/whois/debug",
    params(WhoisQuery),
    responses(
        (status = 200, description = "Whois lookup with debug information", body = WhoisResponse),
        (status = 400, description = "Invalid domain"),
        (status = 500, description = "Internal server error")
    ),
    tag = "whois"
))]
async fn whois_debug(
    Query(params): Query<WhoisQuery>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let start_time = std::time::Instant::now();
    
    // Validate domain using centralized validation
    let validated_domain = ValidatedDomain::from_query_params(&params)?;
    let domain = validated_domain.0;
    
    // Increment request counter
    metrics::increment_requests(&domain);

    // Always perform fresh lookup for debug (no cache)
    let result = three_tier_lookup(&state, &domain).await?;
    
    let query_time = start_time.elapsed().as_millis() as u64;
    
    let response = build_whois_response(domain, result, query_time, true);

    metrics::record_query_time(query_time);

    Ok(Json(response))
}

// Path-based whois lookup for easier testing
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/whois/{domain}",
    params(
        ("domain" = String, Path, description = "Domain name to lookup", example = "google.com")
    ),
    responses(
        (status = 200, description = "Whois lookup successful", body = WhoisResponse),
        (status = 400, description = "Invalid domain format"),
        (status = 500, description = "Internal server error")
    ),
    tag = "whois"
))]
async fn whois_lookup_path(
    validated_domain: ValidatedDomain,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let query = WhoisQuery { domain: validated_domain.0, fresh: false };
    whois_lookup(Query(query), State(state)).await
}

// Path-based debug lookup for easier testing
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/whois/debug/{domain}",
    params(
        ("domain" = String, Path, description = "Domain name to lookup with debug info", example = "google.com")
    ),
    responses(
        (status = 200, description = "Whois lookup with debug information", body = WhoisResponse),
        (status = 400, description = "Invalid domain format"),
        (status = 500, description = "Internal server error")
    ),
    tag = "whois"
))]
async fn whois_debug_path(
    validated_domain: ValidatedDomain,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let query = WhoisQuery { domain: validated_domain.0, fresh: false };
    whois_debug(Query(query), State(state)).await
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    ),
    tag = "system"
))]
async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.config.start_time.elapsed().as_secs(),
    })
}

// Helper function to check cache - eliminates DRY violation
async fn check_cache(cache_service: &CacheService, domain: &str) -> Option<WhoisResponse> {
    match cache_service.get(domain).await {
        Ok(Some(cached_result)) => Some(cached_result),
        Ok(None) => {
            // Cache miss, continue to fresh lookup
            None
        }
        Err(e) => {
            tracing::warn!("Cache read error for {}: {}", domain, e);
            metrics::increment_errors("cache_read_error");
            // Continue to fresh lookup on cache error
            None
        }
    }
} 