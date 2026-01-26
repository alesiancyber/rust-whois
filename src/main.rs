use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, post},
    Router,
};

#[cfg(feature = "openapi")]
use utoipa::{OpenApi, ToSchema};
#[cfg(feature = "openapi")]
use utoipa_swagger_ui::SwaggerUi;
use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower::{ServiceBuilder, timeout::TimeoutLayer, BoxError};
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::{info, warn};

// Constants to eliminate magic numbers
const CACHE_WRITE_TIMEOUT_SECS: u64 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 60;

// Import from the library instead of local modules
use whois_service::{
    whois::WhoisService,
    rdap::RdapService,
    cache::CacheService,
    config::Config,
    errors::WhoisError,
    WhoisResponse,
    ValidatedDomain,
};
#[cfg(feature = "openapi")]
use whois_service::ParsedWhoisData;

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
    /// Application start time for uptime tracking
    start_time: std::time::Instant,
}

/// Result from a three-tier lookup (RDAP -> WHOIS)
struct LookupResult {
    /// The server that provided the response (e.g., "RDAP: rdap.verisign.com")
    server: String,
    /// Raw response data from the server
    raw_data: String,
    /// Parsed/structured whois data (if parsing succeeded)
    parsed_data: Option<whois_service::ParsedWhoisData>,
    /// Debug information about the parsing process
    parsing_analysis: Vec<String>,
}

/// Validate domain from query parameters (wrapper for metrics integration)
fn validate_domain_with_metrics(domain: &str) -> Result<ValidatedDomain, WhoisError> {
    match ValidatedDomain::new(domain) {
        Ok(validated) => Ok(validated),
        Err(e) => {
            metrics::increment_errors("invalid_domain");
            Err(e)
        }
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

/// Optional query params for path-based routes (domain comes from path)
#[derive(Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
struct PathQueryParams {
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
    // Initialize tracing (try_init won't panic if already initialized, e.g., in tests)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "whois_service=info,tower_http=debug".into()),
        )
        .try_init();

    // Load configuration
    let config = Arc::new(Config::load()?);
    info!("Configuration loaded successfully");

    // Initialize services
    let whois_service = Arc::new(WhoisService::new(config.clone()).await?);
    let rdap_service = Arc::new(RdapService::new(config.clone()).await?);
    let cache_service = Arc::new(CacheService::new(config.clone()));

    // Initialize metrics
    metrics::init_metrics();

    let app_state = AppState {
        whois_service,
        rdap_service,
        cache_service,
        start_time: std::time::Instant::now(),
    };

    // Build the application
    #[allow(unused_mut)]
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
    // Note: Layers are applied in reverse order (last added = first executed)
    let app = app.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(HandleErrorLayer::new(handle_timeout_error))
            .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
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
) -> Result<LookupResult, WhoisError> {
    // Tier 1: Try RDAP first (modern, structured JSON)
    match state.rdap_service.lookup(domain).await {
        Ok(rdap_result) => {
            info!("✓ RDAP lookup successful for {}", domain);
            return Ok(LookupResult {
                server: format!("RDAP: {}", rdap_result.server),
                raw_data: rdap_result.raw_data,
                parsed_data: rdap_result.parsed_data,
                parsing_analysis: rdap_result.parsing_analysis,
            });
        }
        Err(e) => {
            info!("⚠ RDAP lookup failed for {}: {} - falling back to WHOIS", domain, e);
        }
    }

    // Tier 2: Fallback to WHOIS (legacy but comprehensive)
    match state.whois_service.lookup(domain).await {
        Ok(whois_result) => {
            info!("✓ WHOIS lookup successful for {}", domain);
            Ok(LookupResult {
                server: format!("WHOIS: {}", whois_result.server),
                raw_data: whois_result.raw_data,
                parsed_data: whois_result.parsed_data,
                parsing_analysis: whois_result.parsing_analysis,
            })
        }
        Err(e) => {
            warn!("❌ Both RDAP and WHOIS lookups failed for {}", domain);
            Err(e)
        }
    }
}

/// Core lookup logic - takes pre-validated domain to avoid double validation
async fn perform_whois_lookup(
    state: &AppState,
    domain: String,
    fresh: bool,
    include_debug: bool,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let start_time = std::time::Instant::now();
    
    // Increment request counter
    metrics::increment_requests(&domain);

    // Check cache first (unless fresh is requested)
    if !fresh {
        if let Some(cached_result) = check_cache(&state.cache_service, &domain).await {
            metrics::increment_cache_hits();
            return Ok(Json(cached_result));
        }
    }

    // Perform three-tier lookup
    let result = three_tier_lookup(state, &domain).await?;
    
    let query_time = start_time.elapsed().as_millis() as u64;
    
    let response = build_whois_response(domain.clone(), result, query_time, include_debug);

    // Cache the result (with error handling) - skip for debug requests
    if !include_debug {
        handle_cache_write(&state.cache_service, &domain, &response).await;
        metrics::increment_cache_misses();
    }
    
    metrics::record_query_time(query_time);

    Ok(Json(response))
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
    let validated = validate_domain_with_metrics(&params.domain)?;
    perform_whois_lookup(&state, validated.into_inner(), params.fresh, false).await
}

// Helper function to handle cache writes with timeout
async fn handle_cache_write(cache_service: &CacheService, domain: &str, response: &WhoisResponse) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(CACHE_WRITE_TIMEOUT_SECS),
        cache_service.set(domain, response)
    ).await {
        Ok(()) => {
            // Cache write successful
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
    result: LookupResult,
    query_time: u64,
    include_debug: bool,
) -> WhoisResponse {
    WhoisResponse {
        domain,
        whois_server: result.server,
        raw_data: result.raw_data,
        parsed_data: result.parsed_data,
        cached: false,
        query_time_ms: query_time,
        parsing_analysis: if include_debug { Some(result.parsing_analysis) } else { None },
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
    let validated = validate_domain_with_metrics(&params.domain)?;
    // Debug always uses fresh lookup (ignore params.fresh, always true)
    perform_whois_lookup(&state, validated.into_inner(), true, true).await
}

// Path-based whois lookup for easier testing
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/whois/{domain}",
    params(
        ("domain" = String, Path, description = "Domain name to lookup", example = "google.com"),
        PathQueryParams
    ),
    responses(
        (status = 200, description = "Whois lookup successful", body = WhoisResponse),
        (status = 400, description = "Invalid domain format"),
        (status = 500, description = "Internal server error")
    ),
    tag = "whois"
))]
async fn whois_lookup_path(
    Path(domain): Path<String>,
    Query(params): Query<PathQueryParams>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let validated = validate_domain_with_metrics(&domain)?;
    perform_whois_lookup(&state, validated.into_inner(), params.fresh, false).await
}

// Path-based debug lookup for easier testing
// Note: Debug always uses fresh lookup regardless of params.fresh
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
    Path(domain): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let validated = validate_domain_with_metrics(&domain)?;
    // Debug always uses fresh lookup (cache bypass)
    perform_whois_lookup(&state, validated.into_inner(), true, true).await
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
        uptime_seconds: state.start_time.elapsed().as_secs(),
    })
}

// Helper function to check cache
async fn check_cache(cache_service: &CacheService, domain: &str) -> Option<WhoisResponse> {
    // get() returns Option directly - cache operations are infallible
    cache_service.get(domain).await
}

// Handle request timeout errors - matches WhoisError JSON format
async fn handle_timeout_error(err: BoxError) -> axum::response::Response {
    use axum::response::IntoResponse;
    
    let (status, message) = if err.is::<tower::timeout::error::Elapsed>() {
        metrics::increment_errors("request_timeout");
        (StatusCode::REQUEST_TIMEOUT, "Request timed out")
    } else {
        metrics::increment_errors("internal_error");
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    };
    
    // Match the JSON format from WhoisError::into_response
    let body = Json(serde_json::json!({
        "error": message,
        "status": status.as_u16()
    }));
    
    (status, body).into_response()
} 