#[cfg(feature = "server")]
use axum::{http::StatusCode, response::IntoResponse};
#[cfg(feature = "server")]
use metrics::{counter, histogram};
#[cfg(feature = "server")]
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
#[cfg(feature = "server")]
use std::sync::{OnceLock, RwLock};
#[cfg(feature = "server")]
use tracing::{info, warn};

/// Global Prometheus handle for rendering metrics
/// Uses std::sync::RwLock (not tokio) since access is rare and brief
#[cfg(feature = "server")]
static PROMETHEUS_HANDLE: OnceLock<RwLock<Option<PrometheusHandle>>> = OnceLock::new();

#[cfg(feature = "server")]
pub fn init_metrics() {
    let builder = PrometheusBuilder::new();

    match builder.install_recorder() {
        Ok(handle) => {
            // Initialize the handle container and set the handle synchronously
            // No race condition - handle is ready before any metrics are recorded
            let handle_container = PROMETHEUS_HANDLE.get_or_init(|| RwLock::new(None));
            
            match handle_container.write() {
                Ok(mut guard) => {
                    *guard = Some(handle);
                    info!("Prometheus metrics initialized");
                }
                Err(e) => {
                    warn!("Failed to acquire metrics handle lock: {}", e);
                }
            }

            // Initialize metrics with zero values
            counter!("whois_requests_total", "tld" => "unknown").absolute(0);
            counter!("whois_cache_hits_total").absolute(0);
            counter!("whois_cache_misses_total").absolute(0);
            counter!("whois_errors_total", "error_type" => "unknown").absolute(0);
            histogram!("whois_request_duration_seconds").record(0.0);
        }
        Err(e) => {
            warn!("Failed to install metrics recorder: {}", e);
        }
    }
}

#[cfg(feature = "server")]
pub fn increment_requests(domain: &str) {
    let tld = extract_tld(domain);
    counter!("whois_requests_total", "tld" => tld).increment(1);
}

#[cfg(feature = "server")]
pub fn increment_cache_hits() {
    counter!("whois_cache_hits_total").increment(1);
}

#[cfg(feature = "server")]
pub fn increment_cache_misses() {
    counter!("whois_cache_misses_total").increment(1);
}

#[cfg(feature = "server")]
pub fn increment_errors(error_type: &str) {
    counter!("whois_errors_total", "error_type" => error_type.to_string()).increment(1);
}

#[cfg(feature = "server")]
pub fn record_query_time(duration_ms: u64) {
    let duration_seconds = duration_ms as f64 / 1000.0;
    histogram!("whois_request_duration_seconds").record(duration_seconds);
}

#[cfg(feature = "server")]
pub async fn metrics_handler() -> impl IntoResponse {
    let handle_container = PROMETHEUS_HANDLE.get_or_init(|| RwLock::new(None));
    
    match handle_container.read() {
        Ok(guard) => {
            if let Some(handle) = guard.as_ref() {
                let metrics = handle.render();
                (StatusCode::OK, metrics)
            } else {
                (StatusCode::SERVICE_UNAVAILABLE, "Metrics not initialized".to_string())
            }
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Metrics lock poisoned".to_string())
        }
    }
}

/// Simple TLD extraction for metrics labeling
/// Uses the shared tld module's simple extraction (no PSL needed for metrics)
///
/// IP queries collapse to fixed "ipv4"/"ipv6" labels - labeling by the raw
/// query would give one Prometheus series per distinct address (unbounded
/// label cardinality; especially bad for IPv6, which has no dots at all).
#[cfg(feature = "server")]
fn extract_tld(domain: &str) -> String {
    match domain.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => "ipv4".to_string(),
        Ok(std::net::IpAddr::V6(_)) => "ipv6".to_string(),
        Err(_) => whois_service::tld::extract_tld_simple(domain),
    }
} 