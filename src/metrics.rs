#[cfg(feature = "server")]
use axum::{http::StatusCode, response::IntoResponse};
#[cfg(feature = "server")]
use metrics::{counter, gauge, histogram};
#[cfg(feature = "server")]
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
#[cfg(feature = "server")]
use std::sync::{Arc, OnceLock};
#[cfg(feature = "server")]
use tokio::sync::RwLock;

// Thread-safe, dynamic metrics handle
#[cfg(feature = "server")]
static PROMETHEUS_HANDLE: OnceLock<Arc<RwLock<Option<PrometheusHandle>>>> = OnceLock::new();

#[cfg(feature = "server")]
pub fn init_metrics() {
    let builder = PrometheusBuilder::new();

    match builder.install_recorder() {
        Ok(handle) => {
            let handle_container = PROMETHEUS_HANDLE.get_or_init(|| {
                Arc::new(RwLock::new(None))
            });
            
            tokio::spawn(async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    handle_container.write()
                ).await {
                    Ok(mut guard) => {
                        *guard = Some(handle);
                    },
                    Err(_) => {
                        eprintln!("Timeout setting up metrics handle");
                    }
                }
            });

            // Initialize metrics with zero values
            counter!("whois_requests_total", "tld" => "unknown").absolute(0);
            counter!("whois_cache_hits_total").absolute(0);
            counter!("whois_cache_misses_total").absolute(0);
            counter!("whois_errors_total", "error_type" => "unknown").absolute(0);
            gauge!("whois_active_connections").set(0.0);
            histogram!("whois_request_duration_seconds").record(0.0);
        }
        Err(e) => {
            eprintln!("Failed to install metrics recorder: {}", e);
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
    let handle_container = PROMETHEUS_HANDLE.get_or_init(|| {
        Arc::new(RwLock::new(None))
    });
    
    let guard = handle_container.read().await;
    if let Some(handle) = guard.as_ref() {
        let metrics = handle.render();
        (StatusCode::OK, metrics)
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Metrics not initialized".to_string())
    }
}

#[cfg(feature = "server")]
fn extract_tld(domain: &str) -> String {
    domain
        .split('.')
        .last()
        .unwrap_or("unknown")
        .to_lowercase()
} 