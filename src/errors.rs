#[cfg(feature = "server")]
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "server")]
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WhoisError {
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Unsupported IP address: {0}")]
    UnsupportedIpAddress(String),

    #[error("Unsupported TLD: {0}")]
    UnsupportedTld(String),

    #[error("Network timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] tokio::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Upstream rate limited: {0}")]
    RateLimited(String),

    #[error("Response too large")]
    ResponseTooLarge,

    #[error("Invalid UTF-8 in response")]
    InvalidUtf8,

    #[error("Configuration error: {0}")]
    ConfigError(#[from] config::ConfigError),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl From<tokio::time::error::Elapsed> for WhoisError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        WhoisError::Timeout
    }
}

impl WhoisError {
    /// Best-effort copy for fanning one failure out to multiple deduplicated waiters.
    ///
    /// Variants with non-cloneable payloads (IO/HTTP/regex/config errors) degrade
    /// to `Internal` carrying the original message.
    pub fn duplicate(&self) -> Self {
        match self {
            Self::InvalidDomain(s) => Self::InvalidDomain(s.clone()),
            Self::InvalidIpAddress(s) => Self::InvalidIpAddress(s.clone()),
            Self::UnsupportedIpAddress(s) => Self::UnsupportedIpAddress(s.clone()),
            Self::UnsupportedTld(s) => Self::UnsupportedTld(s.clone()),
            Self::Timeout => Self::Timeout,
            Self::RateLimited(s) => Self::RateLimited(s.clone()),
            Self::ResponseTooLarge => Self::ResponseTooLarge,
            Self::InvalidUtf8 => Self::InvalidUtf8,
            Self::Internal(s) => Self::Internal(s.clone()),
            other => Self::Internal(other.to_string()),
        }
    }
}

#[cfg(feature = "server")]
impl IntoResponse for WhoisError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            // Client errors - safe to expose details
            WhoisError::InvalidDomain(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::InvalidIpAddress(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::UnsupportedIpAddress(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::UnsupportedTld(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            
            // Timeout - client should retry later
            WhoisError::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string()),

            // Upstream throttled us - client should back off and retry later
            WhoisError::RateLimited(_) => (StatusCode::SERVICE_UNAVAILABLE, "Upstream WHOIS/RDAP server is rate limiting queries, retry later".to_string()),
            
            // Response too large - 413 Payload Too Large
            WhoisError::ResponseTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            
            // Invalid UTF-8 from upstream server - 502 Bad Gateway
            WhoisError::InvalidUtf8 => (StatusCode::BAD_GATEWAY, "Upstream server returned invalid response".to_string()),
            
            // Internal errors - log details but return generic message
            WhoisError::IoError(e) => {
                tracing::warn!("IO error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            WhoisError::HttpError(e) => {
                tracing::warn!("HTTP error: {}", e);
                (StatusCode::BAD_GATEWAY, "Failed to reach upstream server".to_string())
            }
            WhoisError::ConfigError(e) => {
                tracing::error!("Configuration error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            WhoisError::Internal(msg) => {
                tracing::warn!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
} 