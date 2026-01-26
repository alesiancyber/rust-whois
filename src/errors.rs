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
    InvalidIp(String),

    #[error("Unsupported TLD: {0}")]
    UnsupportedTld(String),

    #[error("Network timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] tokio::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

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

#[cfg(feature = "server")]
impl IntoResponse for WhoisError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            // Client errors - safe to expose details
            WhoisError::InvalidDomain(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::InvalidIp(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::UnsupportedTld(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            
            // Timeout - client should retry later
            WhoisError::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string()),
            
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
            WhoisError::RegexError(e) => {
                tracing::warn!("Regex error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
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