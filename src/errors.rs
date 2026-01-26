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

    #[error("Cache error: {0}")]
    CacheError(String),

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
        let (status, error_message) = match self {
            WhoisError::InvalidDomain(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::UnsupportedTld(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            WhoisError::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
} 