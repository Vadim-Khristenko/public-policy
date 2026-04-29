use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use serde::Serialize;
use thiserror::Error;
use url::Url;

const USER_AGENT: &str = "AVRORA/0.1 compliance-scanner";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub max_response_bytes: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: REQUEST_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub url: Url,
    pub final_url: Url,
    pub status: u16,
    pub content_type: Option<String>,
    pub elapsed_ms: u128,
    pub response_bytes: usize,
    pub security_headers: SecurityHeaders,
    pub html: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SecurityHeaders {
    pub content_security_policy: bool,
    pub strict_transport_security: bool,
    pub x_frame_options: bool,
    pub referrer_policy: bool,
    pub permissions_policy: bool,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("request failed for {url}: {source}")]
    Request {
        url: Url,
        #[source]
        source: reqwest::Error,
    },

    #[error("server returned non-success status {status} for {url}")]
    HttpStatus { url: Url, status: StatusCode },

    #[error("response body could not be read for {url}: {source}")]
    Body {
        url: Url,
        #[source]
        source: reqwest::Error,
    },

    #[error("response for {url} is too large: {actual_bytes} bytes exceeds limit {limit_bytes}")]
    ResponseTooLarge {
        url: Url,
        actual_bytes: u64,
        limit_bytes: u64,
    },
}

pub async fn scan_url_with_config(url: &Url, config: &ScanConfig) -> Result<ScanResult, ScanError> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|source| ScanError::Request {
            url: url.clone(),
            source,
        })?;

    let started_at = Instant::now();
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|source| ScanError::Request {
            url: url.clone(),
            source,
        })?;

    let status = response.status();
    let final_url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let security_headers = SecurityHeaders {
        content_security_policy: response
            .headers()
            .contains_key(reqwest::header::CONTENT_SECURITY_POLICY),
        strict_transport_security: response
            .headers()
            .contains_key(reqwest::header::STRICT_TRANSPORT_SECURITY),
        x_frame_options: response.headers().contains_key("x-frame-options"),
        referrer_policy: response.headers().contains_key("referrer-policy"),
        permissions_policy: response.headers().contains_key("permissions-policy"),
    };

    if !status.is_success() {
        return Err(ScanError::HttpStatus {
            url: final_url,
            status,
        });
    }

    if let Some(content_length) = response.content_length()
        && content_length > config.max_response_bytes
    {
        return Err(ScanError::ResponseTooLarge {
            url: final_url,
            actual_bytes: content_length,
            limit_bytes: config.max_response_bytes,
        });
    }

    let bytes = response.bytes().await.map_err(|source| ScanError::Body {
        url: final_url.clone(),
        source,
    })?;
    let response_bytes = bytes.len();

    if response_bytes as u64 > config.max_response_bytes {
        return Err(ScanError::ResponseTooLarge {
            url: final_url,
            actual_bytes: response_bytes as u64,
            limit_bytes: config.max_response_bytes,
        });
    }

    let html = String::from_utf8_lossy(&bytes).into_owned();

    Ok(ScanResult {
        url: url.clone(),
        final_url,
        status: status.as_u16(),
        content_type,
        elapsed_ms: started_at.elapsed().as_millis(),
        response_bytes,
        security_headers,
        html,
    })
}
