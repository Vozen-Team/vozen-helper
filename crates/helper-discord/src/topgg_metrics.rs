//! Optional, bounded Top.gg v1 server-count publishing for Vozen Helper.
//!
//! Discord remains available if Top.gg is unavailable. The caller persists only
//! a sanitized status and aggregate count in the owner-only tracker.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use helper_store::TopggSyncDetail;
use serde_json::Value;
use tokio::sync::Notify;

const TOPGG_V1_PROJECT_URL: &str = "https://top.gg/api/v1/projects/@me";
pub const TOPGG_V1_METRICS_URL: &str = "https://top.gg/api/v1/projects/@me/metrics";
pub const TOPGG_POST_INTERVAL: Duration = Duration::from_secs(30 * 60);
const TOPGG_TIMEOUT: Duration = Duration::from_secs(10);

/// Coalesces lifecycle changes so a burst of guild events cannot cause a
/// request storm. At most one immediate publish is pending at a time.
#[derive(Clone, Default)]
pub struct TopggMetricsTrigger(Arc<Notify>);

impl TopggMetricsTrigger {
    pub fn request_sync(&self) {
        self.0.notify_one();
    }
    pub async fn notified(&self) {
        self.0.notified().await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopggMetricsRequest {
    pub url: String,
    pub method: TopggMetricsMethod,
    pub authorization: String,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopggMetricsMethod {
    Get,
    Patch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopggMetricsResponse {
    pub status: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopggMetricsOutcome {
    Success { status: u16 },
    HttpFailure { status: u16 },
    TransportFailure,
    InvalidConfiguration,
}

impl TopggMetricsOutcome {
    pub const fn succeeded(self) -> bool {
        matches!(self, Self::Success { .. })
    }
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Success { status } | Self::HttpFailure { status } => Some(status),
            Self::TransportFailure | Self::InvalidConfiguration => None,
        }
    }
    pub const fn detail(self) -> TopggSyncDetail {
        match self {
            Self::Success { .. } => TopggSyncDetail::Delivered,
            Self::HttpFailure { status: 401 | 403 } => TopggSyncDetail::V1AuthenticationFailed,
            Self::HttpFailure { status: 404 } => TopggSyncDetail::ProjectNotFound,
            Self::HttpFailure { status: 400 | 422 } => TopggSyncDetail::InvalidMetricsPayload,
            Self::HttpFailure { status: 429 } => TopggSyncDetail::RateLimited,
            Self::HttpFailure { .. } => TopggSyncDetail::HttpFailure,
            Self::TransportFailure => TopggSyncDetail::TransportFailure,
            Self::InvalidConfiguration => TopggSyncDetail::InvalidConfiguration,
        }
    }
}

#[async_trait]
pub trait TopggMetricsHttp: Send + Sync {
    async fn send(&self, request: TopggMetricsRequest) -> Result<TopggMetricsResponse, ()>;
}

pub struct ReqwestTopggMetricsHttp {
    client: reqwest::Client,
}

impl ReqwestTopggMetricsHttp {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder().timeout(TOPGG_TIMEOUT).build()?,
        })
    }
}

#[async_trait]
impl TopggMetricsHttp for ReqwestTopggMetricsHttp {
    async fn send(&self, request: TopggMetricsRequest) -> Result<TopggMetricsResponse, ()> {
        let TopggMetricsRequest {
            url,
            method,
            authorization,
            body,
        } = request;
        let method = match method {
            TopggMetricsMethod::Get => reqwest::Method::GET,
            TopggMetricsMethod::Patch => reqwest::Method::PATCH,
        };
        let request = self
            .client
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, authorization);
        let request = if let Some(body) = body {
            request.json(&body)
        } else {
            request
        };
        let response = request.send().await.map_err(|_| ())?;
        Ok(TopggMetricsResponse {
            status: response.status().as_u16(),
        })
    }
}

/// Validates the current Bearer-token v1 endpoint before a mutable request.
/// Revoked and legacy credentials intentionally map to the same sanitized
/// diagnosis: Top.gg does not safely distinguish them.
pub async fn validate_topgg_v1_token(
    http: &impl TopggMetricsHttp,
    token: &str,
) -> TopggMetricsOutcome {
    if token.trim().is_empty() {
        return TopggMetricsOutcome::InvalidConfiguration;
    }
    match http
        .send(TopggMetricsRequest {
            url: TOPGG_V1_PROJECT_URL.into(),
            method: TopggMetricsMethod::Get,
            authorization: format!("Bearer {token}"),
            body: None,
        })
        .await
    {
        Ok(response) if (200..300).contains(&response.status) => TopggMetricsOutcome::Success {
            status: response.status,
        },
        Ok(response) => TopggMetricsOutcome::HttpFailure {
            status: response.status,
        },
        Err(()) => TopggMetricsOutcome::TransportFailure,
    }
}

pub async fn post_topgg_stats_with_shards(
    http: &impl TopggMetricsHttp,
    bot_id: &str,
    token: &str,
    server_count: usize,
    shard_count: usize,
) -> TopggMetricsOutcome {
    if token.trim().is_empty() || !is_discord_application_id(bot_id) {
        return TopggMetricsOutcome::InvalidConfiguration;
    }
    match http
        .send(TopggMetricsRequest {
            url: TOPGG_V1_METRICS_URL.into(),
            method: TopggMetricsMethod::Patch,
            authorization: format!("Bearer {token}"),
            body: Some(serde_json::json!({
                "server_count": server_count,
                "shard_count": shard_count.max(1),
            })),
        })
        .await
    {
        Ok(response) if (200..300).contains(&response.status) => TopggMetricsOutcome::Success {
            status: response.status,
        },
        Ok(response) => TopggMetricsOutcome::HttpFailure {
            status: response.status,
        },
        Err(()) => TopggMetricsOutcome::TransportFailure,
    }
}

fn is_discord_application_id(value: &str) -> bool {
    (5..=25).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::{collections::VecDeque, sync::Mutex};

    struct FakeHttp {
        responses: Mutex<VecDeque<Result<TopggMetricsResponse, ()>>>,
        requests: Mutex<Vec<TopggMetricsRequest>>,
    }
    #[async_trait]
    impl TopggMetricsHttp for FakeHttp {
        async fn send(&self, request: TopggMetricsRequest) -> Result<TopggMetricsResponse, ()> {
            self.requests.lock().expect("requests lock").push(request);
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .unwrap_or(Err(()))
        }
    }
    fn fake(responses: impl IntoIterator<Item = Result<TopggMetricsResponse, ()>>) -> FakeHttp {
        FakeHttp {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }
    const BOT: &str = "100000000000000003";

    #[tokio::test]
    async fn v1_metrics_use_bearer_auth_and_include_server_and_shard_counts() {
        let http = fake([Ok(TopggMetricsResponse { status: 204 })]);
        assert_eq!(
            post_topgg_stats_with_shards(&http, BOT, "token", 42, 3).await,
            TopggMetricsOutcome::Success { status: 204 }
        );
        assert_eq!(
            http.requests.lock().expect("requests lock").as_slice(),
            &[TopggMetricsRequest {
                url: TOPGG_V1_METRICS_URL.into(),
                method: TopggMetricsMethod::Patch,
                authorization: "Bearer token".into(),
                body: Some(serde_json::json!({ "server_count": 42, "shard_count": 3 })),
            }]
        );
    }
    #[tokio::test]
    async fn invalid_or_legacy_credentials_have_an_actionable_sanitized_state() {
        let http = fake([Ok(TopggMetricsResponse { status: 401 })]);
        let outcome = validate_topgg_v1_token(&http, "old-token").await;
        assert_eq!(outcome.status(), Some(401));
        assert_eq!(outcome.detail(), TopggSyncDetail::V1AuthenticationFailed);
        assert_eq!(http.requests.lock().expect("requests lock").len(), 1);
    }
    #[tokio::test]
    async fn invalid_configuration_does_not_make_a_network_request() {
        let http = fake([Ok(TopggMetricsResponse { status: 200 })]);
        assert_eq!(
            post_topgg_stats_with_shards(&http, "not-a-discord-id", "", 1, 1).await,
            TopggMetricsOutcome::InvalidConfiguration
        );
        assert!(http.requests.lock().expect("requests lock").is_empty());
    }
    #[tokio::test]
    async fn missing_v1_project_is_reported_without_legacy_fallback() {
        let http = fake([Ok(TopggMetricsResponse { status: 404 })]);
        assert_eq!(
            post_topgg_stats_with_shards(&http, BOT, "token", 1, 1).await,
            TopggMetricsOutcome::HttpFailure { status: 404 }
        );
        assert_eq!(http.requests.lock().expect("requests lock").len(), 1);
    }
}
