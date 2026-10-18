//! Bounded retries for idempotent Discord reads. Never used for writes.
use reqwest::{Client, StatusCode, header};
use serde_json::Value;
use std::time::Duration;
use tokio::time::Instant;

const MAX_ATTEMPTS: usize = 4;
const READ_BUDGET: Duration = Duration::from_secs(90);

fn retry_after(headers: &header::HeaderMap, body: &Value) -> Option<Duration> {
    // Use the longer advertised delay; never retry earlier than Discord asks.
    let header = headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<f64>().ok());
    [header, body.get("retry_after").and_then(Value::as_f64)]
        .into_iter()
        .flatten()
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .filter_map(|seconds| Duration::try_from_secs_f64(seconds).ok())
        .max()
        .map(|delay| delay.saturating_add(Duration::from_millis(100)))
}

pub(super) async fn get_json(client: &Client, auth: &str, url: &str) -> Result<Value, String> {
    let deadline = Instant::now() + READ_BUDGET;
    for attempt in 0..MAX_ATTEMPTS {
        let result = tokio::time::timeout_at(
            deadline,
            client.get(url).header(header::AUTHORIZATION, auth).send(),
        )
        .await;
        let (error, delay) = match result {
            Ok(Ok(response)) => {
                let status = response.status();
                let headers = response.headers().clone();
                let body = tokio::time::timeout_at(deadline, response.json::<Value>()).await;
                if status.is_success() {
                    return body
                        .ok()
                        .and_then(Result::ok)
                        .ok_or_else(|| "discord_invalid_response".to_string());
                }
                let error = format!("discord_http_{}", status.as_u16());
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let body = body.ok().and_then(Result::ok).unwrap_or(Value::Null);
                    (error, retry_after(&headers, &body))
                } else if status.is_server_error() {
                    (error, Some(Duration::from_millis(250 << attempt)))
                } else {
                    // Authentication and permissions failures are definitive.
                    return Err(error);
                }
            }
            Ok(Err(_)) => (
                "discord_request_failed".to_string(),
                Some(Duration::from_millis(250 << attempt)),
            ),
            Err(_) => return Err("discord_read_deadline".to_string()),
        };
        let Some(delay) = delay.filter(|delay| {
            attempt + 1 < MAX_ATTEMPTS
                && *delay < deadline.saturating_duration_since(Instant::now())
        }) else {
            tracing::warn!(reason = %error, attempts = attempt + 1, "Discord context read exhausted");
            return Err(error);
        };
        // Do not log the URL, authorization, response body or reqwest error:
        // these can contain private identifiers or credentials.
        tracing::warn!(reason = %error, attempt = attempt + 1, retry_ms = delay.as_millis() as u64,
            "Discord context read retry");
        tokio::time::sleep(delay).await;
    }
    unreachable!("every final attempt returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    async fn fixture(
        statuses: Vec<u16>,
        delay: &'static str,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let app = Router::new().route(
            "/read",
            get(move || {
                let index = counter.fetch_add(1, Ordering::SeqCst);
                let status = statuses[index.min(statuses.len() - 1)];
                async move {
                    (
                        StatusCode::from_u16(status).unwrap(),
                        [(header::RETRY_AFTER, delay)],
                        axum::Json(serde_json::json!({"retry_after": 0.01, "ok": status == 200})),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/read"), calls, task)
    }

    #[tokio::test]
    async fn rate_limit_recovers_without_emptying_context() {
        let (url, calls, server) = fixture(vec![429, 200], "0.15").await;
        let started = Instant::now();
        let value = get_json(&Client::new(), "Bot fixture", &url).await.unwrap();
        assert_eq!(value["ok"], true);
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn transient_server_error_recovers() {
        let (url, calls, server) = fixture(vec![503, 200], "0").await;
        assert!(get_json(&Client::new(), "Bot fixture", &url).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn authorization_failures_are_not_retried() {
        for status in [401, 403, 404] {
            let (url, calls, server) = fixture(vec![status, 200], "0").await;
            assert_eq!(
                get_json(&Client::new(), "Bot fixture", &url)
                    .await
                    .unwrap_err(),
                format!("discord_http_{status}")
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            server.abort();
        }
    }

    #[tokio::test]
    async fn exhausted_rate_limit_fails_closed() {
        let (url, calls, server) = fixture(vec![429], "0").await;
        assert_eq!(
            get_json(&Client::new(), "Bot fixture", &url)
                .await
                .unwrap_err(),
            "discord_http_429"
        );
        assert_eq!(calls.load(Ordering::SeqCst), MAX_ATTEMPTS);
        server.abort();
    }

    #[tokio::test]
    async fn excessive_delay_fails_without_retrying_early() {
        let (url, calls, server) = fixture(vec![429, 200], "120").await;
        assert_eq!(
            get_json(&Client::new(), "Bot fixture", &url)
                .await
                .unwrap_err(),
            "discord_http_429"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn retry_delay_uses_longer_valid_signal() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "0.1".parse().unwrap());
        assert_eq!(
            retry_after(&headers, &serde_json::json!({"retry_after":0.4})),
            Some(Duration::from_millis(500))
        );
        headers.insert(header::RETRY_AFTER, "invalid".parse().unwrap());
        assert_eq!(
            retry_after(&headers, &serde_json::json!({"retry_after":-1})),
            None
        );
    }
}
