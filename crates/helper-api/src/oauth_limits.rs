//! Bound unauthenticated OAuth work before creating state or contacting Discord.
use super::*;
use std::{net::IpAddr, sync::Mutex, time::Instant};

#[derive(Default)]
struct Window {
    started: Option<Instant>,
    total: [u32; 2],
    clients: BTreeMap<IpAddr, [u32; 2]>,
}

#[derive(Default)]
pub struct OAuthLimits(Mutex<Window>);

pub(super) enum Endpoint {
    Start,
    Callback,
}

impl OAuthLimits {
    pub(super) fn check(
        &self,
        headers: &HeaderMap,
        endpoint: Endpoint,
    ) -> Result<(), (StatusCode, Json<ApiError>)> {
        self.check_at(headers, endpoint, Instant::now())
    }

    fn check_at(
        &self,
        headers: &HeaderMap,
        endpoint: Endpoint,
        now: Instant,
    ) -> Result<(), (StatusCode, Json<ApiError>)> {
        // Caddy supplies this header only after validating the Cloudflare peer.
        // A global budget still applies to requests without a trusted client address.
        let client = headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let index = match endpoint {
            Endpoint::Start => 0,
            Endpoint::Callback => 1,
        };
        let mut window = self
            .0
            .lock()
            .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "oauth_unavailable"))?;
        if window
            .started
            .is_none_or(|start| now.saturating_duration_since(start).as_secs() >= 60)
        {
            *window = Window {
                started: Some(now),
                ..Window::default()
            };
        }
        let used = window
            .clients
            .get(&client)
            .map(|counts| counts[index])
            .unwrap_or(0);
        if used >= [20, 30][index] || window.total[index] >= [200, 300][index] {
            return Err(client_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        window.total[index] += 1;
        window.clients.entry(client).or_default()[index] += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_client_is_limited_without_using_its_callback_budget() {
        let limits = OAuthLimits::default();
        let headers = HeaderMap::new();
        let now = Instant::now();
        for _ in 0..20 {
            limits.check_at(&headers, Endpoint::Start, now).unwrap();
        }
        assert_eq!(
            limits
                .check_at(&headers, Endpoint::Start, now)
                .unwrap_err()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        limits.check_at(&headers, Endpoint::Callback, now).unwrap();
        limits
            .check_at(
                &headers,
                Endpoint::Start,
                now + std::time::Duration::from_secs(60),
            )
            .unwrap();
    }

    #[test]
    fn rotating_client_addresses_cannot_bypass_the_global_budget() {
        let limits = OAuthLimits::default();
        let now = Instant::now();
        for index in 0..200 {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cf-connecting-ip",
                format!("2001:db8::{index:x}").parse().unwrap(),
            );
            limits.check_at(&headers, Endpoint::Start, now).unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "2001:db8::ffff".parse().unwrap());
        assert_eq!(
            limits
                .check_at(&headers, Endpoint::Start, now)
                .unwrap_err()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
