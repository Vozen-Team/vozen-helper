//! Recheck Discord authority independently of the login-time guild list.
use super::*;
use std::time::Duration as StdDuration;

pub struct GuildAuthorization {
    client: Client,
    base: String,
    inflight: discord_context::Inflight<Result<u64, StatusCode>>,
    #[cfg(test)]
    fixture: bool,
}

impl GuildAuthorization {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(StdDuration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base: DISCORD_API_BASE.into(),
            inflight: discord_context::Inflight::new(),
            #[cfg(test)]
            fixture: false,
        })
    }

    pub(super) async fn permissions(
        &self,
        state: &ApiState,
        claims: &SessionClaims,
    ) -> Result<u64, (StatusCode, Json<ApiError>)> {
        #[cfg(test)]
        if self.fixture {
            return Ok(state
                .store
                .session_guilds(claims.session_id)
                .unwrap()
                .into_iter()
                .find(|guild| guild.guild_id == claims.guild_id)
                .and_then(|guild| guild.permissions)
                .and_then(|value| value.parse().ok())
                .unwrap_or(u64::MAX));
        }
        if !is_discord_snowflake(&claims.guild_id) || !is_discord_snowflake(&claims.user_id) {
            return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
        }
        let key = format!(
            "{}:{}:{}",
            claims.guild_id,
            claims.user_id,
            hex::encode(Sha256::digest(state.discord_token.as_bytes()))
        );
        let client = self.client.clone();
        let base = self.base.clone();
        let token = state.discord_token.clone();
        let guild = claims.guild_id.clone();
        let user = claims.user_id.clone();
        let result = self
            .inflight
            .read(key, async move {
                tokio::time::timeout(
                    StdDuration::from_secs(8),
                    current_permissions(&client, &base, &token, &guild, &user),
                )
                .await
                .unwrap_or(Err(StatusCode::SERVICE_UNAVAILABLE))
            })
            .await;
        (*result).map_err(|status| {
            client_error(
                status,
                if status == StatusCode::FORBIDDEN {
                    "guild_not_managed"
                } else {
                    "discord_authorization_unavailable"
                },
            )
        })
    }

    pub(super) async fn authorize(
        &self,
        state: &ApiState,
        claims: &SessionClaims,
    ) -> Result<(), (StatusCode, Json<ApiError>)> {
        let permissions = self.permissions(state, claims).await?;
        if permissions & (8 | 32) == 0 {
            return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            fixture: true,
            ..Self::new().unwrap()
        }
    }
}

async fn read(
    client: &Client,
    base: &str,
    token: &str,
    path: &str,
) -> Result<serde_json::Value, StatusCode> {
    let response = client
        .get(format!("{base}{path}"))
        .header(header::AUTHORIZATION, format!("Bot {token}"))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if matches!(response.status().as_u16(), 403 | 404) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !response.status().is_success() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    response
        .json()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn current_permissions(
    client: &Client,
    base: &str,
    token: &str,
    guild_id: &str,
    user_id: &str,
) -> Result<u64, StatusCode> {
    let guild = read(client, base, token, &format!("/guilds/{guild_id}")).await?;
    let owner = guild["owner_id"]
        .as_str()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    if owner == user_id {
        return Ok(u64::MAX);
    }
    let member = read(
        client,
        base,
        token,
        &format!("/guilds/{guild_id}/members/{user_id}"),
    )
    .await?;
    let member_roles = member["roles"]
        .as_array()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .iter()
        .map(|role| role.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let roles = read(client, base, token, &format!("/guilds/{guild_id}/roles")).await?;
    roles
        .as_array()
        .and_then(|roles| effective_bot_permissions(guild_id, roles, &member_roles))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
    use tower::ServiceExt;

    const GUILD: &str = "100000000000000002";
    const USER: &str = "100000000000000003";

    struct Discord {
        permissions: AtomicU64,
        member_status: AtomicU16,
        guild_status: AtomicU16,
        owner: AtomicBool,
    }

    async fn fixture() -> (
        Router,
        Store,
        String,
        Arc<Discord>,
        tokio::task::JoinHandle<()>,
    ) {
        let discord = Arc::new(Discord {
            permissions: AtomicU64::new(32),
            member_status: AtomicU16::new(200),
            guild_status: AtomicU16::new(200),
            owner: AtomicBool::new(false),
        });
        let mock = Router::new()
            .route("/guilds/{guild}", get(|State(d): State<Arc<Discord>>| async move {
                (StatusCode::from_u16(d.guild_status.load(Ordering::SeqCst)).unwrap(),
                    Json(serde_json::json!({"owner_id": if d.owner.load(Ordering::SeqCst) {USER} else {"100000000000000099"}})))
            }))
            .route("/guilds/{guild}/members/{user}", get(|State(d): State<Arc<Discord>>| async move {
                (StatusCode::from_u16(d.member_status.load(Ordering::SeqCst)).unwrap(), Json(serde_json::json!({"roles": ["manager"]})))
            }))
            .route("/guilds/{guild}/roles", get(|State(d): State<Arc<Discord>>| async move {
                Json(serde_json::json!([
                    {"id":GUILD,"permissions":"0"},
                    {"id":"manager","permissions":d.permissions.load(Ordering::SeqCst).to_string()}
                ]))
            }))
            .with_state(discord.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let store = Store::open(":memory:").unwrap();
        let mut state = crate::tests::state(store.clone());
        let mut authorization = GuildAuthorization::new().unwrap();
        authorization.base = format!("http://{address}");
        state.guild_authorization = Arc::new(authorization);
        state.allowed_origin = Some("https://bot.example.com".into());
        let now = Utc::now();
        let claims = SessionClaims {
            session_id: Uuid::new_v4(),
            user_id: USER.into(),
            guild_id: GUILD.into(),
            issued_at: now,
            expires_at: now + Duration::hours(1),
            last_seen_at: now,
        };
        store.save_session(&claims).unwrap();
        store
            .replace_session_guilds(
                claims.session_id,
                &[(GUILD.into(), "Synthetic".into(), Some("32".into()))],
            )
            .unwrap();
        let token = sign_session(&claims, &state.session_secret);
        (router(state), store, token, discord, server)
    }

    async fn request(app: &Router, token: &str, write: Option<&str>) -> StatusCode {
        let mut request =
            Request::builder().header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = if let Some(value) = write {
            request = request
                .method("POST")
                .uri("/api/config/import")
                .header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::json!({"version":1,"settings":[{"key":"test.authorization","value":value}],"tags":[],"workflows":[]}).to_string())
        } else {
            request = request.uri("/api/stats");
            Body::empty()
        };
        app.clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn lost_manager_permissions_block_reads_and_writes_without_changing_data() {
        let (app, store, token, discord, server) = fixture().await;
        assert_eq!(request(&app, &token, None).await, StatusCode::OK);
        assert_eq!(request(&app, &token, Some("before")).await, StatusCode::OK);
        discord.permissions.store(0, Ordering::SeqCst);
        assert_eq!(request(&app, &token, None).await, StatusCode::FORBIDDEN);
        assert_eq!(
            request(&app, &token, Some("forbidden")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            store
                .get_setting(GUILD, "test.authorization")
                .unwrap()
                .as_deref(),
            Some("before")
        );
        server.abort();
    }

    #[tokio::test]
    async fn logout_still_revokes_after_manager_permissions_are_lost() {
        for bearer in [false, true] {
            let (app, store, token, discord, server) = fixture().await;
            discord.permissions.store(0, Ordering::SeqCst);
            assert_eq!(request(&app, &token, None).await, StatusCode::FORBIDDEN);
            let mut logout = Request::builder().method("POST").uri("/api/logout");
            if bearer {
                logout = logout.header(header::AUTHORIZATION, format!("Bearer {token}"));
            } else {
                logout = logout
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .header(header::ORIGIN, "https://bot.example.com");
            }
            let response = app
                .oneshot(logout.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let signed =
                verify_session(&token, "test-session-secret-with-at-least-32-bytes").unwrap();
            assert!(store.load_session(signed.session_id).unwrap().is_none());
            server.abort();
        }
    }

    #[tokio::test]
    async fn membership_removal_denies_but_discord_outage_never_grants_access() {
        let (app, _, token, discord, server) = fixture().await;
        discord.member_status.store(404, Ordering::SeqCst);
        assert_eq!(request(&app, &token, None).await, StatusCode::FORBIDDEN);
        discord.member_status.store(200, Ordering::SeqCst);
        for status in [401, 429, 500] {
            discord.guild_status.store(status, Ordering::SeqCst);
            assert_eq!(
                request(&app, &token, None).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                request(&app, &token, Some("forbidden")).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        discord.guild_status.store(200, Ordering::SeqCst);
        assert_eq!(request(&app, &token, None).await, StatusCode::OK);
        server.abort();
    }

    #[tokio::test]
    async fn owner_and_administrator_are_authorized_without_login_snapshot_permissions() {
        let (app, _, token, discord, server) = fixture().await;
        discord.permissions.store(8, Ordering::SeqCst);
        assert_eq!(request(&app, &token, None).await, StatusCode::OK);
        discord.permissions.store(0, Ordering::SeqCst);
        discord.owner.store(true, Ordering::SeqCst);
        assert_eq!(request(&app, &token, None).await, StatusCode::OK);
        server.abort();
    }
}
