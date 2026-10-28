use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

tokio::task_local! { pub(super) static TEST_BASE: String; }

const GUILD: &str = "100000000000000001";
const CHANNEL: &str = "100000000000000002";
const TOKEN: &str = "synthetic-discord-bot-token";

#[tokio::test]
async fn provider_test_delivery_binds_metadata_to_authenticated_guild_before_post() {
    for (status, metadata, allowed) in [
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD,"type":0}),
            true,
        ),
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":"100000000000000099"}),
            false,
        ),
        (200, serde_json::json!({"id":CHANNEL}), false),
        (200, serde_json::json!({"id":CHANNEL,"guild_id":42}), false),
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD,"type":1}),
            false,
        ),
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD,"type":4}),
            false,
        ),
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD}),
            false,
        ),
        (
            200,
            serde_json::json!({"id":"other","guild_id":GUILD}),
            false,
        ),
        (403, serde_json::json!({"message":"fixture failure"}), false),
        (
            503,
            serde_json::json!({"message":"fixture unavailable"}),
            false,
        ),
    ] {
        let posts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(std::sync::Mutex::new(None));
        let post_counter = posts.clone();
        let saved = received.clone();
        let mock = Router::new()
            .route(
                "/channels/{channel}",
                get(move || {
                    let metadata = metadata.clone();
                    async move { (StatusCode::from_u16(status).unwrap(), Json(metadata)) }
                }),
            )
            .route(
                "/channels/{channel}/messages",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let posts = post_counter.clone();
                        let saved = saved.clone();
                        async move {
                            assert_eq!(headers[header::AUTHORIZATION], format!("Bot {TOKEN}"));
                            posts.fetch_add(1, Ordering::SeqCst);
                            *saved.lock().unwrap() = Some(body);
                            Json(serde_json::json!({"id":"100000000000000003"}))
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let result = discord_send_channel_message_at(
            &client,
            &base,
            TOKEN,
            GUILD,
            CHANNEL,
            "Test @everyone",
        )
        .await;
        assert_eq!(result.is_ok(), allowed);
        assert_eq!(posts.load(Ordering::SeqCst), usize::from(allowed));
        if allowed {
            let body = received.lock().unwrap().clone().unwrap();
            assert_eq!(body["content"], "Test @everyone");
            assert_eq!(body["allowed_mentions"], serde_json::json!({"parse":[]}));
        }
        assert!(
            discord_send_channel_message_at(&client, &base, TOKEN, GUILD, "../invalid", "test")
                .await
                .is_err()
        );
        assert!(
            discord_send_channel_message_at(&client, &base, TOKEN, "invalid", CHANNEL, "test")
                .await
                .is_err()
        );
        assert_eq!(posts.load(Ordering::SeqCst), usize::from(allowed));
        server.abort();
    }
}

fn subscription_state() -> (ApiState, SessionClaims) {
    let mut state = crate::tests::state(Store::open(":memory:").unwrap());
    state.discord_token = TOKEN.into();
    let now = Utc::now();
    let claims = SessionClaims {
        session_id: Uuid::new_v4(),
        user_id: "100000000000000010".into(),
        guild_id: GUILD.into(),
        issued_at: now,
        expires_at: now + Duration::hours(1),
        last_seen_at: now,
    };
    state.store.save_session(&claims).unwrap();
    state
        .store
        .replace_session_guilds(
            claims.session_id,
            &[(GUILD.into(), "Test".into(), Some(u64::MAX.to_string()))],
        )
        .unwrap();
    let mut entitlement = helper_contracts::EntitlementSnapshot::free(claims.user_id.clone());
    entitlement.plan = Plan::Premium { guild_limit: 1 };
    state.store.save_entitlement(&entitlement).unwrap();
    // Unexpired synthetic grant permits a paused subscription without any
    // provider call or dependency on machine environment/approval settings.
    let cipher = TokenCipher::new(&state.session_secret).unwrap();
    state
        .store
        .save_tiktok_grant(
            GUILD,
            "synthetic-open-id",
            "Test",
            &cipher.seal("synthetic-access").unwrap(),
            &cipher.seal("synthetic-refresh").unwrap(),
            "video.list",
            now.timestamp() + 3600,
            now.timestamp() + 7200,
            now.timestamp(),
        )
        .unwrap();
    (state, claims)
}

async fn request_subscription(
    state: ApiState,
    claims: &SessionClaims,
    base: String,
    method: &str,
    path: &str,
    payload: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let token = sign_session(claims, &state.session_secret);
    TEST_BASE
        .scope(base, async move {
            let response = router(state)
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1_000_000)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        })
        .await
}

#[tokio::test]
async fn every_direct_provider_create_update_checks_fresh_destination_before_any_provider_or_store_write()
 {
    for (http_status, metadata, expected) in [
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":"100000000000000099","type":0}),
            StatusCode::FORBIDDEN,
        ),
        (
            200,
            serde_json::json!({"id":CHANNEL,"type":1}),
            StatusCode::FORBIDDEN,
        ),
        (
            404,
            serde_json::json!({"message":"not found"}),
            StatusCode::BAD_GATEWAY,
        ),
        (
            503,
            serde_json::json!({"message":"unavailable"}),
            StatusCode::BAD_GATEWAY,
        ),
    ] {
        let gets = Arc::new(AtomicUsize::new(0));
        let counter = gets.clone();
        let mock = Router::new().route(
            "/channels/{channel}",
            get(move || {
                let metadata = metadata.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::from_u16(http_status).unwrap(), Json(metadata))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        for (provider, payload) in [
            (
                "youtube",
                serde_json::json!({"source_channel_id":"UCexample","target_channel_id":CHANNEL,"enabled":false}),
            ),
            (
                "rss",
                serde_json::json!({"feed_url":"https://example.invalid/feed.xml","target_channel_id":CHANNEL,"enabled":false}),
            ),
            (
                "bluesky",
                serde_json::json!({"sourceHandle":"example.bsky.social","targetChannelId":CHANNEL,"enabled":false}),
            ),
            (
                "tiktok",
                serde_json::json!({"username":"example","targetChannelId":CHANNEL,"enabled":false}),
            ),
            (
                "instagram",
                serde_json::json!({"username":"example","targetChannelId":CHANNEL,"enabled":false}),
            ),
            (
                "kick",
                serde_json::json!({"sourceHandle":"example","targetChannelId":CHANNEL,"enabled":false}),
            ),
            (
                "twitch",
                serde_json::json!({"sourceLogin":"example","targetChannelId":CHANNEL,"enabled":false}),
            ),
        ] {
            for method in ["POST", "PUT"] {
                let (state, claims) = subscription_state();
                let store = state.store.clone();
                let uri = format!(
                    "/api/config/{provider}{}",
                    if method == "PUT" { "/1" } else { "" }
                );
                let (status, body) = request_subscription(
                    state,
                    &claims,
                    base.clone(),
                    method,
                    &uri,
                    payload.clone(),
                )
                .await;
                assert_eq!(status, expected, "{method} {uri}: {body}");
                assert!(store.youtube_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.rss_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.bluesky_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.tiktok_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.instagram_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.kick_subscriptions(GUILD).unwrap().is_empty());
                assert!(store.twitch_subscriptions(GUILD).unwrap().is_empty());
            }
        }
        assert!(gets.load(Ordering::SeqCst) >= 14);
        server.abort();
    }
}

#[tokio::test]
async fn own_guild_channel_allows_paused_create_update_and_foreign_update_preserves_existing_row() {
    let guild = Arc::new(std::sync::Mutex::new(GUILD.to_string()));
    let saved = guild.clone();
    let mock=Router::new().route("/channels/{channel}",get(move || {let saved=saved.clone();async move {Json(serde_json::json!({"id":CHANNEL,"guild_id":saved.lock().unwrap().clone(),"type":0}))}}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let (state, claims) = subscription_state();
    let store = state.store.clone();
    let payload =
        serde_json::json!({"username":"original","targetChannelId":CHANNEL,"enabled":false});
    let (status, body) = request_subscription(
        state.clone(),
        &claims,
        base.clone(),
        "POST",
        "/api/config/tiktok",
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_i64().unwrap();
    let uri = format!("/api/config/tiktok/{id}");
    let payload =
        serde_json::json!({"username":"updated","targetChannelId":CHANNEL,"enabled":false});
    let (status, body) =
        request_subscription(state.clone(), &claims, base.clone(), "PUT", &uri, payload).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        store.tiktok_subscriptions(GUILD).unwrap()[0].source_label,
        "updated"
    );
    *guild.lock().unwrap() = "100000000000000099".into();
    let payload =
        serde_json::json!({"username":"forged","targetChannelId":CHANNEL,"enabled":false});
    let (status, body) = request_subscription(state, &claims, base, "PUT", &uri, payload).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        store.tiktok_subscriptions(GUILD).unwrap()[0].source_label,
        "updated"
    );
    server.abort();
}
