use super::*;
use axum::routing::delete;
use axum::{
    body::{Body, to_bytes},
    extract::Path,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tower::ServiceExt;

const GUILD: &str = "100000000000000001";
const USER: &str = "100000000000000002";
const BOT: &str = "100000000000000009";
const HIGH: &str = "100000000000000030";
const LOW: &str = "100000000000000040";

struct Discord {
    permissions: AtomicU64,
    owner: AtomicBool,
    unavailable: AtomicBool,
    base: String,
    created_roles: AtomicUsize,
    created_channels: AtomicUsize,
    posted_messages: AtomicUsize,
}

async fn fixture() -> (
    ApiState,
    SessionClaims,
    Arc<Discord>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let discord = Arc::new(Discord {
        permissions: AtomicU64::new(32 | (1 << 28)),
        owner: AtomicBool::new(false),
        unavailable: AtomicBool::new(false),
        base: format!("http://{address}"),
        created_roles: AtomicUsize::new(0),
        created_channels: AtomicUsize::new(0),
        posted_messages: AtomicUsize::new(0),
    });
    let mock = Router::new()
        .route("/users/@me", get(|| async { Json(serde_json::json!({"id":BOT})) }))
        .route("/guilds/{guild}", get(|State(d): State<Arc<Discord>>| async move {
            Json(serde_json::json!({"owner_id": if d.owner.load(Ordering::SeqCst) { USER } else { "100000000000000099" }}))
        }))
        .route("/guilds/{guild}/members/{user}", get(|State(d): State<Arc<Discord>>, Path((_, user)): Path<(String, String)>| async move {
            if d.unavailable.load(Ordering::SeqCst) { return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({}))); }
            (StatusCode::OK, Json(serde_json::json!({"roles": [if user == BOT { "100000000000000020" } else { "100000000000000010" }]})))
        }))
        .route("/guilds/{guild}/roles", get(|State(d): State<Arc<Discord>>| async move {
            Json(serde_json::json!([
                {"id":GUILD,"name":"@everyone","position":0,"managed":false,"permissions":"0"},
                {"id":"100000000000000010","name":"Publisher","position":5,"managed":false,"permissions":d.permissions.load(Ordering::SeqCst).to_string()},
                {"id":"100000000000000020","name":"Helper","position":10,"managed":false,"permissions":(1u64 << 28).to_string()},
                {"id":HIGH,"name":"Staff","position":8,"managed":false,"permissions":"8"},
                {"id":LOW,"name":"Members","position":4,"managed":false,"permissions":"0"}
            ]))
        }).post(|State(d): State<Arc<Discord>>| async move {
            d.created_roles.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"id":"100000000000000050","name":"Novo"}))
        }))
        .route("/guilds/{guild}/channels", get(|| async { Json(serde_json::json!([])) }).post(|State(d): State<Arc<Discord>>| async move {
            d.created_channels.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"id":"100000000000000061","name":"boas-vindas"}))
        }))
        .route("/channels/{channel}", get(|Path(channel): Path<String>| async move {
            Json(serde_json::json!({"id":channel,"guild_id":GUILD,"type":0}))
        }))
        .route("/channels/{channel}/messages", post(|State(d): State<Arc<Discord>>| async move {
            d.posted_messages.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"id":"100000000000000071"}))
        }))
        .route("/channels/{channel}/messages/{message}", delete(|| async { StatusCode::NO_CONTENT }))
        .with_state(discord.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    let store = Store::open(":memory:").unwrap();
    let mut state = crate::tests::state(store);
    state.guild_authorization = Arc::new(GuildAuthorization::with_test_base(discord.base.clone()));
    let now = Utc::now();
    let claims = SessionClaims {
        session_id: Uuid::new_v4(),
        user_id: USER.into(),
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
            &[(
                GUILD.into(),
                "Synthetic".into(),
                Some((32u64 | (1 << 28)).to_string()),
            )],
        )
        .unwrap();
    let mut premium = helper_contracts::EntitlementSnapshot::free(USER.to_owned());
    premium.plan = Plan::Premium { guild_limit: 1 };
    state.store.save_entitlement(&premium).unwrap();
    state
        .store
        .set_setting(GUILD, &feature_key("community.role_panels"), "true")
        .unwrap();
    (state, claims, discord, server)
}

#[tokio::test]
async fn fresh_publisher_context_rejects_escalation_and_lost_authority() {
    let (state, claims, discord, server) = fixture().await;
    assert!(
        require_role_offers(&state, GUILD, USER, &[HIGH.into()])
            .await
            .is_err()
    );
    assert!(
        require_role_offers(&state, GUILD, USER, &[LOW.into()])
            .await
            .is_ok()
    );
    discord.owner.store(true, Ordering::SeqCst);
    assert!(
        require_role_offers(&state, GUILD, USER, &[HIGH.into()])
            .await
            .is_ok()
    );
    assert!(
        require_role_offers(&state, GUILD, USER, &["100000000000000020".into()])
            .await
            .is_err()
    );
    discord.owner.store(false, Ordering::SeqCst);
    discord.permissions.store(32, Ordering::SeqCst);
    assert!(
        require_role_offers(&state, GUILD, USER, &[LOW.into()])
            .await
            .is_err()
    );
    discord.unavailable.store(true, Ordering::SeqCst);
    assert!(
        require_role_offers(&state, GUILD, &claims.user_id, &[LOW.into()])
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn publication_routes_reject_above_publisher_before_discord_or_storage_mutation() {
    for (method, uri, payload) in [
        (
            "POST",
            "/api/role-panels",
            serde_json::json!({"channel":"100000000000000060","title":"Roles","roleIds":[HIGH]}),
        ),
        (
            "PUT",
            "/api/role-panels/100000000000000070",
            serde_json::json!({"channel":"100000000000000060","title":"Roles","roleIds":[HIGH]}),
        ),
        (
            "POST",
            "/api/role-panels/100000000000000070/repair",
            serde_json::json!({}),
        ),
    ] {
        let (state, claims, _, server) = fixture().await;
        let store = state.store.clone();
        let key = "community.role_panel.100000000000000070";
        let stored = serde_json::json!({"channel_id":"100000000000000060","title":"Legacy","role_ids":[HIGH]}).to_string();
        store.set_setting(GUILD, key, &stored).unwrap();
        let token = sign_session(&claims, &state.session_secret);
        let response = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], "role_not_offerable", "{uri}: {body}");
        assert_eq!(
            store.get_setting(GUILD, key).unwrap().as_deref(),
            Some(stored.as_str())
        );
        assert_eq!(
            store
                .count_settings_prefix(GUILD, "community.role_panel.")
                .unwrap(),
            1
        );
        server.abort();
    }
}

#[tokio::test]
async fn config_import_rechecks_publisher_hierarchy_and_manage_roles() {
    for (role, permissions) in [(HIGH, 32 | (1 << 28)), (LOW, 32)] {
        let (state, claims, discord, server) = fixture().await;
        discord.permissions.store(permissions, Ordering::SeqCst);
        let store = state.store.clone();
        let token = sign_session(&claims, &state.session_secret);
        let document = serde_json::json!({"version":1,"settings":[
            {"key":"feature.community.role_panels","value":"true"},
            {"key":"feature.config.community.role_panels","value":serde_json::json!({"roleIds":[role]}).to_string()}
        ],"tags":[{"name":"rules","content":"hello","authorId":"forged"}],"workflows":[]});
        let response = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/config/import")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(document.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            store
                .get_feature_setting(GUILD, "community.role_panels")
                .unwrap()
                .is_none()
        );
        assert!(store.get_tag(GUILD, "rules").unwrap().is_none());
        server.abort();
    }
}

#[tokio::test]
async fn shop_role_products_require_actor_role_authority_before_storage() {
    for (method, uri) in [
        ("POST", format!("/api/economy/products?guildId={GUILD}")),
        ("PUT", format!("/api/economy/products/1?guildId={GUILD}")),
    ] {
        let (state, claims, _, server) = fixture().await;
        let store = state.store.clone();
        let product = serde_json::json!({"name":"VIP","price":10,"delivery":"role","roleId":HIGH});
        let payload = if method == "PUT" {
            serde_json::json!({"version":0,"product":product})
        } else {
            product
        };
        let token = sign_session(&claims, &state.session_secret);
        let response = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(&uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], "role_not_offerable", "{uri}: {body}");
        assert!(store.shop_products(GUILD).unwrap().is_empty());
        server.abort();
    }
}

async fn quick_setup_request(
    state: ApiState,
    claims: &SessionClaims,
    base: String,
    step: &str,
    payload: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let token = sign_session(claims, &state.session_secret);
    let uri = format!("/api/quick-setup/steps/{step}");
    crate::discord_channel_tests::TEST_BASE
        .scope(base, async move {
            let response = router(state)
                .oneshot(
                    axum::http::Request::builder()
                        .method("PUT")
                        .uri(uri)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                    .unwrap();
            (status, body)
        })
        .await
}

fn discord_counters(discord: &Discord) -> (usize, usize, usize) {
    (
        discord.created_roles.load(Ordering::SeqCst),
        discord.created_channels.load(Ordering::SeqCst),
        discord.posted_messages.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn quick_setup_roles_reject_reused_role_above_publisher_before_creation() {
    for config in [
        serde_json::json!({"channel":"100000000000000060","roleNames":"Staff, Novo"}),
        // With Manage Channels, a missing channel would be created: the role
        // check must still come first.
        serde_json::json!({"createChannel":true,"roleNames":"Staff, Novo"}),
    ] {
        let (mut state, claims, discord, server) = fixture().await;
        discord
            .permissions
            .store(32 | (1 << 28) | 16, Ordering::SeqCst);
        state.discord_token = "synthetic-discord-bot-token".into();
        let store = state.store.clone();
        let (status, body) = quick_setup_request(
            state,
            &claims,
            discord.base.clone(),
            "roles",
            serde_json::json!({"status":"applied","enabled":true,"config":config}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{config}: {body}");
        assert_eq!(body["code"], "role_not_offerable", "{config}: {body}");
        assert_eq!(discord_counters(&discord), (0, 0, 0), "{config}");
        assert!(
            store
                .get_feature_setting(GUILD, "community.role_panels")
                .unwrap()
                .is_none()
        );
        server.abort();
    }
}

#[tokio::test]
async fn quick_setup_welcome_rejects_auto_role_above_publisher() {
    let (mut state, claims, discord, server) = fixture().await;
    state.discord_token = "synthetic-discord-bot-token".into();
    let reader = state.clone();
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "welcome",
        serde_json::json!({"status":"applied","enabled":true,"config":{"autoRole":HIGH}}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "role_not_offerable", "{body}");
    assert!(
        reader
            .store
            .get_feature_setting(GUILD, "support.welcome")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        read_quick_setup(&reader, GUILD)["revision"].as_u64(),
        Some(0)
    );
    server.abort();
}

#[tokio::test]
async fn quick_setup_roles_on_free_guild_is_rejected_before_discord() {
    let (mut state, claims, discord, server) = fixture().await;
    state.discord_token = "synthetic-discord-bot-token".into();
    state
        .store
        .save_entitlement(&helper_contracts::EntitlementSnapshot::free(USER))
        .unwrap();
    let store = state.store.clone();
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "roles",
        serde_json::json!({"status":"applied","enabled":true,"config":{"channel":"100000000000000060","roleNames":"Members"}}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "premium_required", "{body}");
    assert_eq!(discord_counters(&discord), (0, 0, 0));
    assert!(
        store
            .get_feature_setting(GUILD, "community.role_panels")
            .unwrap()
            .is_none()
    );
    server.abort();
}

#[tokio::test]
async fn quick_setup_skipped_step_touches_nothing() {
    let (mut state, claims, discord, server) = fixture().await;
    state.discord_token = "synthetic-discord-bot-token".into();
    let reader = state.clone();
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "roles",
        serde_json::json!({"status":"skipped","config":{"createChannel":true,"roleNames":"Novo"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(discord_counters(&discord), (0, 0, 0));
    let saved = read_quick_setup(&reader, GUILD);
    let step = saved["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["key"] == "roles")
        .unwrap();
    assert_eq!(step["status"], "skipped", "{saved}");
    server.abort();
}

#[tokio::test]
async fn quick_setup_channel_creation_requires_actor_manage_channels() {
    let (mut state, claims, discord, server) = fixture().await;
    discord.permissions.store(32 | (1 << 28), Ordering::SeqCst);
    state.discord_token = "synthetic-discord-bot-token".into();
    let store = state.store.clone();
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "welcome",
        serde_json::json!({"status":"applied","enabled":true,"config":{"createChannel":true}}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["code"], "quick_setup_manage_channels_required",
        "{body}"
    );
    assert_eq!(discord.created_channels.load(Ordering::SeqCst), 0);
    assert!(
        store
            .get_feature_setting(GUILD, "support.welcome")
            .unwrap()
            .is_none()
    );
    server.abort();
}

#[tokio::test]
async fn quick_setup_welcome_panel_draft_with_manage_channels_creates_one_channel() {
    let (mut state, claims, discord, server) = fixture().await;
    discord
        .permissions
        .store(32 | (1 << 28) | 16, Ordering::SeqCst);
    state.discord_token = "synthetic-discord-bot-token".into();
    let store = state.store.clone();
    let mut config = feature_adapter("support.welcome")
        .unwrap()
        .descriptor()
        .defaults;
    config["mode"] = serde_json::json!("recommended");
    config["createChannel"] = serde_json::json!(true);
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "welcome",
        serde_json::json!({"status":"applied","enabled":true,"config":config}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(discord.created_channels.load(Ordering::SeqCst), 1);
    let record = store
        .get_feature_setting(GUILD, "support.welcome")
        .unwrap()
        .unwrap();
    assert!(record.enabled);
    assert!(
        record
            .config_json
            .contains(r#""channel":"100000000000000061""#),
        "{}",
        record.config_json
    );
    server.abort();
}

#[tokio::test]
async fn quick_setup_roles_reusing_an_existing_role_publishes_one_panel() {
    let (mut state, claims, discord, server) = fixture().await;
    state.discord_token = "synthetic-discord-bot-token".into();
    let (status, body) = quick_setup_request(
        state,
        &claims,
        discord.base.clone(),
        "roles",
        serde_json::json!({"status":"applied","enabled":true,"config":{"channel":"100000000000000060","roleNames":"Members"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(discord.posted_messages.load(Ordering::SeqCst), 1);
    assert_eq!(discord.created_roles.load(Ordering::SeqCst), 0);
    server.abort();
}
