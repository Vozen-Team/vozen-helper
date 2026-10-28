use super::*;
use axum::{
    body::{Body, to_bytes},
    extract::Path,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
}

async fn fixture() -> (
    ApiState,
    SessionClaims,
    Arc<Discord>,
    tokio::task::JoinHandle<()>,
) {
    let discord = Arc::new(Discord {
        permissions: AtomicU64::new(32 | (1 << 28)),
        owner: AtomicBool::new(false),
        unavailable: AtomicBool::new(false),
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
                {"id":GUILD,"position":0,"managed":false,"permissions":"0"},
                {"id":"100000000000000010","position":5,"managed":false,"permissions":d.permissions.load(Ordering::SeqCst).to_string()},
                {"id":"100000000000000020","position":10,"managed":false,"permissions":(1u64 << 28).to_string()},
                {"id":HIGH,"position":8,"managed":false,"permissions":"8"},
                {"id":LOW,"position":4,"managed":false,"permissions":"0"}
            ]))
        })).with_state(discord.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    let store = Store::open(":memory:").unwrap();
    let mut state = crate::tests::state(store);
    state.guild_authorization = Arc::new(GuildAuthorization::with_test_base(format!(
        "http://{address}"
    )));
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
            "PUT",
            "/api/quick-setup/steps/roles",
            serde_json::json!({"status":"applied","enabled":true,"config":{"channel":"100000000000000060","roleIds":[HIGH]}}),
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
