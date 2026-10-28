use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

const GUILD: &str = "100000000000000001";
const CHANNEL: &str = "100000000000000060";

fn fixture(premium: bool) -> (ApiState, SessionClaims) {
    let store = Store::open(":memory:").unwrap();
    let state = crate::tests::state(store);
    let now = Utc::now();
    let claims = SessionClaims {
        session_id: Uuid::new_v4(),
        user_id: "100000000000000002".into(),
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
    if premium {
        let mut value = helper_contracts::EntitlementSnapshot::free(claims.user_id.clone());
        value.plan = Plan::Premium { guild_limit: 1 };
        state.store.save_entitlement(&value).unwrap();
    }
    (state, claims)
}

fn snapshot() -> DiscordGuildSnapshot {
    DiscordGuildSnapshot {
        channels: vec![
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD,"type":0,"permission_overwrites":[]}),
        ],
        roles: vec![
            serde_json::json!({"id":GUILD,"position":0,"permissions":"0"}),
            serde_json::json!({"id":"bot-role","position":10,"permissions":"8"}),
        ],
        bot_role_ids: vec!["bot-role".into()],
        bot_user_id: Some("bot-user".into()),
        channels_ready: true,
        roles_ready: true,
        bot_ready: true,
        ..Default::default()
    }
}

fn document(settings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"version":1,"guildId":"another-guild","settings":settings,"tags":[],"workflows":[],"birthdays":[]})
}

async fn send(
    state: ApiState,
    claims: &SessionClaims,
    document: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let token = sign_session(claims, &state.session_secret);
    TEST_SNAPSHOT
        .scope(snapshot(), async move {
            let response = router(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/config/import")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(document.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                    .unwrap();
            (status, value)
        })
        .await
}

#[tokio::test]
async fn portable_import_updates_canonical_features_and_reports_old_runtime_keys() {
    let (state, claims) = fixture(true);
    let store = state.store.clone();
    store
        .publish_feature_setting(GUILD, "utility.help", false, "{}", None, "old", &[])
        .unwrap();
    let mut doc = document(serde_json::json!([
        {"key":"feature.utility.help","value":"true"},
        {"key":"feature.config.utility.help","value":"{\"showModules\":false,\"showDashboard\":true}"},
        {"key":"community.role_panel.forged","value":"{\"role_ids\":[\"admin\"]}"},
        {"key":"support.welcome.channel_id","value":"foreign"},
        {"key":"oauth.redirect","value":"https://attacker.invalid"}
    ]));
    doc["tags"] =
        serde_json::json!([{"name":"rules","content":"be kind","authorId":"forged-actor"}]);
    doc["workflows"] = serde_json::json!([{"name":"thanks","trigger":"message","condition":"thanks","action":"react","payload":"✅","enabled":true}]);
    doc["birthdays"] = serde_json::json!([{"userId":"member","month":2,"day":29}]);
    let (status, body) = send(state.clone(), &claims, doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["skippedSettingsCount"], 3);
    let feature = store
        .get_feature_setting(GUILD, "utility.help")
        .unwrap()
        .unwrap();
    assert!(feature.enabled);
    assert_eq!(feature.revision, 2);
    assert_eq!(feature.updated_by, claims.user_id);
    assert_eq!(
        store
            .get_setting(GUILD, "utility.help.show_modules")
            .unwrap()
            .as_deref(),
        Some("false")
    );
    for key in [
        "community.role_panel.forged",
        "support.welcome.channel_id",
        "oauth.redirect",
    ] {
        assert!(store.get_setting(GUILD, key).unwrap().is_none());
    }
    assert_eq!(
        store.get_tag(GUILD, "rules").unwrap().unwrap().author_id,
        claims.user_id
    );
    assert_eq!(store.active_workflows(GUILD, "message").unwrap().len(), 1);
    assert_eq!(
        store.export_guild(GUILD).unwrap()["birthdays"][0]["month"],
        2
    );
    let old_export = store.export_guild(GUILD).unwrap();
    let (status, body) = send(state, &claims, old_export).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["skippedSettingsCount"].as_u64().unwrap() > 0);
    assert_eq!(
        store
            .get_feature_setting(GUILD, "utility.help")
            .unwrap()
            .unwrap()
            .revision,
        3
    );
    assert!(
        store
            .get_feature_setting("another-guild", "utility.help")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn import_rejects_malformed_settings_before_any_writes() {
    for settings in [
        serde_json::json!([{"key":"feature.utility.help","value":"TRUE"}]),
        serde_json::json!([{"key":"feature.utility.help","value":"true"},{"key":"feature.utility.help","value":"false"}]),
        serde_json::json!([{"key":"feature.config.utility.help","value":"[]"}]),
        serde_json::json!([{"key":"feature.config.utility.help","value":"{\"showModules\":\"true\"}"}]),
        serde_json::json!([{"key":"feature.config.utility.help","value":"{\"runtimePublisher\":\"forged\"}"}]),
    ] {
        let (state, claims) = fixture(true);
        let store = state.store.clone();
        let mut doc = document(settings);
        doc["tags"] = serde_json::json!([{"name":"rules","content":"hello","authorId":"x"}]);
        let (status, body) = send(state, &claims, doc).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(store.get_tag(GUILD, "rules").unwrap().is_none());
        assert!(
            store
                .get_feature_setting(GUILD, "utility.help")
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn config_only_import_validates_current_enabled_state_and_foreign_channels() {
    let (state, claims) = fixture(true);
    let store = state.store.clone();
    store
        .publish_feature_setting(GUILD, "community.birthdays", true, "{}", None, "old", &[])
        .unwrap();
    let mut doc = document(
        serde_json::json!([{"key":"feature.config.community.birthdays","value":"{\"channel\":\"100000000000000999\",\"message\":\"Happy birthday {user}\"}"}]),
    );
    doc["tags"] = serde_json::json!([{"name":"rules","content":"hello","authorId":"x"}]);
    let (status, body) = send(state, &claims, doc).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
    assert_eq!(
        store
            .get_feature_setting(GUILD, "community.birthdays")
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    assert!(store.get_tag(GUILD, "rules").unwrap().is_none());
}

#[tokio::test]
async fn import_cannot_enable_premium_or_create_paid_workflows_without_entitlement() {
    for mut doc in [
        document(serde_json::json!([{"key":"feature.community.leaderboard","value":"true"}])),
        document(serde_json::json!([])),
    ] {
        if doc["settings"].as_array().unwrap().is_empty() {
            doc["workflows"] = serde_json::json!([{"name":"x","trigger":"message","action":"reply","payload":"hi"}]);
        }
        let (state, claims) = fixture(false);
        let store = state.store.clone();
        let (status, body) = send(state, &claims, doc).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            store
                .get_feature_setting(GUILD, "community.leaderboard")
                .unwrap()
                .is_none()
        );
        assert!(store.workflows(GUILD, 100).unwrap().is_empty());
    }
}

#[tokio::test]
async fn legitimate_disable_and_config_only_update_use_canonical_revisions() {
    let (state, claims) = fixture(true);
    let store = state.store.clone();
    store
        .publish_feature_setting(
            GUILD,
            "utility.help",
            true,
            "{\"showModules\":true,\"showDashboard\":true}",
            None,
            "old",
            &[],
        )
        .unwrap();
    let (status,body)=send(state.clone(),&claims,document(serde_json::json!([{"key":"feature.config.utility.help","value":"{\"showModules\":false,\"showDashboard\":true}"}]))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        store
            .get_feature_setting(GUILD, "utility.help")
            .unwrap()
            .unwrap()
            .enabled
    );
    let (status, body) = send(
        state,
        &claims,
        document(serde_json::json!([{"key":"feature.utility.help","value":"false"}])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let feature = store
        .get_feature_setting(GUILD, "utility.help")
        .unwrap()
        .unwrap();
    assert!(!feature.enabled);
    assert_eq!(feature.revision, 3);
    assert!(feature.config_json.contains("showModules"));
}

#[tokio::test]
async fn rank_card_fractional_opacity_and_nullable_backgrounds_survive_old_export_roundtrip() {
    let (state, claims) = fixture(true);
    let store = state.store.clone();
    let mut card = serde_json::to_value(RankCardConfig::default()).unwrap();
    card["overlay_opacity"] = serde_json::json!(0.35);
    assert!(card["background_preset"].is_null());
    strict_config_types("studio.rank_card", &card).unwrap();
    let doc = document(serde_json::json!([
        {"key":"feature.studio.rank_card","value":"true"},
        {"key":"feature.config.studio.rank_card","value":card.to_string()}
    ]));
    let (status, body) = send(state.clone(), &claims, doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let old_export = store.export_guild(GUILD).unwrap();
    let (status, body) = send(state, &claims, old_export).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored: serde_json::Value = serde_json::from_str(
        &store
            .get_feature_setting(GUILD, "studio.rank_card")
            .unwrap()
            .unwrap()
            .config_json,
    )
    .unwrap();
    assert_eq!(stored["overlay_opacity"], serde_json::json!(0.35));
    assert!(stored["background_preset"].is_null());
    assert!(stored["background_url"].is_null());
    assert!(stored["background_data"].is_null());
    assert!(body["skippedSettingsCount"].as_u64().unwrap() > 0);
    let mut malformed = card;
    malformed["overlay_opacity"] = serde_json::json!("0.35");
    assert!(strict_config_types("studio.rank_card", &malformed).is_err());
    assert!(
        strict_config_types(
            "studio.rank_card",
            &serde_json::json!({"overlayOpacity":0.35})
        )
        .is_ok()
    );
}

#[tokio::test]
async fn nickname_import_is_explicitly_skipped_and_never_replays_external_identity() {
    let (state, claims) = fixture(false);
    let store = state.store.clone();
    let (status, body) = send(
        state,
        &claims,
        document(serde_json::json!([
            {"key":"feature.management.nickname","value":"true"},
            {"key":"feature.config.management.nickname","value":"{\"nickname\":\"Changed\"}"}
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["skippedSettingsCount"], 2);
    assert_eq!(
        body["imported"]["skipped_settings"][0]["reason"],
        "requires_dedicated_nickname_publication"
    );
    assert!(
        store
            .get_feature_setting(GUILD, "management.nickname")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_setting(GUILD, "identity.nickname")
            .unwrap()
            .is_none()
    );
}
