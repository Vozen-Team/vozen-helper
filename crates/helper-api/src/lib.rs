//! Versioned API and compatibility routes for the existing panel.

#![recursion_limit = "256"]

mod achievements;
mod activity_feed;
mod discord_context;
mod discord_read;
mod economy_shop;
mod starboard_channel;
mod ticket_panel;

use anyhow::Result;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, patch, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use helper_contracts::Plan;
use helper_contracts::{
    AntiSpamDecision, AntiSpamObservation, ApiError, FeatureMaturity, RANK_CARD_BACKGROUND_PRESETS,
    RankCardConfig, SessionClaims, SimulationResult, ValidationIssue, is_valid_workflow_reaction,
};
use helper_core::{
    Capability, FEATURE_SCHEMA_VERSION, LeaderboardEntry, ReminderObservation,
    anti_spam_policy_from_json, evaluate_anti_spam, evaluate_leaderboard, evaluate_reminder,
    feature_adapter, feature_maturity, is_known_feature, leaderboard_policy_from_json, quota_limit,
    reminder_policy_from_json,
};
use helper_modules::{
    BlueskyClient, CoinGeckoClient, EntitlementClient, EthereumRpcClient, GasClient,
    InstagramClient, KickClient, RssClient, SiweVerifier, StripeConnectClient, TikTokClient,
    TikTokOAuthClient, TokenCipher, TwitchClient, YouTubeClient, env_flag_is_true,
    first_env_flag_is_true, format_rss_message, format_twitch_message, format_youtube_message,
    tiktok_runtime_allowed,
};
use helper_store::{
    BlueskySubscriptionRecord, BlueskySubscriptionWrite, InstagramSubscriptionRecord,
    InstagramSubscriptionWrite, KickSubscriptionRecord, KickSubscriptionWrite,
    RssSubscriptionRecord, RssSubscriptionWrite, Store, TikTokSubscriptionRecord,
    TikTokSubscriptionWrite, TopggSyncStatus, TwitchSubscriptionRecord, TwitchSubscriptionWrite,
    YouTubeSubscriptionRecord, YouTubeSubscriptionWrite,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
const COOKIE: &str = "vh_session";
const INSTALL_FLOW_MARKER: &str = "install";
// Instalação base: View Channel, Send Messages, Embed Links e Read Message History.
// Permissões sensíveis são verificadas pelo passaporte antes de cada módulo ser publicado.
const HELPER_INSTALL_PERMISSIONS: &str = "84992";
const SESSION_RESPONSE_HEADER: &str = "x-vozen-session";
const SESSION_MAX_HOURS: i64 = 8;
const IDLE_MINUTES: i64 = 30;
static TICKET_PANEL_SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub discord_token: String,
    pub session_secret: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_redirect_uri: String,
    pub oauth_success_redirect: String,
    pub trusted_vozen_oauth_client_id: Option<String>,
    pub private_tracker_client_id: Option<String>,
    pub private_tracker_owner_id: Option<String>,
    pub allow_legacy_session: bool,
    pub allowed_origin: Option<String>,
    pub entitlements: Option<EntitlementClient>,
    pub youtube: Option<YouTubeClient>,
    pub rss: Option<RssClient>,
    pub twitch: Option<TwitchClient>,
    pub bluesky: Option<BlueskyClient>,
    pub tiktok: Option<TikTokClient>,
    pub instagram: Option<InstagramClient>,
    pub kick: Option<KickClient>,
    pub stripe: Option<StripeConnectClient>,
    pub siwe: Option<SiweVerifier>,
    pub coingecko: Option<CoinGeckoClient>,
    pub gas: GasClient,
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
    pub timestamp: String,
}

pub fn router(state: ApiState) -> Router {
    let allowed_origin = state.allowed_origin.clone();
    let router = Router::new()
        .route("/api/economy/notifications", put(economy_shop::settings))
        .route("/api/economy/shop", get(economy_shop::get))
        .route("/api/economy/products", post(economy_shop::create))
        .route(
            "/api/economy/products/{id}",
            put(economy_shop::update).delete(economy_shop::remove),
        )
        .route("/api/economy/orders/{id}", put(economy_shop::resolve))
        .route("/health", get(health))
        .route("/api/v1/health", get(health))
        .route("/api/session", post(create_session))
        .route("/api/session/vozen", post(create_vozen_account_session))
        .route(
            "/api/admin/private-tracker/session",
            post(create_private_tracker_session),
        )
        .route(
            "/api/admin/private-tracker/handoff",
            post(create_private_tracker_handoff),
        )
        .route("/api/admin/growth", get(admin_growth))
        .route("/api/oauth/start", post(oauth_start_post))
        .route("/api/install/start", get(oauth_install_start))
        .route("/api/oauth/callback", get(oauth_callback))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/achievements/{guild}", get(achievements::page))
        .route("/api/starboard/channel", post(starboard_channel::create))
        .route("/api/economy/channel", post(starboard_channel::create_shop))
        .route(
            "/api/temp-channels/category",
            post(starboard_channel::create_temp_category),
        )
        .route(
            "/api/birthdays/channel",
            post(starboard_channel::create_birthday),
        )
        .route(
            "/api/tickets/category",
            post(starboard_channel::create_ticket_category),
        )
        .route(
            "/api/tickets/channel",
            post(starboard_channel::create_ticket_panel),
        )
        .route("/api/providers/youtube/health", get(youtube_health))
        .route(
            "/api/providers/youtube/channels/{channel_id}",
            get(youtube_channel),
        )
        .route(
            "/api/config/youtube",
            get(youtube_subscriptions).post(create_youtube_subscription),
        )
        .route(
            "/api/config/youtube/{id}",
            put(update_youtube_subscription).delete(delete_youtube_subscription),
        )
        .route(
            "/api/config/youtube/{id}/health",
            get(youtube_subscription_health),
        )
        .route("/api/config/youtube/{id}/test", post(test_youtube_delivery))
        .route("/api/providers/rss/preview", get(rss_preview))
        .route(
            "/api/config/rss",
            get(rss_subscriptions).post(create_rss_subscription),
        )
        .route(
            "/api/config/rss/{id}",
            put(update_rss_subscription).delete(delete_rss_subscription),
        )
        .route("/api/config/rss/{id}/health", get(rss_subscription_health))
        .route("/api/config/rss/{id}/test", post(test_rss_delivery))
        .route(
            "/api/config/bluesky",
            get(bluesky_subscriptions).post(create_bluesky_subscription),
        )
        .route(
            "/api/config/bluesky/{id}",
            put(update_bluesky_subscription).delete(delete_bluesky_subscription),
        )
        .route("/api/providers/tiktok/health", get(tiktok_health))
        .route(
            "/api/providers/tiktok/oauth/status",
            get(tiktok_oauth_status),
        )
        .route(
            "/api/providers/tiktok/oauth/start",
            post(tiktok_oauth_start),
        )
        .route(
            "/api/providers/tiktok/oauth/callback",
            get(tiktok_oauth_callback),
        )
        .route(
            "/api/providers/tiktok/oauth/connection",
            axum::routing::delete(tiktok_oauth_disconnect),
        )
        .route(
            "/api/config/tiktok",
            get(tiktok_subscriptions).post(create_tiktok_subscription),
        )
        .route(
            "/api/config/tiktok/{id}",
            put(update_tiktok_subscription).delete(delete_tiktok_subscription),
        )
        .route("/api/config/tiktok/{id}/test", post(test_tiktok_delivery))
        .route("/api/providers/instagram/health", get(instagram_health))
        .route(
            "/api/config/instagram",
            get(instagram_subscriptions).post(create_instagram_subscription),
        )
        .route(
            "/api/config/instagram/{id}",
            put(update_instagram_subscription).delete(delete_instagram_subscription),
        )
        .route("/api/providers/kick/health", get(kick_health))
        .route(
            "/api/config/kick",
            get(kick_subscriptions).post(create_kick_subscription),
        )
        .route(
            "/api/config/kick/{id}",
            put(update_kick_subscription).delete(delete_kick_subscription),
        )
        .route("/api/providers/stripe/health", get(stripe_health))
        .route("/api/providers/stripe/webhook", post(stripe_webhook))
        .route("/api/providers/coingecko/health", get(coingecko_health))
        .route("/api/providers/gas/health", get(gas_health))
        .route("/api/providers/gas/quote", get(gas_quote))
        .route("/api/web3/gating/nonce", post(web3_gating_nonce))
        .route("/api/web3/gating/verify", post(web3_gating_verify))
        .route("/api/providers/twitch/health", get(twitch_health))
        .route(
            "/api/providers/twitch/channels/{login}",
            get(twitch_channel),
        )
        .route("/api/providers/twitch/eventsub", post(twitch_eventsub))
        // Keep the shorter callback used by the existing VPS environment.
        .route("/twitch/eventsub", post(twitch_eventsub))
        .route(
            "/api/config/twitch",
            get(twitch_subscriptions).post(create_twitch_subscription),
        )
        .route(
            "/api/config/twitch/{id}",
            put(update_twitch_subscription).delete(delete_twitch_subscription),
        )
        .route(
            "/api/config/twitch/{id}/health",
            get(twitch_subscription_health),
        )
        .route("/api/config/twitch/{id}/test", post(test_twitch_delivery))
        .route("/api/guilds", get(guilds))
        .route("/api/guild-context", get(guild_context))
        .route("/api/preflight", post(preflight))
        .route("/api/quick-setup", get(quick_setup))
        .route("/api/quick-setup/dismiss", post(quick_setup_dismiss))
        .route("/api/quick-setup/steps/{step}", put(quick_setup_step))
        .route("/api/session/switch", post(switch_session_guild))
        .route("/api/cases", get(cases))
        .route("/api/audit", get(audit))
        .route("/api/activity", get(activity))
        .route("/api/activity/feed", get(activity_feed::get))
        .route("/api/tickets", get(tickets))
        .route("/api/stats", get(stats))
        .route("/api/leaderboard", get(leaderboard))
        .route("/api/quotas", get(quotas))
        .route(
            "/api/premium/server",
            get(premium_server_status).post(premium_server_activate),
        )
        .route("/api/modules", get(modules))
        .route(
            "/api/config/features",
            get(feature_config).put(update_feature_config),
        )
        .route(
            "/api/config/features/{key}",
            get(feature_detail).put(update_feature_detail),
        )
        .route("/api/config/features/{key}/health", get(feature_health))
        .route(
            "/api/config/features/{key}/preflight",
            post(feature_preflight),
        )
        .route("/api/config/features/{key}/test", post(test_feature))
        .route("/api/config/features/{key}/simulate", post(test_feature))
        .route(
            "/api/config/features/{key}/revisions",
            get(feature_revisions),
        )
        .route(
            "/api/config/features/{key}/rollback",
            post(feature_rollback),
        )
        .route("/api/config/features/{key}/repair", post(feature_repair))
        .route(
            "/api/studio/brand",
            get(studio_brand).put(update_studio_brand),
        )
        .route(
            "/api/studio/rank-card",
            get(studio_rank_card).put(update_studio_rank_card),
        )
        .route(
            "/api/studio/templates",
            get(studio_templates).post(create_studio_template),
        )
        .route(
            "/api/studio/templates/{id}",
            get(studio_template)
                .put(update_studio_template)
                .delete(delete_studio_template),
        )
        .route(
            "/api/studio/templates/{id}/revisions",
            get(studio_template_revisions),
        )
        .route(
            "/api/studio/templates/{id}/rollback",
            post(rollback_studio_template),
        )
        .route("/api/permissions", get(permissions))
        .route("/api/security/health", get(security_health))
        .route("/api/analytics", get(analytics))
        .route("/api/privacy/export", get(privacy_export))
        .route("/api/privacy/receipt", get(privacy_receipt))
        .route("/api/privacy/delete", post(privacy_delete))
        .route("/api/config/import", post(import_config))
        .route("/api/workflows", get(workflows).post(create_workflow))
        .route(
            "/api/workflows/{id}",
            patch(update_workflow).delete(delete_workflow),
        )
        .route(
            "/api/custom-commands",
            get(custom_commands).post(create_custom_command),
        )
        .route(
            "/api/custom-commands/{name}",
            put(update_custom_command).delete(delete_custom_command),
        )
        .route("/api/role-panels", get(role_panels).post(create_role_panel))
        .route(
            "/api/role-panels/{message_id}",
            put(update_role_panel).delete(delete_role_panel),
        )
        .route(
            "/api/role-panels/{message_id}/repair",
            post(repair_role_panel),
        );
    let router = if let Some(origins) = allowed_origin {
        let values = origins
            .split(',')
            .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok())
            .collect::<Vec<_>>();
        if !values.is_empty() {
            router.layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(values))
                    .allow_credentials(true)
                    .allow_methods([
                        http::Method::GET,
                        http::Method::POST,
                        http::Method::PUT,
                        http::Method::DELETE,
                        http::Method::OPTIONS,
                    ])
                    .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]),
            )
        } else {
            tracing::warn!("HELPER_ALLOWED_ORIGIN is invalid; CORS disabled");
            router
        }
    } else {
        router
    };
    router.with_state(Arc::new(state))
}

#[derive(Debug, Deserialize)]
struct OAuthStartRequest {
    guild_id: String,
    code_challenge: String,
    code_verifier: String,
}

#[derive(Debug, Serialize)]
struct OAuthStartResponse {
    authorization_url: String,
    state: String,
}

#[derive(Clone, Copy)]
enum OAuthFlow {
    Account,
    Install,
}

async fn oauth_start_post(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<OAuthStartRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    if request.guild_id == INSTALL_FLOW_MARKER {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_oauth_request",
        ));
    }
    oauth_start_inner(
        &state,
        &request.guild_id,
        &request.code_challenge,
        &request.code_verifier,
        OAuthFlow::Account,
    )
}

/// Starts the Helper bot-installation flow from a first-party endpoint.
///
/// Discord only accepts registered OAuth callback URIs. Keeping the flow here
/// means the panel never has to guess at a static callback URL, and lets us
/// safely create the panel session after Discord adds the bot to a server.
#[derive(Debug, Deserialize)]
struct InstallStartQuery {
    source: Option<String>,
}

async fn oauth_install_start(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<InstallStartQuery>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let source = query.source.as_deref().unwrap_or("unknown");
    if source != "unknown" && helper_store::growth_source(source).is_none() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_install_source",
        ));
    }
    let code_verifier = new_code_verifier();
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let install_marker = format!("{INSTALL_FLOW_MARKER}:{source}");
    let authorization_url = oauth_authorization_url(
        &state,
        &install_marker,
        &code_challenge,
        &code_verifier,
        OAuthFlow::Install,
    )?;
    Ok(Redirect::temporary(authorization_url.as_str()).into_response())
}

fn oauth_start_inner(
    state: &ApiState,
    guild_id: &str,
    code_challenge: &str,
    code_verifier: &str,
    flow: OAuthFlow,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let authorization_url =
        oauth_authorization_url(state, guild_id, code_challenge, code_verifier, flow)?;
    let state_token = authorization_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("OAuth authorization URLs always include state");
    let response = Json(OAuthStartResponse {
        authorization_url: authorization_url.into(),
        state: state_token,
    })
    .into_response();
    Ok(response)
}

fn oauth_authorization_url(
    state: &ApiState,
    guild_id: &str,
    code_challenge: &str,
    code_verifier: &str,
    flow: OAuthFlow,
) -> Result<url::Url, (StatusCode, Json<ApiError>)> {
    if !is_valid_pkce_verifier(code_verifier)
        || code_challenge.len() != 43
        || URL_SAFE_NO_PAD
            .decode(code_challenge)
            .map(|decoded| decoded.len() != 32)
            .unwrap_or(true)
    {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_oauth_request",
        ));
    }
    let expected_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    if expected_challenge != code_challenge {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "pkce_challenge_mismatch",
        ));
    }
    let expires = (Utc::now() + Duration::minutes(10)).timestamp();
    let payload = format!("{}.{}.{}", guild_id, expires, code_challenge);
    let state_token = sign_oauth_state(&payload, &state.session_secret);
    let state_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(state_token.as_bytes()));
    state
        .store
        .register_oauth_state(&state_hash, expires, code_verifier)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let mut url = url::Url::parse("https://discord.com/oauth2/authorize").expect("static URL");
    let mut query = url.query_pairs_mut();
    query
        .append_pair("client_id", &state.oauth_client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &state.oauth_redirect_uri)
        .append_pair("state", &state_token)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    match flow {
        OAuthFlow::Account => {
            query.append_pair("scope", "identify guilds");
        }
        OAuthFlow::Install => {
            query
                .append_pair("permissions", HELPER_INSTALL_PERMISSIONS)
                .append_pair("scope", "bot applications.commands identify guilds")
                .append_pair("integration_type", "0");
        }
    }
    drop(query);
    Ok(url)
}

fn new_code_verifier() -> String {
    let mut bytes = [0_u8; 48];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn is_valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
    guild_id: Option<String>,
}

async fn oauth_callback(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let payload = verify_oauth_state(&query.state, &state.session_secret)
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "invalid_oauth_state"))?;
    let parts: Vec<&str> = payload.splitn(3, '.').collect();
    if parts.len() != 3
        || parts[1]
            .parse::<i64>()
            .ok()
            .is_none_or(|exp| exp < Utc::now().timestamp())
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "expired_oauth_state"));
    }
    let state_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(query.state.as_bytes()));
    let stored_verifier = state
        .store
        .consume_oauth_state(&state_hash, Utc::now().timestamp())
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if stored_verifier.is_none() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "oauth_state_replayed",
        ));
    }
    let code_verifier = stored_verifier
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "missing_pkce_verifier"))?;
    let client = Client::new();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    if challenge != parts[2] {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "pkce_verifier_mismatch",
        ));
    }
    let token = client
        .post("https://discord.com/api/v10/oauth2/token")
        .form(&[
            ("client_id", state.oauth_client_id.as_str()),
            ("client_secret", state.oauth_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("redirect_uri", state.oauth_redirect_uri.as_str()),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !token.status().is_success() {
        return Err(client_error(
            StatusCode::UNAUTHORIZED,
            "oauth_exchange_failed",
        ));
    }
    let token: serde_json::Value = token
        .json()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response"))?;
    let access_token = token
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if access_token.is_empty() {
        return Err(client_error(
            StatusCode::UNAUTHORIZED,
            "oauth_token_missing",
        ));
    }
    let install_source = parts[0]
        .strip_prefix(&format!("{INSTALL_FLOW_MARKER}:"))
        .or_else(|| (parts[0] == INSTALL_FLOW_MARKER).then_some("unknown"));
    let guild_id = if install_source.is_some() {
        token
            .get("guild")
            .and_then(|guild| guild.get("id"))
            .and_then(|id| id.as_str())
            .or(query.guild_id.as_deref())
            .filter(|id| is_discord_snowflake(id))
            .map(ToOwned::to_owned)
            .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "missing_installed_guild"))?
    } else {
        parts[0].to_string()
    };
    let success_redirect = state.oauth_success_redirect.clone();
    let mut response = create_session_inner(
        State(state.clone()),
        headers,
        Json(SessionRequest {
            token: access_token.to_string(),
            guild_id: guild_id.clone(),
        }),
    )
    .await?;
    if let Some(source) = install_source {
        state
            .store
            .record_growth_install(&guild_id, source, Utc::now().timestamp_millis())
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    }
    // `create_session_inner` uses this internal response header to pass the
    // opaque session to the legacy OAuth transport. Always remove it before
    // redirecting so a browser can only receive a session through the cookie.
    let session_token = response
        .headers_mut()
        .remove(SESSION_RESPONSE_HEADER)
        .and_then(|value| value.to_str().ok().map(ToOwned::to_owned));
    let mut success_url = url::Url::parse(&success_redirect).map_err(|_| {
        client_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_oauth_success_redirect",
        )
    })?;
    let uses_cookie_session = oauth_redirect_uses_cookie_session(&success_url);
    if install_source.is_some() {
        success_url.query_pairs_mut().append_pair("installed", "1");
    }
    if !uses_cookie_session {
        let session_token = session_token.ok_or_else(|| {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "session_token_missing")
        })?;
        success_url.set_fragment(Some(&format!("session={session_token}")));
    }
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(
        header::LOCATION,
        success_url.as_str().parse().map_err(|_| {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_oauth_redirect")
        })?,
    );
    Ok(response)
}

/// The first-party Vozen Helper panel receives its session through the secure,
/// shared `.vozen.org` cookie. Legacy redirects retain the fragment transport
/// only for the temporary compatibility window.
fn oauth_redirect_uses_cookie_session(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("vozen.org"))
        && url.port_or_known_default() == Some(443)
        && matches!(
            url.path(),
            "/panel/helper-tracker" | "/panel/helper-tracker/"
        )
        && url.query().is_none()
        && url.fragment().is_none()
}

async fn health() -> impl IntoResponse {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: Utc::now().to_rfc3339(),
    })
}

#[derive(Debug, Deserialize)]
struct GrowthQuery {
    product: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

fn valid_helper_growth_product(product: Option<&str>) -> bool {
    matches!(product, None | Some("helper"))
}

/// Aggregate-only growth reporting for the dedicated owner tracker.  A normal
/// server-admin session is deliberately insufficient: this route never
/// returns guild IDs, but acquisition and retention are still business-wide
/// information.
async fn admin_growth(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<GrowthQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let owner_id = state
        .private_tracker_owner_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "private_tracker_unavailable"))?;
    if claims.user_id != owner_id {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "private_tracker_forbidden",
        ));
    }
    if !valid_helper_growth_product(query.product.as_deref()) {
        return Err(client_error(StatusCode::BAD_REQUEST, "bad_product"));
    }
    let today = Utc::now().date_naive();
    let to = query
        .to
        .unwrap_or_else(|| today.format("%Y-%m-%d").to_string());
    let to_date = chrono::NaiveDate::parse_from_str(&to, "%Y-%m-%d")
        .map_err(|_| client_error(StatusCode::BAD_REQUEST, "bad_range"))?;
    let from = query
        .from
        .unwrap_or_else(|| (to_date - Duration::days(6)).format("%Y-%m-%d").to_string());
    let from_date = chrono::NaiveDate::parse_from_str(&from, "%Y-%m-%d")
        .map_err(|_| client_error(StatusCode::BAD_REQUEST, "bad_range"))?;
    let span = (to_date - from_date).num_days();
    if !(0..90).contains(&span) {
        return Err(client_error(StatusCode::BAD_REQUEST, "bad_range"));
    }
    let now_ms = Utc::now().timestamp_millis();
    let overview = state
        .store
        .growth_overview(&from, &to, now_ms)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let topgg = state
        .store
        .topgg_sync_status(now_ms)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let topgg = topgg_admin_payload(topgg, overview.active_guilds);
    let mut daily = BTreeMap::<(String, String), serde_json::Value>::new();
    for point in &overview.daily {
        let row = daily
            .entry((point.day.clone(), point.source.clone()))
            .or_insert_with(|| {
                serde_json::json!({
                    "day": point.day,
                    "source": point.source,
                    "joins": 0,
                    "leaves": 0,
                    "setupCompleted": 0,
                    "firstValue": 0,
                    "active": 0,
                    "votes": 0,
                })
            });
        let field = match point.event.as_str() {
            "join" => "joins",
            "leave" => "leaves",
            "setup_completed" => "setupCompleted",
            "first_value" => "firstValue",
            "active" => "active",
            _ => continue,
        };
        row[field] = serde_json::Value::from(point.value);
    }
    let daily = daily.into_values().collect::<Vec<_>>();
    Ok(Json(helper_growth_admin_payload(&overview, daily, topgg)))
}

fn helper_growth_admin_payload(
    overview: &helper_store::GrowthOverview,
    daily: Vec<serde_json::Value>,
    topgg: Option<serde_json::Value>,
) -> serde_json::Value {
    let setup_completed = daily
        .iter()
        .filter_map(|point| {
            point
                .get("setupCompleted")
                .and_then(serde_json::Value::as_i64)
        })
        .sum::<i64>();
    let first_value = daily
        .iter()
        .filter_map(|point| point.get("firstValue").and_then(serde_json::Value::as_i64))
        .sum::<i64>();
    let joins = overview.joins;
    let rate = |value| {
        if joins == 0 {
            0.0
        } else {
            value as f64 / joins as f64
        }
    };
    serde_json::json!({
        "product": "helper",
        "currentGuilds": overview.active_guilds,
        "baselineGuilds": 0,
        "measurementStartedOn": overview.measurement_started_on,
        "configuredGuilds": overview.configured_guilds,
        "usedGuilds": overview.used_guilds,
        "joins": joins,
        "leaves": overview.leaves,
        "net": overview.net,
        "setupCompleted": setup_completed,
        "firstValue": first_value,
        "votes": 0,
        "setupRate": rate(setup_completed),
        "activationRate": rate(first_value),
        "retainedW7": overview.retained_w7_count,
        "eligibleW7": overview.eligible_w7,
        "retainedW30": overview.retained_w30_count,
        "eligibleW30": overview.eligible_w30,
        "retainedW7Rate": overview.retained_w7,
        "retainedW30Rate": overview.retained_w30,
        "daily": daily,
        "topgg": topgg,
    })
}

fn topgg_admin_payload(
    status: Option<TopggSyncStatus>,
    current_server_count: i64,
) -> Option<serde_json::Value> {
    status.map(|status| {
        let drift_percent = status.last_server_count.map(|reported| {
            if reported == 0 {
                if current_server_count == 0 { 0.0 } else { 1.0 }
            } else {
                (current_server_count.saturating_sub(reported).unsigned_abs() as f64)
                    / reported.unsigned_abs().max(1) as f64
            }
        });
        let alert = status.stale || drift_percent.is_some_and(|value| value > 0.05);
        serde_json::json!({
            "lastAttemptAt": status.last_attempt_at,
            "lastSuccessAt": status.last_success_at,
            "lastStatus": status.last_status,
            "lastServerCount": status.last_server_count,
            "currentServerCount": current_server_count,
            "lastDetail": status.last_detail,
            "consecutiveFailures": status.consecutive_failures,
            "stale": status.stale,
            "driftPercent": drift_percent,
            "alert": alert,
        })
    })
}

#[derive(Debug, Serialize)]
struct TikTokOAuthStartResponse {
    authorization_url: String,
}

#[derive(Debug, Deserialize)]
struct TikTokOAuthCallbackQuery {
    code: Option<String>,
    state: String,
    error: Option<String>,
}

async fn tiktok_oauth_status(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let grant = state
        .store
        .tiktok_grant(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let sandbox = tiktok_sandbox_enabled();
    Ok(Json(match grant {
        Some(grant) => serde_json::json!({
            "connected": true,
            "sandbox": sandbox,
            "openId": grant.open_id,
            "displayName": grant.display_name,
            "scopes": grant.scopes.split(',').map(str::trim).filter(|v| !v.is_empty()).collect::<Vec<_>>(),
            "accessExpiresAt": grant.access_expires_at,
            "updatedAt": grant.updated_at
        }),
        None => serde_json::json!({"connected": false, "sandbox": sandbox}),
    }))
}

async fn tiktok_oauth_start(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<TikTokOAuthStartResponse>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let oauth = TikTokOAuthClient::from_env().ok_or_else(|| {
        client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tiktok_oauth_not_configured",
        )
    })?;
    let expires = (Utc::now() + Duration::minutes(10)).timestamp();
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let payload = format!("tiktok.{}.{}.{}", claims.guild_id, expires, nonce);
    let signed_state = sign_oauth_state(&payload, &state.session_secret);
    let state_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(signed_state.as_bytes()));
    state
        .store
        .register_oauth_state(&state_hash, expires, &nonce)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let authorization_url = oauth
        .authorization_url(&signed_state)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "tiktok_oauth_url_failed"))?;
    Ok(Json(TikTokOAuthStartResponse { authorization_url }))
}

async fn tiktok_oauth_callback(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<TikTokOAuthCallbackQuery>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    if query.error.is_some() {
        return Err(client_error(StatusCode::BAD_REQUEST, "tiktok_oauth_denied"));
    }
    let payload = verify_oauth_state(&query.state, &state.session_secret)
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "invalid_oauth_state"))?;
    let parts = payload.split('.').collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "tiktok"
        || !is_discord_snowflake(parts[1])
        || parts[2]
            .parse::<i64>()
            .ok()
            .is_none_or(|exp| exp < Utc::now().timestamp())
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "expired_oauth_state"));
    }
    let state_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(query.state.as_bytes()));
    let stored_nonce = state
        .store
        .consume_oauth_state(&state_hash, Utc::now().timestamp())
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if stored_nonce.as_deref() != Some(parts[3]) {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "oauth_state_replayed",
        ));
    }
    let oauth = TikTokOAuthClient::from_env().ok_or_else(|| {
        client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tiktok_oauth_not_configured",
        )
    })?;
    let code = query
        .code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "tiktok_oauth_code_missing"))?;
    let grant = oauth
        .exchange_code(code)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "tiktok_oauth_exchange_failed"))?;
    let cipher = TokenCipher::new(&state.session_secret).map_err(|_| {
        client_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_cipher_unavailable",
        )
    })?;
    let now = Utc::now().timestamp();
    state
        .store
        .save_tiktok_grant(
            parts[1],
            &grant.open_id,
            &grant.open_id,
            &cipher.seal(&grant.access_token).map_err(|_| {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "token_seal_failed")
            })?,
            &cipher.seal(&grant.refresh_token).map_err(|_| {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "token_seal_failed")
            })?,
            &grant.scope,
            now.saturating_add(grant.expires_in),
            now.saturating_add(grant.refresh_expires_in),
            now,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let mut redirect = url::Url::parse(&state.oauth_success_redirect).map_err(|_| {
        client_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_oauth_success_redirect",
        )
    })?;
    redirect.set_fragment(Some("/config/social.tiktok?connected=1"));
    Ok(Redirect::to(redirect.as_str()).into_response())
}

async fn tiktok_oauth_disconnect(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    state
        .store
        .delete_tiktok_grant(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// Authenticated, non-secret provider readiness check used by the panel.
/// This intentionally reports only whether the server has a credential; the
/// API key itself never crosses this boundary.
async fn youtube_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let configured = state
        .youtube
        .as_ref()
        .is_some_and(YouTubeClient::is_configured);
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "provider": "youtube",
        "feature": "social.youtube",
        "configured": configured,
        "status": if configured { "ready" } else { "missing_credentials" },
        "message": if configured {
            "The official integration is ready to validate public channels."
        } else {
            "Adiciona YOUTUBE_API_KEY apenas no ambiente do servidor."
        }
    })))
}

async fn coingecko_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let Some(client) = state.coingecko.as_ref() else {
        return Ok(Json(serde_json::json!({
            "guildId": claims.guild_id,
            "provider": "coingecko",
            "feature": "web3.crypto_queries",
            "configured": false,
            "status": "missing_provider",
            "message": "The CoinGecko client is not available in this release."
        })));
    };
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "provider": "coingecko",
        "feature": "web3.crypto_queries",
        "configured": true,
        "mode": if client.has_api_key() { "api_key" } else { "public_keyless" },
        "status": "ready",
        "message": "Read-only CoinGecko prices are available; never treat them as financial advice."
    })))
}

async fn gas_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let networks = state.gas.configured_networks();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "provider": "gas_rpc",
        "feature": "web3.gas_tracker",
        "configured": !networks.is_empty(),
        "status": if networks.is_empty() { "missing_provider" } else { "ready" },
        "networks": networks,
        "message": "Gas data is read-only and comes only from operator-approved HTTPS RPC endpoints."
    })))
}

#[derive(Debug, Deserialize)]
struct SiweVerifyRequest {
    message: String,
    signature: String,
    nonce: String,
}

async fn web3_gating_nonce(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let Some(verifier) = state.siwe.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "siwe_not_configured",
        ));
    };
    let nonce = verifier.issue_nonce();
    let expires_at = Utc::now() + Duration::minutes(10);
    state
        .store
        .issue_siwe_nonce(
            &claims.guild_id,
            &claims.user_id,
            &nonce,
            expires_at.timestamp(),
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "domain": verifier.expected_domain(),
        "uri": verifier.expected_uri(),
        "nonce": nonce,
        "expiresAt": expires_at,
        "message": "Sign the exact SIWE message shown by the wallet; Vozen never requests a seed phrase or private key."
    })))
}

async fn web3_gating_verify(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<SiweVerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let Some(verifier) = state.siwe.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "siwe_not_configured",
        ));
    };
    if request.message.len() > 8_192 || request.signature.len() > 256 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "siwe_payload_too_large",
        ));
    }
    let stored = state
        .store
        .get_feature_setting(&claims.guild_id, "web3.gating")
        .ok()
        .flatten()
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "wallet_gating_not_configured"))?;
    if !stored.enabled {
        return Err(client_error(StatusCode::CONFLICT, "wallet_gating_disabled"));
    }
    let config: serde_json::Value = serde_json::from_str(&stored.config_json)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_saved_config"))?;
    let issues = validate_feature_config("web3.gating", &config);
    if issues.iter().any(|issue| issue.severity == "error") {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "wallet_gating_invalid_config",
        ));
    }
    let verified = verifier
        .verify(
            &request.message,
            &request.signature,
            &request.nonce,
            Utc::now(),
        )
        .map_err(|error| {
            tracing::debug!(%error, guild_id = %claims.guild_id, "SIWE verification rejected");
            client_error(StatusCode::UNAUTHORIZED, "siwe_verification_failed")
        })?;
    if !state
        .store
        .consume_siwe_nonce(
            &claims.guild_id,
            &claims.user_id,
            &request.nonce,
            Utc::now().timestamp(),
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    {
        return Err(client_error(
            StatusCode::UNAUTHORIZED,
            "siwe_nonce_replayed_or_expired",
        ));
    }
    let target_role_id = config
        .get("targetRoleId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.parse::<u64>().is_ok())
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "wallet_role_missing"))?;
    let chain = config
        .get("chain")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("ethereum");
    let contract_address = config
        .get("contractAddress")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !approved_wallet_contract(contract_address) {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "wallet_contract_not_approved",
        ));
    }
    let asset_type = config
        .get("assetType")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("erc721");
    let minimum_balance = config
        .get("minimumBalance")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("1");
    let Some(_rpc) = EthereumRpcClient::from_env(chain) else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "wallet_rpc_not_configured",
        ));
    };
    let expected_chain_id = match chain {
        "ethereum" => 1,
        "polygon" => 137,
        "arbitrum" => 42161,
        "base" => 8453,
        _ => {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "wallet_chain_invalid",
            ));
        }
    };
    if verified.chain_id != expected_chain_id {
        return Err(client_error(
            StatusCode::UNAUTHORIZED,
            "siwe_chain_mismatch",
        ));
    }
    let payload = serde_json::json!({
        "address": verified.address,
        "member_id": claims.user_id,
        "role_id": target_role_id,
        "chain": chain,
        "contract_address": contract_address,
        "asset_type": asset_type,
        "token_id": config.get("tokenId").and_then(serde_json::Value::as_str),
        "minimum_balance": minimum_balance,
        "interval_seconds": config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(3600),
    });
    let job = state
        .store
        .schedule_typed(
            &claims.guild_id,
            "web3_wallet_role_sync",
            &claims.user_id,
            Utc::now().timestamp_millis(),
            &payload.to_string(),
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "wallet_verified",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"jobId": job, "chain": chain}).to_string(),
    );
    Ok(Json(serde_json::json!({
        "accepted": true,
        "jobId": job,
        "address": verified.address,
        "chainId": verified.chain_id,
        "message": "Signature verified. The Helper will check the approved contract and update the role asynchronously."
    })))
}

#[derive(Debug, Deserialize)]
struct GasQuoteQuery {
    network: String,
}

async fn gas_quote(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<GasQuoteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let quote = state.gas.quote(&query.network).await.map_err(|error| {
        let code = error.to_string();
        let status = if code == "unsupported_rpc_network" {
            StatusCode::BAD_REQUEST
        } else if code == "rpc_network_not_configured" {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_GATEWAY
        };
        tracing::warn!(%error, guild_id = %claims.guild_id, "gas quote failed");
        client_error(status, &code)
    })?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "provider": "gas_rpc",
        "quote": quote
    })))
}

/// Resolves a public channel before a guild saves a YouTube alert. Keeping
/// this call server-side means the restricted API key is never exposed to the
/// browser and also gives the panel a friendly validation error.
async fn youtube_channel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _claims = require_auth(&state, &headers)?;
    let Some(client) = state.youtube.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let channel = client.channel(&channel_id).await.map_err(|error| {
        if error.to_string() == "invalid_youtube_channel_id" {
            client_error(StatusCode::BAD_REQUEST, "invalid_youtube_channel_id")
        } else {
            tracing::warn!(%error, "youtube channel lookup failed");
            client_error(StatusCode::BAD_GATEWAY, "youtube_provider_unavailable")
        }
    })?;
    let Some(channel) = channel else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_channel_not_found",
        ));
    };
    Ok(Json(
        serde_json::json!({"provider": "youtube", "channel": channel}),
    ))
}

#[derive(Debug, Deserialize)]
struct YouTubeSubscriptionInput {
    source_channel_id: String,
    target_channel_id: String,
    #[serde(default)]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_youtube_interval")]
    interval_seconds: i64,
    #[serde(default = "quick_default_true")]
    enabled: bool,
}

fn default_youtube_interval() -> i64 {
    300
}

fn default_true() -> bool {
    true
}

fn validate_youtube_subscription(
    input: YouTubeSubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let source = input.source_channel_id.trim().to_string();
    if source.len() < 3
        || source.len() > 64
        || !source
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("invalid_youtube_channel_id");
    }
    let target = input.target_channel_id.trim().to_string();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "New video from {channel}: **{title}**\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1_800 {
        return Err("invalid_youtube_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_string();
    if mention.chars().count() > 100
        || (!mention.is_empty()
            && mention != "@everyone"
            && mention != "@here"
            && !(mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
    {
        return Err("invalid_youtube_mention");
    }
    let interval = input.interval_seconds.clamp(300, 86_400);
    Ok((source, target, template, mention, input.enabled, interval))
}

fn youtube_record_json(record: YouTubeSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "guildId": record.guild_id,
        "sourceChannelId": record.source_channel_id,
        "targetChannelId": record.target_channel_id,
        "messageTemplate": record.message_template,
        "mention": record.mention,
        "enabled": record.enabled,
        "intervalSeconds": record.interval_seconds,
        "lastVideoId": record.last_video_id,
        "nextPollAt": record.next_poll_at,
        "failureCount": record.failure_count,
        "lastError": record.last_error,
        "createdBy": record.created_by,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    })
}

async fn prepare_youtube_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<YouTubeSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .youtube_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| YouTubeSubscriptionWrite {
            source_channel_id: subscription.source_channel_id,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = YouTubeSubscriptionInput {
        source_channel_id: config
            .get("sourceChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(300),
        enabled: true,
    };
    let (source, target, template, mention, _, interval) = validate_youtube_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.youtube.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .channel(&source)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "youtube_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_channel_not_found",
        ));
    }
    Ok(Some(YouTubeSubscriptionWrite {
        source_channel_id: source,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        interval_seconds: interval,
        created_by: claims.user_id.clone(),
    }))
}

async fn youtube_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .youtube_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(youtube_record_json)
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "subscriptions": subscriptions,
        "provider": "youtube"
    })))
}

async fn create_youtube_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<YouTubeSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.youtube").await?;
    let (source, target, template, mention, enabled, interval) =
        validate_youtube_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.youtube.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .channel(&source)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "youtube_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_channel_not_found",
        ));
    }
    let record = state
        .store
        .create_youtube_subscription(
            &claims.guild_id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "youtube_subscription_exists" {
                client_error(StatusCode::CONFLICT, "youtube_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let record = state
        .store
        .youtube_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|item| item.id == record.id)
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok((StatusCode::CREATED, Json(youtube_record_json(record))))
}

async fn update_youtube_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<YouTubeSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.youtube").await?;
    let (source, target, template, mention, enabled, interval) =
        validate_youtube_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.youtube.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .channel(&source)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "youtube_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_channel_not_found",
        ));
    }
    let record = state
        .store
        .update_youtube_subscription(
            &claims.guild_id,
            id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "youtube_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let Some(record) = record else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_subscription_not_found",
        ));
    };
    Ok(Json(youtube_record_json(record)))
}

async fn delete_youtube_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_youtube_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "youtube_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

fn youtube_provider_error_code(error: &str) -> &'static str {
    if error.starts_with("youtube_api_error:429") {
        "youtube_rate_limited"
    } else if error.starts_with("youtube_api_error:404") {
        "youtube_channel_not_found"
    } else {
        "youtube_provider_unavailable"
    }
}

/// Read-only health check for one persisted YouTube subscription. It checks
/// the official uploads endpoint without changing the polling cursor.
async fn youtube_subscription_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let record = state
        .store
        .youtube_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "youtube_subscription_not_found"))?;
    let checked_at = Utc::now().timestamp_millis();
    let Some(client) = state.youtube.as_ref() else {
        return Ok(Json(serde_json::json!({
            "provider": "youtube",
            "subscriptionId": id,
            "status": "dependency_down",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": record.last_error,
            "message": "YouTube is not configured on this server."
        })));
    };
    match client.latest_video(&record.source_channel_id).await {
        Ok(Some(video)) => Ok(Json(serde_json::json!({
            "provider": "youtube",
            "subscriptionId": id,
            "status": "ready",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": record.last_error,
            "channelId": record.source_channel_id,
            "latestVideo": {
                "id": video.id,
                "title": video.title,
                "url": video.url,
                "publishedAt": video.published_at,
                "channelTitle": video.channel_title
            }
        }))),
        Ok(None) => Ok(Json(serde_json::json!({
            "provider": "youtube",
            "subscriptionId": id,
            "status": "degraded",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": "youtube_no_public_video",
            "channelId": record.source_channel_id,
            "message": "The channel is reachable but has no public upload yet."
        }))),
        Err(error) => Ok(Json(serde_json::json!({
            "provider": "youtube",
            "subscriptionId": id,
            "status": "degraded",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": youtube_provider_error_code(&error.to_string()),
            "channelId": record.source_channel_id,
            "message": "The YouTube channel could not be checked right now."
        }))),
    }
}

/// Send a real, bounded Discord message for the newest public upload. This is
/// deliberately a delivery probe: it never advances `last_video_id`.
async fn test_youtube_delivery(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<YouTubeSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let record = state
        .store
        .youtube_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "youtube_subscription_not_found"))?;
    let (source, target, template, _mention, _enabled, _interval) =
        validate_youtube_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.youtube.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let latest = client.latest_video(&source).await.map_err(|error| {
        let code = youtube_provider_error_code(&error.to_string());
        let status = if code == "youtube_channel_not_found" {
            StatusCode::NOT_FOUND
        } else if code == "youtube_rate_limited" {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_GATEWAY
        };
        client_error(status, code)
    })?;
    let video_id = latest.as_ref().map(|video| video.id.clone());
    let content = if let Some(video) = latest.as_ref() {
        let rendered = format_youtube_message(&template, "", video, &source);
        format!("✅ Vozen YouTube test\n{rendered}")
    } else {
        format!(
            "✅ Vozen YouTube test — connected to channel **{source}**. No public video is currently available."
        )
    };
    let content = content.chars().take(2_000).collect::<String>();
    discord_send_channel_message(&state.discord_token, &target, &content)
        .await
        .map_err(|error| {
            let status = if error == "discord_http_403" || error == "discord_http_401" {
                StatusCode::FORBIDDEN
            } else if error == "discord_http_404" {
                StatusCode::NOT_FOUND
            } else if error == "invalid_discord_channel_id" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::BAD_GATEWAY
            };
            let code = if error == "discord_http_403" || error == "discord_http_401" {
                "discord_send_messages_forbidden"
            } else if error == "discord_http_404" {
                "discord_channel_not_found"
            } else if error == "invalid_discord_channel_id" {
                "invalid_discord_channel_id"
            } else {
                "discord_delivery_failed"
            };
            tracing::warn!(subscription_id = id, %error, "YouTube test delivery failed");
            client_error(status, code)
        })?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "youtube_test_delivery",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({
            "subscriptionId": id,
            "sourceChannelId": source,
            "videoId": video_id,
            "mode": "test"
        })
        .to_string(),
    );
    Ok(Json(serde_json::json!({
        "provider": "youtube",
        "subscriptionId": record.id,
        "delivered": true,
        "testedAt": Utc::now().timestamp_millis(),
        "videoId": video_id
    })))
}

#[derive(Debug, Deserialize)]
struct RssPreviewQuery {
    url: String,
}

async fn rss_preview(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<RssPreviewQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _claims = require_auth(&state, &headers)?;
    if query.url.trim().len() > 2_048 {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_rss_url"));
    }
    let Some(client) = state.rss.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let feed = client.fetch(&query.url).await.map_err(|error| {
        let code = error.to_string();
        if code.starts_with("invalid_rss_url") || code.starts_with("rss_private_host") {
            client_error(StatusCode::BAD_REQUEST, "invalid_rss_url")
        } else if code.starts_with("rss_http_error:404") {
            client_error(StatusCode::NOT_FOUND, "rss_feed_not_found")
        } else {
            tracing::warn!(%error, "rss preview failed");
            client_error(StatusCode::BAD_GATEWAY, "rss_provider_unavailable")
        }
    })?;
    let Some(feed) = feed else {
        return Err(client_error(StatusCode::BAD_REQUEST, "rss_feed_empty"));
    };
    Ok(Json(serde_json::json!({"provider": "rss", "feed": feed})))
}

fn rss_provider_error_code(error: &str) -> &'static str {
    if error.starts_with("invalid_rss_url") || error.starts_with("rss_private_host") {
        "invalid_rss_url"
    } else if error.starts_with("rss_http_error:404") {
        "rss_feed_not_found"
    } else if error.starts_with("rss_http_error:429") {
        "rss_rate_limited"
    } else {
        "rss_provider_unavailable"
    }
}

/// Read-only health check for one persisted feed. It intentionally returns a
/// degraded result as JSON when the external feed is unavailable so the
/// panel can distinguish a provider incident from an authentication failure.
async fn rss_subscription_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let record = state
        .store
        .rss_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "rss_subscription_not_found"))?;
    let checked_at = Utc::now().timestamp_millis();
    let Some(client) = state.rss.as_ref() else {
        return Ok(Json(serde_json::json!({
            "provider": "rss",
            "subscriptionId": id,
            "status": "dependency_down",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": record.last_error,
            "message": "RSS provider is not configured on this server."
        })));
    };
    match client.fetch(&record.feed_url).await {
        Ok(Some(feed)) => Ok(Json(serde_json::json!({
            "provider": "rss",
            "subscriptionId": id,
            "status": "ready",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": record.last_error,
            "feed": {
                "title": feed.title,
                "latestItemId": feed.latest.as_ref().map(|item| item.id.clone()),
                "latestTitle": feed.latest.as_ref().map(|item| item.title.clone())
            }
        }))),
        Ok(None) => Ok(Json(serde_json::json!({
            "provider": "rss",
            "subscriptionId": id,
            "status": "degraded",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": "rss_feed_empty",
            "message": "The feed responded but contains no readable item."
        }))),
        Err(error) => Ok(Json(serde_json::json!({
            "provider": "rss",
            "subscriptionId": id,
            "status": "degraded",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": rss_provider_error_code(&error.to_string()),
            "message": "The feed could not be checked right now."
        }))),
    }
}

/// Send a real, bounded Discord message using the configured bot. This does
/// not update `last_item_id`, `next_poll_at` or any subscription state; it is
/// deliberately a delivery probe rather than a poll.
async fn test_rss_delivery(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<RssSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let record = state
        .store
        .rss_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "rss_subscription_not_found"))?;
    let (feed_url, target, template, _mention, _enabled, _interval) =
        validate_rss_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.rss.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let feed = client.fetch(&feed_url).await.map_err(|error| {
        let code = rss_provider_error_code(&error.to_string());
        let status = if code == "invalid_rss_url" {
            StatusCode::BAD_REQUEST
        } else if code == "rss_feed_not_found" {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        };
        client_error(status, code)
    })?;
    let Some(feed) = feed else {
        return Err(client_error(StatusCode::BAD_REQUEST, "rss_feed_empty"));
    };
    let item_id = feed.latest.as_ref().map(|item| item.id.clone());
    let content = if let Some(item) = feed.latest.as_ref() {
        let rendered = format_rss_message(&template, "", item);
        format!("✅ Vozen RSS test\n{rendered}")
    } else {
        format!(
            "✅ Vozen RSS test — connected to **{}**. No item is currently available.",
            feed.title
        )
    };
    let content = content.chars().take(2_000).collect::<String>();
    discord_send_channel_message(&state.discord_token, &target, &content)
        .await
        .map_err(|error| {
            let status = if error == "discord_http_403" || error == "discord_http_401" {
                StatusCode::FORBIDDEN
            } else if error == "discord_http_404" {
                StatusCode::NOT_FOUND
            } else if error == "invalid_discord_channel_id" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::BAD_GATEWAY
            };
            let code = if error == "discord_http_403" || error == "discord_http_401" {
                "discord_send_messages_forbidden"
            } else if error == "discord_http_404" {
                "discord_channel_not_found"
            } else if error == "invalid_discord_channel_id" {
                "invalid_discord_channel_id"
            } else {
                "discord_delivery_failed"
            };
            tracing::warn!(subscription_id = id, %error, "RSS test delivery failed");
            client_error(status, code)
        })?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "rss_test_delivery",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({
            "subscriptionId": id,
            "itemId": item_id,
            "feedUrl": feed_url,
            "mode": "test"
        })
        .to_string(),
    );
    Ok(Json(serde_json::json!({
        "provider": "rss",
        "subscriptionId": record.id,
        "delivered": true,
        "testedAt": Utc::now().timestamp_millis(),
        "itemId": item_id
    })))
}

#[derive(Debug, Deserialize)]
struct RssSubscriptionInput {
    feed_url: String,
    target_channel_id: String,
    #[serde(default)]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_rss_interval")]
    interval_seconds: i64,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_rss_interval() -> i64 {
    300
}

fn validate_rss_subscription(
    input: RssSubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let feed_url = input.feed_url.trim().to_string();
    let parsed = url::Url::parse(&feed_url).map_err(|_| "invalid_rss_url")?;
    if feed_url.len() > 2_048
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("invalid_rss_url");
    }
    let target = input.target_channel_id.trim().to_string();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "New post from {feed}: **{title}**\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1_800 {
        return Err("invalid_rss_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_string();
    if mention.chars().count() > 100
        || (!mention.is_empty()
            && mention != "@everyone"
            && mention != "@here"
            && !(mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
    {
        return Err("invalid_rss_mention");
    }
    Ok((
        feed_url,
        target,
        template,
        mention,
        input.enabled,
        input.interval_seconds.clamp(300, 86_400),
    ))
}

fn rss_record_json(record: RssSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "guildId": record.guild_id,
        "feedUrl": record.feed_url,
        "targetChannelId": record.target_channel_id,
        "messageTemplate": record.message_template,
        "mention": record.mention,
        "enabled": record.enabled,
        "intervalSeconds": record.interval_seconds,
        "lastItemId": record.last_item_id,
        "nextPollAt": record.next_poll_at,
        "failureCount": record.failure_count,
        "lastError": record.last_error,
        "createdBy": record.created_by,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    })
}

async fn prepare_bluesky_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<BlueskySubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .bluesky_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| BlueskySubscriptionWrite {
            source_handle: subscription.source_handle,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = BlueskySubscriptionInput {
        source_handle: config
            .get("sourceHandle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(300),
        enabled: true,
    };
    let (source_handle, target, template, mention, _, interval) =
        validate_bluesky_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = state
        .bluesky
        .as_ref()
        .expect("Bluesky client is always configured");
    if client
        .latest_post(&source_handle)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "bluesky_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "bluesky_profile_not_found",
        ));
    }
    Ok(Some(BlueskySubscriptionWrite {
        source_handle,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        interval_seconds: interval,
        created_by: claims.user_id.clone(),
    }))
}

async fn prepare_tiktok_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<TikTokSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .tiktok_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| TikTokSubscriptionWrite {
            source_label: subscription.source_label,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = TikTokSubscriptionInput {
        username: config
            .get("username")
            .or_else(|| config.get("sourceLabel"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(900),
        enabled: true,
    };
    let (source_label, target_channel_id, message_template, mention, _, interval_seconds) =
        validate_tiktok_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = tiktok_provider_for_guild(state, &claims.guild_id).await?;
    client
        .latest_videos()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "tiktok_provider_unavailable"))?;
    Ok(Some(TikTokSubscriptionWrite {
        source_label,
        target_channel_id,
        message_template,
        mention,
        enabled: true,
        interval_seconds,
        created_by: claims.user_id.clone(),
    }))
}

async fn prepare_instagram_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<InstagramSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .instagram_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| InstagramSubscriptionWrite {
            source_label: subscription.source_label,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = InstagramSubscriptionInput {
        username: config
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(900),
        enabled: true,
    };
    let (username, target, template, mention, _, interval) = validate_instagram_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = require_instagram_provider(state)?;
    client
        .latest_media()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "instagram_provider_unavailable"))?;
    Ok(Some(InstagramSubscriptionWrite {
        source_label: username,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        interval_seconds: interval,
        created_by: claims.user_id.clone(),
    }))
}

async fn prepare_kick_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<KickSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .kick_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| KickSubscriptionWrite {
            source_handle: subscription.source_handle,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = KickSubscriptionInput {
        source_handle: config
            .get("sourceHandle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(300),
        enabled: true,
    };
    let (source, target, template, mention, _, interval) = validate_kick_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = require_kick_provider(state)?;
    client
        .latest_stream(&source)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "kick_provider_unavailable"))?;
    Ok(Some(KickSubscriptionWrite {
        source_handle: source,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        interval_seconds: interval,
        created_by: claims.user_id.clone(),
    }))
}

async fn prepare_rss_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<RssSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .rss_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| RssSubscriptionWrite {
            feed_url: subscription.feed_url,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            interval_seconds: subscription.interval_seconds,
            created_by: subscription.created_by,
        }));
    }
    let input = RssSubscriptionInput {
        feed_url: config
            .get("feedUrl")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        interval_seconds: config
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(300),
        enabled: true,
    };
    let (feed_url, target, template, mention, _, interval) = validate_rss_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.rss.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .fetch(&feed_url)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "rss_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "rss_feed_empty"));
    }
    Ok(Some(RssSubscriptionWrite {
        feed_url,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        interval_seconds: interval,
        created_by: claims.user_id.clone(),
    }))
}

async fn rss_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .rss_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(rss_record_json)
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "subscriptions": subscriptions,
        "provider": "rss"
    })))
}

async fn create_rss_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<RssSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.rss").await?;
    let (feed_url, target, template, mention, enabled, interval) = validate_rss_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.rss.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .fetch(&feed_url)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "rss_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "rss_feed_empty"));
    }
    let record = state
        .store
        .create_rss_subscription(
            &claims.guild_id,
            &feed_url,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "rss_subscription_exists" {
                client_error(StatusCode::CONFLICT, "rss_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(rss_record_json(record))))
}

async fn update_rss_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<RssSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.rss").await?;
    let (feed_url, target, template, mention, enabled, interval) = validate_rss_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.rss.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    if client
        .fetch(&feed_url)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "rss_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "rss_feed_empty"));
    }
    let record = state
        .store
        .update_rss_subscription(
            &claims.guild_id,
            id,
            &feed_url,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "rss_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let Some(record) = record else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "rss_subscription_not_found",
        ));
    };
    Ok(Json(rss_record_json(record)))
}

async fn delete_rss_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_rss_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "rss_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

#[derive(Debug, Deserialize)]
struct BlueskySubscriptionInput {
    #[serde(rename = "sourceHandle")]
    source_handle: String,
    #[serde(rename = "targetChannelId")]
    target_channel_id: String,
    #[serde(default, rename = "messageTemplate")]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_bluesky_interval")]
    interval_seconds: i64,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_bluesky_interval() -> i64 {
    300
}

fn validate_bluesky_subscription(
    input: BlueskySubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let handle = input
        .source_handle
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    if !(3..=253).contains(&handle.len())
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || handle.starts_with('.')
        || handle.ends_with('.')
        || handle.contains("..")
    {
        return Err("invalid_bluesky_handle");
    }
    let target = input.target_channel_id.trim().to_string();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "New Bluesky post from {handle}: **{text}**\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1_800 {
        return Err("invalid_bluesky_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_string();
    if mention.chars().count() > 100
        || (!mention.is_empty()
            && mention != "@everyone"
            && mention != "@here"
            && !(mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
    {
        return Err("invalid_bluesky_mention");
    }
    if !(300..=86_400).contains(&input.interval_seconds) {
        return Err("invalid_bluesky_interval");
    }
    Ok((
        handle,
        target,
        template,
        mention,
        input.enabled,
        input.interval_seconds,
    ))
}

fn bluesky_record_json(record: BlueskySubscriptionRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "guildId": record.guild_id,
        "sourceHandle": record.source_handle,
        "targetChannelId": record.target_channel_id,
        "messageTemplate": record.message_template,
        "mention": record.mention,
        "enabled": record.enabled,
        "intervalSeconds": record.interval_seconds,
        "lastPostUri": record.last_post_uri,
        "nextPollAt": record.next_poll_at,
        "failureCount": record.failure_count,
        "lastError": record.last_error,
        "createdBy": record.created_by,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    })
}

async fn bluesky_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .bluesky_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(bluesky_record_json)
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "subscriptions": subscriptions,
        "provider": "bluesky"
    })))
}

async fn create_bluesky_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<BlueskySubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.bluesky").await?;
    let (handle, target, template, mention, enabled, interval) =
        validate_bluesky_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = state
        .bluesky
        .as_ref()
        .expect("Bluesky client is always configured");
    if client
        .latest_post(&handle)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "bluesky_provider_unavailable"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "bluesky_profile_not_found",
        ));
    }
    let record = state
        .store
        .create_bluesky_subscription(
            &claims.guild_id,
            &handle,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "bluesky_subscription_exists" {
                client_error(StatusCode::CONFLICT, "bluesky_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(bluesky_record_json(record))))
}

async fn update_bluesky_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<BlueskySubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.bluesky").await?;
    let (handle, target, template, mention, enabled, interval) =
        validate_bluesky_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = state
        .bluesky
        .as_ref()
        .expect("Bluesky client is always configured");
    client
        .latest_post(&handle)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "bluesky_provider_unavailable"))?;
    let record = state
        .store
        .update_bluesky_subscription(
            &claims.guild_id,
            id,
            &handle,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "bluesky_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let Some(record) = record else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "bluesky_subscription_not_found",
        ));
    };
    Ok(Json(bluesky_record_json(record)))
}

async fn delete_bluesky_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_bluesky_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "bluesky_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

#[derive(Debug, Deserialize)]
struct TikTokSubscriptionInput {
    // Keep accepting the legacy sourceLabel spelling while the adapter's
    // canonical field remains username.
    #[serde(rename = "username", alias = "sourceLabel")]
    username: String,
    #[serde(rename = "targetChannelId")]
    target_channel_id: String,
    #[serde(default, rename = "messageTemplate")]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_tiktok_interval")]
    interval_seconds: i64,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_tiktok_interval() -> i64 {
    900
}

fn validate_tiktok_subscription(
    input: TikTokSubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let source = input.username.trim().to_owned();
    if !(2..=80).contains(&source.chars().count()) || source.contains(['\n', '\r']) {
        return Err("invalid_tiktok_source_label");
    }
    let target = input.target_channel_id.trim().to_string();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "New TikTok video from {label}: **{title}**\\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1_800 {
        return Err("invalid_tiktok_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_string();
    if mention.chars().count() > 100
        || (!mention.is_empty()
            && mention != "@everyone"
            && mention != "@here"
            && !(mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
    {
        return Err("invalid_tiktok_mention");
    }
    if !(900..=86_400).contains(&input.interval_seconds) {
        return Err("invalid_tiktok_interval");
    }
    Ok((
        source,
        target,
        template,
        mention,
        input.enabled,
        input.interval_seconds,
    ))
}

fn tiktok_record_json(record: TikTokSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "guildId": record.guild_id,
        "username": record.source_label,
        "sourceLabel": record.source_label,
        "targetChannelId": record.target_channel_id,
        "messageTemplate": record.message_template,
        "mention": record.mention,
        "enabled": record.enabled,
        "intervalSeconds": record.interval_seconds,
        "lastVideoId": record.last_video_id,
        "nextPollAt": record.next_poll_at,
        "failureCount": record.failure_count,
        "lastError": record.last_error,
        "createdBy": record.created_by,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    })
}

fn tiktok_approved() -> bool {
    first_env_flag_is_true(&["TIKTOK_APP_APPROVED", "TIKTOK_DISPLAY_API_APPROVED"])
}

/// TikTok requires first-time Display API integrations to demonstrate the
/// complete flow with developer-portal test users before App Review.  This
/// flag exposes that real OAuth-backed flow without claiming production
/// approval or enabling the legacy global access-token fallback.
fn tiktok_sandbox_enabled() -> bool {
    first_env_flag_is_true(&["TIKTOK_SANDBOX_MODE"])
}

async fn tiktok_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let connected = state
        .store
        .tiktok_grant(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .is_some();
    let oauth_configured = TikTokOAuthClient::from_env().is_some();
    let configured = connected || state.tiktok.is_some();
    let approved = tiktok_approved();
    let sandbox = tiktok_sandbox_enabled();
    Ok(Json(serde_json::json!({
        "provider": "tiktok",
        "configured": configured,
        "connected": connected,
        "oauthConfigured": oauth_configured,
        "apiApproval": approved,
        "sandbox": sandbox,
        "status": if connected { "ready" } else if !oauth_configured && !configured { "dependency_down" } else { "authorization_required" },
        "readOnly": true,
        "scopes": ["user.info.basic", "video.list"],
    })))
}

async fn tiktok_provider_for_guild(
    state: &ApiState,
    guild_id: &str,
) -> Result<TikTokClient, (StatusCode, Json<ApiError>)> {
    if let Some(mut grant) = state
        .store
        .tiktok_grant(guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    {
        let cipher = TokenCipher::new(&state.session_secret).map_err(|_| {
            client_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_cipher_unavailable",
            )
        })?;
        let now = Utc::now().timestamp();
        if grant.access_expires_at <= now + 300 {
            let oauth = TikTokOAuthClient::from_env().ok_or_else(|| {
                client_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "tiktok_oauth_not_configured",
                )
            })?;
            let refresh = cipher
                .open(&grant.refresh_token_sealed)
                .map_err(|_| client_error(StatusCode::UNAUTHORIZED, "tiktok_reconnect_required"))?;
            let refreshed = oauth
                .refresh(&refresh)
                .await
                .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "tiktok_refresh_failed"))?;
            grant.access_token_sealed = cipher.seal(&refreshed.access_token).map_err(|_| {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "token_seal_failed")
            })?;
            grant.refresh_token_sealed = cipher.seal(&refreshed.refresh_token).map_err(|_| {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "token_seal_failed")
            })?;
            grant.scopes = refreshed.scope;
            grant.access_expires_at = now.saturating_add(refreshed.expires_in);
            grant.refresh_expires_at = now.saturating_add(refreshed.refresh_expires_in);
            grant.updated_at = now;
            state
                .store
                .save_tiktok_grant(
                    guild_id,
                    &refreshed.open_id,
                    &grant.display_name,
                    &grant.access_token_sealed,
                    &grant.refresh_token_sealed,
                    &grant.scopes,
                    grant.access_expires_at,
                    grant.refresh_expires_at,
                    grant.updated_at,
                )
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
        }
        let access = cipher
            .open(&grant.access_token_sealed)
            .map_err(|_| client_error(StatusCode::UNAUTHORIZED, "tiktok_reconnect_required"))?;
        return TikTokClient::new(access, "https://open.tiktokapis.com")
            .ok_or_else(|| client_error(StatusCode::UNAUTHORIZED, "tiktok_reconnect_required"));
    }
    if tiktok_approved() {
        return state.tiktok.clone().ok_or_else(|| {
            client_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tiktok_provider_not_configured",
            )
        });
    }
    Err(client_error(
        StatusCode::PRECONDITION_REQUIRED,
        "tiktok_authorization_required",
    ))
}

async fn tiktok_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .tiktok_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(tiktok_record_json)
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "subscriptions": subscriptions, "provider": "tiktok", "readOnly": true}),
    ))
}

async fn create_tiktok_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<TikTokSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.tiktok").await?;
    let (source, target, template, mention, enabled, interval) =
        validate_tiktok_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = tiktok_provider_for_guild(&state, &claims.guild_id).await?;
    if enabled {
        client
            .latest_videos()
            .await
            .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "tiktok_provider_unavailable"))?;
    }
    let record = state
        .store
        .create_tiktok_subscription(
            &claims.guild_id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "tiktok_subscription_exists" {
                client_error(StatusCode::CONFLICT, "tiktok_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(tiktok_record_json(record))))
}

async fn update_tiktok_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<TikTokSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.tiktok").await?;
    let (source, target, template, mention, enabled, interval) =
        validate_tiktok_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let _client = tiktok_provider_for_guild(&state, &claims.guild_id).await?;
    let record = state
        .store
        .update_tiktok_subscription(
            &claims.guild_id,
            id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "tiktok_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let Some(record) = record else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "tiktok_subscription_not_found",
        ));
    };
    Ok(Json(tiktok_record_json(record)))
}

/// Deliver the latest public TikTok video to the configured Discord channel
/// without advancing the polling cursor. This gives App Review a truthful,
/// repeatable end-to-end sandbox demonstration.
async fn test_tiktok_delivery(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<TikTokSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.tiktok").await?;
    let record = state
        .store
        .tiktok_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "tiktok_subscription_not_found"))?;
    let (source, target, template, mention, _enabled, _interval) =
        validate_tiktok_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = tiktok_provider_for_guild(&state, &claims.guild_id).await?;
    let latest = client
        .latest_videos()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "tiktok_provider_unavailable"))?
        .into_iter()
        .next();
    let video_id = latest.as_ref().map(|video| video.id.clone());
    let content = if let Some(video) = latest.as_ref() {
        let rendered = template
            .replace("{label}", &source)
            .replace("{title}", &video.title)
            .replace("{description}", &video.description)
            .replace("{url}", &video.url)
            .replace("{created_at}", &video.created_at)
            .replace("{id}", &video.id);
        let rendered = if mention.is_empty() {
            rendered
        } else {
            format!("{mention} {rendered}")
        };
        format!("✅ Vozen TikTok sandbox test\n{rendered}")
    } else {
        format!(
            "✅ Vozen TikTok sandbox test — connected to **{source}**. No public video is currently available."
        )
    };
    let content = content.chars().take(2_000).collect::<String>();
    discord_send_channel_message(&state.discord_token, &target, &content)
        .await
        .map_err(|error| {
            let status = if error == "discord_http_403" || error == "discord_http_401" {
                StatusCode::FORBIDDEN
            } else if error == "discord_http_404" {
                StatusCode::NOT_FOUND
            } else if error == "invalid_discord_channel_id" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::BAD_GATEWAY
            };
            let code = if error == "discord_http_403" || error == "discord_http_401" {
                "discord_send_messages_forbidden"
            } else if error == "discord_http_404" {
                "discord_channel_not_found"
            } else if error == "invalid_discord_channel_id" {
                "invalid_discord_channel_id"
            } else {
                "discord_delivery_failed"
            };
            client_error(status, code)
        })?;
    Ok(Json(serde_json::json!({
        "provider": "tiktok",
        "subscriptionId": record.id,
        "delivered": true,
        "testedAt": Utc::now().timestamp_millis(),
        "videoId": video_id,
        "cursorAdvanced": false,
        "sandbox": tiktok_sandbox_enabled(),
    })))
}

async fn delete_tiktok_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_tiktok_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "tiktok_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

#[derive(Debug, Deserialize)]
struct InstagramSubscriptionInput {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "targetChannelId")]
    target_channel_id: String,
    #[serde(default, rename = "messageTemplate")]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_instagram_interval")]
    interval_seconds: i64,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_instagram_interval() -> i64 {
    900
}
fn valid_mention(mention: &str) -> bool {
    mention.chars().count() <= 100
        && (mention.is_empty()
            || mention == "@everyone"
            || mention == "@here"
            || (mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
}

fn validate_instagram_subscription(
    input: InstagramSubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let username = input.username.trim().trim_start_matches('@').to_owned();
    if !(2..=80).contains(&username.chars().count())
        || username.contains(['/', ':', '\\', '\n', '\r', ' '])
    {
        return Err("invalid_instagram_username");
    }
    let target = input.target_channel_id.trim().to_owned();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "New Instagram post from @{username}: **{caption}**\\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1800 {
        return Err("invalid_instagram_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_owned();
    if !valid_mention(&mention) {
        return Err("invalid_instagram_mention");
    }
    if !(900..=86400).contains(&input.interval_seconds) {
        return Err("invalid_instagram_interval");
    }
    Ok((
        username,
        target,
        template,
        mention,
        input.enabled,
        input.interval_seconds,
    ))
}

fn instagram_record_json(record: InstagramSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({"id":record.id,"guildId":record.guild_id,"username":record.source_label,"targetChannelId":record.target_channel_id,"messageTemplate":record.message_template,"mention":record.mention,"enabled":record.enabled,"intervalSeconds":record.interval_seconds,"lastMediaId":record.last_media_id,"nextPollAt":record.next_poll_at,"failureCount":record.failure_count,"lastError":record.last_error,"createdBy":record.created_by,"createdAt":record.created_at,"updatedAt":record.updated_at})
}

fn instagram_approved() -> bool {
    first_env_flag_is_true(&["META_APP_APPROVED", "META_INSTAGRAM_APP_APPROVED"])
}

/// Allows an explicitly configured Meta/Instagram tester account to be used
/// while the app is still in development mode. This never changes the
/// production approval flag and must be opted into by the operator.
fn instagram_development_mode() -> bool {
    env_flag_is_true("META_INSTAGRAM_DEVELOPMENT_MODE")
}

fn instagram_access_allowed(approved: bool, development_mode: bool) -> bool {
    approved || development_mode
}

fn instagram_runtime_allowed() -> bool {
    instagram_access_allowed(instagram_approved(), instagram_development_mode())
}

async fn instagram_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = require_auth(&state, &headers)?;
    let configured = state
        .instagram
        .as_ref()
        .is_some_and(InstagramClient::is_configured);
    let approved = instagram_approved();
    let development_mode = instagram_development_mode();
    Ok(Json(serde_json::json!({
        "provider":"instagram",
        "configured":configured,
        "apiApproval":approved,
        "developmentMode":development_mode,
        "status":if !configured {"missing_credentials"} else if approved {"ready"} else if development_mode {"ready_development"} else {"blocked_app_approval"},
        "scopes":["instagram_basic","instagram_manage_insights"]
    })))
}
fn require_instagram_provider(
    state: &ApiState,
) -> Result<&InstagramClient, (StatusCode, Json<ApiError>)> {
    if !instagram_runtime_allowed() {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "instagram_app_approval_required",
        ));
    }
    state.instagram.as_ref().ok_or_else(|| {
        client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "instagram_provider_not_configured",
        )
    })
}
async fn instagram_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .instagram_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(instagram_record_json)
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId":claims.guild_id,"subscriptions":subscriptions,"provider":"instagram"}),
    ))
}
async fn create_instagram_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<InstagramSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.instagram").await?;
    let (username, target, template, mention, enabled, interval) =
        validate_instagram_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = require_instagram_provider(&state)?;
    if enabled {
        client
            .latest_media()
            .await
            .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "instagram_provider_unavailable"))?;
    }
    let record = state
        .store
        .create_instagram_subscription(
            &claims.guild_id,
            &username,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "instagram_subscription_exists" {
                client_error(StatusCode::CONFLICT, "instagram_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(instagram_record_json(record))))
}
async fn update_instagram_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<InstagramSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.instagram").await?;
    let (username, target, template, mention, enabled, interval) =
        validate_instagram_subscription(input)
            .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let _ = require_instagram_provider(&state)?;
    let record = state
        .store
        .update_instagram_subscription(
            &claims.guild_id,
            id,
            &username,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "instagram_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    record
        .map(instagram_record_json)
        .map(Json)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "instagram_subscription_not_found"))
}
async fn delete_instagram_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_instagram_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "instagram_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}

#[derive(Debug, Deserialize)]
struct KickSubscriptionInput {
    #[serde(rename = "sourceHandle")]
    source_handle: String,
    #[serde(rename = "targetChannelId")]
    target_channel_id: String,
    #[serde(default, rename = "messageTemplate")]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_kick_interval")]
    interval_seconds: i64,
    #[serde(default = "default_true")]
    enabled: bool,
}
fn default_kick_interval() -> i64 {
    300
}
fn validate_kick_subscription(
    input: KickSubscriptionInput,
) -> Result<(String, String, String, String, bool, i64), &'static str> {
    let source = input
        .source_handle
        .trim()
        .trim_start_matches('@')
        .to_lowercase();
    if !(2..=80).contains(&source.chars().count())
        || source.contains(['/', ':', '\\', '\n', '\r', ' '])
    {
        return Err("invalid_kick_source_handle");
    }
    let target = input.target_channel_id.trim().to_owned();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "{handle} is live!\\n{url}".into());
    if template.trim().is_empty() || template.chars().count() > 1800 {
        return Err("invalid_kick_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_owned();
    if !valid_mention(&mention) {
        return Err("invalid_kick_mention");
    }
    if !(300..=86400).contains(&input.interval_seconds) {
        return Err("invalid_kick_interval");
    }
    Ok((
        source,
        target,
        template,
        mention,
        input.enabled,
        input.interval_seconds,
    ))
}
fn kick_record_json(record: KickSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({"id":record.id,"guildId":record.guild_id,"sourceHandle":record.source_handle,"targetChannelId":record.target_channel_id,"messageTemplate":record.message_template,"mention":record.mention,"enabled":record.enabled,"intervalSeconds":record.interval_seconds,"lastStreamId":record.last_stream_id,"nextPollAt":record.next_poll_at,"failureCount":record.failure_count,"lastError":record.last_error,"createdBy":record.created_by,"createdAt":record.created_at,"updatedAt":record.updated_at})
}
fn kick_approved() -> bool {
    first_env_flag_is_true(&["KICK_APP_APPROVED", "KICK_API_APPROVED"])
}
async fn kick_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = require_auth(&state, &headers)?;
    let configured = state.kick.is_some();
    let approved = kick_approved();
    Ok(Json(
        serde_json::json!({"provider":"kick","configured":configured,"apiApproval":approved,"status":if !approved{"blocked_app_approval"}else if !configured{"missing_credentials"}else{"ready"},"officialApi":true}),
    ))
}
fn require_kick_provider(state: &ApiState) -> Result<&KickClient, (StatusCode, Json<ApiError>)> {
    if !kick_approved() {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "kick_app_approval_required",
        ));
    }
    state.kick.as_ref().ok_or_else(|| {
        client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "kick_provider_not_configured",
        )
    })
}
async fn kick_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .kick_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(kick_record_json)
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId":claims.guild_id,"subscriptions":subscriptions,"provider":"kick"}),
    ))
}
async fn create_kick_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<KickSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.kick").await?;
    let (source, target, template, mention, enabled, interval) = validate_kick_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let client = require_kick_provider(&state)?;
    if enabled {
        client
            .latest_stream(&source)
            .await
            .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "kick_provider_unavailable"))?;
    }
    let record = state
        .store
        .create_kick_subscription(
            &claims.guild_id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "kick_subscription_exists" {
                client_error(StatusCode::CONFLICT, "kick_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(kick_record_json(record))))
}
async fn update_kick_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<KickSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.kick").await?;
    let (source, target, template, mention, enabled, interval) = validate_kick_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let _ = require_kick_provider(&state)?;
    let record = state
        .store
        .update_kick_subscription(
            &claims.guild_id,
            id,
            &source,
            &target,
            &template,
            &mention,
            enabled,
            interval,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "kick_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    record
        .map(kick_record_json)
        .map(Json)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "kick_subscription_not_found"))
}
async fn delete_kick_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_kick_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "kick_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}

#[derive(Debug, Deserialize)]
struct TwitchSubscriptionInput {
    #[serde(rename = "sourceLogin")]
    source_login: String,
    #[serde(rename = "targetChannelId")]
    target_channel_id: String,
    #[serde(default, rename = "messageTemplate")]
    message_template: Option<String>,
    #[serde(default)]
    mention: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn validate_twitch_subscription(
    input: TwitchSubscriptionInput,
) -> Result<(String, String, String, String, bool), &'static str> {
    let login = input
        .source_login
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    if login.is_empty()
        || login.len() > 25
        || !login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("invalid_twitch_login");
    }
    let target = input.target_channel_id.trim().to_string();
    if target.len() < 15 || target.len() > 22 || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_discord_channel_id");
    }
    let template = input
        .message_template
        .unwrap_or_else(|| "{broadcaster} is live!\nhttps://twitch.tv/{login}".to_string());
    if template.trim().is_empty() || template.chars().count() > 1_800 {
        return Err("invalid_twitch_template");
    }
    let mention = input.mention.unwrap_or_default().trim().to_string();
    if mention.chars().count() > 100
        || (!mention.is_empty()
            && mention != "@everyone"
            && mention != "@here"
            && !(mention.starts_with("<@&")
                && mention.ends_with('>')
                && mention[3..mention.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())))
    {
        return Err("invalid_twitch_mention");
    }
    Ok((login, target, template, mention, input.enabled))
}

fn twitch_record_json(record: TwitchSubscriptionRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "guildId": record.guild_id,
        "sourceLogin": record.source_login,
        "sourceUserId": record.source_user_id,
        "targetChannelId": record.target_channel_id,
        "messageTemplate": record.message_template,
        "mention": record.mention,
        "enabled": record.enabled,
        "pendingEventId": record.pending_event_id,
        "pendingStreamId": record.pending_stream_id,
        "pendingStartedAt": record.pending_started_at,
        "nextPollAt": record.next_poll_at,
        "failureCount": record.failure_count,
        "lastError": record.last_error,
        "createdBy": record.created_by,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    })
}

async fn twitch_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let configured = state
        .twitch
        .as_ref()
        .is_some_and(TwitchClient::is_configured);
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "provider": "twitch",
        "feature": "social.twitch",
        "configured": configured,
        "status": if configured { "ready" } else { "missing_credentials" },
        "message": if configured {
            "The official Twitch integration is ready for EventSub."
        } else {
            "Adiciona TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET e TWITCH_EVENTSUB_SECRET apenas no servidor."
        }
    })))
}

async fn twitch_channel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(login): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _claims = require_auth(&state, &headers)?;
    let Some(client) = state.twitch.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let user = client.user(&login).await.map_err(|error| {
        if error.to_string() == "invalid_twitch_login" {
            client_error(StatusCode::BAD_REQUEST, "invalid_twitch_login")
        } else {
            tracing::warn!(%error, "twitch channel lookup failed");
            client_error(StatusCode::BAD_GATEWAY, "twitch_provider_unavailable")
        }
    })?;
    let Some(user) = user else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_channel_not_found",
        ));
    };
    Ok(Json(
        serde_json::json!({"provider": "twitch", "channel": user}),
    ))
}

async fn prepare_twitch_feature(
    state: &ApiState,
    claims: &SessionClaims,
    config: &serde_json::Value,
    enabled: bool,
) -> Result<Option<TwitchSubscriptionWrite>, (StatusCode, Json<ApiError>)> {
    let existing = state
        .store
        .twitch_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .next();
    if !enabled {
        return Ok(existing.map(|subscription| TwitchSubscriptionWrite {
            source_login: subscription.source_login,
            source_user_id: subscription.source_user_id,
            target_channel_id: subscription.target_channel_id,
            message_template: subscription.message_template,
            mention: subscription.mention,
            enabled: false,
            created_by: subscription.created_by,
        }));
    }
    let input = TwitchSubscriptionInput {
        source_login: config
            .get("sourceLogin")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        target_channel_id: config
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        message_template: config
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        mention: config
            .get("mention")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        enabled: true,
    };
    let (login, target, template, mention, _) = validate_twitch_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.twitch.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let user = client
        .user(&login)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "twitch_provider_unavailable"))?;
    let Some(user) = user else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_channel_not_found",
        ));
    };
    client
        .ensure_stream_online_subscription(&user.id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "twitch EventSub subscription failed");
            client_error(StatusCode::BAD_GATEWAY, "twitch_eventsub_unavailable")
        })?;
    Ok(Some(TwitchSubscriptionWrite {
        source_login: user.login,
        source_user_id: user.id,
        target_channel_id: target,
        message_template: template,
        mention,
        enabled: true,
        created_by: claims.user_id.clone(),
    }))
}

async fn twitch_subscriptions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let subscriptions = state
        .store
        .twitch_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .map(twitch_record_json)
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "subscriptions": subscriptions, "provider": "twitch"}),
    ))
}

async fn create_twitch_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<TwitchSubscriptionInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.twitch").await?;
    let (login, target, template, mention, enabled) = validate_twitch_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.twitch.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let user = client
        .user(&login)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "twitch_provider_unavailable"))?;
    let Some(user) = user else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_channel_not_found",
        ));
    };
    if enabled {
        client
            .ensure_stream_online_subscription(&user.id)
            .await
            .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "twitch_eventsub_unavailable"))?;
    }
    let record = state
        .store
        .create_twitch_subscription(
            &claims.guild_id,
            &user.login,
            &user.id,
            &target,
            &template,
            &mention,
            enabled,
            &claims.user_id,
        )
        .map_err(|error| {
            if error.to_string() == "twitch_subscription_exists" {
                client_error(StatusCode::CONFLICT, "twitch_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok((StatusCode::CREATED, Json(twitch_record_json(record))))
}

async fn update_twitch_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<TwitchSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "social.twitch").await?;
    let (login, target, template, mention, enabled) = validate_twitch_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.twitch.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let user = client
        .user(&login)
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "twitch_provider_unavailable"))?;
    let Some(user) = user else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_channel_not_found",
        ));
    };
    if enabled {
        client
            .ensure_stream_online_subscription(&user.id)
            .await
            .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "twitch_eventsub_unavailable"))?;
    }
    let record = state
        .store
        .update_twitch_subscription(
            &claims.guild_id,
            id,
            &user.login,
            &user.id,
            &target,
            &template,
            &mention,
            enabled,
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                client_error(StatusCode::CONFLICT, "twitch_subscription_exists")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    let Some(record) = record else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_subscription_not_found",
        ));
    };
    Ok(Json(twitch_record_json(record)))
}

async fn delete_twitch_subscription(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let deleted = state
        .store
        .delete_twitch_subscription(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_subscription_not_found",
        ));
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

fn twitch_provider_error_code(error: &str) -> &'static str {
    if error.starts_with("twitch_api_error:429") {
        "twitch_rate_limited"
    } else if error.starts_with("twitch_auth_error") {
        "twitch_auth_failed"
    } else if error == "invalid_twitch_login" {
        "invalid_twitch_login"
    } else {
        "twitch_provider_unavailable"
    }
}

/// Read-only health check for one EventSub-backed subscription. It verifies
/// the broadcaster and confirms that an enabled stream.online subscription
/// exists without creating or changing one.
async fn twitch_subscription_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let record = state
        .store
        .twitch_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "twitch_subscription_not_found"))?;
    let checked_at = Utc::now().timestamp_millis();
    let Some(client) = state.twitch.as_ref() else {
        return Ok(Json(serde_json::json!({
            "provider": "twitch",
            "subscriptionId": id,
            "status": "dependency_down",
            "checkedAt": checked_at,
            "failureCount": record.failure_count,
            "lastError": record.last_error,
            "message": "Twitch is not configured on this server."
        })));
    };
    let user = match client.user(&record.source_login).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "provider": "twitch", "subscriptionId": id, "status": "degraded",
                "checkedAt": checked_at, "failureCount": record.failure_count,
                "lastError": "twitch_channel_not_found",
                "message": "The Twitch channel no longer exists or is unavailable."
            })));
        }
        Err(error) => {
            return Ok(Json(serde_json::json!({
                "provider": "twitch", "subscriptionId": id, "status": "degraded",
                "checkedAt": checked_at, "failureCount": record.failure_count,
                "lastError": twitch_provider_error_code(&error.to_string()),
                "message": "The Twitch channel could not be checked right now."
            })));
        }
    };
    match client.has_stream_online_subscription(&user.id).await {
        Ok(true) => Ok(Json(serde_json::json!({
            "provider": "twitch", "subscriptionId": id, "status": "ready",
            "checkedAt": checked_at, "failureCount": record.failure_count,
            "lastError": record.last_error,
            "channel": {"id": user.id, "login": user.login, "displayName": user.display_name},
            "eventSub": "enabled"
        }))),
        Ok(false) => Ok(Json(serde_json::json!({
            "provider": "twitch", "subscriptionId": id, "status": "degraded",
            "checkedAt": checked_at, "failureCount": record.failure_count,
            "lastError": "twitch_eventsub_missing",
            "channel": {"id": user.id, "login": user.login, "displayName": user.display_name},
            "eventSub": "missing",
            "message": "The EventSub subscription is not enabled; save the feature to repair it."
        }))),
        Err(error) => Ok(Json(serde_json::json!({
            "provider": "twitch", "subscriptionId": id, "status": "degraded",
            "checkedAt": checked_at, "failureCount": record.failure_count,
            "lastError": twitch_provider_error_code(&error.to_string()),
            "channel": {"id": user.id, "login": user.login, "displayName": user.display_name},
            "message": "EventSub health could not be checked right now."
        }))),
    }
}

/// Send a real Discord message proving that the configured Twitch destination
/// works. It uses a clearly marked synthetic stream payload and does not stage
/// or acknowledge an EventSub event.
async fn test_twitch_delivery(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<TwitchSubscriptionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let record = state
        .store
        .twitch_subscriptions(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "twitch_subscription_not_found"))?;
    let (login, target, template, _mention, _enabled) = validate_twitch_subscription(input)
        .map_err(|code| client_error(StatusCode::BAD_REQUEST, code))?;
    let Some(client) = state.twitch.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let user = client.user(&login).await.map_err(|error| {
        let code = twitch_provider_error_code(&error.to_string());
        client_error(
            if code == "invalid_twitch_login" {
                StatusCode::BAD_REQUEST
            } else if code == "twitch_rate_limited" {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_GATEWAY
            },
            code,
        )
    })?;
    let Some(user) = user else {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "twitch_channel_not_found",
        ));
    };
    let started_at = Utc::now().to_rfc3339();
    let content = format_twitch_message(&template, "", &user.login, "test-stream", &started_at);
    let content = format!("✅ Vozen Twitch test\n{content}")
        .chars()
        .take(2_000)
        .collect::<String>();
    discord_send_channel_message(&state.discord_token, &target, &content)
        .await
        .map_err(|error| {
            let status = if error == "discord_http_403" || error == "discord_http_401" {
                StatusCode::FORBIDDEN
            } else if error == "discord_http_404" {
                StatusCode::NOT_FOUND
            } else if error == "invalid_discord_channel_id" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::BAD_GATEWAY
            };
            let code = if error == "discord_http_403" || error == "discord_http_401" {
                "discord_send_messages_forbidden"
            } else if error == "discord_http_404" {
                "discord_channel_not_found"
            } else if error == "invalid_discord_channel_id" {
                "invalid_discord_channel_id"
            } else {
                "discord_delivery_failed"
            };
            tracing::warn!(subscription_id = id, %error, "Twitch test delivery failed");
            client_error(status, code)
        })?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "twitch_test_delivery",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"subscriptionId": id, "sourceLogin": user.login, "mode": "test"})
            .to_string(),
    );
    Ok(Json(serde_json::json!({
        "provider": "twitch",
        "subscriptionId": record.id,
        "delivered": true,
        "testedAt": Utc::now().timestamp_millis()
    })))
}

fn stripe_approved() -> bool {
    env_flag_is_true("STRIPE_CONNECT_APPROVED")
}

async fn stripe_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = require_auth(&state, &headers)?;
    let configured = state.stripe.is_some();
    let approved = stripe_approved();
    Ok(Json(serde_json::json!({
        "provider": "stripe_connect",
        "configured": configured,
        "approval": approved,
        "status": if !approved { "blocked_business_review" } else if !configured { "missing_credentials" } else { "ready" },
        "cardDataStored": false,
        "webhook": configured,
    })))
}

/// Receives signed Stripe events and turns successful server subscriptions
/// into an idempotent Discord role job. Metadata is supplied by the hosted
/// checkout; the Helper never receives card details.
async fn stripe_webhook(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let Some(client) = state.stripe.as_ref() else {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stripe_not_configured",
        ));
    };
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !client.verify_webhook(&body, signature, Utc::now().timestamp()) {
        return Err(client_error(
            StatusCode::UNAUTHORIZED,
            "invalid_stripe_signature",
        ));
    }
    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| client_error(StatusCode::BAD_REQUEST, "invalid_stripe_event"))?;
    let event_id = event
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if event_id.is_empty() || event_id.len() > 255 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_stripe_event_id",
        ));
    }
    if !state
        .store
        .record_provider_event("stripe", event_id, &String::from_utf8_lossy(&body))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    {
        return Ok(Json(serde_json::json!({"received":true,"duplicate":true})));
    }
    let event_type = event
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let object = event.pointer("/data/object").cloned().unwrap_or_default();
    if matches!(event_type, "checkout.session.completed" | "invoice.paid") {
        let metadata = object
            .get("metadata")
            .and_then(serde_json::Value::as_object);
        let guild_id = metadata
            .and_then(|m| m.get("guild_id"))
            .and_then(serde_json::Value::as_str);
        let member_id = metadata
            .and_then(|m| m.get("member_id"))
            .and_then(serde_json::Value::as_str);
        let role_id = metadata
            .and_then(|m| m.get("role_id"))
            .and_then(serde_json::Value::as_str);
        if let (Some(guild_id), Some(member_id), Some(role_id)) = (guild_id, member_id, role_id)
            && [guild_id, member_id, role_id].iter().all(|value| {
                value.len() >= 15
                    && value.len() <= 22
                    && value.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            state.store.schedule_typed(guild_id,"monetization_entitlement",member_id,Utc::now().timestamp_millis(),&serde_json::json!({"member_id":member_id,"role_id":role_id,"event_id":event_id}).to_string()).map_err(|_|client_error(StatusCode::INTERNAL_SERVER_ERROR,"store_error"))?;
        }
    }
    Ok(Json(
        serde_json::json!({"received":true,"eventId":event_id}),
    ))
}

fn twitch_error_response(status: StatusCode, code: &'static str) -> Response {
    let body = serde_json::to_vec(&ApiError {
        code: code.to_string(),
        message: code.to_string(),
        request_id: None,
    })
    .unwrap_or_else(|_| b"{\"code\":\"invalid_request\"}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()))
}

async fn twitch_eventsub(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let Some(client) = state.twitch.as_ref() else {
        return Err(twitch_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    let message_id = headers
        .get("Twitch-Eventsub-Message-Id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let timestamp = headers
        .get("Twitch-Eventsub-Message-Timestamp")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let signature = headers
        .get("Twitch-Eventsub-Message-Signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let received = DateTime::parse_from_rfc3339(timestamp)
        .map(|value| value.with_timezone(&Utc))
        .ok();
    if message_id.is_empty()
        || signature.is_empty()
        || received
            .is_none_or(|value| Utc::now().signed_duration_since(value).num_seconds().abs() > 600)
    {
        return Err(twitch_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_twitch_signature",
        ));
    }
    let Some(encoded) = signature.strip_prefix("sha256=") else {
        return Err(twitch_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_twitch_signature",
        ));
    };
    let Ok(expected) = hex::decode(encoded) else {
        return Err(twitch_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_twitch_signature",
        ));
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(client.eventsub_secret().as_bytes()) else {
        return Err(twitch_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_configured",
        ));
    };
    mac.update(message_id.as_bytes());
    mac.update(timestamp.as_bytes());
    mac.update(&body);
    if mac.verify_slice(&expected).is_err() {
        return Err(twitch_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_twitch_signature",
        ));
    }
    let message_type = headers
        .get("Twitch-Eventsub-Message-Type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| twitch_error_response(StatusCode::BAD_REQUEST, "invalid_twitch_payload"))?;
    match message_type {
        "webhook_callback_verification" => {
            let challenge = payload
                .get("challenge")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if challenge.is_empty() || challenge.len() > 2_048 {
                return Err(twitch_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_twitch_challenge",
                ));
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(axum::body::Body::from(challenge.to_string()))
                .unwrap_or_else(|_| Response::new(axum::body::Body::empty())))
        }
        "notification" => {
            if payload
                .get("subscription")
                .and_then(|value| value.get("type"))
                .and_then(serde_json::Value::as_str)
                == Some("stream.online")
            {
                let event = payload.get("event").cloned().unwrap_or_default();
                let broadcaster = event
                    .get("broadcaster_user_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let stream_id = event
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let started_at = event
                    .get("started_at")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if !broadcaster.is_empty() && !stream_id.is_empty() && !started_at.is_empty() {
                    state
                        .store
                        .stage_twitch_event(broadcaster, message_id, stream_id, started_at)
                        .map_err(|_| {
                            twitch_error_response(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
                        })?;
                }
            }
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| Response::new(axum::body::Body::empty())))
        }
        "revocation" => {
            tracing::warn!(message_id, "Twitch EventSub subscription revoked");
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| Response::new(axum::body::Body::empty())))
        }
        _ => Err(twitch_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_twitch_message",
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub token: String,
    pub guild_id: String,
}

#[derive(Debug, Deserialize)]
struct VozenAccountSessionRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct PrivateTrackerSessionRequest {
    token: String,
}
#[derive(Debug, Deserialize)]
struct DiscordOAuthIdentity {
    application: DiscordOAuthApplication,
    scopes: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct DiscordOAuthApplication {
    id: String,
}
#[derive(Debug, Deserialize, Serialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
}
#[derive(Debug, Deserialize)]
struct DiscordGuild {
    id: String,
    name: String,
    permissions: Option<String>,
}
#[derive(Debug, Deserialize)]
struct DiscordBotGuild {
    id: String,
    name: String,
    #[serde(default)]
    icon: Option<String>,
}
#[derive(Debug, Serialize)]
struct SessionResponse {
    ok: bool,
    user: DiscordUser,
    token: String,
    expires_at: String,
}

/// Exchanges the already authenticated first-party Vozen account for a
/// short-lived Helper session. The Discord token is accepted only from
/// `https://vozen.org`, verified against the configured Vozen OAuth app, and
/// never returned to the browser or placed in a URL.
async fn create_vozen_account_session(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<VozenAccountSessionRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let expected_client_id = state
        .trusted_vozen_oauth_client_id
        .as_deref()
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "vozen_account_bridge_unavailable"))?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin != Some("https://vozen.org") {
        return Err(client_error(StatusCode::FORBIDDEN, "csrf_origin_invalid"));
    }

    let token = request.token.trim();
    if !valid_discord_oauth_token(token) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_token"));
    }

    let identity = Client::new()
        .get("https://discord.com/api/v10/oauth2/@me")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !identity.status().is_success() {
        return Err(client_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let identity: DiscordOAuthIdentity = identity
        .json()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response"))?;
    if !is_trusted_vozen_account_identity(
        expected_client_id,
        &identity.application.id,
        &identity.scopes,
    ) {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "vozen_account_scope_missing",
        ));
    }

    let session = create_session_inner(
        State(state),
        headers,
        Json(SessionRequest {
            token: token.to_owned(),
            guild_id: String::new(),
        }),
    )
    .await?;
    let cookie = session
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "session_cookie_missing"))?;
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub fn is_trusted_vozen_account_identity(
    expected_client_id: &str,
    received_client_id: &str,
    scopes: &[String],
) -> bool {
    !expected_client_id.is_empty()
        && expected_client_id == received_client_id
        && scopes.iter().any(|scope| scope == "identify")
        && scopes.iter().any(|scope| scope == "guilds")
}

fn valid_discord_oauth_token(token: &str) -> bool {
    (20..=4096).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~'))
}

async fn create_private_tracker_session(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<PrivateTrackerSessionRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    create_private_tracker_session_inner(state, headers, request).await
}

/// First-party navigation bridge for the private TTS tracker.  A regular cross-origin fetch
/// cannot reliably set the Helper cookie when third-party cookies are blocked, so the tracker
/// submits a top-level form POST here.  The OAuth token stays in the request body, then this
/// handler creates the normal Helper session and redirects to the public Helper tracker.
async fn create_private_tracker_handoff(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Form(request): Form<PrivateTrackerSessionRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let success_redirect = state.oauth_success_redirect.clone();
    let session = create_private_tracker_session_inner(state, headers, request).await?;
    let cookie = session
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "session_cookie_missing"))?;
    let mut response = Redirect::to(&success_redirect).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

async fn create_private_tracker_session_inner(
    state: Arc<ApiState>,
    headers: HeaderMap,
    request: PrivateTrackerSessionRequest,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let (expected_client_id, expected_owner_id) = state
        .private_tracker_client_id
        .as_deref()
        .zip(state.private_tracker_owner_id.as_deref())
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "private_tracker_unavailable"))?;
    let token = request.token.trim();
    if token.is_empty() {
        return Err(client_error(StatusCode::BAD_REQUEST, "missing_token"));
    }

    let identity = Client::new()
        .get("https://discord.com/api/v10/oauth2/@me")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !identity.status().is_success() {
        return Err(client_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let identity_body = identity
        .text()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_response_unreadable"))?;
    let identity: serde_json::Value = serde_json::from_str(&identity_body).map_err(|_| {
        tracing::warn!(
            body_len = identity_body.len(),
            "Discord OAuth identity was not valid JSON"
        );
        client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response")
    })?;
    let received_client_id = identity
        .pointer("/application/id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let received_owner_id = identity
        .pointer("/user/id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !is_private_tracker_identity(
        expected_client_id,
        expected_owner_id,
        received_client_id,
        received_owner_id,
    ) {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "private_tracker_forbidden",
        ));
    }

    create_session_inner(
        State(state),
        headers,
        Json(SessionRequest {
            token: token.to_owned(),
            guild_id: String::new(),
        }),
    )
    .await
}

fn is_private_tracker_identity(
    expected_client_id: &str,
    expected_owner_id: &str,
    received_client_id: &str,
    received_owner_id: &str,
) -> bool {
    !expected_client_id.is_empty()
        && !expected_owner_id.is_empty()
        && expected_client_id == received_client_id
        && expected_owner_id == received_owner_id
}

async fn create_session(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<SessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if !state.allow_legacy_session {
        return Err(client_error(StatusCode::GONE, "oauth_required"));
    }
    create_session_inner(State(state), headers, Json(req)).await
}

async fn create_session_inner(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<SessionRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    if req.token.trim().is_empty() {
        return Err(client_error(StatusCode::BAD_REQUEST, "missing_token"));
    }
    let client = Client::new();
    let discord_user = fetch_discord_user(&client, &req.token).await?;
    // The Discord OAuth endpoint returns every guild in the account, but the
    // Helper can only ever expose servers the account can manage.  Filtering
    // first avoids a serial bot-presence lookup for unrelated guilds, which
    // made the first-party account handoff exceed the browser deadline.
    let guilds = manageable_guilds(fetch_discord_guilds(&client, &req.token).await?);
    let guilds = filter_guilds_with_bot(&client, &state.discord_token, guilds).await?;
    create_session_response(state, headers, discord_user, guilds, req.guild_id)
}

async fn fetch_discord_user(
    client: &Client,
    token: &str,
) -> Result<DiscordUser, (StatusCode, Json<ApiError>)> {
    let user = client
        .get("https://discord.com/api/v10/users/@me")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !user.status().is_success() {
        return Err(client_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let user_body = user
        .text()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_response_unreadable"))?;
    serde_json::from_str(&user_body).map_err(|_| {
        tracing::warn!(
            body_len = user_body.len(),
            "Discord user response was not valid JSON"
        );
        client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response")
    })
}

async fn fetch_discord_guilds(
    client: &Client,
    token: &str,
) -> Result<Vec<DiscordGuild>, (StatusCode, Json<ApiError>)> {
    let guilds = client
        .get("https://discord.com/api/v10/users/@me/guilds")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    let guilds_status = guilds.status();
    let guilds_body = guilds
        .text()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_response_unreadable"))?;
    if !guilds_status.is_success() {
        tracing::warn!(%guilds_status, body_len = guilds_body.len(), "Discord guild list request failed");
        let (status, code) = discord_guilds_error(guilds_status);
        return Err(client_error(status, code));
    }
    serde_json::from_str(&guilds_body).map_err(|_| {
        tracing::warn!(
            body_len = guilds_body.len(),
            "Discord guild list response was not valid JSON"
        );
        client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response")
    })
}

fn discord_guilds_error(status: StatusCode) -> (StatusCode, &'static str) {
    match status {
        StatusCode::UNAUTHORIZED => (StatusCode::UNAUTHORIZED, "invalid_token"),
        StatusCode::FORBIDDEN => (StatusCode::FORBIDDEN, "discord_scope_missing"),
        StatusCode::TOO_MANY_REQUESTS => (StatusCode::TOO_MANY_REQUESTS, "discord_rate_limited"),
        _ => (StatusCode::BAD_GATEWAY, "discord_guilds_unavailable"),
    }
}

async fn fetch_bot_guild_by_id(
    client: &Client,
    discord_token: &str,
    guild_id: &str,
) -> Result<Option<DiscordBotGuild>, (StatusCode, Json<ApiError>)> {
    if discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_bot_unavailable",
        ));
    }
    let response = client
        .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}"))
        .header(header::AUTHORIZATION, format!("Bot {discord_token}"))
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_response_unreadable"))?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        tracing::warn!(%status, body_len = body.len(), "Discord bot guild request failed");
        return Err(client_error(
            StatusCode::BAD_GATEWAY,
            "discord_bot_guild_unavailable",
        ));
    }
    serde_json::from_str(&body).map(Some).map_err(|_| {
        tracing::warn!(
            body_len = body.len(),
            "Discord bot guild list response was not valid JSON"
        );
        client_error(StatusCode::BAD_GATEWAY, "invalid_discord_response")
    })
}

async fn filter_guilds_with_bot(
    client: &Client,
    discord_token: &str,
    guilds: Vec<DiscordGuild>,
) -> Result<Vec<DiscordGuild>, (StatusCode, Json<ApiError>)> {
    let mut installed = Vec::with_capacity(guilds.len());
    for guild in guilds {
        if fetch_bot_guild_by_id(client, discord_token, &guild.id)
            .await?
            .is_some()
        {
            installed.push(guild);
        }
    }
    Ok(installed)
}

fn manageable_guilds(guilds: Vec<DiscordGuild>) -> Vec<DiscordGuild> {
    guilds
        .into_iter()
        .filter(|guild| {
            guild
                .permissions
                .as_deref()
                .is_some_and(has_manage_permission)
        })
        .collect()
}

fn create_session_response(
    state: Arc<ApiState>,
    headers: HeaderMap,
    discord_user: DiscordUser,
    guilds: Vec<DiscordGuild>,
    guild_id: String,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let selected_guild = if guild_id.trim().is_empty() {
        guilds
            .iter()
            .find(|guild| {
                guild
                    .permissions
                    .as_deref()
                    .is_some_and(has_manage_permission)
            })
            .map(|guild| guild.id.clone())
            .ok_or_else(|| client_error(StatusCode::FORBIDDEN, "guild_not_managed"))?
    } else {
        guild_id
    };
    let can_manage = guilds
        .iter()
        .find(|guild| guild.id == selected_guild)
        .map(|guild| {
            guild
                .permissions
                .as_deref()
                .is_some_and(has_manage_permission)
        })
        .unwrap_or(false);
    if !can_manage {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    }
    let now = Utc::now();
    let claims = SessionClaims {
        session_id: Uuid::new_v4(),
        user_id: discord_user.id.clone(),
        guild_id: selected_guild,
        issued_at: now,
        expires_at: now + Duration::hours(SESSION_MAX_HOURS),
        last_seen_at: now,
    };
    state
        .store
        .save_session(&claims)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let managed_guilds = guilds
        .iter()
        .filter(|guild| {
            guild
                .permissions
                .as_deref()
                .is_some_and(has_manage_permission)
        })
        .map(|guild| {
            (
                guild.id.clone(),
                guild.name.clone(),
                guild.permissions.clone(),
            )
        })
        .collect::<Vec<_>>();
    state
        .store
        .replace_session_guilds(claims.session_id, &managed_guilds)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let token = sign_session(&claims, &state.session_secret);
    let mut response = Json(SessionResponse {
        ok: true,
        user: discord_user,
        token: token.clone(),
        expires_at: claims.expires_at.to_rfc3339(),
    })
    .into_response();
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        && state
            .allowed_origin
            .as_deref()
            .is_some_and(|allowed| origin_allowed(allowed, origin))
    {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.parse().unwrap());
    }
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{COOKIE}={token};{} HttpOnly; Secure; SameSite=None; Path=/; Max-Age={}",
            cookie_domain(&state),
            SESSION_MAX_HOURS * 3600
        )
        .parse()
        .unwrap(),
    );
    response.headers_mut().insert(
        SESSION_RESPONSE_HEADER,
        token.parse().map_err(|_| {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_session_token")
        })?,
    );
    Ok(response)
}

async fn logout(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(claims) = authenticate(&state, &headers) {
        let _ = state.store.revoke_session(claims.session_id);
    }
    (
        [(
            header::SET_COOKIE,
            format!(
                "{COOKIE}=;{} HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0",
                cookie_domain(&state)
            ),
        )],
        Json(serde_json::json!({"ok":true})),
    )
}

async fn me(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    Ok(Json(
        serde_json::json!({"id":claims.user_id,"guildId":claims.guild_id,"expiresAt":claims.expires_at,"dbOk":true}),
    ))
}

async fn guilds(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let managed_guilds = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let client = Client::new();
    let mut installed = Vec::new();
    for guild in managed_guilds {
        if let Some(bot_guild) =
            fetch_bot_guild_by_id(&client, &state.discord_token, &guild.guild_id).await?
        {
            let icon_url = bot_guild.icon.as_deref().map(|icon| {
                format!(
                    "https://cdn.discordapp.com/icons/{}/{icon}.png?size=64",
                    bot_guild.id
                )
            });
            installed.push(serde_json::json!({
                "id": bot_guild.id,
                "name": bot_guild.name,
                "iconUrl": icon_url,
                "canManage": true,
                "botPresent": true
            }));
        }
    }
    Ok(Json(serde_json::json!({
        "guilds": installed
    })))
}

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

#[derive(Debug, Default, Clone)]
struct DiscordGuildSnapshot {
    channels: Vec<serde_json::Value>,
    roles: Vec<serde_json::Value>,
    bot_user_id: Option<String>,
    bot_role_ids: Vec<String>,
    channels_ready: bool,
    roles_ready: bool,
    bot_ready: bool,
    bot_reason: Option<String>,
    stale_reason: Option<String>,
}

async fn discord_json(
    client: &Client,
    auth: &str,
    path: &str,
) -> Result<serde_json::Value, String> {
    discord_read::get_json(client, auth, &format!("{DISCORD_API_BASE}{path}")).await
}

async fn discord_send_channel_message(
    discord_token: &str,
    channel_id: &str,
    content: &str,
) -> Result<(), String> {
    if discord_token.len() < 20 {
        return Err("discord_adapter_unavailable".into());
    }
    let channel_id = channel_id.trim();
    if channel_id.len() < 15
        || channel_id.len() > 22
        || !channel_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid_discord_channel_id".into());
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|_| "discord_request_failed".to_string())?;
    let response = client
        .post(format!("{DISCORD_API_BASE}/channels/{channel_id}/messages"))
        .header(header::AUTHORIZATION, format!("Bot {discord_token}"))
        .json(&serde_json::json!({
            "content": content,
            "allowed_mentions": {"parse": []}
        }))
        .send()
        .await
        .map_err(|_| "discord_request_failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("discord_http_{}", response.status().as_u16()));
    }
    Ok(())
}

async fn fetch_discord_guild_snapshot(guild_id: &str, discord_token: &str) -> DiscordGuildSnapshot {
    static INFLIGHT: std::sync::OnceLock<discord_context::Inflight<DiscordGuildSnapshot>> =
        std::sync::OnceLock::new();
    // Scope sharing to both the guild and credential, without storing tokens in
    // the index. Only overlapping reads share the same fresh Discord request.
    let key = format!(
        "{guild_id}:{}",
        hex::encode(Sha256::digest(discord_token.as_bytes()))
    );
    let guild_id = guild_id.to_owned();
    let discord_token = discord_token.to_owned();
    INFLIGHT
        .get_or_init(discord_context::Inflight::new)
        .read(key, async move {
            fetch_discord_guild_snapshot_uncached(&guild_id, &discord_token).await
        })
        .await
        .as_ref()
        .clone()
}

async fn fetch_discord_guild_snapshot_uncached(
    guild_id: &str,
    discord_token: &str,
) -> DiscordGuildSnapshot {
    if discord_token.len() < 20 {
        return DiscordGuildSnapshot {
            bot_reason: Some("bot_token_not_configured".into()),
            stale_reason: Some("discord_context_refresh_required".into()),
            ..Default::default()
        };
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let auth = format!("Bot {discord_token}");
    let mut snapshot = DiscordGuildSnapshot::default();

    match discord_json(&client, &auth, &format!("/guilds/{guild_id}/channels")).await {
        Ok(value) if value.is_array() => {
            snapshot.channels = value.as_array().cloned().unwrap_or_default();
            snapshot.channels_ready = true;
        }
        Ok(_) | Err(_) => {
            snapshot.stale_reason = Some("discord_channels_unavailable".into());
        }
    }

    match discord_json(&client, &auth, &format!("/guilds/{guild_id}/roles")).await {
        Ok(value) if value.is_array() => {
            snapshot.roles = value.as_array().cloned().unwrap_or_default();
            snapshot.roles_ready = true;
        }
        Ok(_) | Err(_) => {
            if snapshot.stale_reason.is_none() {
                snapshot.stale_reason = Some("discord_roles_unavailable".into());
            }
        }
    }

    let bot_user_id = match discord_json(&client, &auth, "/users/@me").await {
        Ok(value) => value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        Err(_) => None,
    };
    let Some(bot_user_id) = bot_user_id else {
        snapshot.bot_reason = Some("discord_bot_identity_unavailable".into());
        if snapshot.stale_reason.is_none() {
            snapshot.stale_reason = Some("discord_bot_context_unavailable".into());
        }
        return snapshot;
    };
    snapshot.bot_user_id = Some(bot_user_id.clone());

    match discord_json(
        &client,
        &auth,
        &format!("/guilds/{guild_id}/members/{bot_user_id}"),
    )
    .await
    {
        Ok(value) => {
            snapshot.bot_role_ids = value
                .get("roles")
                .and_then(serde_json::Value::as_array)
                .map(|roles| {
                    roles
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            snapshot.bot_ready = true;
        }
        Err(_) => {
            snapshot.bot_reason = Some("discord_bot_member_unavailable".into());
            if snapshot.stale_reason.is_none() {
                snapshot.stale_reason = Some("discord_bot_context_unavailable".into());
            }
        }
    }
    snapshot
}

fn parse_permission_bits(value: &serde_json::Value) -> Option<u64> {
    value
        .get("permissions")
        .and_then(serde_json::Value::as_str)
        .and_then(|permissions| permissions.parse::<u64>().ok())
}

fn effective_bot_permissions(
    guild_id: &str,
    roles: &[serde_json::Value],
    bot_role_ids: &[String],
) -> Option<u64> {
    let mut effective = 0_u64;
    let mut found = false;
    for role in roles {
        let role_id = role.get("id").and_then(serde_json::Value::as_str)?;
        if role_id != guild_id && !bot_role_ids.iter().any(|id| id == role_id) {
            continue;
        }
        effective |= parse_permission_bits(role)?;
        found = true;
    }
    found.then_some(effective)
}

fn overwrite_values(overwrite: &serde_json::Value) -> Option<(u64, u64)> {
    let allow = overwrite
        .get("allow")
        .and_then(serde_json::Value::as_str)?
        .parse::<u64>()
        .ok()?;
    let deny = overwrite
        .get("deny")
        .and_then(serde_json::Value::as_str)?
        .parse::<u64>()
        .ok()?;
    Some((allow, deny))
}

fn apply_overwrite(bits: &mut u64, overwrite: &serde_json::Value) -> Option<()> {
    let (allow, deny) = overwrite_values(overwrite)?;
    *bits &= !deny;
    *bits |= allow;
    Some(())
}

fn channel_bot_permissions(
    base: u64,
    guild_id: &str,
    bot_user_id: &str,
    bot_role_ids: &[String],
    overwrites: &serde_json::Value,
) -> Option<u64> {
    let overwrites = overwrites.as_array()?;
    let mut bits = base;
    let everyone = overwrites.iter().find(|overwrite| {
        overwrite.get("id").and_then(serde_json::Value::as_str) == Some(guild_id)
            && overwrite
                .get("type")
                .and_then(serde_json::Value::as_i64)
                .map(|kind| kind == 0)
                .unwrap_or(true)
    });
    if let Some(overwrite) = everyone {
        apply_overwrite(&mut bits, overwrite)?;
    }
    let mut role_deny = 0_u64;
    let mut role_allow = 0_u64;
    for overwrite in overwrites {
        let role_id = overwrite.get("id").and_then(serde_json::Value::as_str);
        let is_role = overwrite
            .get("type")
            .and_then(serde_json::Value::as_i64)
            .map(|kind| kind == 0)
            .unwrap_or(true);
        if is_role && role_id.is_some_and(|id| bot_role_ids.iter().any(|role| role == id)) {
            let (allow, deny) = overwrite_values(overwrite)?;
            role_allow |= allow;
            role_deny |= deny;
        }
    }
    bits &= !role_deny;
    bits |= role_allow;
    if let Some(member_overwrite) = overwrites.iter().find(|overwrite| {
        overwrite.get("id").and_then(serde_json::Value::as_str) == Some(bot_user_id)
            && overwrite
                .get("type")
                .and_then(serde_json::Value::as_i64)
                .map(|kind| kind == 1)
                .unwrap_or(true)
    }) {
        apply_overwrite(&mut bits, member_overwrite)?;
    }
    Some(bits)
}

async fn guild_context(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let guild = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|guild| guild.guild_id == claims.guild_id);
    let Some(guild) = guild else {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    };
    let permissions = guild.permissions.unwrap_or_default();
    let snapshot = fetch_discord_guild_snapshot(&guild.guild_id, &state.discord_token).await;
    let bot_permissions =
        effective_bot_permissions(&guild.guild_id, &snapshot.roles, &snapshot.bot_role_ids);
    let bot_top_role_position = snapshot
        .roles
        .iter()
        .filter(|role| {
            role.get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| snapshot.bot_role_ids.iter().any(|bot_role| bot_role == id))
        })
        .filter_map(|role| role.get("position").and_then(serde_json::Value::as_i64))
        .max();
    let bot_user_id = snapshot.bot_user_id.as_deref();
    let roles = snapshot
        .roles
        .iter()
        .filter_map(|value| {
            let id = value.get("id").and_then(serde_json::Value::as_str)?;
            let position = value.get("position").and_then(serde_json::Value::as_i64)?;
            let managed = value
                .get("managed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Some(serde_json::json!({
                "id": id,
                "name": value.get("name").and_then(serde_json::Value::as_str).unwrap_or("role"),
                "position": position,
                "permissions": value.get("permissions").and_then(serde_json::Value::as_str),
                "managed": managed,
                "manageable": id != guild.guild_id && !managed && bot_top_role_position.is_some_and(|top| position < top)
            }))
        })
        .collect::<Vec<_>>();
    let channels = snapshot
        .channels
        .iter()
        .filter_map(|value| {
            let channel_type = value.get("type").and_then(serde_json::Value::as_i64).unwrap_or(0);
            if channel_type != 0 && channel_type != 4 && channel_type != 5 {
                return None;
            }
            let id = value.get("id").and_then(serde_json::Value::as_str)?;
            let overwrites = value.get("permission_overwrites");
            let bot_channel_permissions = bot_permissions
                .zip(bot_user_id)
                .and_then(|(base, user_id)| {
                    channel_bot_permissions(
                        base,
                        &guild.guild_id,
                        user_id,
                        &snapshot.bot_role_ids,
                        overwrites?,
                    )
                });
            Some(serde_json::json!({
                "id": id,
                "name": value.get("name").and_then(serde_json::Value::as_str).unwrap_or("channel"),
                "type": if channel_type == 4 { "category" } else if channel_type == 5 { "announcement" } else { "text" },
                "overwritesKnown": overwrites.and_then(serde_json::Value::as_array).is_some(),
                "overwriteCount": overwrites.and_then(serde_json::Value::as_array).map_or(0, Vec::len),
                "botPermissions": bot_channel_permissions.map(|bits| bits.to_string()),
                "botPermissionsKnown": bot_channel_permissions.is_some()
            }))
        })
        .collect::<Vec<_>>();
    let bot_available = snapshot.bot_ready && bot_permissions.is_some();
    let stale = !snapshot.channels_ready || !snapshot.roles_ready || !bot_available;
    let bot_reason = if bot_available {
        None
    } else {
        snapshot
            .bot_reason
            .clone()
            .or_else(|| Some("discord_bot_permissions_unavailable".into()))
    };
    Ok(Json(serde_json::json!({
        "guildId": guild.guild_id,
        "name": guild.name,
        "permissions": permissions,
        "channels": channels,
        "roles": roles,
        "bot": {
            "available": bot_available,
            "userId": snapshot.bot_user_id,
            "roleIds": snapshot.bot_role_ids,
            "topRolePosition": bot_top_role_position,
            "permissions": bot_permissions.map(|value| value.to_string()),
            "permissionBitfieldAvailable": bot_permissions.is_some(),
            "reason": bot_reason
        },
        "hierarchy": {"known": bot_available && snapshot.roles_ready, "topRolePosition": bot_top_role_position, "reason": if stale { snapshot.stale_reason.clone().or_else(|| Some("discord_context_refresh_required".into())) } else { None::<String> }},
        "capabilities": {
            "channelSelectors": snapshot.channels_ready,
            "roleSelectors": snapshot.roles_ready,
            "permissionPreflight": !permissions.is_empty() && bot_available && snapshot.channels_ready && snapshot.roles_ready
        },
        "stale": stale,
        "message": if stale { Some(snapshot.stale_reason.unwrap_or_else(|| "discord_context_refresh_required".into())) } else { None::<String> }
    })))
}

#[derive(Debug, Deserialize)]
struct PreflightRequest {
    operation: String,
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct FeaturePreflightRequest {
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn permission_bit(permissions: &str, bit: u8) -> bool {
    permissions
        .parse::<u64>()
        .map(|value| value & (1_u64 << 3) != 0 || value & (1_u64 << bit) != 0)
        .unwrap_or(false)
}

fn permission_bitfield_has(permissions: u64, bit: u8) -> bool {
    permissions & (1_u64 << 3) != 0 || permissions & (1_u64 << bit) != 0
}

fn dependency_permission(dependency: &str) -> Option<(u8, &'static str)> {
    Some(match dependency {
        "manage_channels" | "Manage Channels" => (4, "Manage Channels"),
        "move_members" | "Move Members" => (24, "Move Members"),
        "connect" | "Connect" => (20, "Connect"),
        "view_channel" | "View Channel" => (10, "View Channel"),
        "manage_guild" | "Manage Server" => (5, "Manage Server"),
        "manage_messages" | "Manage Messages" => (13, "Manage Messages"),
        "embed_links" | "Embed Links" => (14, "Embed Links"),
        "attach_files" | "Attach Files" => (15, "Attach Files"),
        "read_message_history" | "Read Message History" => (16, "Read Message History"),
        "manage_nicknames" | "Manage Nicknames" => (27, "Manage Nicknames"),
        "change_nickname" | "Change Nickname" => (26, "Change Nickname"),
        "manage_roles" | "Manage Roles" => (28, "Manage Roles"),
        "manage_expressions" | "Manage Expressions" => (30, "Manage Expressions"),
        "manage_events" | "Manage Events" => (33, "Manage Events"),
        "manage_threads" | "Manage Threads" => (34, "Manage Threads"),
        "moderate_members" | "Moderate Members" => (40, "Moderate Members"),
        "send_messages" | "Send Messages" => (11, "Send Messages"),
        "send_messages_in_threads" | "Send Messages in Threads" => (38, "Send Messages in Threads"),
        "view_channel" | "View Channels" => (10, "View Channels"),
        "view_audit_log" | "View Audit Log" => (7, "View Audit Log"),
        "guild_invites" | "Manage Invites" => (5, "Manage Server"),
        "voice_channels" | "Connect to Voice" => (20, "Connect to Voice"),
        "add_reactions" | "Add Reactions" => (6, "Add Reactions"),
        "use_external_emojis" | "Use External Emojis" => (18, "Use External Emojis"),
        "use_application_commands" | "Use Application Commands" => (31, "Use Application Commands"),
        _ => return None,
    })
}

fn dependency_requires_role_management(dependency: &str) -> bool {
    dependency_permission(dependency).is_some_and(|(_, label)| label == "Manage Roles")
}

fn internal_feature_dependency(dependency: &str) -> Option<&'static str> {
    match dependency {
        "levels" => Some("community.levels"),
        _ => None,
    }
}

fn runtime_gateway_intent(dependency: &str) -> Option<&'static str> {
    match dependency {
        "message_content" | "message_content_intent" => Some("MESSAGE_CONTENT"),
        "guild_members" | "guild_members_intent" => Some("GUILD_MEMBERS"),
        "voice_states" => Some("GUILD_VOICE_STATES"),
        "interactions" => Some("GUILDS"),
        "message_events" => Some("GUILD_MESSAGES"),
        _ => None,
    }
}

fn collect_configured_resources(
    value: &serde_json::Value,
    path: &str,
    channels: &mut BTreeSet<(String, String)>,
    roles: &mut BTreeSet<(String, String)>,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(id) = child.as_str().filter(|id| !id.trim().is_empty()) {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("channel") || lower == "category" || lower == "categoryid" {
                        channels.insert((child_path.clone(), id.to_string()));
                    }
                    if lower.contains("role") {
                        roles.insert((child_path.clone(), id.to_string()));
                    }
                }
                // Resource selectors are commonly arrays ("roleIds",
                // "ignoredChannels", etc.). Preserve the parent field name
                // while walking scalar array items so preflight can validate
                // existence and permissions for every selected resource.
                if let serde_json::Value::Array(items) = child {
                    let lower = key.to_ascii_lowercase();
                    for (index, item) in items.iter().enumerate() {
                        let Some(id) = item.as_str().filter(|id| !id.trim().is_empty()) else {
                            continue;
                        };
                        let item_path = format!("{child_path}[{index}]");
                        if lower.contains("channel") || lower == "category" || lower == "categoryid"
                        {
                            channels.insert((item_path.clone(), id.to_string()));
                        }
                        if lower.contains("role") && id.parse::<u64>().is_ok() {
                            roles.insert((item_path, id.to_string()));
                        }
                    }
                }
                collect_configured_resources(child, &child_path, channels, roles);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_configured_resources(child, &format!("{path}[{index}]"), channels, roles);
            }
        }
        _ => {}
    }
}

fn collect_level_reward_roles(value: &serde_json::Value, roles: &mut BTreeSet<(String, String)>) {
    let Some(rewards) = value
        .get("levelRoles")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for (index, reward) in rewards.iter().enumerate() {
        let Some(raw) = reward.as_str() else {
            continue;
        };
        let Some((_, role_id)) = raw.split_once('=') else {
            continue;
        };
        let role_id = role_id.trim();
        if !role_id.is_empty() && role_id.parse::<u64>().is_ok() {
            roles.insert((format!("levelRoles[{index}]"), role_id.to_string()));
        }
    }
}

fn add_dependency_issue(
    issues: &mut Vec<ValidationIssue>,
    path: String,
    code: &str,
    message: String,
    severity: &str,
) {
    issues.push(ValidationIssue {
        path,
        code: code.into(),
        message,
        severity: severity.into(),
    });
}

fn ticket_staff_notification_issues(
    guild_id: &str,
    config: &serde_json::Value,
    roles: &[serde_json::Value],
    bot_permissions: u64,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let role_id = config
        .get("staffRole")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if role_id.is_empty() {
        add_dependency_issue(&mut issues, "staffRole".into(), "staff_role_missing",
            "No staff role is selected. Tickets will open without notifying a team. Choose the staff role to notify.".into(), "warning");
    } else if role_id == guild_id {
        add_dependency_issue(
            &mut issues,
            "staffRole".into(),
            "everyone_not_allowed",
            "Choose a staff role other than @everyone to keep tickets private.".into(),
            "error",
        );
    } else if let Some(role) = roles
        .iter()
        .find(|role| role["id"].as_str() == Some(role_id))
        && !role["mentionable"].as_bool().unwrap_or(false)
        && !permission_bitfield_has(bot_permissions, 17)
    {
        add_dependency_issue(&mut issues, "staffRole".into(), "staff_role_not_mentionable",
            "The selected staff role cannot receive role pings from the Helper. Make the role mentionable in Discord or grant the Helper permission to mention roles. Members' personal notification settings still apply.".into(), "warning");
    }
    issues
}

fn role_hierarchy_issues(
    guild_id: &str,
    bot_role_ids: &[String],
    roles: &[serde_json::Value],
    configured_roles: &BTreeSet<(String, String)>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let bot_top_position = roles
        .iter()
        .filter(|role| {
            role.get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| {
                    id != guild_id && bot_role_ids.iter().any(|bot_role| bot_role == id)
                })
        })
        .filter_map(|role| role.get("position").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0);
    for (path, id) in configured_roles {
        let field = path.split(['.', '[']).next().unwrap_or(path);
        // These roles are references used for authorization/exemptions. They
        // are never assigned by the bot, so hierarchy must not block them.
        if matches!(field, "staffRole" | "requiredRole" | "ignoredRoles") {
            continue;
        }
        let Some(role) = roles
            .iter()
            .find(|role| role.get("id").and_then(serde_json::Value::as_str) == Some(id))
        else {
            continue;
        };
        let managed = role
            .get("managed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let position = role
            .get("position")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if managed || id == guild_id || position >= bot_top_position {
            add_dependency_issue(
                &mut issues,
                format!("{path}.hierarchy"),
                "role_not_manageable",
                format!(
                    "The selected role ({id}) must be unmanaged and below the Helper bot's highest role."
                ),
                "error",
            );
        }
    }
    issues
}

fn channel_dependency_issues(
    guild_id: &str,
    snapshot: &DiscordGuildSnapshot,
    base_permissions: u64,
    dependencies: &[String],
    configured_channels: &BTreeSet<(String, String)>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let Some(bot_user_id) = snapshot.bot_user_id.as_deref() else {
        return issues;
    };
    for (path, id) in configured_channels {
        // Exclusions still need to exist in this guild, but the bot need not
        // read or send anything there. Destination permissions apply elsewhere.
        if path
            .split(['.', '[', ']'])
            .any(|part| part == "ignoredChannels")
        {
            continue;
        }
        let Some(channel) = snapshot
            .channels
            .iter()
            .find(|channel| channel.get("id").and_then(serde_json::Value::as_str) == Some(id))
        else {
            continue;
        };
        let Some(overwrites) = channel.get("permission_overwrites") else {
            continue;
        };
        let Some(effective) = channel_bot_permissions(
            base_permissions,
            guild_id,
            bot_user_id,
            &snapshot.bot_role_ids,
            overwrites,
        ) else {
            continue;
        };
        for dependency in dependencies {
            let Some((bit, label)) = dependency_permission(dependency) else {
                continue;
            };
            if !permission_bitfield_has(effective, bit) {
                add_dependency_issue(
                    &mut issues,
                    format!("permissions.channel.{path}.{dependency}"),
                    "missing_channel_permission",
                    format!("The Helper bot lacks {label} in the selected channel ({id})."),
                    "error",
                );
            }
        }
    }
    issues
}

async fn generic_feature_preflight(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    key: String,
    request: FeaturePreflightRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if key == "support.welcome_channel" {
        return Err(client_error(
            StatusCode::GONE,
            "feature_merged_into_support.welcome",
        ));
    }
    let guild = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|guild| guild.guild_id == claims.guild_id)
        .ok_or_else(|| client_error(StatusCode::FORBIDDEN, "guild_not_managed"))?;

    if key == "community.levels" && request.config.get("rankCard").is_some() {
        require_feature_premium(&state, &claims, "studio.rank_card").await?;
    }
    let descriptor = feature_adapter(&key).map(|adapter| adapter.descriptor());
    if key == "community.levels"
        && let Some(card) = request.config.get("rankCard")
    {
        let card = serde_json::from_value::<RankCardConfig>(card.clone())
            .map_err(|_| client_error(StatusCode::BAD_REQUEST, "invalid_rank_card"))?;
        if !valid_rank_card_config(&card) {
            return Err(client_error(StatusCode::BAD_REQUEST, "invalid_rank_card"));
        }
    }
    // Disabling a feature must not require a complete replacement config. A
    // historical revision may intentionally contain `{}` (or a provider
    // credential may have been removed since it was last enabled). Keep the
    // object-shape check, but only enforce field-level requirements when the
    // proposed state will actually run in Discord.
    let mut issues = if request.enabled {
        validate_feature_config(&key, &request.config)
    } else if request.config.is_object() {
        Vec::new()
    } else {
        validate_feature_config(&key, &request.config)
    };
    if descriptor.is_none() {
        add_dependency_issue(
            &mut issues,
            "feature.adapter".into(),
            "adapter_unavailable",
            "This feature has no runtime adapter yet and cannot be published safely.".into(),
            "error",
        );
    }
    if !feature_configurable_for(&state, &key) {
        add_dependency_issue(
            &mut issues,
            "feature.maturity".into(),
            "feature_not_released",
            "This feature is not released for configuration until its required provider or approval is available.".into(),
            "error",
        );
    }
    if request.enabled
        && provider_needs_runtime_ready(&key)
        && !provider_runtime_ready(&state, &key)
    {
        add_dependency_issue(
            &mut issues,
            "feature.provider".into(),
            "provider_not_ready",
            "The official provider is not ready in this running Helper. Configure its server-side credentials and restart the Helper before enabling this feature.".into(),
            "error",
        );
    }

    let snapshot = fetch_discord_guild_snapshot(&claims.guild_id, &state.discord_token).await;
    let bot_permissions =
        effective_bot_permissions(&claims.guild_id, &snapshot.roles, &snapshot.bot_role_ids);
    let bot_context_available = snapshot.bot_ready && bot_permissions.is_some();
    let guild_permissions = guild.permissions.unwrap_or_default();
    let mut required_permissions = Vec::new();
    let mut bot_permission_results = serde_json::Map::new();
    let mut user_permission_results = serde_json::Map::new();
    let mut required_intents = BTreeSet::new();

    if let Some(descriptor) = &descriptor {
        for dependency in &descriptor.dependencies {
            if request.enabled
                && let Some(required_feature) = internal_feature_dependency(dependency)
                && required_feature != key
                && !feature_enabled(&state, &claims.guild_id, required_feature)
            {
                add_dependency_issue(
                    &mut issues,
                    format!("dependencies.features.{required_feature}"),
                    "feature_dependency_disabled",
                    format!("Enable {required_feature} first; this feature uses its runtime data."),
                    "error",
                );
            }
            if let Some((bit, label)) = dependency_permission(dependency) {
                required_permissions.push(label);
                let user_has = permission_bit(&guild_permissions, bit);
                let bot_has = bot_permissions
                    .map(|permissions| permission_bit(&permissions.to_string(), bit))
                    .unwrap_or(false);
                user_permission_results.insert(dependency.clone(), serde_json::json!(user_has));
                bot_permission_results.insert(dependency.clone(), serde_json::json!(bot_has));
                if request.enabled && !user_has {
                    add_dependency_issue(
                        &mut issues,
                        format!("permissions.{dependency}"),
                        "missing_permission",
                        format!("Your Discord account needs {label} to publish this feature."),
                        "error",
                    );
                }
                if request.enabled && !bot_context_available {
                    add_dependency_issue(
                        &mut issues,
                        "permissions.bot_context".into(),
                        "discord_context_unavailable",
                        "Refresh the Discord context before publishing; the Helper bot's effective permissions could not be verified.".into(),
                        "error",
                    );
                } else if request.enabled && !bot_has {
                    add_dependency_issue(
                        &mut issues,
                        format!("permissions.bot.{dependency}"),
                        "missing_bot_permission",
                        format!("The Helper bot needs {label} to run this feature."),
                        "error",
                    );
                }
            } else if let Some(intent) = runtime_gateway_intent(dependency) {
                required_intents.insert(intent);
            } else if request.enabled
                && dependency
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character == '_')
                && std::env::var(dependency)
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true)
            {
                add_dependency_issue(
                    &mut issues,
                    format!("dependencies.{dependency}"),
                    "missing_provider_credential",
                    format!(
                        "The required {dependency} environment variable is not configured on the API."
                    ),
                    "error",
                );
            }
        }
    }

    let mut configured_channels = BTreeSet::new();
    let mut configured_roles = BTreeSet::new();
    collect_configured_resources(
        &request.config,
        "",
        &mut configured_channels,
        &mut configured_roles,
    );
    // Levels encode rewards as "level=role_id", so the role ID is not a
    // standalone JSON string that the generic resource walker can recognise.
    // Extract it explicitly to make role existence, Manage Roles and
    // hierarchy checks apply before publishing the policy.
    if key == "community.levels" {
        collect_level_reward_roles(&request.config, &mut configured_roles);
    }
    let channel_ids: BTreeSet<String> = snapshot
        .channels
        .iter()
        .filter_map(|value| value.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect();
    let role_ids: BTreeSet<String> = snapshot
        .roles
        .iter()
        .filter_map(|value| value.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect();
    for (path, id) in &configured_channels {
        if snapshot.channels_ready && !channel_ids.contains(id) {
            add_dependency_issue(
                &mut issues,
                path.clone(),
                "channel_not_found",
                "Choose a channel that still exists in this server.".into(),
                "error",
            );
        }
    }
    for (path, id) in &configured_roles {
        if snapshot.roles_ready && !role_ids.contains(id) {
            add_dependency_issue(
                &mut issues,
                path.clone(),
                "role_not_found",
                "Choose a role that still exists in this server.".into(),
                "error",
            );
        }
    }

    if request.enabled && key == "support.tickets" && snapshot.roles_ready && bot_context_available
    {
        issues.extend(ticket_staff_notification_issues(
            &claims.guild_id,
            &request.config,
            &snapshot.roles,
            bot_permissions.unwrap_or(0),
        ));
    }

    // A role can exist and still be unusable: Discord only lets the bot
    // assign/edit roles strictly below its highest role, and managed roles
    // can never be changed by a bot.  Check this before publishing any
    // feature whose adapter declares Manage Roles.  Without this check a
    // dashboard save would look successful and fail later in an interaction.
    let needs_role_management = descriptor.as_ref().is_some_and(|value| {
        value
            .dependencies
            .iter()
            .any(|dependency| dependency_requires_role_management(dependency))
    }) || (key == "community.achievements"
        && !configured_roles.is_empty());
    // Achievement reward roles are optional.  Only require Manage Roles when
    // the proposed policy actually assigns one; a server that only announces
    // milestones should not be blocked by an unrelated role permission.
    if request.enabled && key == "community.achievements" && !configured_roles.is_empty() {
        if !required_permissions.contains(&"Manage Roles") {
            required_permissions.push("Manage Roles");
        }
        let user_has = permission_bit(&guild_permissions, 28);
        let bot_has = bot_permissions
            .map(|permissions| permission_bit(&permissions.to_string(), 28))
            .unwrap_or(false);
        user_permission_results.insert("manage_roles".into(), serde_json::json!(user_has));
        bot_permission_results.insert("manage_roles".into(), serde_json::json!(bot_has));
        if !user_has {
            add_dependency_issue(
                &mut issues,
                "permissions.manage_roles".into(),
                "missing_permission",
                "Your Discord account needs Manage Roles to publish achievement reward roles."
                    .into(),
                "error",
            );
        }
        if !bot_context_available {
            add_dependency_issue(
                &mut issues,
                "permissions.bot_context".into(),
                "discord_context_unavailable",
                "Refresh the Discord context before publishing achievement reward roles.".into(),
                "error",
            );
        } else if !bot_has {
            add_dependency_issue(
                &mut issues,
                "permissions.bot.manage_roles".into(),
                "missing_bot_permission",
                "The Helper bot needs Manage Roles to assign achievement reward roles.".into(),
                "error",
            );
        }
    }
    if request.enabled && needs_role_management && snapshot.roles_ready && bot_context_available {
        issues.extend(role_hierarchy_issues(
            &claims.guild_id,
            &snapshot.bot_role_ids,
            &snapshot.roles,
            &configured_roles,
        ));
    }

    // Base guild permissions are not enough when a configured destination
    // has channel overwrites.  Resolve the effective bot bitfield for every
    // selected channel and report the exact permission that would fail at
    // delivery time.  This deliberately stays read-only and uses the same
    // Discord REST snapshot returned to the panel.
    if request.enabled
        && snapshot.channels_ready
        && bot_context_available
        && let (Some(descriptor), Some(base_permissions)) = (descriptor.as_ref(), bot_permissions)
    {
        issues.extend(channel_dependency_issues(
            &claims.guild_id,
            &snapshot,
            base_permissions,
            &descriptor.dependencies,
            &configured_channels,
        ));
    }
    if request.enabled
        && (!snapshot.channels_ready || !snapshot.roles_ready)
        && descriptor.is_some()
    {
        add_dependency_issue(
            &mut issues,
            "discord_context".into(),
            "discord_context_stale",
            "Refresh the Discord context so channel, role and hierarchy checks use current resources.".into(),
            "warning",
        );
    }

    let error_count = issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .count();
    Ok(Json(serde_json::json!({
        "operation": format!("{key}.publish"),
        "guildId": claims.guild_id,
        "ok": error_count == 0,
        "issues": issues,
        "checks": {
            "guildManaged": true,
            "featureAdapter": descriptor.is_some(),
            "featureConfigurable": feature_configurable_for(&state, &key),
            "botContextAvailable": bot_context_available,
            "botPermissionBitfieldAvailable": bot_permissions.is_some(),
            "requiredPermissions": required_permissions,
            "userPermissions": user_permission_results,
            "botPermissions": bot_permission_results,
            "configuredChannels": configured_channels,
            "configuredRoles": configured_roles,
            "discordResourcesFresh": snapshot.channels_ready && snapshot.roles_ready,
            "requiredIntents": required_intents,
            "missingIntents": Vec::<String>::new()
        }
    })))
}

async fn preflight(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<PreflightRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let key = match request.operation.as_str() {
        "protection.antispam.publish" | "protection.antispam.rollback" => "protection.antispam",
        "protection.antiscam.publish" | "protection.antiscam.rollback" => "protection.antiscam",
        _ => {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "unknown_preflight_operation",
            ));
        }
    };
    let protection_name = if key == "protection.antispam" {
        "anti-spam"
    } else {
        "anti-scam"
    };

    let mut issues = validate_feature_config(key, &request.config);
    let guild = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .find(|guild| guild.guild_id == claims.guild_id)
        .ok_or_else(|| client_error(StatusCode::FORBIDDEN, "guild_not_managed"))?;
    let permissions = guild.permissions.unwrap_or_default();
    let discord_snapshot =
        fetch_discord_guild_snapshot(&guild.guild_id, &state.discord_token).await;
    let bot_permissions = effective_bot_permissions(
        &guild.guild_id,
        &discord_snapshot.roles,
        &discord_snapshot.bot_role_ids,
    );
    let bot_permission_string = bot_permissions.map(|value| value.to_string());
    let bot_context_available = discord_snapshot.bot_ready && bot_permissions.is_some();
    let alert_only = request
        .config
        .get("alertOnly")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let timeout_seconds = request
        .config
        .get("timeoutSeconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(60);
    let delete_message = request
        .config
        .get("deleteMessage")
        .and_then(serde_json::Value::as_bool)
        // Anti-scam historically deleted confirmed matches. Keep that safe
        // default for older revisions that predate the explicit toggle.
        .unwrap_or(key == "protection.antiscam")
        && !alert_only;
    let selected_log_channel = request
        .config
        .get("logChannel")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty());
    // Anti-spam gives immediate feedback in the originating channel, while
    // anti-scam only speaks when an administrator selected a log channel.
    let requires_send_messages = key == "protection.antispam" || selected_log_channel.is_some();
    if request.enabled && !bot_context_available {
        issues.push(ValidationIssue {
            path: "permissions.bot_context".into(),
            code: "discord_context_unavailable".into(),
            message: "Refresh the Discord context before publishing; the Helper's effective permissions and role hierarchy could not be verified.".into(),
            severity: "error".into(),
        });
    }
    let bot_moderate_members = bot_permission_string
        .as_deref()
        .is_some_and(|value| permission_bit(value, 40));
    let bot_manage_messages = bot_permission_string
        .as_deref()
        .is_some_and(|value| permission_bit(value, 13));
    let bot_send_messages = bot_permission_string
        .as_deref()
        .is_some_and(|value| permission_bit(value, 11));
    if request.enabled && !alert_only && timeout_seconds > 0 && !bot_moderate_members {
        issues.push(ValidationIssue {
            path: "permissions.bot_moderate_members".into(),
            code: "missing_bot_permission".into(),
            message: format!("The Helper bot needs Moderate Members and a manageable role below its highest role to apply {protection_name} timeouts."),
            severity: "error".into(),
        });
    }
    if request.enabled && requires_send_messages && !bot_send_messages {
        issues.push(ValidationIssue {
            path: "permissions.bot_send_messages".into(),
            code: "missing_bot_permission".into(),
            message: format!(
                "The Helper bot needs Send Messages to publish {protection_name} alerts."
            ),
            severity: "error".into(),
        });
    }
    if request.enabled && delete_message && !bot_manage_messages {
        issues.push(ValidationIssue {
            path: "permissions.bot_manage_messages".into(),
            code: "missing_bot_permission".into(),
            message: format!("The Helper bot needs Manage Messages to delete {protection_name} matches. Disable message deletion or grant that permission before publishing."),
            severity: "error".into(),
        });
    }
    if request.enabled && !alert_only && timeout_seconds > 0 && !permission_bit(&permissions, 40) {
        issues.push(ValidationIssue {
            path: "permissions.moderate_members".into(),
            code: "missing_permission".into(),
            message: "The Moderate Members permission is required to apply timeouts. You can publish in alert-only mode.".into(),
            severity: "error".into(),
        });
    }
    if request.enabled && requires_send_messages && !permission_bit(&permissions, 11) {
        issues.push(ValidationIssue {
            path: "permissions.send_messages".into(),
            code: "missing_permission".into(),
            message: format!(
                "The Send Messages permission is required to publish {protection_name} alerts."
            ),
            severity: "error".into(),
        });
    }
    if let Some(channel) = request
        .config
        .get("logChannel")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        && channel.parse::<u64>().is_err()
    {
        issues.push(ValidationIssue {
            path: "logChannel".into(),
            code: "invalid_channel_id".into(),
            message: "Choose a channel from the server list; this ID is not valid.".into(),
            severity: "error".into(),
        });
    }
    let mut selected_channel_send_messages = None;
    if let Some(channel_id) = selected_log_channel.filter(|value| value.parse::<u64>().is_ok()) {
        let channel = discord_snapshot
            .channels
            .iter()
            .find(|value| value.get("id").and_then(serde_json::Value::as_str) == Some(channel_id));
        if discord_snapshot.channels_ready && channel.is_none() {
            issues.push(ValidationIssue {
                path: "logChannel".into(),
                code: "channel_not_found".into(),
                message: "Choose a text channel that still exists in this server.".into(),
                severity: "error".into(),
            });
        }
        if let (Some(channel), Some(base), Some(bot_user_id)) = (
            channel,
            bot_permissions,
            discord_snapshot.bot_user_id.as_deref(),
        ) && let Some(overwrites) = channel.get("permission_overwrites")
        {
            selected_channel_send_messages = channel_bot_permissions(
                base,
                &guild.guild_id,
                bot_user_id,
                &discord_snapshot.bot_role_ids,
                overwrites,
            )
            .map(|value| permission_bit(&value.to_string(), 11));
            if selected_channel_send_messages == Some(false) {
                issues.push(ValidationIssue {
                    path: "permissions.bot_send_messages_channel".into(),
                    code: "missing_channel_permission".into(),
                    message: "The Helper bot cannot send messages in the selected log channel. Check its channel permissions.".into(),
                    severity: "error".into(),
                });
            }
        }
    }

    let error_count = issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .count();
    Ok(Json(serde_json::json!({
        "operation": request.operation,
        "guildId": claims.guild_id,
        "ok": error_count == 0,
        "issues": issues,
        "checks": {
            "guildManaged": true,
            "permissionBitfieldAvailable": permissions.parse::<u64>().is_ok(),
            "moderateMembers": permission_bit(&permissions, 40),
            "sendMessages": permission_bit(&permissions, 11),
            "botContextAvailable": bot_context_available,
            "botPermissionBitfieldAvailable": bot_permissions.is_some(),
            "botModerateMembers": bot_moderate_members,
            "botManageMessages": bot_manage_messages,
            "botSendMessages": bot_send_messages,
            "selectedLogChannelSendMessages": selected_channel_send_messages,
            "discordResourcesFresh": discord_snapshot.channels_ready && discord_snapshot.roles_ready,
            "shadowModeAvailable": true
        }
    })))
}

async fn feature_preflight(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(request): Json<FeaturePreflightRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    if key == "management.nickname" {
        return nickname_preflight(State(state), headers, request).await;
    }
    if matches!(key.as_str(), "protection.antispam" | "protection.antiscam") {
        return preflight(
            State(state),
            headers,
            Json(PreflightRequest {
                operation: format!("{key}.publish"),
                config: request.config,
                enabled: request.enabled,
            }),
        )
        .await;
    }
    generic_feature_preflight(State(state), headers, key, request).await
}

async fn nickname_preflight(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    request: FeaturePreflightRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let managed = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .any(|guild| guild.guild_id == claims.guild_id);
    if !managed {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    }
    nickname_preflight_for_claims(&state, &claims, request).await
}

async fn nickname_preflight_for_claims(
    state: &ApiState,
    claims: &helper_contracts::SessionClaims,
    request: FeaturePreflightRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mut issues = validate_feature_config("management.nickname", &request.config);
    let snapshot = fetch_discord_guild_snapshot(&claims.guild_id, &state.discord_token).await;
    let bot_permissions =
        effective_bot_permissions(&claims.guild_id, &snapshot.roles, &snapshot.bot_role_ids);
    let bot_permission_string = bot_permissions.map(|value| value.to_string());
    let bot_context_available = snapshot.bot_ready && bot_permissions.is_some();
    let bot_change_nickname = bot_permission_string
        .as_deref()
        .is_some_and(|value| permission_bit(value, 26));
    let bot_manage_nicknames = bot_permission_string
        .as_deref()
        .is_some_and(|value| permission_bit(value, 27));
    if request.enabled && !bot_context_available {
        issues.push(ValidationIssue {
            path: "permissions.bot_context".into(),
            code: "discord_context_unavailable".into(),
            message: "Refresh the Discord context before publishing; the Helper bot member and role could not be verified.".into(),
            severity: "error".into(),
        });
    }
    if request.enabled && !bot_change_nickname && !bot_manage_nicknames {
        issues.push(ValidationIssue {
            path: "permissions.bot_nickname".into(),
            code: "missing_bot_permission".into(),
            message: "The Helper bot needs Change Nickname or Manage Nicknames to apply its server nickname.".into(),
            severity: "error".into(),
        });
    }
    let error_count = issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .count();
    Ok(Json(serde_json::json!({
        "operation": "management.nickname.publish",
        "guildId": claims.guild_id,
        "ok": error_count == 0,
        "issues": issues,
        "checks": {
            "guildManaged": true,
            "botContextAvailable": bot_context_available,
            "botPermissionBitfieldAvailable": bot_permissions.is_some(),
            "botChangeNickname": bot_change_nickname,
            "botManageNicknames": bot_manage_nicknames,
            "discordResourcesFresh": snapshot.roles_ready,
            "nicknameLength": request.config.get("nickname").and_then(serde_json::Value::as_str).map(|value| value.chars().count())
        }
    })))
}

const QUICK_SETUP_KEY: &str = "quick_setup.state";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuickSetupStepUpdate {
    status: String,
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_true")]
    enabled: bool,
    expected_revision: Option<u64>,
}

fn quick_default_true() -> bool {
    true
}

fn empty_quick_setup(guild_id: &str) -> serde_json::Value {
    serde_json::json!({
        "guildId": guild_id,
        "status": "not_started",
        "currentStep": "welcome",
        "revision": 0,
        "steps": [
            {"key": "welcome", "status": "pending"},
            {"key": "roles", "status": "pending"},
            {"key": "moderation", "status": "pending"},
            {"key": "protection", "status": "pending"}
        ],
        "createdResources": []
    })
}

fn read_quick_setup(state: &ApiState, guild_id: &str) -> serde_json::Value {
    state
        .store
        .get_setting(guild_id, QUICK_SETUP_KEY)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_else(|| empty_quick_setup(guild_id))
}

async fn discord_create_channel(
    state: &ApiState,
    guild_id: &str,
    name: &str,
) -> Result<(String, String), (StatusCode, Json<ApiError>)> {
    if state.discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_adapter_unavailable",
        ));
    }
    let safe_name: String = name
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
        })
        .take(90)
        .collect();
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let response = client.post(format!("https://discord.com/api/v10/guilds/{guild_id}/channels"))
        .header(header::AUTHORIZATION, format!("Bot {}", state.discord_token))
        .json(&serde_json::json!({"name": if safe_name.is_empty() { "vozen-setup" } else { &safe_name }, "type": 0, "reason": "Vozen Quick Setup"}))
        .send().await.map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !response.status().is_success() {
        return Err(client_error(
            StatusCode::BAD_GATEWAY,
            "discord_channel_create_failed",
        ));
    }
    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    Ok((id.to_string(), safe_name))
}

async fn discord_find_resource(
    state: &ApiState,
    guild_id: &str,
    name: &str,
    resource: &str,
) -> Option<(String, String)> {
    if state.discord_token.len() < 20 {
        return None;
    }
    let endpoint = if resource == "role" {
        format!("https://discord.com/api/v10/guilds/{guild_id}/roles")
    } else {
        format!("https://discord.com/api/v10/guilds/{guild_id}/channels")
    };
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let response = client
        .get(endpoint)
        .header(
            header::AUTHORIZATION,
            format!("Bot {}", state.discord_token),
        )
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let values = response.json::<Vec<serde_json::Value>>().await.ok()?;
    values.into_iter().find_map(|value| {
        let value_name = value.get("name").and_then(serde_json::Value::as_str)?;
        let id = value.get("id").and_then(serde_json::Value::as_str)?;
        (value_name.eq_ignore_ascii_case(name)).then(|| (id.to_string(), value_name.to_string()))
    })
}

async fn discord_create_role(
    state: &ApiState,
    guild_id: &str,
    name: &str,
) -> Result<(String, String), (StatusCode, Json<ApiError>)> {
    if state.discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_adapter_unavailable",
        ));
    }
    let safe_name: String = name
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect();
    if safe_name.is_empty() {
        return Err(client_error(StatusCode::BAD_REQUEST, "role_name_required"));
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let response = client.post(format!("https://discord.com/api/v10/guilds/{guild_id}/roles"))
        .header(header::AUTHORIZATION, format!("Bot {}", state.discord_token))
        .json(&serde_json::json!({"name": safe_name, "permissions": "0", "mentionable": false, "reason": "Vozen Quick Setup"}))
        .send().await.map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !response.status().is_success() {
        return Err(client_error(
            StatusCode::BAD_GATEWAY,
            "discord_role_create_failed",
        ));
    }
    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    Ok((id.to_string(), safe_name))
}

/// Publishes the role panel created by Quick Setup directly in Discord.  The
/// old flow only created roles and left the administrator with a slash command
/// to finish the panel, which made the web setting look applied while no
/// usable panel existed.  Keep this operation idempotent by reusing the first
/// panel already stored for the guild.
async fn discord_publish_role_panel(
    state: &ApiState,
    guild_id: &str,
    config: &serde_json::Value,
    reuse_existing: bool,
    source: &str,
) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    let channel_id = config
        .get("channel")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.parse::<u64>().is_ok())
        .unwrap_or_default();
    let role_ids = config
        .get("roleIds")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|value| value.parse::<u64>().is_ok())
                .take(5)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if channel_id.is_empty() || role_ids.is_empty() {
        return Ok(None);
    }
    if reuse_existing
        && state
            .store
            .count_settings_prefix(guild_id, "community.role_panel.")
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
            > 0
    {
        return Ok(None);
    }
    if state.discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_adapter_unavailable",
        ));
    }
    let title = config
        .get("panelTitle")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Choose your roles");
    let description = config
        .get("panelDescription")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_default()
        .to_owned();
    let selection_mode = config
        .get("selectionMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "unique")
        .unwrap_or("multiple");
    let remove_on_unselect = config
        .get("removeOnUnselect")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let content = if description.is_empty() {
        title.to_owned()
    } else {
        format!("{title}\n{description}")
    };
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let role_values = match client
        .get(format!(
            "https://discord.com/api/v10/guilds/{guild_id}/roles"
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bot {}", state.discord_token),
        )
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .json::<Vec<serde_json::Value>>()
            .await
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let components = serde_json::json!([{
        "type": 1,
        "components": role_ids.iter().enumerate().map(|(index, role_id)| serde_json::json!({
            "type": 2,
            "style": 2,
            "label": role_values.iter().find(|role| role.get("id").and_then(serde_json::Value::as_str) == Some(role_id.as_str())).and_then(|role| role.get("name")).and_then(serde_json::Value::as_str).filter(|name| !name.trim().is_empty()).map(|name| name.chars().take(80).collect::<String>()).unwrap_or_else(|| format!("Role {}", index + 1)),
            "custom_id": format!("role:toggle:{role_id}")
        })).collect::<Vec<_>>()
    }]);
    let response = client
        .post(format!(
            "https://discord.com/api/v10/channels/{channel_id}/messages"
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bot {}", state.discord_token),
        )
        .json(&serde_json::json!({
            "content": content,
            "components": components,
            "allowed_mentions": {"parse": []},
            "reason": "Vozen Quick Setup role panel"
        }))
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if !response.status().is_success() {
        return Err(client_error(
            StatusCode::BAD_GATEWAY,
            "discord_role_panel_publish_failed",
        ));
    }
    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    let message_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| client_error(StatusCode::BAD_GATEWAY, "discord_invalid_response"))?;
    state
        .store
        .set_setting(
            guild_id,
            &format!("community.role_panel.{message_id}"),
            &serde_json::json!({
                "channel_id": channel_id,
                "message_id": message_id,
                "title": title,
                "description": description,
                "role_ids": role_ids,
                "selection_mode": selection_mode,
                "remove_on_unselect": remove_on_unselect,
                "source": source
            })
            .to_string(),
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Some(message_id.to_owned()))
}

#[derive(Debug, Deserialize)]
struct RolePanelRequest {
    channel: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default, rename = "roleIds")]
    role_ids: Vec<String>,
    #[serde(default, rename = "selectionMode")]
    selection_mode: String,
    #[serde(default = "default_true", rename = "removeOnUnselect")]
    remove_on_unselect: bool,
}

fn normalize_role_panel_request(
    request: RolePanelRequest,
) -> Result<serde_json::Value, (StatusCode, Json<ApiError>)> {
    let channel = request.channel.trim();
    if channel.parse::<u64>().is_err() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_channel_required",
        ));
    }
    let mut role_ids = Vec::new();
    for role_id in request.role_ids {
        let role_id = role_id.trim();
        if role_id.parse::<u64>().is_err() || role_ids.iter().any(|value| value == role_id) {
            continue;
        }
        role_ids.push(role_id.to_owned());
        if role_ids.len() == 5 {
            break;
        }
    }
    if role_ids.is_empty() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_roles_required",
        ));
    }
    let title = request.title.trim();
    if title.is_empty() || title.chars().count() > 80 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_title_invalid",
        ));
    }
    let description = request.description.trim();
    if description.chars().count() > 1_000 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_description_invalid",
        ));
    }
    let selection_mode = match request.selection_mode.as_str() {
        "unique" => "unique",
        "" | "multiple" => "multiple",
        _ => {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "role_panel_selection_invalid",
            ));
        }
    };
    Ok(serde_json::json!({
        "channel": channel,
        "roleIds": role_ids,
        "panelTitle": title,
        "panelDescription": description,
        "maxRoles": if selection_mode == "unique" { 1 } else { role_ids.len().clamp(1, 5) },
        "selectionMode": selection_mode,
        "removeOnUnselect": request.remove_on_unselect,
    }))
}

fn stored_role_panel_value(key: &str, value: &str) -> Option<serde_json::Value> {
    let message_id = key.strip_prefix("community.role_panel.")?;
    if message_id.parse::<u64>().is_err() {
        return None;
    }
    let mut panel = serde_json::from_str::<serde_json::Value>(value).ok()?;
    panel["message_id"] = serde_json::json!(message_id);
    Some(panel)
}

async fn discord_delete_role_panel(
    state: &ApiState,
    channel_id: &str,
    message_id: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if state.discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_adapter_unavailable",
        ));
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let response = client
        .delete(format!(
            "{DISCORD_API_BASE}/channels/{channel_id}/messages/{message_id}"
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bot {}", state.discord_token),
        )
        .header("X-Audit-Log-Reason", "Vozen role panel repair")
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "discord_unreachable"))?;
    if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    Err(client_error(
        StatusCode::BAD_GATEWAY,
        "discord_role_panel_delete_failed",
    ))
}

async fn role_panels(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let panels = state
        .store
        .settings_with_prefix(&claims.guild_id, "community.role_panel.")
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .filter_map(|(key, value)| stored_role_panel_value(&key, &value))
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "panels": panels}),
    ))
}

async fn create_role_panel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<RolePanelRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "community.role_panels").await?;
    if !feature_enabled(&state, &claims.guild_id, "community.role_panels") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    let config = normalize_role_panel_request(request)?;
    let preflight = generic_feature_preflight(
        State(state.clone()),
        headers.clone(),
        "community.role_panels".into(),
        FeaturePreflightRequest {
            config: config.clone(),
            enabled: true,
        },
    )
    .await?;
    if !preflight
        .0
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(client_error(
            StatusCode::PRECONDITION_FAILED,
            "feature_preflight_failed",
        ));
    }
    let plan = effective_plan(&state, &claims).await;
    let limit = quota_limit(&plan, "role_panels");
    if state
        .store
        .count_settings_prefix(&claims.guild_id, "community.role_panel.")
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        >= limit
    {
        return Err(client_error(
            StatusCode::TOO_MANY_REQUESTS,
            "role_panel_quota_exceeded",
        ));
    }
    let message_id = discord_publish_role_panel(&state, &claims.guild_id, &config, false, "panel")
        .await?
        .ok_or_else(|| {
            client_error(StatusCode::BAD_GATEWAY, "discord_role_panel_publish_failed")
        })?;
    let enabled_value = "true".to_owned();
    let mut projections = vec![
        (feature_key("community.role_panels"), enabled_value),
        (
            feature_config_key("community.role_panels"),
            config.to_string(),
        ),
    ];
    projections.extend(runtime_projection_pairs("community.role_panels", &config));
    state
        .store
        .publish_feature_setting(
            &claims.guild_id,
            "community.role_panels",
            true,
            &config.to_string(),
            None,
            &claims.user_id,
            &projections,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "role_panel_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"publish","messageId":message_id}).to_string(),
    );
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"messageId": message_id, "config": config})),
    ))
}

async fn update_role_panel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
    Json(request): Json<RolePanelRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "community.role_panels").await?;
    if !feature_enabled(&state, &claims.guild_id, "community.role_panels") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    if message_id.parse::<u64>().is_err() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_message_invalid",
        ));
    }
    let old_key = format!("community.role_panel.{message_id}");
    let old_value = state
        .store
        .get_setting(&claims.guild_id, &old_key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "role_panel_not_found"))?;
    let old_panel = stored_role_panel_value(&old_key, &old_value)
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "role_panel_invalid"))?;
    let old_channel_id = old_panel
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let config = normalize_role_panel_request(request)?;
    let preflight = generic_feature_preflight(
        State(state.clone()),
        headers.clone(),
        "community.role_panels".into(),
        FeaturePreflightRequest {
            config: config.clone(),
            enabled: true,
        },
    )
    .await?;
    if !preflight
        .0
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(client_error(
            StatusCode::PRECONDITION_FAILED,
            "feature_preflight_failed",
        ));
    }
    let new_id = discord_publish_role_panel(&state, &claims.guild_id, &config, false, "update")
        .await?
        .ok_or_else(|| {
            client_error(StatusCode::BAD_GATEWAY, "discord_role_panel_publish_failed")
        })?;
    if !old_channel_id.is_empty() {
        let _ = discord_delete_role_panel(&state, &old_channel_id, &message_id).await;
    }
    state
        .store
        .delete_setting(&claims.guild_id, &old_key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let enabled_value = "true".to_owned();
    let mut projections = vec![
        (feature_key("community.role_panels"), enabled_value),
        (
            feature_config_key("community.role_panels"),
            config.to_string(),
        ),
    ];
    projections.extend(runtime_projection_pairs("community.role_panels", &config));
    state
        .store
        .publish_feature_setting(
            &claims.guild_id,
            "community.role_panels",
            true,
            &config.to_string(),
            None,
            &claims.user_id,
            &projections,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "role_panel_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"update","oldMessageId":message_id,"messageId":new_id})
            .to_string(),
    );
    Ok(Json(
        serde_json::json!({"ok": true, "messageId": new_id, "config": config}),
    ))
}

async fn delete_role_panel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if message_id.parse::<u64>().is_err() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_message_invalid",
        ));
    }
    let key = format!("community.role_panel.{message_id}");
    let stored = state
        .store
        .get_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "role_panel_not_found"))?;
    let panel = stored_role_panel_value(&key, &stored)
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "role_panel_invalid"))?;
    let channel_id = panel
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "role_panel_invalid"))?;
    discord_delete_role_panel(&state, channel_id, &message_id).await?;
    state
        .store
        .delete_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "role_panel_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"delete","messageId":message_id}).to_string(),
    );
    Ok(Json(
        serde_json::json!({"ok": true, "messageId": message_id}),
    ))
}

async fn repair_role_panel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "community.role_panels").await?;
    if message_id.parse::<u64>().is_err() {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "role_panel_message_invalid",
        ));
    }
    let key = format!("community.role_panel.{message_id}");
    let stored = state
        .store
        .get_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "role_panel_not_found"))?;
    let panel = stored_role_panel_value(&key, &stored)
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "role_panel_invalid"))?;
    let channel_id = panel
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let config = serde_json::json!({
        "channel": channel_id,
        "roleIds": panel.get("role_ids").cloned().unwrap_or_else(|| serde_json::json!([])),
        "panelTitle": panel.get("title").and_then(serde_json::Value::as_str).unwrap_or("Choose your roles"),
        "panelDescription": panel.get("description").and_then(serde_json::Value::as_str).unwrap_or_default(),
        "selectionMode": panel.get("selection_mode").and_then(serde_json::Value::as_str).unwrap_or("multiple"),
        "removeOnUnselect": panel.get("remove_on_unselect").and_then(serde_json::Value::as_bool).unwrap_or(true),
    });
    let new_id = discord_publish_role_panel(&state, &claims.guild_id, &config, false, "repair")
        .await?
        .ok_or_else(|| {
            client_error(StatusCode::BAD_GATEWAY, "discord_role_panel_publish_failed")
        })?;
    // Publish first so a Discord failure never destroys the last known-good
    // panel. Cleanup is best-effort after the replacement is stored.
    if !channel_id.is_empty() {
        let _ = discord_delete_role_panel(&state, channel_id, &message_id).await;
    }
    state
        .store
        .delete_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "role_panel_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"repair","oldMessageId":message_id,"messageId":new_id})
            .to_string(),
    );
    Ok(Json(
        serde_json::json!({"ok": true, "messageId": new_id, "config": config}),
    ))
}

fn publish_quick_setup_feature(
    state: &ApiState,
    guild_id: &str,
    user_id: &str,
    key: &str,
    enabled: bool,
    config: &serde_json::Value,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let enabled_value = if enabled { "true" } else { "false" };
    let mut projections = vec![
        (feature_key(key), enabled_value.to_owned()),
        (feature_config_key(key), config.to_string()),
    ];
    projections.extend(runtime_projection_pairs(key, config));
    state
        .store
        .publish_feature_setting(
            guild_id,
            key,
            enabled,
            &config.to_string(),
            None,
            user_id,
            &projections,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(())
}

async fn quick_setup(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    Ok(Json(read_quick_setup(&state, &claims.guild_id)))
}

async fn quick_setup_dismiss(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let mut value = read_quick_setup(&state, &claims.guild_id);
    value["status"] = serde_json::json!("dismissed");
    value["revision"] =
        serde_json::json!(value["revision"].as_u64().unwrap_or(0).saturating_add(1));
    value["updatedAt"] = serde_json::json!(Utc::now().to_rfc3339());
    state
        .store
        .set_setting(&claims.guild_id, QUICK_SETUP_KEY, &value.to_string())
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(value))
}

async fn quick_setup_step(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(step): Path<String>,
    Json(update): Json<QuickSetupStepUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if !["welcome", "roles", "moderation", "protection"].contains(&step.as_str()) {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "unknown_quick_setup_step",
        ));
    }
    if !["applied", "skipped"].contains(&update.status.as_str()) {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_quick_setup_status",
        ));
    }
    let mut value = read_quick_setup(&state, &claims.guild_id);
    let revision = value["revision"].as_u64().unwrap_or(0);
    if update
        .expected_revision
        .is_some_and(|expected| expected != revision)
    {
        return Err(client_error(
            StatusCode::CONFLICT,
            "quick_setup_revision_conflict",
        ));
    }
    let mut normalized_config = update.config.clone();
    let mut created_resources = Vec::new();
    let create_channel = update
        .config
        .get("createChannel")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let channel_key = if step == "moderation" || step == "protection" {
        "logChannel"
    } else {
        "channel"
    };
    if create_channel
        && update
            .config
            .get(channel_key)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
    {
        let suggested = match step.as_str() {
            "welcome" => "boas-vindas",
            "roles" => "escolhe-cargos",
            _ => "vozen-alertas",
        };
        let (id, name, resource_state) = if let Some((id, name)) =
            discord_find_resource(&state, &claims.guild_id, suggested, "channel").await
        {
            (id, name, "reused")
        } else {
            let (id, name) = discord_create_channel(&state, &claims.guild_id, suggested).await?;
            (id, name, "created")
        };
        normalized_config[channel_key] = serde_json::json!(id);
        created_resources.push(serde_json::json!({"type": "channel", "name": format!("#{name}"), "id": id, "state": resource_state}));
    }
    if step == "roles" {
        let role_names = update
            .config
            .get("roleNames")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .take(5);
        let mut role_ids = Vec::new();
        for role_name in role_names {
            let (id, name, resource_state) = if let Some((id, name)) =
                discord_find_resource(&state, &claims.guild_id, role_name, "role").await
            {
                (id, name, "reused")
            } else {
                let (id, name) = discord_create_role(&state, &claims.guild_id, role_name).await?;
                (id, name, "created")
            };
            role_ids.push(serde_json::json!(id));
            created_resources.push(serde_json::json!({"type": "role", "name": name, "id": id, "state": resource_state}));
        }
        normalized_config["roleIds"] = serde_json::Value::Array(role_ids);
    }
    if update.status == "applied" {
        match step.as_str() {
            "welcome" => publish_quick_setup_feature(
                &state,
                &claims.guild_id,
                &claims.user_id,
                "support.welcome",
                update.enabled,
                &normalized_config,
            )?,
            "roles" => {
                publish_quick_setup_feature(
                    &state,
                    &claims.guild_id,
                    &claims.user_id,
                    "community.role_panels",
                    update.enabled,
                    &normalized_config,
                )?;
                if update.enabled
                    && let Some(message_id) = discord_publish_role_panel(
                        &state,
                        &claims.guild_id,
                        &normalized_config,
                        true,
                        "quick_setup",
                    )
                    .await?
                {
                    created_resources.push(
                        serde_json::json!({"type": "role_panel", "messageId": message_id, "state": "published"}),
                    );
                }
            }
            _ => {}
        }
    }
    if let Some(steps) = value["steps"].as_array_mut()
        && let Some(item) = steps
            .iter_mut()
            .find(|item| item.get("key").and_then(serde_json::Value::as_str) == Some(step.as_str()))
    {
        item["status"] = serde_json::json!(update.status);
        item["updatedAt"] = serde_json::json!(Utc::now().to_rfc3339());
        item["summary"] = serde_json::json!(format!("Etapa {} guardada pelo painel", step));
    }
    let next = ["welcome", "roles", "moderation", "protection"]
        .iter()
        .find(|candidate| {
            value["steps"].as_array().is_some_and(|steps| {
                steps.iter().any(|item| {
                    item.get("key").and_then(serde_json::Value::as_str) == Some(**candidate)
                        && item.get("status").and_then(serde_json::Value::as_str) == Some("pending")
                })
            })
        });
    value["currentStep"] = next
        .map(|item| serde_json::json!(*item))
        .unwrap_or(serde_json::Value::Null);
    value["status"] = if next.is_none() {
        serde_json::json!("completed")
    } else {
        serde_json::json!("in_progress")
    };
    value["revision"] = serde_json::json!(revision.saturating_add(1));
    value["updatedAt"] = serde_json::json!(Utc::now().to_rfc3339());
    if !normalized_config.is_null() {
        value["draft"] = normalized_config;
    }
    value["createdResources"] = serde_json::Value::Array(created_resources);
    state
        .store
        .set_setting(&claims.guild_id, QUICK_SETUP_KEY, &value.to_string())
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(value))
}

/// Switches the active guild without asking Discord for another access token.
/// The target must be present in the managed-guild snapshot captured during
/// OAuth, so a user cannot select a guild they did not authorise for this
/// session. A fresh signed cookie keeps the active tenant explicit for every
/// subsequent request.
#[derive(Debug, Deserialize)]
struct SwitchGuildRequest {
    guild_id: String,
}

async fn switch_session_guild(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<SwitchGuildRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let current = require_mutation_auth(&state, &headers)?;
    let managed = state
        .store
        .session_guilds(current.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if request.guild_id.trim().is_empty()
        || !managed
            .iter()
            .any(|guild| guild.guild_id == request.guild_id)
    {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    }
    let now = Utc::now();
    let claims = SessionClaims {
        session_id: Uuid::new_v4(),
        user_id: current.user_id,
        guild_id: request.guild_id,
        issued_at: now,
        expires_at: current.expires_at,
        last_seen_at: now,
    };
    state
        .store
        .save_session(&claims)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let guilds = managed
        .iter()
        .map(|guild| {
            (
                guild.guild_id.clone(),
                guild.name.clone(),
                guild.permissions.clone(),
            )
        })
        .collect::<Vec<_>>();
    state
        .store
        .replace_session_guilds(claims.session_id, &guilds)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.revoke_session(current.session_id);
    let token = sign_session(&claims, &state.session_secret);
    let mut response = Json(serde_json::json!({
        "ok": true,
        "guildId": claims.guild_id,
        "expiresAt": claims.expires_at,
    }))
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{COOKIE}={token};{} HttpOnly; Secure; SameSite=None; Path=/; Max-Age={}",
            cookie_domain(&state),
            SESSION_MAX_HOURS * 3600
        )
        .parse()
        .unwrap(),
    );
    Ok(response)
}

#[derive(Debug, Clone, Serialize)]
struct FeatureDefinition {
    key: String,
    label: String,
    description: String,
    category: String,
    capability: String,
    available: bool,
    enabled: bool,
    maturity: FeatureMaturity,
    configurable: bool,
    premium_required: bool,
    premium_unlocked: bool,
    config_schema_version: u32,
    revision: u64,
    issues: Vec<ValidationIssue>,
    health: FeatureHealthSummary,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureHealthSummary {
    status: &'static str,
    operational: bool,
    adapter: Option<String>,
    dependencies: Vec<String>,
}

/// The anti-spam editor is deliberately described by the API.  This keeps
/// the panel from exposing a field that the runtime does not understand and
/// gives us one place to document bounded limits and real Discord resources.
fn feature_schema(key: &str) -> Option<serde_json::Value> {
    feature_adapter(key).map(|adapter| adapter.descriptor().schema)
}

fn feature_defaults(key: &str) -> Option<serde_json::Value> {
    feature_adapter(key).map(|adapter| adapter.descriptor().defaults)
}

const FEATURE_DEFINITIONS: &[(&str, &str, &str, &str, &str, bool)] = &[
    (
        "protection.antispam",
        "Proteção contra spam",
        "Deteta flood, mensagens repetidas e excesso de menções.",
        "protection",
        "security",
        true,
    ),
    (
        "protection.antiscam",
        "Proteção contra fraude",
        "Bloqueia links suspeitos, convites e padrões de phishing.",
        "protection",
        "security",
        true,
    ),
    (
        "protection.anti_raid",
        "Anti-raid",
        "Ativa uma resposta rápida a entradas anormais.",
        "protection",
        "security",
        true,
    ),
    (
        "protection.join_gate",
        "Join gate",
        "Pede verificação antes de dar acesso completo.",
        "protection",
        "security",
        true,
    ),
    (
        "community.levels",
        "Níveis e XP",
        "Recompensa conversa saudável com XP e níveis.",
        "community",
        "community",
        true,
    ),
    (
        "community.leaderboard",
        "Leaderboard de XP",
        "Mostra a progressão da comunidade com privacidade configurável.",
        "community",
        "community",
        true,
    ),
    (
        "community.starboard",
        "Starboard",
        "Destaca mensagens que a comunidade mais gosta.",
        "community",
        "community",
        true,
    ),
    (
        "community.suggestions",
        "Sugestões",
        "Recolhe ideias e deixa a comunidade votar.",
        "community",
        "community",
        true,
    ),
    (
        "community.giveaways",
        "Giveaways",
        "Cria sorteios com entradas rastreáveis.",
        "community",
        "events",
        true,
    ),
    (
        "support.tickets",
        "Tickets",
        "Organiza pedidos de suporte num só lugar.",
        "management",
        "support",
        true,
    ),
    (
        "support.welcome",
        "Boas-vindas",
        "Recebe novos membros com uma mensagem guiada.",
        "management",
        "core",
        true,
    ),
    (
        "support.welcome_channel",
        "Canal de boas-vindas",
        "Organiza regras, informação e primeiros passos para quem chega.",
        "management",
        "core",
        true,
    ),
    (
        "management.nickname",
        "Nickname",
        "Define o nome que o Helper mostra neste servidor.",
        "management",
        "core",
        true,
    ),
    (
        "management.workflows",
        "Automações",
        "Liga um gatilho a uma resposta sem código.",
        "management",
        "automate",
        true,
    ),
    (
        "management.polls",
        "Enquetes",
        "Publica votações simples para decisões rápidas.",
        "management",
        "events",
        true,
    ),
    (
        "insights.stats",
        "Canais de estatísticas",
        "Acompanha atividade e tendências do servidor.",
        "management",
        "insights",
        true,
    ),
    (
        "studio.rank_card",
        "XP card",
        "Personaliza a carta de nível mostrada no Discord.",
        "community",
        "studio",
        true,
    ),
    (
        "management.moderation",
        "Moderador",
        "Centraliza regras, avisos e ações de moderação do servidor.",
        "management",
        "security",
        true,
    ),
    (
        "management.custom_commands",
        "Comandos personalizados",
        "Cria respostas reutilizáveis para perguntas frequentes.",
        "management",
        "automate",
        true,
    ),
    (
        "management.audit",
        "Auditoria e permissões",
        "Acompanha alterações importantes e mantém a equipa alinhada.",
        "management",
        "security",
        true,
    ),
    (
        "management.privacy",
        "Privacidade e dados",
        "Consulta, exporta e elimina dados do servidor com segurança.",
        "management",
        "core",
        true,
    ),
    (
        "management.templates",
        "Modelos e importação",
        "Guarda uma configuração e reutiliza-a noutro servidor.",
        "management",
        "core",
        true,
    ),
    (
        "community.role_panels",
        "Painéis de cargos",
        "Deixa os membros escolherem cargos através de painéis simples.",
        "community",
        "community",
        true,
    ),
    (
        "community.events",
        "Eventos do servidor",
        "Cria eventos, inscrições e check-ins sem sair do painel.",
        "community",
        "events",
        true,
    ),
    (
        "community.achievements",
        "Conquistas",
        "Cria metas e celebra marcos da comunidade.",
        "community",
        "community",
        true,
    ),
    (
        "management.invite_tracker",
        "Rastreador de convites",
        "Percebe quem trouxe novos membros para o servidor.",
        "management",
        "insights",
        true,
    ),
    (
        "utility.help",
        "Ajuda",
        "Explica os módulos e mostra o próximo passo para cada equipa.",
        "utility",
        "core",
        true,
    ),
    (
        "utility.reminders",
        "Temporizadores",
        "Agenda lembretes para mensagens, tarefas e eventos.",
        "utility",
        "events",
        true,
    ),
    (
        "utility.emojis",
        "Emojis",
        "Organiza e melhora a utilização de emojis personalizados.",
        "utility",
        "community",
        true,
    ),
    (
        "utility.embeds",
        "Mensagens incorporadas",
        "Cria mensagens ricas para regras, anúncios e informação útil.",
        "utility",
        "community",
        true,
    ),
    (
        "utility.search",
        "Procura algo",
        "Pesquisa conteúdos, vídeos e referências sem trocar de aplicação.",
        "utility",
        "utility",
        false,
    ),
    (
        "utility.temp_channels",
        "Canais temporários",
        "Cria canais de voz que desaparecem quando deixam de ser usados.",
        "utility",
        "community",
        true,
    ),
    (
        "social.twitch",
        "Alertas da Twitch",
        "Publica um aviso quando um canal começa uma transmissão.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.youtube",
        "Alertas do YouTube",
        "Notifica o servidor quando sai um novo vídeo.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.instagram",
        "Alertas do Instagram",
        "Acompanha novas publicações de contas escolhidas.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.tiktok",
        "Alertas do TikTok",
        "Notifica o servidor sobre novos vídeos.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.rss",
        "RSS Feeds",
        "Transforma qualquer feed RSS numa atualização automática.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.podcasts",
        "Podcasts",
        "Avisa quando sai um novo episódio dos teus podcasts.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.kick",
        "Alertas da Kick",
        "Notifica quando um criador começa uma transmissão.",
        "social",
        "alerts",
        false,
    ),
    (
        "social.bluesky",
        "Alertas do Bluesky",
        "Acompanha novas publicações de perfis escolhidos.",
        "social",
        "alerts",
        false,
    ),
    (
        "community.birthdays",
        "Aniversários",
        "Celebra aniversários automaticamente, com privacidade configurável.",
        "community",
        "community",
        true,
    ),
    (
        "community.economy",
        "Economia",
        "Cria uma economia virtual com recompensas e progressão.",
        "community",
        "community",
        true,
    ),
    (
        "growth.monetization",
        "Monetização",
        "Prepara benefícios e cargos para apoiar o servidor.",
        "growth",
        "billing",
        false,
    ),
    (
        "web3.crypto_stats",
        "Estatísticas de cripto",
        "Acompanha indicadores de moedas digitais.",
        "web3",
        "web3",
        false,
    ),
    (
        "web3.crypto_queries",
        "Consultas de criptomoedas",
        "Consulta informação de criptomoedas no servidor.",
        "web3",
        "web3",
        false,
    ),
    (
        "web3.gas_tracker",
        "Gas tracker",
        "Mostra as taxas de rede atuais para a comunidade.",
        "web3",
        "web3",
        false,
    ),
    (
        "web3.gating",
        "Gating",
        "Controla acesso e cargos com base em coleções verificadas.",
        "web3",
        "web3",
        false,
    ),
];

// Premium is deliberately scoped to advanced server operations.  The free
// plan keeps the core safety, welcome, basic roles, XP and activity tools;
// Premium adds the deeper automation, customisation and feed surfaces listed
// on the public plan comparison.  Keep this policy next to the API catalogue
// so the cards, detail routes and write endpoints share one source of truth.
const PREMIUM_FEATURE_KEYS: &[&str] = &[
    "community.role_panels",
    "community.achievements",
    "community.leaderboard",
    "studio.rank_card",
    "management.templates",
    "management.workflows",
    "social.twitch",
    "social.youtube",
    "social.instagram",
    "social.tiktok",
    "social.rss",
    "social.podcasts",
    "social.kick",
    "social.bluesky",
];

fn feature_requires_premium(key: &str) -> bool {
    PREMIUM_FEATURE_KEYS.contains(&key)
}

fn entitlement_is_active(snapshot: &helper_contracts::EntitlementSnapshot) -> bool {
    snapshot.active
        && snapshot
            .expires_at
            .is_none_or(|expires_at| expires_at > Utc::now())
}

/// Premium is a server entitlement.  When the central service is configured,
/// never fall back to a user-wide cached record: a seat assigned to guild A
/// must not unlock guild B while the entitlement service is unavailable.
async fn guild_has_premium(state: &ApiState, claims: &SessionClaims) -> bool {
    if let Some(client) = &state.entitlements {
        return match client
            .resolve(&claims.user_id, Some(&claims.guild_id))
            .await
        {
            Ok(snapshot) => {
                entitlement_is_active(&snapshot) && matches!(snapshot.plan, Plan::Premium { .. })
            }
            Err(error) => {
                tracing::warn!(
                    guild_id = %claims.guild_id,
                    error = %error,
                    "central Premium entitlement lookup failed"
                );
                false
            }
        };
    }

    matches!(effective_plan(state, claims).await, Plan::Premium { .. })
}

async fn feature_premium_unlocked(state: &ApiState, claims: &SessionClaims, key: &str) -> bool {
    !feature_requires_premium(key) || guild_has_premium(state, claims).await
}

async fn require_feature_premium(
    state: &ApiState,
    claims: &SessionClaims,
    key: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if feature_premium_unlocked(state, claims, key).await {
        Ok(())
    } else {
        Err(client_error(StatusCode::FORBIDDEN, "premium_required"))
    }
}

fn feature_key(key: &str) -> String {
    format!("feature.{key}")
}

fn runtime_feature_key(key: &str) -> Option<&'static str> {
    match key {
        "protection.anti_raid" => Some("security.anti_raid.enabled"),
        "protection.join_gate" => Some("security.join_gate.enabled"),
        "management.nickname" => Some("identity.nickname.enabled"),
        _ => None,
    }
}

async fn feature_config(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let premium_enabled = guild_has_premium(&state, &claims).await;
    let rows = FEATURE_DEFINITIONS
        .iter()
        .filter(|definition| definition.0 != "support.welcome_channel")
        .map(
            |(key, label, description, category, capability, available)| {
                let maturity = effective_feature_maturity(&state, key);
                let configurable = feature_configurable_for(&state, key);
                let stored = state
                    .store
                    .get_feature_setting(&claims.guild_id, key)
                    .ok()
                    .flatten();
                let config = stored
                    .as_ref()
                    .and_then(|value| {
                        serde_json::from_str::<serde_json::Value>(&value.config_json).ok()
                    })
                    .unwrap_or_else(|| serde_json::json!({}));
                let mut issues = validate_feature_config(key, &config);
                issues.extend(lifecycle_issues(key, maturity));
                // Use the same provider/maturity guard used by feature detail
                // and runtime checks.  A stale legacy flag must never make a
                // blocked or dependency-down feature appear active.
                let premium_required = feature_requires_premium(key);
                let premium_unlocked = !premium_required || premium_enabled;
                let enabled = premium_unlocked && feature_enabled(&state, &claims.guild_id, key);
                let adapter = feature_adapter(key).map(|value| value.descriptor());
                let health = FeatureHealthSummary {
                    status: feature_health_status(
                        &state,
                        &claims.guild_id,
                        key,
                        enabled,
                        maturity,
                        &issues,
                    ),
                    operational: feature_is_operational(&state, key, maturity, &issues),
                    adapter: adapter.as_ref().map(|value| value.source.clone()),
                    dependencies: adapter
                        .as_ref()
                        .map(|value| value.dependencies.clone())
                        .unwrap_or_default(),
                };
                FeatureDefinition {
                    key: (*key).to_string(),
                    label: (*label).to_string(),
                    description: (*description).to_string(),
                    category: (*category).to_string(),
                    capability: (*capability).to_string(),
                    // `available` means implemented/discoverable, not
                    // immediately activatable.  Provider credentials and
                    // approvals are represented by `maturity`, `health` and
                    // `configurable`; keeping all adapter-backed entries
                    // discoverable prevents the old thirteen-card allow-list
                    // regression while still blocking unsafe activation.
                    available: feature_adapter(key).is_some() || *available,
                    enabled,
                    maturity,
                    configurable,
                    premium_required,
                    premium_unlocked,
                    config_schema_version: FEATURE_SCHEMA_VERSION,
                    revision: stored.as_ref().map(|value| value.revision).unwrap_or(0),
                    issues,
                    health,
                }
            },
        )
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "features": rows}),
    ))
}

#[derive(Debug, Deserialize)]
struct FeatureUpdate {
    key: String,
    enabled: bool,
    #[serde(default)]
    expected_revision: Option<u64>,
}

fn feature_definition(
    key: &str,
) -> Option<&'static (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    bool,
)> {
    is_known_feature(key).then(|| FEATURE_DEFINITIONS.iter().find(|item| item.0 == key))?
}

fn feature_enabled(state: &ApiState, guild_id: &str, key: &str) -> bool {
    if key == "support.welcome" {
        return state
            .store
            .welcome_configuration(guild_id)
            .map(|value| value.0)
            .unwrap_or(false);
    }
    // Keep runtime/API checks aligned with the lifecycle registry. A legacy
    // true flag cannot activate a blocked provider or an unknown feature.
    if !feature_configurable_for(state, key) {
        return false;
    }
    state
        .store
        .get_feature_setting(guild_id, key)
        .ok()
        .flatten()
        .map(|value| value.enabled)
        .or_else(|| {
            state
                .store
                .get_setting(guild_id, &feature_key(key))
                .ok()
                .flatten()
                .and_then(|value| value.parse::<bool>().ok())
        })
        .or_else(|| {
            runtime_feature_key(key).and_then(|runtime_key| {
                state
                    .store
                    .get_setting(guild_id, runtime_key)
                    .ok()
                    .flatten()
                    .and_then(|value| value.parse::<bool>().ok())
            })
        })
        .unwrap_or(false)
        && provider_dependencies_ready(state, key)
        && effective_feature_maturity(state, key) != FeatureMaturity::Blocked
}

fn feature_config_key(key: &str) -> String {
    format!("feature.config.{key}")
}

#[allow(dead_code)]
fn sync_runtime_feature_config(
    store: &Store,
    guild_id: &str,
    key: &str,
    config: &serde_json::Value,
) -> Result<()> {
    let object = config.as_object();
    let number = |name: &str| {
        object
            .and_then(|values| values.get(name))
            .and_then(serde_json::Value::as_i64)
    };
    let text = |name: &str| {
        object
            .and_then(|values| values.get(name))
            .and_then(serde_json::Value::as_str)
    };
    match key {
        "protection.anti_raid" => {
            if let Some(value) = number("joinThreshold") {
                store.set_setting(guild_id, "security.anti_raid.joins", &value.to_string())?;
            }
            if let Some(value) = number("windowSeconds") {
                store.set_setting(
                    guild_id,
                    "security.anti_raid.window_seconds",
                    &value.to_string(),
                )?;
            }
        }
        "protection.join_gate" => {
            if let Some(value) = number("minimumAccountDays") {
                store.set_setting(
                    guild_id,
                    "security.join_gate.min_age_days",
                    &value.to_string(),
                )?;
            }
            if let Some(value) = text("verifiedRole") {
                store.set_setting(guild_id, "security.join_gate.role_id", value)?;
            }
        }
        "community.starboard" => {
            if let Some(value) = text("channel") {
                store.set_setting(guild_id, "community.starboard.channel_id", value)?;
            }
            if let Some(value) = number("threshold") {
                store.set_setting(
                    guild_id,
                    "community.starboard.threshold",
                    &value.to_string(),
                )?;
            }
            if let Some(value) = text("emoji") {
                store.set_setting(guild_id, "community.starboard.emoji", value)?;
            }
            if let Some(value) = object
                .and_then(|values| values.get("allowSelfStar"))
                .and_then(serde_json::Value::as_bool)
            {
                store.set_setting(
                    guild_id,
                    "community.starboard.allow_self_star",
                    &value.to_string(),
                )?;
            }
            if let Some(value) = object
                .and_then(|values| values.get("includeImages"))
                .and_then(serde_json::Value::as_bool)
            {
                store.set_setting(
                    guild_id,
                    "community.starboard.include_images",
                    &value.to_string(),
                )?;
            }
            if let Some(values) = object
                .and_then(|values| values.get("ignoredChannels"))
                .and_then(serde_json::Value::as_array)
            {
                store.set_setting(
                    guild_id,
                    "community.starboard.ignored_channels",
                    &values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                )?;
            }
        }
        "support.tickets" => {
            if let Some(value) = object
                .and_then(|values| values.get("staffRoles"))
                .and_then(|values| values.as_array())
                .and_then(|values| values.first())
                .and_then(serde_json::Value::as_str)
            {
                store.set_setting(guild_id, "support.ticket.staff_role_id", value)?;
            }
            if let Some(value) = text("transcriptChannel") {
                store.set_setting(guild_id, "support.ticket.transcript_channel_id", value)?;
            }
            if let Some(value) = number("closeAfterHours") {
                store.set_setting(
                    guild_id,
                    "support.ticket.sla_ms",
                    &(value * 3_600_000).to_string(),
                )?;
            }
        }
        "management.nickname" => {
            if let Some(value) = text("nickname") {
                store.set_setting(guild_id, "identity.nickname", value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn runtime_projection_pairs(key: &str, config: &serde_json::Value) -> Vec<(String, String)> {
    if let Some(adapter) = feature_adapter(key) {
        return adapter.runtime_projection(config);
    }
    let object = config.as_object();
    let number = |name: &str| {
        object
            .and_then(|values| values.get(name))
            .and_then(serde_json::Value::as_i64)
    };
    let text = |name: &str| {
        object
            .and_then(|values| values.get(name))
            .and_then(serde_json::Value::as_str)
    };
    let mut pairs = Vec::new();
    let mut add = |name: &str, value: String| pairs.push((name.to_string(), value));
    match key {
        "protection.anti_raid" => {
            if let Some(value) = number("joinThreshold") {
                add("security.anti_raid.joins", value.to_string());
            }
            if let Some(value) = number("windowSeconds") {
                add("security.anti_raid.window_seconds", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("alertOnly"))
                .and_then(serde_json::Value::as_bool)
            {
                add("security.anti_raid.alert_only", value.to_string());
            }
            if let Some(value) = text("alertChannel") {
                add("security.anti_raid.alert_channel", value.to_string());
            }
        }
        "protection.join_gate" => {
            if let Some(value) = number("minimumAccountDays") {
                add("security.join_gate.min_age_days", value.to_string());
            }
            if let Some(value) = text("verifiedRole") {
                add("security.join_gate.role_id", value.to_string());
            }
        }
        "community.starboard" => {
            if let Some(value) = text("channel") {
                add("community.starboard.channel_id", value.to_string());
            }
            if let Some(value) = number("threshold") {
                add("community.starboard.threshold", value.to_string());
            }
            if let Some(value) = text("emoji") {
                add("community.starboard.emoji", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("allowSelfStar"))
                .and_then(serde_json::Value::as_bool)
            {
                add("community.starboard.allow_self_star", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("includeImages"))
                .and_then(serde_json::Value::as_bool)
            {
                add("community.starboard.include_images", value.to_string());
            }
            if let Some(values) = object
                .and_then(|values| values.get("ignoredChannels"))
                .and_then(serde_json::Value::as_array)
            {
                add(
                    "community.starboard.ignored_channels",
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
        }
        "support.tickets" => {
            if let Some(value) = object
                .and_then(|values| values.get("staffRoles"))
                .and_then(|values| values.as_array())
                .and_then(|values| values.first())
                .and_then(serde_json::Value::as_str)
            {
                add("support.ticket.staff_role_id", value.to_string());
            }
            if let Some(value) = text("transcriptChannel") {
                add("support.ticket.transcript_channel_id", value.to_string());
            }
            if let Some(value) = number("closeAfterHours") {
                add("support.ticket.sla_ms", (value * 3_600_000).to_string());
            }
        }
        "management.nickname" => {
            if let Some(value) = text("nickname") {
                add("identity.nickname", value.to_string());
            }
        }
        "community.levels" => {
            if let Some(value) = number("xpMin") {
                add("community.levels.xp_min", value.to_string());
            }
            if let Some(value) = number("xpMax") {
                add("community.levels.xp_max", value.to_string());
            }
            if let Some(value) = number("cooldownSeconds") {
                add("community.levels.cooldown_seconds", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("voiceXpEnabled"))
                .and_then(serde_json::Value::as_bool)
            {
                add("community.levels.voice_xp_enabled", value.to_string());
            }
            if let Some(value) = number("voiceXpPerMinute") {
                add("community.levels.voice_xp_per_minute", value.to_string());
            }
            if let Some(values) = object
                .and_then(|values| values.get("ignoredChannels"))
                .and_then(serde_json::Value::as_array)
            {
                add(
                    "community.levels.ignored_channels",
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            if let Some(values) = object
                .and_then(|values| values.get("levelRoles"))
                .and_then(serde_json::Value::as_array)
            {
                add(
                    "community.levels.level_roles",
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            if let Some(value) = text("announceChannel") {
                add("community.levels.announce_channel", value.to_string());
            }
            if let Some(value) = text("announceTemplate") {
                add("community.levels.announce_template", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("stackRoles"))
                .and_then(serde_json::Value::as_bool)
            {
                add("community.levels.stack_roles", value.to_string());
            }
        }
        "support.welcome" => {
            if let Some(value) = text("channel") {
                add("support.welcome.channel_id", value.to_string());
            }
            if let Some(value) = text("message") {
                add("support.welcome.message", value.to_string());
            }
            if let Some(value) = object
                .and_then(|values| values.get("sendDm"))
                .and_then(serde_json::Value::as_bool)
            {
                add("support.welcome.send_dm", value.to_string());
            }
            if let Some(value) = text("dmMessage") {
                add("support.welcome.dm_message", value.to_string());
            }
            if let Some(value) = text("autoRole") {
                add("support.welcome.auto_role", value.to_string());
            }
        }
        _ => {}
    }
    pairs
}

fn validate_feature_config(key: &str, config: &serde_json::Value) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    if !config.is_object() {
        issues.push(ValidationIssue {
            path: "config".into(),
            code: "object_required".into(),
            message: "A configuração tem de ser um objeto.".into(),
            severity: "error".into(),
        });
        return issues;
    }
    if config.to_string().len() > 64 * 1024 {
        issues.push(ValidationIssue {
            path: "config".into(),
            code: "too_large".into(),
            message: "A configuração excede o limite de 64 KiB.".into(),
            severity: "error".into(),
        });
    }
    if key == "management.nickname" && feature_adapter(key).is_none() {
        match config.get("nickname").and_then(serde_json::Value::as_str) {
            Some(value) if value.chars().count() <= 32 && !value.chars().any(char::is_control) => {}
            Some(_) => issues.push(ValidationIssue {
                path: "nickname".into(),
                code: "invalid_nickname".into(),
                message:
                    "O nickname tem de ter no máximo 32 caracteres e não pode conter controlos."
                        .into(),
                severity: "error".into(),
            }),
            None => issues.push(ValidationIssue {
                path: "nickname".into(),
                code: "required".into(),
                message: "Indica o nickname do Helper.".into(),
                severity: "error".into(),
            }),
        }
    }
    if key != "protection.antispam" {
        for (name, min, max) in [
            ("threshold", 1_i64, 100_i64),
            ("joinThreshold", 1, 10_000),
            ("windowSeconds", 1, 86_400),
            ("minimumAccountDays", 0, 365),
            ("floodCount", 3, 30),
            ("duplicateLimit", 2, 12),
            ("timeoutSeconds", 0, 86_400),
            ("mentionLimit", 1, 30),
            ("xpMin", 1, 1_000),
            ("xpMax", 1, 2_000),
            ("cooldownSeconds", 0, 3_600),
        ] {
            if let Some(value) = config.get(name).and_then(serde_json::Value::as_i64)
                && !(min..=max).contains(&value)
            {
                issues.push(ValidationIssue {
                    path: name.into(),
                    code: "out_of_range".into(),
                    message: format!("O valor tem de estar entre {min} e {max}."),
                    severity: "error".into(),
                });
            }
        }
    }
    if let Some(adapter) = feature_adapter(key) {
        issues.extend(adapter.validate(config));
    }
    if key == "community.levels"
        && let (Some(minimum), Some(maximum)) = (
            config.get("xpMin").and_then(serde_json::Value::as_i64),
            config.get("xpMax").and_then(serde_json::Value::as_i64),
        )
        && minimum > maximum
    {
        issues.push(ValidationIssue {
            path: "xpMax".into(),
            code: "xp_range_reversed".into(),
            message: "O XP máximo tem de ser igual ou superior ao mínimo.".into(),
            severity: "error".into(),
        });
    }
    issues
}

fn lifecycle_issues_legacy(maturity: FeatureMaturity) -> Vec<ValidationIssue> {
    if maturity == FeatureMaturity::Blocked {
        return vec![ValidationIssue {
            path: "feature".into(),
            code: "official_integration_required".into(),
            message: "This integration is blocked until an official provider, valid credentials, and the required legal review are available.".into(),
            severity: "info".into(),
        }];
    }
    Vec::new()
}

fn lifecycle_issues(key: &str, maturity: FeatureMaturity) -> Vec<ValidationIssue> {
    if maturity != FeatureMaturity::Blocked {
        return Vec::new();
    }
    let message = match key {
        "social.instagram" => {
            "Blocked until a Meta app, professional account OAuth grant, App Review and deletion callbacks are configured."
        }
        "social.tiktok" => {
            "Blocked until TikTok Display API review is approved and a creator authorizes the required scopes."
        }
        "social.kick" => {
            "Blocked until an approved Kick developer app and official webhook/API access are available."
        }
        "growth.monetization" => {
            "Blocked until Stripe Connect onboarding, KYC, tax, refunds and chargeback support are approved."
        }
        "web3.gas_tracker" => {
            "Blocked until an approved RPC endpoint and network allow-list are configured."
        }
        "web3.gating" => {
            "Blocked until SIWE domain/session settings, RPC endpoints and an approved contract allow-list are configured."
        }
        _ => {
            "Blocked until an official provider, valid credentials and the required legal/security review are available."
        }
    };
    let mut issues = lifecycle_issues_legacy(maturity);
    if let Some(issue) = issues.first_mut() {
        issue.code = "dependency_required".into();
        issue.message = message.into();
    }
    issues
}

/// Provider-backed features start in the canonical `blocked` lifecycle while
/// their app review/credentials are absent. Once the server has the approved
/// official client, the panel can configure the feature in Beta instead of
/// remaining permanently hidden behind the original global allow-list.
fn provider_runtime_ready(state: &ApiState, key: &str) -> bool {
    match key {
        // Feed/provider adapters are promoted from beta only when the process
        // has the same client that the worker uses.  This keeps the catalogue
        // honest: a configured form is not enough to claim operational
        // delivery.
        "social.youtube" => state
            .youtube
            .as_ref()
            .is_some_and(YouTubeClient::is_configured),
        "social.rss" | "social.podcasts" => state.rss.is_some(),
        "social.bluesky" => state.bluesky.is_some(),
        "social.twitch" => state
            .twitch
            .as_ref()
            .is_some_and(TwitchClient::is_configured),
        "web3.gas_tracker" => !state.gas.configured_networks().is_empty(),
        "social.tiktok" => tiktok_runtime_allowed(
            tiktok_approved(),
            tiktok_sandbox_enabled(),
            TikTokOAuthClient::from_env().is_some(),
            state.tiktok.is_some(),
        ),
        "social.instagram" => {
            state
                .instagram
                .as_ref()
                .is_some_and(InstagramClient::is_configured)
                && instagram_runtime_allowed()
        }
        "social.kick" => state.kick.is_some() && kick_approved(),
        "growth.monetization" => state.stripe.is_some() && stripe_approved(),
        "web3.gating" => {
            state.siwe.as_ref().is_some_and(SiweVerifier::is_configured)
                && web3_gating_dependencies_ready()
        }
        _ => false,
    }
}

fn effective_feature_maturity(state: &ApiState, key: &str) -> FeatureMaturity {
    let maturity = feature_maturity(key);
    if provider_runtime_ready(state, key) {
        // A provider is operational only after its process client and all
        // required credentials/approvals are present.  Until then a beta
        // provider remains beta and an unapproved integration remains
        // blocked; the panel can show the exact dependency instead of a
        // misleading activation toggle.
        if matches!(maturity, FeatureMaturity::Beta | FeatureMaturity::Blocked) {
            return FeatureMaturity::Operational;
        }
    }
    maturity
}

fn feature_configurable_for(state: &ApiState, key: &str) -> bool {
    // A registered adapter means the panel has a real schema, validation,
    // preview and runtime projection.  Provider credentials and approvals
    // decide whether *enabling* the feature is allowed, not whether the
    // owner can see/configure its setup page.  Keeping these concepts
    // separate prevents the old 13/45-card regressions and gives owners an
    // actionable requirements view for every one of the 47 features.
    let _ = state;
    is_known_feature(key) && feature_adapter(key).is_some()
}

fn feature_health_status(
    state: &ApiState,
    guild_id: &str,
    key: &str,
    enabled: bool,
    maturity: FeatureMaturity,
    issues: &[ValidationIssue],
) -> &'static str {
    // `enabled` is the effective runtime state. A revision can still have
    // requested `enabled=true` while a provider is down (or while a Discord
    // dependency disappeared). Keep that distinction visible instead of
    // showing a misleading plain "disabled" badge.
    let requested_enabled = state
        .store
        .get_feature_setting(guild_id, key)
        .ok()
        .flatten()
        .is_some_and(|record| record.enabled);
    if !enabled {
        if requested_enabled
            && (maturity == FeatureMaturity::Blocked || !provider_dependencies_ready(state, key))
        {
            return "dependency_down";
        }
        return "disabled";
    }
    if maturity == FeatureMaturity::Blocked {
        return "dependency_down";
    }
    if !provider_dependencies_ready(state, key) {
        return "dependency_down";
    }
    if feature_adapter(key).is_none() {
        return "degraded";
    }
    if issues.iter().any(|issue| issue.severity == "error") {
        return "misconfigured";
    }
    "ready"
}

fn provider_dependencies_ready(state: &ApiState, key: &str) -> bool {
    match key {
        // Health must inspect the clients constructed at process start, not
        // the environment again.  This prevents the panel from claiming a
        // provider is ready after its environment changed while the worker
        // is still running with an old client (or vice versa).
        "social.youtube" => state
            .youtube
            .as_ref()
            .is_some_and(YouTubeClient::is_configured),
        "social.rss" | "social.podcasts" => state.rss.is_some(),
        "social.bluesky" => state.bluesky.is_some(),
        "social.twitch" => state
            .twitch
            .as_ref()
            .is_some_and(TwitchClient::is_configured),
        // Gas tracking is read-only but still needs at least one explicitly
        // allow-listed HTTPS RPC endpoint.  Do not report a configured card as
        // operational when the worker would have no network to poll.
        "web3.gas_tracker" => !state.gas.configured_networks().is_empty(),
        "social.tiktok" => tiktok_runtime_allowed(
            tiktok_approved(),
            tiktok_sandbox_enabled(),
            TikTokOAuthClient::from_env().is_some(),
            state.tiktok.is_some(),
        ),
        "social.instagram" => {
            state
                .instagram
                .as_ref()
                .is_some_and(InstagramClient::is_configured)
                && instagram_runtime_allowed()
        }
        "social.kick" => state.kick.is_some() && kick_approved(),
        "growth.monetization" => state.stripe.is_some() && stripe_approved(),
        "web3.gating" => {
            state.siwe.as_ref().is_some_and(SiweVerifier::is_configured)
                && web3_gating_dependencies_ready()
        }
        _ => true,
    }
}

fn provider_needs_runtime_ready(key: &str) -> bool {
    matches!(
        key,
        "social.youtube"
            | "social.rss"
            | "social.podcasts"
            | "social.twitch"
            | "social.bluesky"
            | "web3.gas_tracker"
            | "social.instagram"
            | "social.tiktok"
            | "social.kick"
            | "growth.monetization"
            | "web3.gating"
    )
}

fn web3_gating_dependencies_ready() -> bool {
    let configured_rpc = [
        "ETHEREUM_RPC_URL",
        "POLYGON_RPC_URL",
        "ARBITRUM_RPC_URL",
        "BASE_RPC_URL",
    ]
    .into_iter()
    .any(|name| {
        std::env::var(name)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
    });
    configured_rpc
        && std::env::var("SIWE_ALLOWED_CONTRACTS")
            .ok()
            .is_some_and(|value| value.split(',').any(|item| is_eth_address(item.trim())))
}

fn is_eth_address(value: &str) -> bool {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    body.is_some_and(|text| text.len() == 40 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn approved_wallet_contract(value: &str) -> bool {
    is_eth_address(value)
        && std::env::var("SIWE_ALLOWED_CONTRACTS")
            .ok()
            .is_some_and(|list| {
                list.split(',')
                    .any(|item| item.trim().eq_ignore_ascii_case(value))
            })
}

fn feature_is_operational(
    state: &ApiState,
    key: &str,
    _maturity: FeatureMaturity,
    issues: &[ValidationIssue],
) -> bool {
    // `effective_feature_maturity` is allowed to promote a globally blocked
    // provider once its official client, credentials and approvals are
    // present.  Do not re-check the static maturity here: doing so made a
    // correctly configured provider appear non-operational forever even
    // though the API had already promoted it to `operational`.
    effective_feature_maturity(state, key) != FeatureMaturity::Blocked
        && feature_adapter(key).is_some()
        && provider_dependencies_ready(state, key)
        && issues.iter().all(|issue| issue.severity != "error")
}

/// Health must reflect the same Discord checks that protect a publication.
/// Keeping this call behind the enabled guard avoids making a disabled card
/// depend on a live Discord REST request, while an enabled card can never be
/// reported as ready merely because its JSON happens to validate.
async fn feature_health_preflight(
    state: Arc<ApiState>,
    headers: HeaderMap,
    key: &str,
    config: serde_json::Value,
    enabled: bool,
) -> serde_json::Value {
    if !enabled {
        return serde_json::json!({
            "ok": true,
            "skipped": true,
            "issues": [],
            "checks": {"reason": "feature_disabled"}
        });
    }

    match feature_preflight(
        State(state),
        headers,
        Path(key.to_owned()),
        Json(FeaturePreflightRequest { config, enabled }),
    )
    .await
    {
        Ok(Json(value)) => value,
        Err((status, _)) => serde_json::json!({
            "ok": false,
            "skipped": false,
            "issues": [{
                "path": "discord.preflight",
                "code": "preflight_unavailable",
                "message": format!("Discord preflight could not be completed (HTTP {status}). Refresh the server context and try again."),
                "severity": "error"
            }],
            "checks": {"available": false}
        }),
    }
}

fn preflight_issues(value: &serde_json::Value) -> Vec<ValidationIssue> {
    value
        .get("issues")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|issue| {
            Some(ValidationIssue {
                path: issue.get("path")?.as_str()?.to_owned(),
                code: issue.get("code")?.as_str()?.to_owned(),
                message: issue.get("message")?.as_str()?.to_owned(),
                severity: issue.get("severity")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

async fn feature_detail(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let key = if key == "support.welcome_channel" {
        "support.welcome".to_string()
    } else {
        key
    };
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    let premium_required = feature_requires_premium(&key);
    let premium_unlocked = feature_premium_unlocked(&state, &claims, &key).await;
    if premium_required && !premium_unlocked {
        return Ok(Json(serde_json::json!({
            "guildId": claims.guild_id,
            "key": key,
            "enabled": false,
            "config": {},
            "defaults": feature_defaults(&key),
            "schema": feature_schema(&key),
            "revision": 0,
            "maturity": effective_feature_maturity(&state, &key),
            "configurable": feature_configurable_for(&state, &key),
            "premiumRequired": true,
            "premiumUnlocked": false,
            "schemaVersion": FEATURE_SCHEMA_VERSION,
            "health": {
                "status": "premium_required",
                "operational": false,
                "issues": [{
                    "path": "plan",
                    "code": "premium_required",
                    "message": "This feature is available with Vozen Premium on this server.",
                    "severity": "error"
                }]
            }
        })));
    }
    let stored = state
        .store
        .get_feature_setting(&claims.guild_id, &key)
        .ok()
        .flatten();
    let config = stored
        .as_ref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(&value.config_json).ok())
        .filter(|value| value.is_object())
        .or_else(|| {
            state
                .store
                .get_setting(&claims.guild_id, &feature_config_key(&key))
                .ok()
                .flatten()
                .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
                .filter(|value| value.is_object())
        })
        .unwrap_or_else(|| serde_json::json!({}));
    let maturity = effective_feature_maturity(&state, &key);
    let mut config = if key == "support.welcome" {
        state
            .store
            .welcome_configuration(&claims.guild_id)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
            .1
    } else {
        config
    };
    if key == "community.levels"
        && let Some(config) = config.as_object_mut()
    {
        config.insert("bannerEnabled".into(), serde_json::Value::Bool(true));
    }
    let mut issues = validate_feature_config(&key, &config);
    issues.extend(lifecycle_issues(&key, maturity));
    let revision = stored.as_ref().map(|value| value.revision).unwrap_or(0);
    let enabled = feature_enabled(&state, &claims.guild_id, &key);
    let adapter = feature_adapter(&key).map(|value| value.descriptor());
    let preflight = feature_health_preflight(
        state.clone(),
        headers.clone(),
        &key,
        config.clone(),
        enabled,
    )
    .await;
    let preflight_ok = preflight
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut health_issues = issues.clone();
    health_issues.extend(preflight_issues(&preflight));
    let health_status = feature_health_status(
        &state,
        &claims.guild_id,
        &key,
        enabled,
        maturity,
        &health_issues,
    );
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "key": key,
        "enabled": enabled,
        "config": config,
        "defaults": feature_defaults(&key),
        "schema": feature_schema(&key),
        "adapter": adapter.as_ref().map(|value| value.source.clone()),
        "dependencies": adapter.as_ref().map(|value| value.dependencies.clone()).unwrap_or_default(),
        "revision": revision,
        "maturity": maturity,
        "configurable": feature_configurable_for(&state, &key),
        "premiumRequired": premium_required,
        "premiumUnlocked": premium_unlocked,
        "schemaVersion": FEATURE_SCHEMA_VERSION,
        "health": {"maturity": maturity, "status": health_status, "adapter": adapter.as_ref().map(|value| value.source.clone()), "dependencies": adapter.as_ref().map(|value| value.dependencies.clone()).unwrap_or_default(), "operational": feature_is_operational(&state, &key, maturity, &health_issues) && preflight_ok, "issues": health_issues, "preflight": preflight},
    })))
}

async fn feature_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    let config = state
        .store
        .get_feature_setting(&claims.guild_id, &key)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(&value.config_json).ok())
        .filter(|value| value.is_object())
        .or_else(|| {
            state
                .store
                .get_setting(&claims.guild_id, &feature_config_key(&key))
                .ok()
                .flatten()
                .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
                .filter(|value| value.is_object())
        })
        .unwrap_or_else(|| serde_json::json!({}));
    let maturity = effective_feature_maturity(&state, &key);
    let mut issues = validate_feature_config(&key, &config);
    issues.extend(lifecycle_issues(&key, maturity));
    let enabled = feature_enabled(&state, &claims.guild_id, &key);
    let descriptor = feature_adapter(&key).map(|adapter| adapter.descriptor());
    let preflight =
        feature_health_preflight(state.clone(), headers.clone(), &key, config, enabled).await;
    let preflight_ok = preflight
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    issues.extend(preflight_issues(&preflight));
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "key": key,
        "enabled": enabled,
        "maturity": maturity,
        "status": feature_health_status(&state, &claims.guild_id, &key, enabled, maturity, &issues),
        "operational": feature_is_operational(&state, &key, maturity, &issues) && preflight_ok,
        "adapter": descriptor.as_ref().map(|value| value.source.clone()),
        "dependencies": descriptor.as_ref().map(|value| value.dependencies.clone()).unwrap_or_default(),
        "issues": issues,
        "preflight": preflight,
    })))
}

#[derive(Debug, Deserialize)]
struct FeatureDetailUpdate {
    enabled: bool,
    config: serde_json::Value,
    #[serde(default)]
    expected_revision: Option<u64>,
}

async fn apply_discord_nickname(
    state: &ApiState,
    guild_id: &str,
    nickname: &str,
) -> Result<Option<String>, String> {
    if state.discord_token.len() < 20 {
        return Err("discord_bot_unavailable".into());
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let auth = format!("Bot {}", state.discord_token);
    let bot = discord_json(&client, &auth, "/users/@me").await?;
    let bot_id = bot
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "discord_bot_identity_unavailable".to_string())?;
    let member = discord_json(
        &client,
        &auth,
        &format!("/guilds/{guild_id}/members/{bot_id}"),
    )
    .await?;
    let previous_nickname = member
        .get("nick")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let value = if nickname.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(nickname.trim().to_owned())
    };
    let response = client
        .patch(format!(
            "{DISCORD_API_BASE}/guilds/{guild_id}/members/{bot_id}"
        ))
        .header(header::AUTHORIZATION, auth)
        .json(&serde_json::json!({"nick": value}))
        .send()
        .await
        .map_err(|_| "discord_request_failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("discord_http_{}", response.status().as_u16()));
    }
    Ok(previous_nickname)
}

fn record_setup_for_enabled_feature(
    store: &Store,
    guild_id: &str,
    enabled: bool,
    now_ms: i64,
) -> Result<()> {
    if enabled {
        store.record_growth_setup_completed(guild_id, now_ms)?;
    }
    Ok(())
}

async fn update_feature_detail(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(mut update): Json<FeatureDetailUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if key == "community.levels"
        && let Some(config) = update.config.as_object_mut()
    {
        config.insert("bannerEnabled".into(), serde_json::Value::Bool(true));
    }
    let _ticket_save_guard = if key == "support.tickets" {
        Some(TICKET_PANEL_SAVE_LOCK.lock().await)
    } else {
        None
    };
    let Some(_definition) = feature_definition(&key) else {
        return Err(client_error(StatusCode::BAD_REQUEST, "unknown_feature"));
    };
    if update.enabled {
        require_feature_premium(&state, &claims, &key).await?;
    }
    if !feature_configurable_for(&state, &key) {
        return Err(client_error(
            StatusCode::NOT_IMPLEMENTED,
            "feature_not_available",
        ));
    }
    let preflight = if key == "management.nickname" {
        nickname_preflight_for_claims(
            &state,
            &claims,
            FeaturePreflightRequest {
                config: update.config.clone(),
                enabled: update.enabled,
            },
        )
        .await?
    } else if matches!(key.as_str(), "protection.antispam" | "protection.antiscam") {
        preflight(
            State(state.clone()),
            headers.clone(),
            Json(PreflightRequest {
                operation: format!("{key}.publish"),
                config: update.config.clone(),
                enabled: update.enabled,
            }),
        )
        .await?
    } else {
        generic_feature_preflight(
            State(state.clone()),
            headers.clone(),
            key.clone(),
            FeaturePreflightRequest {
                config: update.config.clone(),
                enabled: update.enabled,
            },
        )
        .await?
    };
    if !preflight
        .0
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(client_error(
            StatusCode::PRECONDITION_FAILED,
            "feature_preflight_failed",
        ));
    }
    let issues = validate_feature_config(&key, &update.config);
    if update.enabled && issues.iter().any(|issue| issue.severity == "error") {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_feature_config",
        ));
    }
    // Check the revision before touching Discord.  The store repeats this
    // check inside its transaction; this early guard avoids changing the
    // Helper nickname for a stale panel tab in the common conflict case.
    if key == "management.nickname"
        && let Some(expected_revision) = update.expected_revision
    {
        let current_revision = state
            .store
            .get_feature_setting(&claims.guild_id, &key)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
            .map(|record| record.revision)
            .unwrap_or(0);
        if current_revision != expected_revision {
            return Err(client_error(
                StatusCode::CONFLICT,
                "feature_revision_conflict",
            ));
        }
    }
    // Nickname is the one feature whose publish path has an immediate
    // external Discord mutation.  Apply it before committing the revision so
    // a Discord failure cannot leave the panel showing an active but inert
    // feature.  Keep the old value for compensation if the store rejects the
    // publish (for example because another moderator won a race).
    let previous_nickname = if key == "management.nickname" {
        let requested_nickname = update
            .config
            .get("nickname")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Some(
            apply_discord_nickname(&state, &claims.guild_id, requested_nickname)
                .await
                .map_err(|_| {
                    client_error(StatusCode::BAD_GATEWAY, "discord_nickname_apply_failed")
                })?,
        )
    } else {
        None
    };
    let youtube_subscription = if key == "social.youtube" {
        prepare_youtube_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let rss_subscription = if matches!(key.as_str(), "social.rss" | "social.podcasts") {
        prepare_rss_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let twitch_subscription = if key == "social.twitch" {
        prepare_twitch_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let bluesky_subscription = if key == "social.bluesky" {
        prepare_bluesky_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let tiktok_subscription = if key == "social.tiktok" {
        prepare_tiktok_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let instagram_subscription = if key == "social.instagram" {
        prepare_instagram_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let kick_subscription = if key == "social.kick" {
        prepare_kick_feature(&state, &claims, &update.config, update.enabled).await?
    } else {
        None
    };
    let enabled_value = if update.enabled { "true" } else { "false" };
    let mut projections = vec![
        (feature_key(&key), enabled_value.to_string()),
        (feature_config_key(&key), update.config.to_string()),
    ];
    projections.extend(runtime_projection_pairs(&key, &update.config));
    if let Some(runtime_key) = runtime_feature_key(&key) {
        projections.push((runtime_key.to_string(), enabled_value.to_string()));
    }
    let config_json = update.config.to_string();
    let publish_result = if key == "social.youtube" {
        state.store.publish_youtube_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            youtube_subscription.as_ref(),
        )
    } else if matches!(key.as_str(), "social.rss" | "social.podcasts") {
        state.store.publish_rss_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            rss_subscription.as_ref(),
        )
    } else if key == "social.twitch" {
        state.store.publish_twitch_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            twitch_subscription.as_ref(),
        )
    } else if key == "social.bluesky" {
        state.store.publish_bluesky_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            bluesky_subscription.as_ref(),
        )
    } else if key == "social.tiktok" {
        state.store.publish_tiktok_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            tiktok_subscription.as_ref(),
        )
    } else if key == "social.instagram" {
        state.store.publish_instagram_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            instagram_subscription.as_ref(),
        )
    } else if key == "social.kick" {
        state.store.publish_kick_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
            kick_subscription.as_ref(),
        )
    } else {
        state.store.publish_feature_setting(
            &claims.guild_id,
            &key,
            update.enabled,
            &config_json,
            update.expected_revision,
            &claims.user_id,
            &projections,
        )
    };
    let record = match publish_result {
        Ok(record) => record,
        Err(error) if error.to_string().starts_with("feature_revision_conflict:") => {
            if let Some(previous_nickname) = previous_nickname.as_ref() {
                let _ = apply_discord_nickname(
                    &state,
                    &claims.guild_id,
                    previous_nickname.as_deref().unwrap_or_default(),
                )
                .await;
            }
            return Err(client_error(
                StatusCode::CONFLICT,
                "feature_revision_conflict",
            ));
        }
        Err(_) => {
            if let Some(previous_nickname) = previous_nickname.as_ref() {
                let _ = apply_discord_nickname(
                    &state,
                    &claims.guild_id,
                    previous_nickname.as_deref().unwrap_or_default(),
                )
                .await;
            }
            return Err(client_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
            ));
        }
    };
    let discord_apply = if key == "management.nickname" {
        serde_json::json!({"applied": true})
    } else if key == "support.tickets" && record.enabled {
        let plan = effective_plan(&state, &claims).await;
        match ticket_panel::publish(
            &state.store,
            &state.discord_token,
            &claims.guild_id,
            &update.config,
            quota_limit(&plan, "panels"),
            DISCORD_API_BASE,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => serde_json::json!({"applied": false, "code": "ticket_panel_publish_failed"}),
        }
    } else {
        serde_json::json!(null)
    };
    record_setup_for_enabled_feature(
        &state.store,
        &claims.guild_id,
        record.enabled,
        Utc::now().timestamp_millis(),
    )
    .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(
        serde_json::json!({ "guildId": claims.guild_id, "key": key, "enabled": record.enabled, "config": update.config, "revision": record.revision, "maturity": effective_feature_maturity(&state, &key), "issues": issues, "discordApply": discord_apply }),
    ))
}

#[derive(Debug, Deserialize)]
struct FeatureTestRequest {
    config: serde_json::Value,
    #[serde(default)]
    fixture: Option<AntiSpamObservation>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    reaction_count: Option<u64>,
    #[serde(default)]
    reactor_ids: Vec<String>,
    #[serde(default)]
    author_id: Option<String>,
    #[serde(default)]
    author_role_ids: Vec<String>,
    #[serde(default)]
    has_attachments: Option<bool>,
    #[serde(default)]
    join_count: Option<u64>,
    #[serde(default)]
    account_age_days: Option<i64>,
    #[serde(default)]
    has_avatar: Option<bool>,
    #[serde(default)]
    display_name: Option<String>,
    /// Bounded embed fixture values used by the same renderer as `/embed`.
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    footer: Option<String>,
    #[serde(default, rename = "actorIsStaff")]
    actor_is_staff: Option<bool>,
    #[serde(default, rename = "tagContent")]
    tag_content: Option<String>,
    #[serde(default, rename = "userId")]
    user_id: Option<String>,
    #[serde(default, rename = "serverName")]
    server_name: Option<String>,
    #[serde(default, rename = "memberMention")]
    member_mention: Option<String>,
    /// Optional bounded rows for the leaderboard simulator. Keeping this in
    /// the shared test request lets the API exercise the same ordering and
    /// opt-out evaluator used by the Discord command.
    #[serde(default, rename = "leaderboardEntries")]
    leaderboard_entries: Vec<LeaderboardEntry>,
    /// Bounded role-panel fixture fields used by the same selection evaluator
    /// as the Discord component handler.
    #[serde(default, rename = "selectedRoleIds")]
    selected_role_ids: Vec<String>,
    #[serde(default, rename = "clickedRoleId")]
    clicked_role_id: Option<String>,
    #[serde(default, rename = "activeTempRooms")]
    active_temp_rooms: Option<u64>,
    #[serde(default, rename = "userName")]
    user_name: Option<String>,
    #[serde(default, rename = "reminderDelayMs")]
    reminder_delay_ms: Option<i64>,
    #[serde(default, rename = "reminderText")]
    reminder_text: Option<String>,
    #[serde(default, rename = "reminderRepeat")]
    reminder_repeat: Option<String>,
    #[serde(default, rename = "reminderTimezone")]
    reminder_timezone: Option<String>,
    /// Bounded poll fixture values used by the same publication evaluator as
    /// the Discord `/poll` command.
    #[serde(default)]
    question: Option<String>,
    #[serde(default)]
    options: Vec<String>,
    #[serde(default, rename = "durationMs")]
    duration_ms: Option<i64>,
    #[serde(default)]
    prize: Option<String>,
    #[serde(default)]
    winners: Option<i64>,
    #[serde(default, rename = "requiredRole")]
    required_role: Option<String>,
    /// Bounded birthday fixture values used by the same calendar and
    /// delivery evaluator as the scheduled Discord worker.
    #[serde(default, rename = "month")]
    month: Option<u32>,
    #[serde(default, rename = "day")]
    day: Option<u32>,
    #[serde(default, rename = "memberId")]
    member_id: Option<String>,
    /// Bounded native-event fixture fields used by the same schedule
    /// evaluator as the Discord event command.
    #[serde(default, rename = "eventName")]
    event_name: Option<String>,
    #[serde(default, rename = "eventLocation")]
    event_location: Option<String>,
    #[serde(default, rename = "eventStartUnix")]
    event_start_unix: Option<i64>,
    #[serde(default, rename = "eventEndUnix")]
    event_end_unix: Option<i64>,
    #[serde(default, rename = "eventNowUnix")]
    event_now_unix: Option<i64>,
    #[serde(default, rename = "eventCapacity")]
    event_capacity: Option<i64>,
    #[serde(default, rename = "destructiveActions")]
    destructive_actions: Option<u64>,
    #[serde(default, rename = "openTickets")]
    open_tickets: Option<u64>,
    /// Bounded XP fixture values used by the same message/voice evaluator as
    /// the Discord levels runtime.
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "eventId")]
    event_id: Option<String>,
    #[serde(default, rename = "cooldownReady")]
    cooldown_ready: Option<bool>,
    #[serde(default, rename = "durationMinutes")]
    duration_minutes: Option<u64>,
    #[serde(default, rename = "currentXp")]
    current_xp: Option<i64>,
    /// Bounded economy fixture values used by the same reward evaluator as
    /// the Discord economy commands.
    #[serde(default, rename = "economyAction")]
    economy_action: Option<String>,
    #[serde(default, rename = "currentBalance")]
    current_balance: Option<i64>,
    #[serde(default, rename = "rewardCooldownReady")]
    reward_cooldown_ready: Option<bool>,
    /// Bounded server-stat fixtures used by the same channel-name evaluator
    /// as the live statistics worker.
    #[serde(default, rename = "statsMessages")]
    stats_messages: Option<i64>,
    #[serde(default, rename = "statsJoins")]
    stats_joins: Option<i64>,
    #[serde(default, rename = "statsLeaves")]
    stats_leaves: Option<i64>,
    #[serde(default, rename = "statsMembers")]
    stats_members: Option<u64>,
    #[serde(default, rename = "privacyAction")]
    privacy_action: Option<String>,
    #[serde(default, rename = "inviteCount")]
    invite_count: Option<u64>,
    #[serde(default, rename = "emojiCount")]
    emoji_count: Option<u64>,
    #[serde(default, rename = "animatedEmojiCount")]
    animated_emoji_count: Option<u64>,
    #[serde(default, rename = "searchProvider")]
    search_provider: Option<String>,
    #[serde(default, rename = "searchQuery")]
    search_query: Option<String>,
}

async fn test_feature(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(test): Json<FeatureTestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _claims = require_auth(&state, &headers)?;
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    let mut issues = validate_feature_config(&key, &test.config);
    let maturity = effective_feature_maturity(&state, &key);
    issues.extend(lifecycle_issues(&key, maturity));
    if feature_adapter(&key).is_none() {
        issues.push(ValidationIssue {
            path: "feature".into(),
            code: "feature_not_operational".into(),
            message: "Esta funcionalidade ainda não tem um adaptador operacional.".into(),
            severity: "error".into(),
        });
    }
    // A provider can expose a real adapter and therefore deserve a setup page
    // in the catalogue, while still being unable to execute until its official
    // credentials/approval are present. Keep that distinction explicit in the
    // simulation: it must never report a blocked or not-yet-ready provider as
    // applicable. This mirrors publish preflight instead of claiming that a
    // valid JSON draft can already run in Discord.
    if maturity == FeatureMaturity::Blocked
        || (provider_needs_runtime_ready(&key) && !provider_runtime_ready(&state, &key))
    {
        let message = lifecycle_issues(&key, maturity)
            .into_iter()
            .find(|issue| issue.severity == "error")
            .map(|issue| issue.message)
            .unwrap_or_else(|| {
                "The official provider is not ready in this running Helper. Configure its server-side credentials and restart the Helper before enabling it.".into()
            });
        issues.push(ValidationIssue {
            path: "feature.provider".into(),
            code: "provider_not_ready".into(),
            message,
            severity: "error".into(),
        });
    }
    // The adapter owns the projection used for a preview.  The HTTP layer
    // only supplies bounded fixture data and keeps specialised evaluators
    // (anti-spam/scam) below for their detailed explanations.
    let anti_spam_fixture = test.fixture.clone().unwrap_or_else(|| AntiSpamObservation {
        channel_id: "preview-channel".into(),
        role_ids: Vec::new(),
        message_count: 6,
        duplicate_count: 3,
        mention_count: 5,
        link_count: 0,
        uppercase_letters: 0,
        letter_count: 0,
    });
    let adapter_fixture = serde_json::json!({
        "content": test.content.clone(),
        "channelId": test.channel_id.clone().unwrap_or_else(|| anti_spam_fixture.channel_id.clone()),
        "roleIds": anti_spam_fixture.role_ids.clone(),
        "messageCount": anti_spam_fixture.message_count,
        "duplicateCount": anti_spam_fixture.duplicate_count,
        "mentionCount": anti_spam_fixture.mention_count,
        "linkCount": anti_spam_fixture.link_count,
        "uppercaseLetters": anti_spam_fixture.uppercase_letters,
        "letterCount": anti_spam_fixture.letter_count,
        "reactionCount": test.reaction_count,
        "reactorIds": test.reactor_ids,
        "authorId": test.author_id.clone(),
        "authorRoleIds": test.author_role_ids,
        "hasAttachments": test.has_attachments,
        "joinCount": test.join_count,
        "accountAgeDays": test.account_age_days,
        "hasAvatar": test.has_avatar,
        "displayName": test.display_name.clone(),
        "title": test.title.clone(),
        "description": test.description.clone(),
        "color": test.color.clone(),
        "footer": test.footer.clone(),
        "actorIsStaff": test.actor_is_staff,
        "tagContent": test.tag_content.clone(),
        "userId": test.user_id.clone(),
        "serverName": test.server_name.clone(),
        "memberMention": test.member_mention.clone(),
        "leaderboardEntries": test.leaderboard_entries.clone(),
        "selectedRoleIds": test.selected_role_ids.clone(),
        "clickedRoleId": test.clicked_role_id.clone(),
        "activeTempRooms": test.active_temp_rooms,
        "userName": test.user_name.clone(),
        "delayMs": test.reminder_delay_ms,
        "reminderText": test.reminder_text.clone().or_else(|| test.content.clone()),
        "repeat": test.reminder_repeat.clone(),
        "timezone": test.reminder_timezone.clone(),
        "question": test.question.clone(),
        "options": test.options.clone(),
        "durationMs": test.duration_ms,
        "prize": test.prize.clone(),
        "winners": test.winners,
        "requiredRole": test.required_role.clone(),
        "month": test.month,
        "day": test.day,
        "memberId": test.member_id.clone(),
        "name": test.event_name.clone(),
        "location": test.event_location.clone(),
        "startUnix": test.event_start_unix,
        "endUnix": test.event_end_unix,
        "nowUnix": test.event_now_unix,
        "capacity": test.event_capacity,
        "destructiveActions": test.destructive_actions,
        "openTickets": test.open_tickets,
        "source": test.source.clone(),
        "eventId": test.event_id.clone(),
        "cooldownReady": test.cooldown_ready,
        "durationMinutes": test.duration_minutes,
        "currentXp": test.current_xp,
        "economyAction": test.economy_action.clone(),
        "currentBalance": test.current_balance,
        "rewardCooldownReady": test.reward_cooldown_ready,
        "statsMessages": test.stats_messages,
        "statsJoins": test.stats_joins,
        "statsLeaves": test.stats_leaves,
        "statsMembers": test.stats_members,
        "privacyAction": test.privacy_action.clone(),
        "inviteCount": test.invite_count,
        "emojiCount": test.emoji_count,
        "animatedEmojiCount": test.animated_emoji_count,
        "searchProvider": test.search_provider.clone(),
        "searchQuery": test.search_query.clone(),
    });
    let adapter_effects = if maturity == FeatureMaturity::Blocked {
        // A blocked provider must never claim that a JSON draft would be
        // applied. Keep the simulation useful as a readiness explanation,
        // while preserving the same validation path used by publication.
        Some(vec![
            lifecycle_issues(&key, maturity)
                .first()
                .map(|issue| issue.message.clone())
                .unwrap_or_else(|| {
                    "This provider is blocked until its official dependencies are ready.".into()
                }),
        ])
    } else if let Some(adapter) = feature_adapter(&key) {
        Some(adapter.simulate(&test.config, &adapter_fixture))
    } else {
        // A known feature without an adapter is a server defect, not a valid
        // simulation. Never fabricate an effect for a form with no runtime
        // consumer.
        issues.push(ValidationIssue {
            path: "feature".into(),
            code: "feature_not_operational".into(),
            message: "This feature has no runtime adapter in the running Helper.".into(),
            severity: "error".into(),
        });
        Some(vec![
            "Simulation unavailable: this feature has no runtime adapter.".into(),
        ])
    };
    let mut anti_spam_decision: Option<AntiSpamDecision> = None;
    let mut reminder_decision = None;
    let effects = match key.as_str() {
        "protection.antispam" => {
            let fixture = anti_spam_fixture.clone();
            let decision = evaluate_anti_spam(&anti_spam_policy_from_json(&test.config), &fixture);
            anti_spam_decision = Some(decision);
            adapter_effects.clone().unwrap_or_else(|| {
                vec!["The anti-spam adapter could not produce a preview.".into()]
            })
        }
        "protection.antiscam" => adapter_effects
            .clone()
            .unwrap_or_else(|| vec!["The anti-scam adapter could not produce a preview.".into()]),
        "protection.anti_raid" => adapter_effects
            .clone()
            .unwrap_or_else(|| vec!["The anti-raid adapter could not produce a preview.".into()]),
        "protection.join_gate" => adapter_effects
            .clone()
            .unwrap_or_else(|| vec!["The join-gate adapter could not produce a preview.".into()]),
        "community.levels" => adapter_effects
            .clone()
            .unwrap_or_else(|| vec!["Atribuir XP e verificar uma recompensa de nível".into()]),
        "support.tickets" => adapter_effects.clone().unwrap_or_else(|| {
            vec!["Criar um ticket privado com as permissões configuradas".into()]
        }),
        "community.starboard" => adapter_effects
            .clone()
            .unwrap_or_else(|| vec!["The starboard adapter could not produce a preview.".into()]),
        "management.workflows" => adapter_effects.clone().unwrap_or_else(|| {
            vec!["Executar o fluxo em modo dry-run e registar o resultado".into()]
        }),
        "utility.reminders" => {
            let policy = reminder_policy_from_json(&test.config);
            let observation = ReminderObservation {
                delay_ms: test.reminder_delay_ms.unwrap_or(600_000),
                text: test
                    .reminder_text
                    .clone()
                    .or_else(|| test.content.clone())
                    .unwrap_or_else(|| "Preview reminder".into()),
                repeat: test.reminder_repeat.clone(),
                timezone: test
                    .reminder_timezone
                    .clone()
                    .unwrap_or_else(|| policy.timezone.clone()),
            };
            let decision = evaluate_reminder(&policy, &observation);
            reminder_decision = Some(decision);
            adapter_effects
                .clone()
                .unwrap_or_else(|| vec!["The reminder adapter could not produce a preview.".into()])
        }
        // Every non-blocked catalogue entry must reach its adapter. Keep the
        // fallback as a hard failure description only for rolling upgrades;
        // never describe a generic JSON save as a runtime effect.
        _ => adapter_effects.clone().unwrap_or_else(|| {
            vec!["Simulation unavailable: no runtime adapter is registered.".into()]
        }),
    };
    let result = SimulationResult {
        key: key.clone(),
        would_apply: feature_configurable_for(&state, &key)
            && issues.iter().all(|issue| issue.severity != "error"),
        issues,
        effects,
    };
    Ok(Json(serde_json::json!({
        "ok": result.would_apply,
        "key": result.key,
        "preview": test.config,
        "mode": "simulation",
        "maturity": maturity,
        "result": result,
        "decision": anti_spam_decision,
        "reminderDecision": reminder_decision,
        "adapterEffects": adapter_effects,
    })))
}

async fn feature_revisions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    let revisions = state
        .store
        .feature_revisions(&claims.guild_id, &key, 50)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "key": key,
        "revisions": revisions,
    })))
}

#[derive(Debug, Deserialize)]
struct FeatureRollbackRequest {
    revision: u64,
    #[serde(default)]
    expected_revision: Option<u64>,
}

async fn feature_rollback(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(request): Json<FeatureRollbackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    if !feature_configurable_for(&state, &key) {
        return Err(client_error(
            StatusCode::NOT_IMPLEMENTED,
            "feature_not_available",
        ));
    }
    let Some(previous) = state
        .store
        .feature_revision(&claims.guild_id, &key, request.revision)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    else {
        return Err(client_error(StatusCode::NOT_FOUND, "revision_not_found"));
    };
    if previous.enabled {
        require_feature_premium(&state, &claims, &key).await?;
    }
    let config: serde_json::Value = serde_json::from_str(&previous.config_json)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_stored_config"))?;
    // Rollback is a mutation just like a fresh publish: re-run the same
    // guild-scoped preflight before touching either the feature setting or a
    // provider subscription. This prevents a historical revision from
    // bypassing current permissions/hierarchy checks.
    let preflight = if key == "management.nickname" {
        nickname_preflight_for_claims(
            &state,
            &claims,
            FeaturePreflightRequest {
                config: config.clone(),
                enabled: previous.enabled,
            },
        )
        .await?
    } else if matches!(key.as_str(), "protection.antispam" | "protection.antiscam") {
        preflight(
            State(state.clone()),
            headers.clone(),
            Json(PreflightRequest {
                operation: format!("{key}.rollback"),
                config: config.clone(),
                enabled: previous.enabled,
            }),
        )
        .await?
    } else {
        generic_feature_preflight(
            State(state.clone()),
            headers.clone(),
            key.clone(),
            FeaturePreflightRequest {
                config: config.clone(),
                enabled: previous.enabled,
            },
        )
        .await?
    };
    if !preflight
        .0
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(client_error(
            StatusCode::PRECONDITION_FAILED,
            "feature_preflight_failed",
        ));
    }
    let issues = validate_feature_config(&key, &config);
    if previous.enabled && issues.iter().any(|issue| issue.severity == "error") {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_stored_config",
        ));
    }
    // Provider revisions need their subscription projection restored in the
    // same transaction as feature_settings/feature_revisions. Reusing the
    // normal preparation path also validates the historical source and
    // ensures the provider is still reachable before the transaction starts.
    let youtube_subscription = if key == "social.youtube" {
        prepare_youtube_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let rss_subscription = if matches!(key.as_str(), "social.rss" | "social.podcasts") {
        prepare_rss_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let twitch_subscription = if key == "social.twitch" {
        prepare_twitch_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let bluesky_subscription = if key == "social.bluesky" {
        prepare_bluesky_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let tiktok_subscription = if key == "social.tiktok" {
        prepare_tiktok_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let instagram_subscription = if key == "social.instagram" {
        prepare_instagram_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let kick_subscription = if key == "social.kick" {
        prepare_kick_feature(&state, &claims, &config, previous.enabled).await?
    } else {
        None
    };
    let mut projections = vec![
        (
            feature_key(&key),
            if previous.enabled { "true" } else { "false" }.into(),
        ),
        (feature_config_key(&key), previous.config_json.clone()),
    ];
    projections.extend(runtime_projection_pairs(&key, &config));
    if let Some(runtime_key) = runtime_feature_key(&key) {
        projections.push((
            runtime_key.to_string(),
            if previous.enabled { "true" } else { "false" }.into(),
        ));
    }
    let publish_result = if key == "social.youtube" {
        state.store.publish_youtube_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            youtube_subscription.as_ref(),
        )
    } else if matches!(key.as_str(), "social.rss" | "social.podcasts") {
        state.store.publish_rss_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            rss_subscription.as_ref(),
        )
    } else if key == "social.twitch" {
        state.store.publish_twitch_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            twitch_subscription.as_ref(),
        )
    } else if key == "social.bluesky" {
        state.store.publish_bluesky_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            bluesky_subscription.as_ref(),
        )
    } else if key == "social.tiktok" {
        state.store.publish_tiktok_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            tiktok_subscription.as_ref(),
        )
    } else if key == "social.instagram" {
        state.store.publish_instagram_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            instagram_subscription.as_ref(),
        )
    } else if key == "social.kick" {
        state.store.publish_kick_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
            kick_subscription.as_ref(),
        )
    } else {
        state.store.publish_feature_setting(
            &claims.guild_id,
            &key,
            previous.enabled,
            &previous.config_json,
            request.expected_revision,
            &claims.user_id,
            &projections,
        )
    };
    let record = publish_result.map_err(|error| {
        if error.to_string().starts_with("feature_revision_conflict:") {
            client_error(StatusCode::CONFLICT, "feature_revision_conflict")
        } else {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
        }
    })?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "key": key,
        "enabled": record.enabled,
        "config": config,
        "revision": record.revision,
        "rolledBackFrom": request.revision,
        "issues": issues,
    })))
}

/// Rebuild the runtime projection (and any provider subscription) from the
/// currently published feature configuration.  Repair deliberately goes
/// through the normal update path so it gets the same authentication,
/// validation, preflight, revision checks and atomic provider handling as a
/// regular publish.  A successful repair therefore creates a new revision
/// instead of mutating history in place.
async fn feature_repair(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if feature_definition(&key).is_none() {
        return Err(client_error(StatusCode::NOT_FOUND, "unknown_feature"));
    }
    let Some(current) = state
        .store
        .get_feature_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    else {
        return Err(client_error(StatusCode::NOT_FOUND, "feature_not_published"));
    };
    let config = serde_json::from_str(&current.config_json)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_stored_config"))?;
    let response = update_feature_detail(
        State(state),
        headers,
        Path(key),
        Json(FeatureDetailUpdate {
            enabled: current.enabled,
            config,
            expected_revision: Some(current.revision),
        }),
    )
    .await?;
    let mut body = response.0;
    if let Some(object) = body.as_object_mut() {
        object.insert("repaired".to_string(), serde_json::Value::Bool(true));
    }
    Ok(Json(body))
}

async fn update_feature_config(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(update): Json<FeatureUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if feature_definition(&update.key).is_none() {
        return Err(client_error(StatusCode::BAD_REQUEST, "unknown_feature"));
    }
    let current = state
        .store
        .get_feature_setting(&claims.guild_id, &update.key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let observed_revision = current.as_ref().map(|record| record.revision).unwrap_or(0);
    let config_json = match current {
        Some(record) => Some(record.config_json),
        None => state
            .store
            .get_setting(&claims.guild_id, &feature_config_key(&update.key))
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
    };
    let config = match config_json {
        Some(raw) => serde_json::from_str(&raw).map_err(|_| {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_stored_config")
        })?,
        None => feature_defaults(&update.key).unwrap_or_else(|| serde_json::json!({})),
    };
    let config = if update.key == "support.welcome" {
        state
            .store
            .welcome_configuration(&claims.guild_id)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
            .1
    } else {
        config
    };
    // A toggle is a publish too: use the same validation, permissions and
    // atomic provider subscription updates as the full configuration route.
    // Bind the read to its revision even for old clients without a revision,
    // so a concurrent edit cannot be overwritten with the config read here.
    let Json(mut body) = update_feature_detail(
        State(state),
        headers,
        Path(update.key),
        Json(FeatureDetailUpdate {
            enabled: update.enabled,
            config,
            expected_revision: Some(update.expected_revision.unwrap_or(observed_revision)),
        }),
    )
    .await?;
    body["ok"] = serde_json::Value::Bool(true);
    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    limit: Option<u32>,
}
async fn cases(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let list = state
        .store
        .recent_cases(&claims.guild_id, query.limit.unwrap_or(50).min(200))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({"cases":list})))
}

async fn audit(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let list = state
        .store
        .recent_audit_events(&claims.guild_id, query.limit.unwrap_or(50).min(200))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "events": list,
    })))
}

async fn activity(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let list = state
        .store
        .recent_activity(&claims.guild_id, query.limit.unwrap_or(50).min(200))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "activity": list,
    })))
}

async fn stats(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let cases = state
        .store
        .recent_cases(&claims.guild_id, 200)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let storage = state.store.storage_metrics();
    Ok(Json(serde_json::json!({
        "totalCases": cases.len(),
        "guildId": claims.guild_id,
        "storage": storage,
        "activeSessions": null,
        "activeServers": []
    })))
}

async fn leaderboard_member_names(
    base: &str,
    token: &str,
    guild_id: &str,
    entries: &[LeaderboardEntry],
) -> BTreeMap<String, String> {
    let ids = entries
        .iter()
        .filter(|entry| !entry.opted_out)
        .take(100)
        .map(|entry| entry.user_id.clone())
        .collect::<Vec<_>>();
    discord_member_names(base, token, guild_id, &ids).await
}

async fn discord_member_names(
    base: &str,
    token: &str,
    guild_id: &str,
    ids: &[String],
) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    let Some(guild_id) = guild_id.parse::<u64>().ok().filter(|id| *id > 0) else {
        return names;
    };
    let Ok(client) = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(3))
        .build()
    else {
        return names;
    };
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    for user_id in ids.iter().take(100) {
        let Some(id) = user_id.parse::<u64>().ok().filter(|id| *id > 0) else {
            continue;
        };
        let user_id = user_id.clone();
        let url = format!("{base}/guilds/{guild_id}/members/{id}");
        let auth = format!("Bot {token}");
        let base = base.to_owned();
        let client = client.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await.ok()?;
            let member = match discord_read::get_json(&client, &auth, &url).await {
                Ok(member) => member,
                Err(error) if error == "discord_http_404" => {
                    let user =
                        discord_read::get_json(&client, &auth, &format!("{base}/users/{id}"))
                            .await
                            .ok()?;
                    serde_json::json!({"user":user})
                }
                Err(_) => return None,
            };
            [
                member.get("nick"),
                member.pointer("/user/global_name"),
                member.pointer("/user/username"),
            ]
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .find(|name| !name.is_empty())
            .map(|name| (user_id, name.chars().take(80).collect::<String>()))
        });
    }
    // Missing members or a slow Discord API must not hide the saved XP ranking.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while let Ok(Some(result)) = tokio::time::timeout_at(deadline, tasks.join_next()).await {
        if let Ok(Some((id, name))) = result {
            names.insert(id, name);
        }
    }
    names
}

async fn leaderboard(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let setting = |key: &str| {
        state
            .store
            .get_setting(&claims.guild_id, key)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))
    };
    let policy = leaderboard_policy_from_json(&serde_json::json!({
        "maxEntries": setting("community.leaderboard.max_entries")?
            .and_then(|value| value.parse::<u64>().ok()).unwrap_or(10),
        "public": setting("community.leaderboard.public")?
            .and_then(|value| value.parse::<bool>().ok()).unwrap_or(true),
    }));
    let enabled = feature_enabled(&state, &claims.guild_id, "community.leaderboard");
    let mut entries = Vec::new();
    if enabled {
        // Match the command's bounded input before applying privacy and ranking.
        let rows = state
            .store
            .top_levels(&claims.guild_id, 100)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
        for row in rows {
            let opted_out = setting(&format!("community.leaderboard.optout.{}", row.user_id))?
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(false);
            entries.push(LeaderboardEntry {
                user_id: row.user_id,
                xp: row.xp,
                opted_out,
            });
        }
    }
    let decision = evaluate_leaderboard(&policy, entries);
    let names = leaderboard_member_names(
        DISCORD_API_BASE,
        &state.discord_token,
        &claims.guild_id,
        &decision.entries,
    )
    .await;
    let entries: Vec<_> = decision
        .entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let mut value =
                serde_json::json!({"userId": entry.user_id, "xp": entry.xp, "rank": index + 1});
            if let Some(name) = names.get(&entry.user_id) {
                value["displayName"] = serde_json::json!(name);
            }
            value
        })
        .collect();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id, "enabled": enabled, "public": decision.public,
        "maxEntries": policy.max_entries, "entries": entries,
    })))
}

async fn tickets(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let list = state
        .store
        .tickets_for_guild(&claims.guild_id, query.limit.unwrap_or(50).min(200))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "tickets": list}),
    ))
}

async fn quotas(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let plan = effective_plan(&state, &claims).await;
    let keys = [
        "panels",
        "forms",
        "role_panels",
        "workflows",
        "workflow_runs",
        "feeds",
        "templates",
        "analytics_days",
        "audit_days",
        "transcript_days",
        "personal_drafts",
        "personal_views",
        "personal_templates",
    ];
    let limits = keys
        .into_iter()
        .map(|key| (key, quota_limit(&plan, key)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let usage = std::collections::BTreeMap::from([
        (
            "panels",
            state
                .store
                .count_settings_prefix(&claims.guild_id, "support.panel.")
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
        ),
        (
            "role_panels",
            state
                .store
                .count_settings_prefix(&claims.guild_id, "community.role_panel.")
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
        ),
        (
            "workflows",
            state
                .store
                .workflows(&claims.guild_id, u32::MAX)
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
                .len() as u64,
        ),
        (
            "templates",
            state
                .store
                .count_settings_prefix(&claims.guild_id, TEMPLATE_PREFIX)
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
        ),
    ]);
    Ok(Json(serde_json::json!({
        "plan": plan,
        "guildLimit": plan.guild_limit(),
        "limits": limits,
        "usage": usage,
    })))
}

async fn effective_plan(state: &ApiState, claims: &SessionClaims) -> Plan {
    if let Some(client) = &state.entitlements
        && let Ok(snapshot) = client
            .resolve(&claims.user_id, Some(&claims.guild_id))
            .await
        && snapshot.active
        && snapshot
            .expires_at
            .is_none_or(|expires_at| expires_at > Utc::now())
    {
        return snapshot.plan;
    }
    state
        .store
        .load_entitlement(&claims.user_id)
        .ok()
        .flatten()
        .filter(|snapshot| {
            snapshot.active
                && snapshot
                    .expires_at
                    .is_none_or(|expires_at| expires_at > Utc::now())
        })
        .map(|snapshot| snapshot.plan)
        .unwrap_or(Plan::Free)
}

async fn modules(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = require_auth(&state, &headers)?;
    let modules = [
        ("core", Capability::Core),
        ("studio", Capability::Studio),
        ("security", Capability::Security),
        ("support", Capability::Support),
        ("events", Capability::Events),
        ("community", Capability::Community),
        ("automate", Capability::Automate),
        ("insights", Capability::Insights),
    ];
    Ok(Json(serde_json::json!({
        "modules": modules.into_iter().map(|(name, _)| name).collect::<Vec<_>>()
    })))
}

#[derive(Debug, Serialize, Deserialize)]
struct BrandKit {
    primary_color: String,
    secondary_color: String,
    logo_url: Option<String>,
    font: String,
}

fn default_brand_kit() -> BrandKit {
    BrandKit {
        primary_color: "#5865F2".into(),
        secondary_color: "#2B2D31".into(),
        logo_url: None,
        font: "system".into(),
    }
}

fn valid_hex_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
}

fn parse_brand_kit(value: Option<String>) -> BrandKit {
    value
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(default_brand_kit)
}

const TEMPLATE_PREFIX: &str = "studio.template.";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StudioTemplate {
    id: String,
    name: String,
    description: String,
    modules: Vec<String>,
    config: serde_json::Value,
    version: u64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct StudioTemplateInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    modules: Vec<String>,
    #[serde(default = "default_template_config")]
    config: serde_json::Value,
    /// Optional optimistic-concurrency token for edits made in the panel.
    /// Older clients may omit it; new clients can prevent a stale tab from
    /// silently overwriting a newer template revision.
    #[serde(default, rename = "expectedVersion")]
    expected_version: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct StudioTemplateRollbackInput {
    revision: u64,
    #[serde(default, rename = "expectedVersion")]
    expected_version: Option<u64>,
}

fn default_template_config() -> serde_json::Value {
    serde_json::json!({})
}

fn valid_template_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn validate_template_input(input: &StudioTemplateInput) -> bool {
    let valid_modules = [
        "core",
        "studio",
        "security",
        "support",
        "events",
        "community",
        "automate",
        "insights",
    ];
    let name_len = input.name.trim().chars().count();
    let description_len = input.description.chars().count();
    name_len > 0
        && name_len <= 80
        && description_len <= 500
        && input.modules.len() <= valid_modules.len()
        && input
            .modules
            .iter()
            .all(|module| valid_modules.contains(&module.as_str()))
        && input.config.is_object()
        && serde_json::to_vec(&input.config)
            .map(|bytes| bytes.len() <= 32 * 1024)
            .unwrap_or(false)
}

fn template_key(id: &str) -> String {
    format!("{TEMPLATE_PREFIX}{id}")
}

fn parse_template(raw: &str) -> Option<StudioTemplate> {
    serde_json::from_str(raw).ok()
}

fn template_from_input(id: String, input: StudioTemplateInput, now: String) -> StudioTemplate {
    StudioTemplate {
        id,
        name: input.name.trim().to_string(),
        description: input.description.trim().to_string(),
        modules: input.modules,
        config: input.config,
        version: 1,
        created_at: now.clone(),
        updated_at: now,
    }
}

async fn studio_templates(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let templates = state
        .store
        .settings_with_prefix(&claims.guild_id, TEMPLATE_PREFIX)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .filter_map(|(_, value)| parse_template(&value))
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "templates": templates,
    })))
}

async fn studio_template(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if !valid_template_id(&id) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_template_id"));
    }
    let template = state
        .store
        .get_setting(&claims.guild_id, &template_key(&id))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .and_then(|value| parse_template(&value))
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_not_found"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "template": template,
    })))
}

async fn studio_template_revisions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if !valid_template_id(&id) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_template_id"));
    }
    let revisions = state
        .store
        .studio_template_revisions(&claims.guild_id, &id, 50)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "templateId": id,
        "revisions": revisions,
    })))
}

async fn create_studio_template(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<StudioTemplateInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.templates").await?;
    if !validate_template_input(&input) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_template"));
    }
    let plan = effective_plan(&state, &claims).await;
    let id = Uuid::new_v4().simple().to_string();
    let now = Utc::now().to_rfc3339();
    let template = template_from_input(id.clone(), input, now);
    let value = serde_json::to_string(&template)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error"))?;
    let inserted = state
        .store
        .insert_studio_template(
            &claims.guild_id,
            &template_key(&id),
            &value,
            TEMPLATE_PREFIX,
            quota_limit(&plan, "templates"),
            &template.id,
            &claims.user_id,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !inserted {
        return Err(client_error(
            StatusCode::TOO_MANY_REQUESTS,
            "template_quota_exceeded",
        ));
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"guildId": claims.guild_id, "template": template})),
    ))
}

async fn update_studio_template(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<StudioTemplateInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.templates").await?;
    if !valid_template_id(&id) || !validate_template_input(&input) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_template"));
    }
    let key = template_key(&id);
    let current_raw = state
        .store
        .get_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_not_found"))?;
    let current = parse_template(&current_raw)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_not_found"))?;
    if input
        .expected_version
        .is_some_and(|expected| expected != current.version)
    {
        return Err(client_error(
            StatusCode::CONFLICT,
            "template_revision_conflict",
        ));
    }
    let now = Utc::now().to_rfc3339();
    let template = StudioTemplate {
        id,
        name: input.name.trim().to_string(),
        description: input.description.trim().to_string(),
        modules: input.modules,
        config: input.config,
        version: current.version.saturating_add(1),
        created_at: current.created_at,
        updated_at: now,
    };
    let replacement = serde_json::to_string(&template)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error"))?;
    let replaced = state
        .store
        .compare_and_swap_studio_template(
            &claims.guild_id,
            &key,
            &current_raw,
            &replacement,
            &template.id,
            template.version,
            &claims.user_id,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !replaced {
        return Err(client_error(
            StatusCode::CONFLICT,
            "template_revision_conflict",
        ));
    }
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "template": template,
    })))
}

async fn rollback_studio_template(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<StudioTemplateRollbackInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.templates").await?;
    if !valid_template_id(&id) || input.revision == 0 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "invalid_template_revision",
        ));
    }
    let key = template_key(&id);
    let current_raw = state
        .store
        .get_setting(&claims.guild_id, &key)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_not_found"))?;
    let current = parse_template(&current_raw)
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_not_found"))?;
    if input
        .expected_version
        .is_some_and(|expected| expected != current.version)
    {
        return Err(client_error(
            StatusCode::CONFLICT,
            "template_revision_conflict",
        ));
    }
    let snapshot = state
        .store
        .studio_template_revision(&claims.guild_id, &id, input.revision)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::NOT_FOUND, "template_revision_not_found"))?;
    let mut restored = parse_template(&snapshot.template_json).ok_or_else(|| {
        client_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_template_revision",
        )
    })?;
    restored.id = id.clone();
    restored.version = current.version.saturating_add(1);
    restored.created_at = current.created_at;
    restored.updated_at = Utc::now().to_rfc3339();
    let replacement = serde_json::to_string(&restored)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error"))?;
    let replaced = state
        .store
        .compare_and_swap_studio_template(
            &claims.guild_id,
            &key,
            &current_raw,
            &replacement,
            &restored.id,
            restored.version,
            &claims.user_id,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !replaced {
        return Err(client_error(
            StatusCode::CONFLICT,
            "template_revision_conflict",
        ));
    }
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "template": restored,
        "restoredRevision": input.revision,
    })))
}

async fn delete_studio_template(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if !valid_template_id(&id) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_template_id"));
    }
    let deleted = state
        .store
        .delete_setting(&claims.guild_id, &template_key(&id))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(StatusCode::NOT_FOUND, "template_not_found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn studio_brand(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let brand = parse_brand_kit(
        state
            .store
            .get_setting(&claims.guild_id, "studio.brand_kit")
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
    );
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "brand": brand}),
    ))
}

async fn update_studio_brand(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(brand): Json<BrandKit>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if !valid_hex_color(&brand.primary_color)
        || !valid_hex_color(&brand.secondary_color)
        || !matches!(
            brand.font.as_str(),
            "system" | "inter" | "roboto" | "poppins"
        )
        || brand
            .logo_url
            .as_deref()
            .is_some_and(|url| !url.starts_with("https://") || url.len() > 2_048)
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_brand_kit"));
    }
    state
        .store
        .set_setting(
            &claims.guild_id,
            "studio.brand_kit",
            &serde_json::to_string(&brand).map_err(|_| {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error")
            })?,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(
        serde_json::json!({"guildId": claims.guild_id, "brand": brand}),
    ))
}

const RANK_CARD_SETTING: &str = "community.rank_card";

fn valid_rank_card_hex(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
}

fn valid_rank_card_preset(value: Option<&str>) -> bool {
    value.is_none_or(|preset| {
        RANK_CARD_BACKGROUND_PRESETS
            .iter()
            .any(|(id, _)| *id == preset)
    })
}

fn valid_rank_card_config(config: &RankCardConfig) -> bool {
    matches!(
        config.font.as_str(),
        "system" | "inter" | "roboto" | "poppins" | "space_grotesk" | "lexend"
    ) && valid_rank_card_hex(&config.primary_color)
        && valid_rank_card_hex(&config.text_color)
        && valid_rank_card_hex(&config.background_color)
        && valid_rank_card_hex(&config.avatar_ring_color)
        && config.overlay_opacity.is_finite()
        && (0.0..=0.85).contains(&config.overlay_opacity)
        && config.avatar_ring_width <= 8
        && valid_rank_card_preset(config.background_preset.as_deref())
        // Custom image input is deliberately disabled. This keeps the
        // feature a curated catalogue and avoids server-owner liability for
        // member-provided offensive or infringing artwork.
        && config.background_url.is_none()
        && config.background_data.is_none()
}

fn parse_rank_card(value: Option<String>) -> RankCardConfig {
    value
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .filter(valid_rank_card_config)
        .unwrap_or_default()
}

async fn studio_rank_card(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let config = parse_rank_card(
        state
            .store
            .get_setting(&claims.guild_id, RANK_CARD_SETTING)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?,
    );
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "config": config,
        "backgroundPresets": RANK_CARD_BACKGROUND_PRESETS
            .iter()
            .map(|(id, label)| serde_json::json!({"id": id, "label": label}))
            .collect::<Vec<_>>(),
    })))
}

async fn update_studio_rank_card(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(config): Json<RankCardConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "studio.rank_card").await?;
    if !valid_rank_card_config(&config) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_rank_card"));
    }
    let value = serde_json::to_string(&config)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error"))?;
    state
        .store
        .set_setting(&claims.guild_id, RANK_CARD_SETTING, &value)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "config": config,
    })))
}

async fn permissions(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = require_auth(&state, &headers)?;
    Ok(Json(permission_passport_document()))
}

async fn security_health(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let guild_id = &claims.guild_id;
    let setting = |key: &str| {
        state
            .store
            .get_setting(guild_id, key)
            .ok()
            .flatten()
            .unwrap_or_else(|| "false".into())
    };
    let mut findings = Vec::new();
    let mut penalty = 0_u64;
    for (key, label, severity, points, remediation) in [
        (
            "security.anti_raid.enabled",
            "Anti-raid desativado",
            "high",
            25,
            "Ativa anti-raid com /anti-raid e testa primeiro em shadow mode.",
        ),
        (
            "security.anti_nuke.enabled",
            "Anti-nuke desativado",
            "high",
            25,
            "Ativa anti-nuke com limiar conservador e mantém revisão humana.",
        ),
        (
            "security.join_gate.enabled",
            "Join gate desativado",
            "medium",
            15,
            "Configura um cargo de verificação e ativa o join gate.",
        ),
    ] {
        let value = setting(key);
        if value != "true" {
            penalty += points;
            findings.push(serde_json::json!({
                "id": key,
                "label": label,
                "severity": severity,
                "points": points,
                "evidence": {"setting": key, "value": value},
                "remediation": remediation
            }));
        }
    }
    let shadow_mode = setting("security.shadow_mode") == "true";
    if shadow_mode {
        findings.push(serde_json::json!({
            "id": "security.shadow_mode",
            "label": "Shadow mode ativo",
            "severity": "info",
            "points": 0,
            "evidence": {"setting": "security.shadow_mode", "value": "true"},
            "remediation": "Desativa depois de rever falsos positivos e confirmar a política."
        }));
    }
    Ok(Json(serde_json::json!({
        "version": 1,
        "guildId": guild_id,
        "score": 100_u64.saturating_sub(penalty),
        "findings": findings,
        "method": "deterministic_settings_v1",
        "limitations": ["Discord role hierarchy, channel overwrites and backup restore require a live diagnostic check"]
    })))
}

fn permission_passport_document() -> serde_json::Value {
    serde_json::json!({
        "permissions": [
            {
                "key": "VIEW_CHANNEL",
                "scope": "base",
                "modules": ["Core", "Support", "Events", "Community"],
                "risk": "low",
                "data": "channel visibility and metadata",
                "missingConsequence": "the Helper cannot inspect or respond in that channel"
            },
            {
                "key": "SEND_MESSAGES",
                "scope": "base",
                "modules": ["Core", "Support", "Events", "Community"],
                "risk": "low",
                "data": "bot responses and operational notices",
                "missingConsequence": "the Helper can detect a flow but cannot notify members"
            },
            {
                "key": "READ_MESSAGE_HISTORY",
                "scope": "base",
                "modules": ["Core", "Support", "Insights"],
                "risk": "low",
                "data": "message history needed for transcripts and context",
                "missingConsequence": "transcripts and historical context are incomplete"
            },
            {
                "key": "EMBED_LINKS",
                "scope": "base",
                "modules": ["Studio", "Support", "Events", "Community"],
                "risk": "low",
                "data": "formatted embeds and previews",
                "missingConsequence": "messages fall back to plain text"
            },
            {
                "key": "MANAGE_MESSAGES",
                "scope": "optional",
                "modules": ["Security"],
                "risk": "medium",
                "data": "message deletion for configured moderation actions",
                "missingConsequence": "purge and delete-based enforcement remain unavailable"
            },
            {
                "key": "MODERATE_MEMBERS",
                "scope": "optional",
                "modules": ["Security"],
                "risk": "high",
                "data": "timeouts and moderation cases",
                "missingConsequence": "timeout enforcement is unavailable; cases remain auditable"
            },
            {
                "key": "MANAGE_ROLES",
                "scope": "optional",
                "modules": ["Security", "Community", "Events"],
                "risk": "high",
                "data": "join-gate, self-roles and temporary event roles",
                "missingConsequence": "role assignment and quarantine restoration are unavailable"
            },
            {
                "key": "MANAGE_CHANNELS",
                "scope": "optional",
                "modules": ["Support", "Events"],
                "risk": "high",
                "data": "private ticket channels and temporary event channels",
                "missingConsequence": "ticket and temporary-channel workflows are unavailable"
            },
            {
                "key": "MESSAGE_CONTENT_INTENT",
                "scope": "gateway",
                "modules": ["Security", "Automate", "Insights"],
                "risk": "high",
                "data": "message content for bounded rules and workflows",
                "missingConsequence": "content-based detection runs in degraded mode"
            },
            {
                "key": "GUILD_MEMBERS_INTENT",
                "scope": "gateway",
                "modules": ["Security", "Community"],
                "risk": "high",
                "data": "member joins, leaves and account-age checks",
                "missingConsequence": "join-gate and member lifecycle features are incomplete"
            }
        ]
    })
}

async fn analytics(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let days = query.limit.unwrap_or(30).clamp(1, 365);
    let rows = state
        .store
        .stats_for(&claims.guild_id, days)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let cases = state
        .store
        .recent_cases(&claims.guild_id, 200)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "days": rows,
        "totalCases": cases.len(),
    })))
}

async fn privacy_export(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    if !feature_enabled(&state, &claims.guild_id, "management.privacy") {
        return Err(client_error(StatusCode::FORBIDDEN, "feature_disabled"));
    }
    let export = state
        .store
        .export_guild(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(export))
}

async fn privacy_receipt(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    // The receipt is a safety and transparency endpoint, not a guild feature
    // toggle. It must remain readable even before a manager enables the
    // optional export/delete workflows.
    Ok(Json(serde_json::json!({
        "version": 1,
        "source": "helper_runtime_metadata_v1",
        "guildId": claims.guild_id,
        "intents": [
            {"key": "GUILDS", "purpose": "guild and channel metadata"},
            {"key": "GUILD_MEMBERS", "purpose": "joins, leaves, join-gate and anti-raid"},
            {"key": "MESSAGE_CONTENT", "purpose": "bounded moderation and message workflows"},
            {"key": "AUTO_MODERATION_EXECUTION", "purpose": "audit Discord AutoMod outcomes"},
            {"key": "GUILD_MODERATION", "purpose": "destructive-action Audit Log guard"}
        ],
        "persistedFields": [
            "guild-scoped settings", "moderation cases", "aggregate daily stats",
            "ticket metadata", "workflow definitions and run metadata", "quota counters",
            "managed guild metadata scoped to the session"
        ],
        "notPersistedByDefault": ["message bodies", "Discord tokens", "OAuth client secrets", "session cookies"],
        "retention": {
            "analyticsDays": 30,
            "auditDays": 30,
            "transcriptDays": 30,
            "configuration": "until changed or guild purge"
        },
        "subprocessors": [],
        "lastPurgeAt": null,
        "exportEndpoint": "/api/privacy/export",
        "deleteEndpoint": "/api/privacy/delete"
    })))
}

#[derive(Debug, Deserialize)]
struct PrivacyDeleteRequest {
    confirmation: String,
}

async fn privacy_delete(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<PrivacyDeleteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // Destructive privacy operations must not be authorisable by the ambient
    // SameSite=None session cookie; require an explicit bearer token to limit
    // cross-site request-forgery impact.
    let bearer_present = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| !value.trim().is_empty());
    if !bearer_present {
        return Err(client_error(StatusCode::UNAUTHORIZED, "bearer_required"));
    }
    let claims = require_auth(&state, &headers)?;
    if !feature_enabled(&state, &claims.guild_id, "management.privacy") {
        return Err(client_error(StatusCode::FORBIDDEN, "feature_disabled"));
    }
    if request.confirmation.trim() != claims.guild_id {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
        ));
    }
    state
        .store
        .purge_guild(&claims.guild_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "guildId": claims.guild_id,
        "deleted": "guild_operational_data"
    })))
}

async fn import_config(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(document): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let summary = state
        .store
        .import_guild_config(&claims.guild_id, &document)
        .map_err(|error| {
            let code = error.to_string();
            let invalid = [
                "invalid_target_guild",
                "config_too_large",
                "invalid_config_document",
                "unsupported_config_version",
                "invalid_settings",
                "invalid_tags",
                "invalid_workflows",
                "config_limits_exceeded",
                "invalid_setting_key",
                "invalid_setting_value",
                "invalid_setting_bounds",
                "secret_setting_rejected",
                "invalid_tag_name",
                "invalid_tag_content",
                "invalid_tag_author",
                "invalid_tag_bounds",
                "invalid_workflow_name",
                "invalid_workflow_trigger",
                "invalid_workflow_action",
                "invalid_workflow_payload",
                "unsupported_workflow",
            ];
            if invalid.contains(&code.as_str()) {
                client_error(StatusCode::BAD_REQUEST, "invalid_config_import")
            } else {
                client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
            }
        })?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "guildId": claims.guild_id,
        "imported": summary,
    })))
}

#[derive(Debug, Deserialize)]
struct WorkflowRequest {
    name: String,
    trigger: String,
    condition: Option<String>,
    action: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct WorkflowUpdateRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct CustomCommandRequest {
    name: String,
    content: String,
}

fn normalize_custom_command_name(raw: &str) -> Option<String> {
    let name = raw.trim().to_ascii_lowercase();
    if !(1..=32).contains(&name.len())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    Some(name)
}

fn custom_command_limits(state: &ApiState, guild_id: &str) -> (u32, usize) {
    let read_u64 = |key: &str, fallback: u64| {
        state
            .store
            .get_setting(guild_id, key)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback)
    };
    (
        read_u64("management.custom_commands.max_tags", 100).clamp(1, 100) as u32,
        read_u64("management.custom_commands.max_response_length", 1_000).clamp(1, 2_000) as usize,
    )
}

fn workflow_limits(state: &ApiState, guild_id: &str, plan: &Plan) -> (u64, u64, usize) {
    let read_u64 = |key: &str, fallback: u64| {
        state
            .store
            .get_setting(guild_id, key)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback)
    };
    let plan_limit = quota_limit(plan, "workflows");
    let configured_limit = read_u64("management.workflows.max_workflows", plan_limit).clamp(1, 100);
    let max_reply_length =
        read_u64("management.workflows.max_reply_length", 1_000).clamp(1, 1_500) as usize;
    (
        plan_limit,
        plan_limit.min(configured_limit),
        max_reply_length,
    )
}

fn custom_command_error(code: &'static str) -> (StatusCode, Json<ApiError>) {
    client_error(StatusCode::BAD_REQUEST, code)
}

async fn custom_commands(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let (limit, max_response_length) = custom_command_limits(&state, &claims.guild_id);
    let commands = state
        .store
        .list_tag_records(&claims.guild_id, limit)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "enabled": feature_enabled(&state, &claims.guild_id, "management.custom_commands"),
        "limit": limit,
        "maxResponseLength": max_response_length,
        "commands": commands,
    })))
}

async fn save_custom_command(
    state: &ApiState,
    claims: &SessionClaims,
    request: CustomCommandRequest,
    expected_name: Option<&str>,
) -> Result<helper_store::TagRecord, (StatusCode, Json<ApiError>)> {
    if !feature_enabled(state, &claims.guild_id, "management.custom_commands") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    let name = normalize_custom_command_name(&request.name)
        .ok_or_else(|| custom_command_error("invalid_custom_command_name"))?;
    if expected_name.is_some_and(|expected| expected != name) {
        return Err(custom_command_error("custom_command_name_mismatch"));
    }
    let (limit, max_response_length) = custom_command_limits(state, &claims.guild_id);
    let content = request.content.trim().to_string();
    if content.is_empty() || content.chars().count() > max_response_length {
        return Err(custom_command_error("invalid_custom_command_content"));
    }
    let existing = state
        .store
        .get_tag(&claims.guild_id, &name)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if existing.is_none()
        && state
            .store
            .list_tags(&claims.guild_id, limit.saturating_add(1))
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
            .len()
            >= limit as usize
    {
        return Err(client_error(
            StatusCode::TOO_MANY_REQUESTS,
            "custom_command_limit_reached",
        ));
    }
    state
        .store
        .upsert_tag(&claims.guild_id, &name, &content, &claims.user_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        "custom_command_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"upsert","name":name}).to_string(),
    );
    state
        .store
        .get_tag(&claims.guild_id, &name)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .ok_or_else(|| client_error(StatusCode::INTERNAL_SERVER_ERROR, "custom_command_missing"))
}

async fn create_custom_command(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<CustomCommandRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let command = save_custom_command(&state, &claims, request, None).await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"command": command})),
    ))
}

async fn update_custom_command(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(request): Json<CustomCommandRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let expected_name = normalize_custom_command_name(&name)
        .ok_or_else(|| custom_command_error("invalid_custom_command_name"))?;
    if state
        .store
        .get_tag(&claims.guild_id, &expected_name)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .is_none()
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "custom_command_not_found",
        ));
    }
    let command = save_custom_command(&state, &claims, request, Some(&expected_name)).await?;
    Ok(Json(serde_json::json!({"command": command})))
}

async fn delete_custom_command(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    if !feature_enabled(&state, &claims.guild_id, "management.custom_commands") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    let name = normalize_custom_command_name(&name)
        .ok_or_else(|| custom_command_error("invalid_custom_command_name"))?;
    let deleted = state
        .store
        .delete_tag(&claims.guild_id, &name)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "custom_command_not_found",
        ));
    }
    let _ = state.store.record_activity(
        &claims.guild_id,
        "custom_command_config",
        &claims.user_id,
        None,
        Some(&claims.user_id),
        &serde_json::json!({"operation":"delete","name":name}).to_string(),
    );
    Ok(Json(serde_json::json!({"ok": true, "name": name})))
}

async fn workflows(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    let plan = effective_plan(&state, &claims).await;
    let (plan_limit, max_workflows, max_reply_length) =
        workflow_limits(&state, &claims.guild_id, &plan);
    let rows = state
        .store
        .workflows(&claims.guild_id, 100)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    Ok(Json(serde_json::json!({
        "guildId": claims.guild_id,
        "enabled": feature_enabled(&state, &claims.guild_id, "management.workflows"),
        "planLimit": plan_limit,
        "maxWorkflows": max_workflows,
        "maxReplyLength": max_reply_length,
        "workflows": rows,
    })))
}

async fn create_workflow(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<WorkflowRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.workflows").await?;
    if !feature_enabled(&state, &claims.guild_id, "management.workflows") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    let plan = effective_plan(&state, &claims).await;
    let (_, workflow_limit, max_reply_length) = workflow_limits(&state, &claims.guild_id, &plan);
    let payload = request.payload.trim();
    let payload_is_valid = match request.action.as_str() {
        "reply" => (1..=max_reply_length).contains(&payload.len()),
        "react" => is_valid_workflow_reaction(payload),
        _ => false,
    };
    if !(1..=50).contains(&request.name.trim().len())
        || request.trigger != "message"
        || !payload_is_valid
        || request.condition.as_deref().unwrap_or_default().len() > 200
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_workflow"));
    }
    let Some(id) = state
        .store
        .create_workflow_bounded(
            &claims.guild_id,
            request.name.trim(),
            &request.trigger,
            request.condition.as_deref().unwrap_or_default(),
            &request.action,
            payload,
            workflow_limit,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    else {
        return Err(client_error(
            StatusCode::TOO_MANY_REQUESTS,
            "workflow_quota_exceeded",
        ));
    };
    Ok((StatusCode::CREATED, Json(serde_json::json!({"id": id}))))
}

async fn update_workflow(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<WorkflowUpdateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.workflows").await?;
    if !feature_enabled(&state, &claims.guild_id, "management.workflows") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    if id <= 0 {
        return Err(client_error(StatusCode::BAD_REQUEST, "workflow_not_found"));
    }
    let updated = state
        .store
        .set_workflow_enabled(&claims.guild_id, id, request.enabled)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !updated {
        return Err(client_error(StatusCode::NOT_FOUND, "workflow_not_found"));
    }
    Ok(Json(
        serde_json::json!({"ok": true, "id": id, "enabled": request.enabled}),
    ))
}

async fn delete_workflow(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    require_feature_premium(&state, &claims, "management.workflows").await?;
    if !feature_enabled(&state, &claims.guild_id, "management.workflows") {
        return Err(client_error(StatusCode::CONFLICT, "feature_disabled"));
    }
    let deleted = state
        .store
        .delete_workflow(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    if !deleted {
        return Err(client_error(StatusCode::NOT_FOUND, "workflow_not_found"));
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn premium_server_status(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Json<helper_modules::PremiumSeats>, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    premium_request_limit(&claims.user_id)?;
    let client = state
        .entitlements
        .as_ref()
        .ok_or_else(|| client_error(StatusCode::SERVICE_UNAVAILABLE, "premium_unavailable"))?;
    client
        .premium_seats(&claims.user_id, &claims.guild_id, false)
        .await
        .map(Json)
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "premium_unavailable"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PremiumActivationRequest {
    guild_id: String,
}

async fn premium_server_activate(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(input): Json<PremiumActivationRequest>,
) -> Result<Json<helper_modules::PremiumSeats>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    premium_request_limit(&claims.user_id)?;
    // Bind the confirmation to the server the person saw, even if another tab changed session.
    if input.guild_id != claims.guild_id {
        return Err(client_error(StatusCode::CONFLICT, "guild_changed"));
    }
    let central = state
        .entitlements
        .as_ref()
        .ok_or_else(|| client_error(StatusCode::SERVICE_UNAVAILABLE, "premium_unavailable"))?;
    // Recheck current Discord permissions rather than trusting the login-time guild list.
    let http = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "discord_unavailable"))?;
    let auth = format!("Bot {}", state.discord_token);
    let guild = discord_json(&http, &auth, &format!("/guilds/{}", claims.guild_id))
        .await
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "discord_unavailable"))?;
    if guild.get("owner_id").and_then(serde_json::Value::as_str) != Some(claims.user_id.as_str()) {
        let member = discord_json(
            &http,
            &auth,
            &format!("/guilds/{}/members/{}", claims.guild_id, claims.user_id),
        )
        .await
        .map_err(|_| client_error(StatusCode::FORBIDDEN, "guild_not_managed"))?;
        let roles = discord_json(&http, &auth, &format!("/guilds/{}/roles", claims.guild_id))
            .await
            .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "discord_unavailable"))?;
        let member_roles: Vec<String> = member
            .get("roles")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
        let permissions = roles
            .as_array()
            .and_then(|roles| effective_bot_permissions(&claims.guild_id, roles, &member_roles))
            .unwrap_or(0);
        if permissions & (8 | 32) == 0 {
            return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
        }
    }
    central
        .premium_seats(&claims.user_id, &claims.guild_id, true)
        .await
        .map(Json)
        .map_err(|_| client_error(StatusCode::CONFLICT, "premium_activation_failed"))
}

fn premium_request_limit(user: &str) -> Result<(), (StatusCode, Json<ApiError>)> {
    static REQUESTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (i64, u32)>>,
    > = std::sync::OnceLock::new();
    let now = Utc::now().timestamp();
    let mut requests = REQUESTS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "premium_unavailable"))?;
    requests.retain(|_, (start, _)| now.saturating_sub(*start) < 60);
    if requests.len() >= 4096 && !requests.contains_key(user) {
        return Err(client_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    let (_, count) = requests.entry(user.to_owned()).or_insert((now, 0));
    if *count >= 10 {
        return Err(client_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    *count += 1;
    Ok(())
}

fn require_auth(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<SessionClaims, (StatusCode, Json<ApiError>)> {
    authenticate(state, headers)
        .ok_or_else(|| client_error(StatusCode::UNAUTHORIZED, "unauthenticated"))
}

/// State-changing browser requests must prove they came from the configured
/// panel origin when authentication is carried by the ambient session cookie.
/// API clients using an explicit Bearer token remain usable without an Origin
/// header because browsers do not attach that credential automatically.
fn require_mutation_auth(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<SessionClaims, (StatusCode, Json<ApiError>)> {
    let bearer_present = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| !value.trim().is_empty());
    let claims = require_auth(state, headers)?;
    if bearer_present {
        return Ok(claims);
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !state
        .allowed_origin
        .as_deref()
        .is_some_and(|allowed| origin.is_some_and(|value| origin_allowed(allowed, value)))
    {
        return Err(client_error(StatusCode::FORBIDDEN, "csrf_origin_invalid"));
    }
    Ok(claims)
}
fn origin_allowed(allowed: &str, origin: &str) -> bool {
    allowed.split(',').any(|value| value.trim() == origin)
}
fn cookie_domain(state: &ApiState) -> &'static str {
    if state.oauth_redirect_uri.contains(".vozen.org") {
        " Domain=.vozen.org;"
    } else {
        ""
    }
}
fn authenticate(state: &ApiState, headers: &HeaderMap) -> Option<SessionClaims> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(|value| {
                    value
                        .split(';')
                        .find_map(|item| item.trim().strip_prefix("vh_session="))
                })
        });
    raw.and_then(|token| verify_session(token, &state.session_secret))
        .and_then(|signed| {
            let mut persisted = state.store.load_session(signed.session_id).ok().flatten()?;
            let now = Utc::now();
            if persisted.user_id != signed.user_id
                || persisted.guild_id != signed.guild_id
                || persisted.expires_at.timestamp() != signed.expires_at.timestamp()
                || persisted.expires_at <= now
                || persisted.last_seen_at + Duration::minutes(IDLE_MINUTES) <= now
            {
                return None;
            }
            if persisted.last_seen_at + Duration::minutes(1) <= now
                && !state.store.touch_session(persisted.session_id, now).ok()?
            {
                return None;
            }
            persisted.last_seen_at = now;
            Some(persisted)
        })
}

fn sign_session(claims: &SessionClaims, secret: &str) -> String {
    let payload = format!(
        "{}.{}.{}.{}",
        claims.session_id,
        claims.user_id,
        claims.guild_id,
        claims.expires_at.timestamp()
    );
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts every key length");
    mac.update(payload.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
fn verify_session(token: &str, secret: &str) -> Option<SessionClaims> {
    let (payload, signature) = token.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&payload);
    mac.verify_slice(&signature).ok()?;
    let values: Vec<&str> = std::str::from_utf8(&payload).ok()?.split('.').collect();
    if values.len() != 4 {
        return None;
    }
    Some(SessionClaims {
        session_id: Uuid::parse_str(values[0]).ok()?,
        user_id: values[1].into(),
        guild_id: values[2].into(),
        issued_at: Utc::now(),
        expires_at: chrono::DateTime::from_timestamp(values[3].parse().ok()?, 0)?,
        last_seen_at: Utc::now(),
    })
}
fn sign_oauth_state(payload: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts every key length");
    mac.update(payload.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
fn verify_oauth_state(token: &str, secret: &str) -> Option<String> {
    let (payload, signature) = token.split_once('.')?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&payload_bytes);
    mac.verify_slice(&signature).ok()?;
    String::from_utf8(payload_bytes).ok()
}
fn has_manage_permission(value: &str) -> bool {
    value
        .parse::<u64>()
        .map(|bits| bits & (1 << 5) != 0 || bits & (1 << 3) != 0)
        .unwrap_or(false)
}

fn is_discord_snowflake(value: &str) -> bool {
    (17..=22).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn client_error(status: StatusCode, code: &str) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            code: code.into(),
            message: code.into(),
            request_id: None,
        }),
    )
}

pub async fn serve(bind_addr: &str, state: ApiState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "helper api listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ticket_staff_notification_preflight_checks_role_and_mention_permission() {
        let roles = vec![serde_json::json!({"id":"9","mentionable":false,"position":100})];
        let config = serde_json::json!({"staffRole":"9"});
        let issues = ticket_staff_notification_issues("1", &config, &roles, 0);
        assert_eq!(issues[0].code, "staff_role_not_mentionable");
        assert_eq!(issues[0].severity, "warning");
        assert!(ticket_staff_notification_issues("1", &config, &roles, 1 << 17).is_empty());
        assert!(ticket_staff_notification_issues("1", &config, &roles, 1 << 3).is_empty());
        let mentionable = vec![serde_json::json!({"id":"9","mentionable":true})];
        assert!(ticket_staff_notification_issues("1", &config, &mentionable, 0).is_empty());
        assert_eq!(
            ticket_staff_notification_issues(
                "1",
                &serde_json::json!({"staffRole":"1"}),
                &roles,
                u64::MAX
            )[0]
            .severity,
            "error"
        );
        assert_eq!(
            ticket_staff_notification_issues("1", &serde_json::json!({"staffRole":""}), &roles, 0)
                [0]
            .code,
            "staff_role_missing"
        );
        assert_eq!(
            ticket_staff_notification_issues("1", &serde_json::json!({}), &roles, 0)[0].code,
            "staff_role_missing"
        );
    }
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use helper_store::Store;
    use tower::ServiceExt;

    #[test]
    fn setup_growth_only_marks_an_enabled_valid_feature() {
        let store = Store::open(":memory:").expect("open test store");
        let now = 1_800_000_000_000_i64;
        store.record_growth_join("guild", now).unwrap();

        record_setup_for_enabled_feature(&store, "guild", false, now + 1).unwrap();
        let before = store
            .growth_overview("2027-01-01", "2027-12-31", now + 1)
            .unwrap();
        assert_eq!(before.configured_guilds, 0);

        record_setup_for_enabled_feature(&store, "guild", true, now + 2).unwrap();
        let after = store
            .growth_overview("2027-01-01", "2027-12-31", now + 2)
            .unwrap();
        assert_eq!(after.configured_guilds, 1);
    }

    #[test]
    fn helper_growth_payload_matches_the_shared_aggregate_contract() {
        let overview = helper_store::GrowthOverview {
            active_guilds: 4,
            configured_guilds: 3,
            used_guilds: 2,
            joins: 2,
            leaves: 1,
            net: 1,
            setup_rate: 0.75,
            activation_rate: 0.5,
            retained_w7_count: 1,
            eligible_w7: 2,
            retained_w30_count: 0,
            eligible_w30: 1,
            retained_w7: Some(0.5),
            retained_w30: Some(0.0),
            measurement_started_on: Some("2026-08-28".into()),
            daily: Vec::new(),
        };
        let daily = vec![serde_json::json!({
            "day": "2026-09-04",
            "source": "helper-hero",
            "joins": 2,
            "leaves": 1,
            "setupCompleted": 1,
            "firstValue": 1,
            "active": 2,
            "votes": 0,
        })];
        let payload = helper_growth_admin_payload(&overview, daily, None);

        assert_eq!(payload["product"], "helper");
        assert_eq!(payload["currentGuilds"], 4);
        assert_eq!(payload["baselineGuilds"], 0);
        assert_eq!(payload["measurementStartedOn"], "2026-08-28");
        assert_eq!(payload["configuredGuilds"], 3);
        assert_eq!(payload["usedGuilds"], 2);
        assert_eq!(payload["retainedW7"], 1);
        assert_eq!(payload["eligibleW7"], 2);
        assert_eq!(payload["retainedW30"], 0);
        assert_eq!(payload["eligibleW30"], 1);
        assert_eq!(payload["retainedW7Rate"], 0.5);
        assert_eq!(payload["retainedW30Rate"], 0.0);
        assert_eq!(payload["votes"], 0);
        assert_eq!(payload["daily"][0]["votes"], 0);
        let encoded = serde_json::to_string(&payload).expect("json");
        assert!(!encoded.contains("guildId"));
        assert!(!encoded.contains("userId"));
    }

    #[test]
    fn helper_growth_route_rejects_a_mismatched_product() {
        assert!(valid_helper_growth_product(None));
        assert!(valid_helper_growth_product(Some("helper")));
        assert!(!valid_helper_growth_product(Some("tts")));
        assert!(!valid_helper_growth_product(Some("")));
    }

    #[test]
    fn topgg_owner_payload_alerts_on_staleness_or_more_than_five_percent_drift() {
        let healthy = TopggSyncStatus {
            last_attempt_at: 1_000,
            last_success_at: Some(1_000),
            last_status: Some(204),
            last_server_count: Some(100),
            last_detail: helper_store::TopggSyncDetail::Delivered,
            consecutive_failures: 0,
            stale: false,
        };
        let boundary = topgg_admin_payload(Some(healthy), 105).expect("payload");
        assert_eq!(boundary["alert"], false);
        assert_eq!(boundary["driftPercent"], serde_json::json!(0.05));

        let drifted = topgg_admin_payload(Some(healthy), 106).expect("payload");
        assert_eq!(drifted["alert"], true);
        assert_eq!(drifted["lastDetail"], "delivered");

        let reduced = topgg_admin_payload(Some(healthy), 50).expect("payload");
        assert_eq!(reduced["driftPercent"], serde_json::json!(0.5));
        assert_eq!(reduced["alert"], true);

        let stale = TopggSyncStatus {
            stale: true,
            ..healthy
        };
        assert_eq!(
            topgg_admin_payload(Some(stale), 100).unwrap()["alert"],
            true
        );
    }

    #[test]
    fn instagram_development_mode_only_bypasses_the_external_approval_gate() {
        assert!(instagram_access_allowed(true, false));
        assert!(instagram_access_allowed(false, true));
        assert!(instagram_access_allowed(true, true));
        assert!(!instagram_access_allowed(false, false));
    }

    #[test]
    fn first_party_helper_redirect_uses_cookie_transport() {
        let redirect = url::Url::parse("https://vozen.org/panel/helper-tracker/").unwrap();
        assert!(oauth_redirect_uses_cookie_session(&redirect));

        let slashless = url::Url::parse("https://vozen.org/panel/helper-tracker").unwrap();
        assert!(oauth_redirect_uses_cookie_session(&slashless));
    }

    #[test]
    fn other_oauth_redirects_keep_the_legacy_fragment_transport() {
        for redirect in [
            "http://vozen.org/panel/helper/",
            "https://api.vozen.org/panel/helper/",
            "https://vozen.org/panel/helper/?next=1",
            "https://vozen.org/panel/helper-tracker/?next=1",
            "https://vozen.org/panel/helper-tracker/#/config/protection.antispam",
            "https://vozen.org/account",
        ] {
            assert!(
                !oauth_redirect_uses_cookie_session(&url::Url::parse(redirect).unwrap()),
                "{redirect} must not opt into the cookie-only transport"
            );
        }
    }

    #[test]
    fn account_handoff_checks_bot_presence_only_for_manageable_guilds() {
        let guilds = manageable_guilds(vec![
            DiscordGuild {
                id: "member-only".into(),
                name: "Member-only server".into(),
                permissions: Some("0".into()),
            },
            DiscordGuild {
                id: "managed".into(),
                name: "Managed server".into(),
                permissions: Some((1_u64 << 5).to_string()),
            },
            DiscordGuild {
                id: "administrator".into(),
                name: "Administrator server".into(),
                permissions: Some((1_u64 << 3).to_string()),
            },
        ]);

        assert_eq!(
            guilds
                .iter()
                .map(|guild| guild.id.as_str())
                .collect::<Vec<_>>(),
            vec!["managed", "administrator"]
        );
    }

    #[test]
    fn private_tracker_identity_requires_the_dedicated_application_and_owner() {
        assert!(is_private_tracker_identity(
            "1534014665187655760",
            "1523489275155583056",
            "1534014665187655760",
            "1523489275155583056",
        ));
        assert!(!is_private_tracker_identity(
            "1534014665187655760",
            "1523489275155583056",
            "another-application",
            "1523489275155583056",
        ));
        assert!(!is_private_tracker_identity(
            "1534014665187655760",
            "1523489275155583056",
            "1534014665187655760",
            "another-user",
        ));
    }

    #[tokio::test]
    async fn private_tracker_session_is_hidden_until_its_identity_is_configured() {
        let store = Store::open(":memory:").expect("in-memory store");
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/admin/private-tracker/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"token":"not-used"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn private_tracker_handoff_is_hidden_until_its_identity_is_configured() {
        let store = Store::open(":memory:").expect("in-memory store");
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/admin/private-tracker/handoff")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("token=not-used"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn temp_category_creation_checks_auth_origin_scope_and_input() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        store
            .set_setting("guild-a", "utility.temp_channels.category_id", "existing")
            .unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        for (cookie, origin, body, expected) in [
            (
                false,
                None,
                r#"{"name":"voice-rooms","guildId":"guild-a"}"#,
                StatusCode::UNAUTHORIZED,
            ),
            (
                true,
                None,
                r#"{"name":"voice-rooms","guildId":"guild-a"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some("https://evil.test"),
                r#"{"name":"voice-rooms","guildId":"guild-a"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"voice-rooms","guildId":"guild-b"}"#,
                StatusCode::CONFLICT,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"../bad","guildId":"guild-a"}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"voice-rooms","guildId":"guild-a","permission_overwrites":[]}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"voice-rooms","guildId":"guild-a","moderatorRoleIds":["other"]}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"voice-rooms","guildId":"guild-a"}"#,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let mut api_state = state(store.clone());
            api_state.allowed_origin = Some("https://vozen.org".into());
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/temp-channels/category")
                .header(header::CONTENT_TYPE, "application/json");
            if cookie {
                request = request.header(header::COOKIE, format!("vh_session={token}"));
            }
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let response = router(api_state)
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        assert!(
            store
                .get_setting("guild-a", "utility.temp_channels.created_category")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_setting("guild-b", "utility.temp_channels.created_category")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_setting("guild-a", "utility.temp_channels.category_id")
                .unwrap()
                .as_deref(),
            Some("existing")
        );
    }

    #[tokio::test]
    async fn channel_creation_checks_session_origin_and_input_before_discord() {
        for endpoint in [
            "/api/tickets/channel",
            "/api/tickets/category",
            "/api/birthdays/channel",
            "/api/economy/channel?guildId=guild-a",
        ] {
            let store = Store::open(":memory:").unwrap();
            let session = claims("guild-a");
            let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
            store.save_session(&session).unwrap();
            for (cookie, origin, body, expected) in [
                (
                    false,
                    None,
                    r#"{"name":"tickets"}"#,
                    StatusCode::UNAUTHORIZED,
                ),
                (true, None, r#"{"name":"tickets"}"#, StatusCode::FORBIDDEN),
                (
                    true,
                    Some("https://evil.test"),
                    r#"{"name":"tickets"}"#,
                    StatusCode::FORBIDDEN,
                ),
                (
                    true,
                    Some("https://vozen.org"),
                    r#"{"name":"../bad"}"#,
                    StatusCode::BAD_REQUEST,
                ),
                (
                    true,
                    Some("https://vozen.org"),
                    r#"{"name":"tickets","guildId":"other"}"#,
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    true,
                    Some("https://vozen.org"),
                    r#"{"name":"tickets","moderatorRoleIds":["arbitrary"]}"#,
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    true,
                    Some("https://vozen.org"),
                    r#"{"name":"tickets"}"#,
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
            ] {
                let mut api_state = state(store.clone());
                api_state.allowed_origin = Some("https://vozen.org".into());
                let mut request = Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header(header::CONTENT_TYPE, "application/json");
                if cookie {
                    request = request.header(header::COOKIE, format!("vh_session={token}"));
                }
                if let Some(origin) = origin {
                    request = request.header(header::ORIGIN, origin);
                }
                let response = router(api_state)
                    .oneshot(request.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected, "{cookie} {origin:?} {body}");
            }
            assert!(
                store
                    .get_setting("guild-a", "support.tickets.created_panel_channel")
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .get_setting("guild-a", "support.ticket.panel_channel_id")
                    .unwrap()
                    .is_none()
            );
            for key in [
                "community.birthdays.created_channel",
                "community.birthdays.channel_id",
                "community.economy.created_channel",
                "community.economy.staff_channel",
            ] {
                assert!(store.get_setting("guild-a", key).unwrap().is_none());
            }
            assert!(
                store
                    .get_setting("guild-a", "support.tickets.created_category")
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn starboard_creation_checks_session_origin_and_input_before_discord() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        for (cookie, origin, body, expected) in [
            (
                false,
                None,
                r#"{"name":"starboard"}"#,
                StatusCode::UNAUTHORIZED,
            ),
            (true, None, r#"{"name":"starboard"}"#, StatusCode::FORBIDDEN),
            (
                true,
                Some("https://evil.test"),
                r#"{"name":"starboard"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"../bad"}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"starboard","guildId":"other"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                true,
                Some("https://vozen.org"),
                r#"{"name":"starboard"}"#,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let mut api_state = state(store.clone());
            api_state.allowed_origin = Some("https://vozen.org".into());
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/starboard/channel")
                .header(header::CONTENT_TYPE, "application/json");
            if cookie {
                request = request.header(header::COOKIE, format!("vh_session={token}"));
            }
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let response = router(api_state)
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{cookie} {origin:?} {body}");
        }
        assert!(
            store
                .get_setting("guild-a", "community.starboard.created_channel")
                .unwrap()
                .is_none()
        );
    }

    pub(super) fn state(store: Store) -> ApiState {
        ApiState {
            store,
            discord_token: "test-token".into(),
            session_secret: "test-session-secret-with-at-least-32-bytes".into(),
            oauth_client_id: "client".into(),
            oauth_client_secret: "secret".into(),
            oauth_redirect_uri: "https://example.test/callback".into(),
            oauth_success_redirect: "https://example.test/".into(),
            trusted_vozen_oauth_client_id: None,
            private_tracker_client_id: None,
            private_tracker_owner_id: None,
            allow_legacy_session: false,
            allowed_origin: None,
            entitlements: None,
            youtube: None,
            rss: None,
            twitch: None,
            bluesky: Some(BlueskyClient::new()),
            tiktok: TikTokClient::from_env(),
            instagram: InstagramClient::from_env(),
            kick: KickClient::from_env(),
            stripe: StripeConnectClient::from_env(),
            siwe: SiweVerifier::from_env(),
            coingecko: Some(CoinGeckoClient::new()),
            gas: GasClient::new(),
        }
    }

    fn claims(guild_id: &str) -> SessionClaims {
        let now = Utc::now();
        SessionClaims {
            session_id: Uuid::new_v4(),
            user_id: "user-1".into(),
            guild_id: guild_id.into(),
            issued_at: now,
            expires_at: now + Duration::hours(1),
            last_seen_at: now,
        }
    }

    fn grant_premium(store: &Store, session: &SessionClaims) {
        let mut entitlement = helper_contracts::EntitlementSnapshot::free(session.user_id.clone());
        entitlement.plan = Plan::Premium { guild_limit: 1 };
        store.save_entitlement(&entitlement).unwrap();
    }

    #[test]
    fn preflight_does_not_require_assignable_support_or_filter_roles() {
        let roles = vec![
            serde_json::json!({"id":"guild", "position":0}),
            serde_json::json!({"id":"bot-role", "position":5}),
            serde_json::json!({"id":"admin-role", "position":10}),
            serde_json::json!({"id":"managed-role", "position":2, "managed":true}),
        ];
        let references = BTreeSet::from([
            ("staffRole".into(), "admin-role".into()),
            ("requiredRole".into(), "managed-role".into()),
            ("ignoredRoles[0]".into(), "admin-role".into()),
        ]);
        assert!(
            role_hierarchy_issues("guild", &["bot-role".into()], &roles, &references).is_empty()
        );
        for (path, id) in [
            ("autoRole", "admin-role"),
            ("verifiedRole", "managed-role"),
            ("levelRoles[0]", "admin-role"),
            ("roleIds[0]", "guild"),
        ] {
            assert_eq!(
                role_hierarchy_issues(
                    "guild",
                    &["bot-role".into()],
                    &roles,
                    &BTreeSet::from([(path.into(), id.into())])
                )
                .len(),
                1,
                "{path}"
            );
        }
    }

    #[test]
    fn preflight_collects_array_resources_and_level_reward_roles() {
        let config = serde_json::json!({
            "roleIds": ["111111111111111111", "222222222222222222"],
            "ignoredChannels": ["333333333333333333"],
            "levelRoles": ["5=444444444444444444", "10=555555555555555555"]
        });
        let mut channels = BTreeSet::new();
        let mut roles = BTreeSet::new();
        collect_configured_resources(&config, "", &mut channels, &mut roles);
        collect_level_reward_roles(&config, &mut roles);

        assert!(channels.contains(&("ignoredChannels[0]".into(), "333333333333333333".into())));
        assert!(roles.contains(&("roleIds[0]".into(), "111111111111111111".into())));
        assert!(roles.contains(&("roleIds[1]".into(), "222222222222222222".into())));
        assert!(roles.contains(&("levelRoles[0]".into(), "444444444444444444".into())));
        assert!(roles.contains(&("levelRoles[1]".into(), "555555555555555555".into())));
    }

    #[test]
    fn preflight_ignored_channels_do_not_require_delivery_permissions() {
        let snapshot = DiscordGuildSnapshot {
            bot_user_id: Some("bot".into()),
            bot_role_ids: vec!["bot-role".into()],
            channels: vec![serde_json::json!({
                "id": "123",
                "permission_overwrites": [{"id":"guild", "type":0, "allow":"0", "deny":"2048"}]
            })],
            ..Default::default()
        };
        let dependencies = vec!["send_messages".into()];
        for path in ["ignoredChannels[0]", "rules[0].ignoredChannels[1]"] {
            assert!(
                channel_dependency_issues(
                    "guild",
                    &snapshot,
                    2048,
                    &dependencies,
                    &BTreeSet::from([(path.into(), "123".into())]),
                )
                .is_empty(),
                "{path} is an exclusion, not a destination"
            );
        }
        // The very same channel still needs permission when used for delivery.
        for path in ["channelId", "logChannel", "targetChannelId"] {
            let issues = channel_dependency_issues(
                "guild",
                &snapshot,
                2048,
                &dependencies,
                &BTreeSet::from([(path.into(), "123".into())]),
            );
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].code, "missing_channel_permission");
        }
    }

    #[tokio::test]
    async fn rss_health_and_test_routes_require_a_session() {
        let store = Store::open(":memory:").expect("in-memory store");
        let app = router(state(store));
        for path in ["/api/config/rss/1/health", "/api/config/rss/1/test"] {
            let method = if path.ends_with("/test") {
                http::Method::POST
            } else {
                http::Method::GET
            };
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"feed_url":"https://example.com/feed.xml","target_channel_id":"123456789012345","message_template":"{title}","mention":"","interval_seconds":300,"enabled":true}"#,
                ))
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[tokio::test]
    async fn youtube_health_and_test_routes_require_a_session() {
        let store = Store::open(":memory:").expect("in-memory store");
        let app = router(state(store));
        for path in ["/api/config/youtube/1/health", "/api/config/youtube/1/test"] {
            let method = if path.ends_with("/test") {
                http::Method::POST
            } else {
                http::Method::GET
            };
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"source_channel_id":"UC12345678901234567890","target_channel_id":"123456789012345","message_template":"{title}","mention":"","interval_seconds":300,"enabled":true}"#,
                ))
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[tokio::test]
    async fn twitch_health_and_test_routes_require_a_session() {
        let store = Store::open(":memory:").expect("in-memory store");
        let app = router(state(store));
        for path in ["/api/config/twitch/1/health", "/api/config/twitch/1/test"] {
            let method = if path.ends_with("/test") {
                http::Method::POST
            } else {
                http::Method::GET
            };
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"sourceLogin":"vozen","targetChannelId":"123456789012345","messageTemplate":"{broadcaster} is live","mention":"","enabled":true}"#,
                ))
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[tokio::test]
    async fn tiktok_test_route_requires_a_session() {
        let store = Store::open(":memory:").expect("in-memory store");
        let app = router(state(store));
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/config/tiktok/1/test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"username":"vozen","targetChannelId":"123456789012345","messageTemplate":"{title}","mention":"","intervalSeconds":900,"enabled":true}"#,
            ))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn twitch_test_delivery_maps_provider_errors_without_leaking_bodies() {
        assert_eq!(
            super::twitch_provider_error_code("twitch_api_error:429"),
            "twitch_rate_limited"
        );
        assert_eq!(
            super::twitch_provider_error_code("twitch_auth_error:401"),
            "twitch_auth_failed"
        );
        assert_eq!(
            super::twitch_provider_error_code("request failed with secret"),
            "twitch_provider_unavailable"
        );
    }

    #[test]
    fn youtube_test_delivery_maps_provider_errors_without_leaking_bodies() {
        assert_eq!(
            super::youtube_provider_error_code("youtube_api_error:429"),
            "youtube_rate_limited"
        );
        assert_eq!(
            super::youtube_provider_error_code("youtube_api_error:404"),
            "youtube_channel_not_found"
        );
        assert_eq!(
            super::youtube_provider_error_code("request failed with secret"),
            "youtube_provider_unavailable"
        );
    }

    #[test]
    fn rss_test_delivery_rejects_private_or_invalid_channel_before_discord() {
        assert_eq!(
            super::rss_provider_error_code("rss_http_error:429"),
            "rss_rate_limited"
        );
        assert_eq!(
            super::rss_provider_error_code("rss_private_host"),
            "invalid_rss_url"
        );
    }

    #[test]
    fn permission_passport_combines_everyone_and_bot_roles() {
        let roles = vec![
            serde_json::json!({"id":"guild-a","permissions":"1024"}),
            serde_json::json!({"id":"role-bot","permissions":"2048"}),
            serde_json::json!({"id":"role-other","permissions":"4"}),
        ];
        let bot_roles = vec!["role-bot".to_string()];
        assert_eq!(
            effective_bot_permissions("guild-a", &roles, &bot_roles),
            Some(3072)
        );
        assert!(permission_bit("3072", 10));
        assert!(permission_bit("3072", 11));
        assert!(!permission_bit("3072", 2));
    }

    #[test]
    fn permission_passport_applies_channel_overwrites_in_discord_order() {
        let overwrites = serde_json::json!([
            {"id":"guild-a","type":0,"allow":"0","deny":"2048"},
            {"id":"role-bot","type":0,"allow":"2048","deny":"0"},
            {"id":"bot-user","type":1,"allow":"0","deny":"2048"}
        ]);
        let permissions = channel_bot_permissions(
            2048,
            "guild-a",
            "bot-user",
            &["role-bot".into()],
            &overwrites,
        )
        .unwrap();
        assert_eq!(permissions, 0);
        assert!(!permission_bit(&permissions.to_string(), 11));
    }

    #[tokio::test]
    async fn feature_catalogue_is_allow_listed_and_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();
        // Simulate a rolling-deploy/legacy row that says a blocked provider
        // is enabled.  The catalogue must surface the dependency failure
        // rather than reporting the feature as merely disabled.
        store
            .publish_feature_setting(
                "guild-a",
                "social.instagram",
                true,
                "{}",
                None,
                "migration-test",
                &[],
            )
            .unwrap();
        let app = router(state(store.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["features"].as_array().unwrap().len(), 46);
        assert!(
            !body["features"]
                .as_array()
                .unwrap()
                .iter()
                .any(|feature| feature["key"] == "support.welcome_channel")
        );
        // Every adapter-backed feature is discoverable.  Provider credentials
        // and approvals affect activation/health, not whether the setup page
        // exists in the catalogue.
        let available_count = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["available"].as_bool() == Some(true))
            .count();
        // The legacy welcome guide is now part of the one welcome entry.
        assert_eq!(available_count, 46, "available_count={available_count}");
        let configurable_count = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["configurable"].as_bool() == Some(true))
            .count();
        assert_eq!(
            configurable_count, 46,
            "configurable_count={configurable_count}"
        );
        let mut keys = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 46);
        let maturity_count = |value: &str| {
            body["features"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| item["maturity"] == value)
                .count()
        };
        assert_eq!(maturity_count("operational"), 38);
        assert_eq!(maturity_count("beta"), 3);
        assert_eq!(maturity_count("blocked"), 5);
        assert_eq!(maturity_count("planned"), 0);
        assert!(
            body["features"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["key"] == "community.levels")
        );
        let blocked_instagram = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == "social.instagram")
            .unwrap();
        assert_eq!(blocked_instagram["maturity"], "blocked");
        assert_eq!(blocked_instagram["configurable"], true);
        assert!(
            blocked_instagram["issues"][0]["message"]
                .as_str()
                .unwrap()
                .contains("Meta app")
        );
        assert_eq!(
            blocked_instagram["health"]["adapter"],
            "meta_instagram_official_v1"
        );
        assert!(
            blocked_instagram["health"]["dependencies"]
                .as_array()
                .is_some_and(|dependencies| !dependencies.is_empty())
        );
        assert_eq!(blocked_instagram["health"]["status"], "dependency_down");
        let anti_spam = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == "protection.antispam")
            .unwrap();
        assert_eq!(anti_spam["health"]["adapter"], "anti_spam_adapter_v1");
        assert_eq!(anti_spam["health"]["operational"], true);
        assert_eq!(anti_spam["premium_required"], false);
        assert_eq!(anti_spam["premium_unlocked"], true);
        let premium_workflows = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == "management.workflows")
            .unwrap();
        assert_eq!(premium_workflows["premium_required"], true);
        assert_eq!(premium_workflows["premium_unlocked"], false);
        assert_eq!(premium_workflows["enabled"], false);
        let levels = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == "community.levels")
            .unwrap();
        assert_eq!(levels["health"]["operational"], true);
        let nickname = body["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == "management.nickname")
            .unwrap();
        assert_eq!(nickname["maturity"], "operational");
        assert_eq!(nickname["health"]["adapter"], "nickname_adapter_v1");
        assert_eq!(nickname["configurable"], true);

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"community.levels","enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(
            store
                .get_setting("guild-a", "feature.community.levels")
                .unwrap()
                .is_none()
        );

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"management.workflows","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["code"], "premium_required");

        let mut entitlement = helper_contracts::EntitlementSnapshot::free(session.user_id.clone());
        entitlement.plan = Plan::Premium { guild_limit: 1 };
        store.save_entitlement(&entitlement).unwrap();
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"management.workflows","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(
            store
                .get_setting("guild-a", "feature.management.workflows")
                .unwrap()
                .is_none()
        );

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features/management.nickname")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"config":{"nickname":"Vozen Helper"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"not-a-feature","enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn every_catalogue_feature_exposes_a_bounded_api_detail() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();

        for key in helper_core::FEATURE_KEYS {
            let response = router(state(store.clone()))
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/config/features/{key}"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "feature detail must be available for {key}"
            );
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                    .unwrap();
            assert_eq!(
                body["key"],
                if *key == "support.welcome_channel" {
                    "support.welcome"
                } else {
                    *key
                }
            );
            assert_eq!(body["configurable"], true, "{key} must remain discoverable");
            assert!(body["schema"].is_object(), "{key} has no schema");
            assert!(body["defaults"].is_object(), "{key} has no defaults");
            assert!(body["health"]["status"].as_str().is_some());
            if feature_requires_premium(key) {
                assert_eq!(
                    body["premiumRequired"], true,
                    "{key} must advertise Premium"
                );
                assert_eq!(body["premiumUnlocked"], false, "{key} must be locked");
                assert_eq!(body["health"]["status"], "premium_required");
            } else {
                assert!(body["adapter"].as_str().is_some(), "{key} has no adapter");
                assert_eq!(body["premiumRequired"], false);
                assert_eq!(body["premiumUnlocked"], true);
            }
        }
    }

    #[tokio::test]
    async fn levels_customization_requires_premium_and_projects_card_atomically() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("8".into()))],
            )
            .unwrap();
        let card = RankCardConfig {
            background_preset: Some("neon-rain".into()),
            ..Default::default()
        };
        // Old clients cannot turn mandatory cards off. Free servers still
        // cannot save custom styles, even alongside a legacy disabled flag.
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features/community.levels")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"enabled":false,"config":{"bannerEnabled":false}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["config"]["bannerEnabled"], true);
        assert_eq!(
            store
                .get_setting("guild-a", "community.levels.banner_enabled")
                .unwrap()
                .as_deref(),
            None
        );
        assert!(
            store
                .get_setting("guild-a", "community.rank_card")
                .unwrap()
                .is_none()
        );
        let payload = serde_json::json!({"enabled": false, "config": {"bannerEnabled": true, "rankCard": card}});
        for premium in [false, true] {
            if premium {
                grant_premium(&store, &session);
            }
            let response = router(state(store.clone()))
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/api/config/features/community.levels")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if premium {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                }
            );
            assert_eq!(
                store
                    .get_setting("guild-a", "community.rank_card")
                    .unwrap()
                    .is_some(),
                premium
            );
            assert!(
                store
                    .get_setting("guild-b", "community.rank_card")
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            store
                .get_setting("guild-a", "community.levels.banner_enabled")
                .unwrap()
                .as_deref(),
            None
        );
        assert!(
            store
                .get_setting("guild-a", "community.rank_card")
                .unwrap()
                .unwrap()
                .contains("neon-rain")
        );
    }

    #[tokio::test]
    async fn premium_activation_requires_auth_origin_and_matching_guild() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        for (auth, guild, expected) in [
            ("none", "guild-a", StatusCode::UNAUTHORIZED),
            ("cookie", "guild-a", StatusCode::FORBIDDEN),
            ("bearer", "guild-b", StatusCode::CONFLICT),
            ("bearer", "guild-a", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/premium/server")
                .header(header::CONTENT_TYPE, "application/json");
            if auth == "cookie" {
                request = request.header(header::COOKIE, format!("vh_session={token}"));
            }
            if auth == "bearer" {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = router(state(store.clone()))
                .oneshot(
                    request
                        .body(Body::from(
                            serde_json::json!({"guild_id":guild}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{auth}/{guild}");
        }
    }

    #[tokio::test]
    async fn unified_welcome_alias_reads_legacy_but_rejects_legacy_writes() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("8".into()))],
            )
            .unwrap();
        store
            .set_setting("guild-a", "feature.support.welcome_channel", "true")
            .unwrap();
        store
            .set_setting(
                "guild-a",
                "feature.config.support.welcome_channel",
                r#"{"channelId":"123","message":"Hello Alpha","steps":["help"]}"#,
            )
            .unwrap();
        store
            .set_setting(
                "guild-b",
                "feature.config.support.welcome_channel",
                r#"{"channelId":"999","message":"Private Beta"}"#,
            )
            .unwrap();
        let app = router(state(store.clone()));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/config/features/support.welcome_channel")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["key"], "support.welcome");
        assert_eq!(body["enabled"], true);
        assert_eq!(body["config"]["channel"], "123");
        assert_eq!(body["config"]["message"], "Hello Alpha");
        assert_eq!(body["config"]["guideEnabled"], true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features/support.welcome_channel")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false,"config":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        assert!(
            store
                .get_feature_setting("guild-a", "support.welcome_channel")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn anti_spam_simulation_uses_the_runtime_evaluator() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let body = serde_json::json!({
            "config": {
                "floodCount": 4,
                "windowSeconds": 12,
                "duplicateLimit": 2,
                "mentionLimit": 3,
                "maxLinks": 3,
                "capsPercent": 75,
                "capsMinLetters": 8,
                "deleteMessage": true,
                "timeoutSeconds": 90,
                "alertOnly": false
            },
            "fixture": {
                "channel_id": "general",
                "role_ids": [],
                "message_count": 4,
                "duplicate_count": 2,
                "mention_count": 3,
                "link_count": 3,
                "uppercase_letters": 9,
                "letter_count": 10
            }
        });
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/protection.antispam/simulate")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let response: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(response["result"]["would_apply"], true);
        assert_eq!(
            response["decision"]["matched"],
            serde_json::json!(["flood", "duplicate", "mentions", "links", "caps"])
        );
        assert_eq!(response["decision"]["timeout_seconds"], 90);
        assert_eq!(response["decision"]["should_delete"], true);
        assert!(
            response["adapterEffects"]
                .as_array()
                .is_some_and(|effects| effects.iter().any(|effect| {
                    effect
                        .as_str()
                        .is_some_and(|text| text.contains("security.antispam.flood_count"))
                }))
        );
        assert!(
            response["result"]["effects"][0]
                .as_str()
                .unwrap()
                .contains("timeout")
        );
        assert!(
            response["result"]["effects"]
                .as_array()
                .is_some_and(|effects| effects
                    .iter()
                    .any(|effect| { effect.as_str().is_some_and(|text| text.contains("delete")) }))
        );
    }

    #[tokio::test]
    async fn leaderboard_member_names_prefer_nick_then_global_then_username() {
        use std::sync::Mutex;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let received = calls.clone();
        let app = Router::new().route("/guilds/{guild}/members/{user}", get(
            move |Path((guild, user)): Path<(String, String)>, headers: HeaderMap| {
                let received = received.clone();
                async move {
                    assert_eq!(headers[header::AUTHORIZATION], "Bot fixture-token");
                    received.lock().unwrap().push((guild, user.clone()));
                    let body = match user.as_str() {
                        "1" => serde_json::json!({"nick":"Nome no servidor", "user":{"global_name":"Global", "username":"login"}}),
                        "2" => serde_json::json!({"nick":"  ", "user":{"global_name":"Nome global", "username":"login"}}),
                        "3" => serde_json::json!({"user":{"global_name":null, "username":"utilizador"}}),
                        "5" => serde_json::json!({"nick":null, "user":{"global_name":42, "username":"  "}}),
                        "6" => serde_json::json!({"nick":"x".repeat(120)}),
                        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({}))),
                    };
                    (StatusCode::OK, Json(body))
                }
            }
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut entries = ["1", "2", "3", "4", "5", "6", "../invalid"]
            .map(|id| LeaderboardEntry {
                user_id: id.into(),
                xp: 42,
                opted_out: false,
            })
            .to_vec();
        entries.push(LeaderboardEntry {
            user_id: "7".into(),
            xp: 999,
            opted_out: true,
        });
        let names = leaderboard_member_names(&base, "fixture-token", "10", &entries).await;
        assert_eq!(
            names,
            BTreeMap::from([
                ("1".into(), "Nome no servidor".into()),
                ("2".into(), "Nome global".into()),
                ("3".into(), "utilizador".into()),
                ("6".into(), "x".repeat(80)),
            ])
        );
        assert_eq!(calls.lock().unwrap().len(), 6);
        assert!(calls.lock().unwrap().iter().all(|(guild, _)| guild == "10"));
        assert!(
            leaderboard_member_names(&base, "fixture-token", "../invalid", &entries)
                .await
                .is_empty()
        );
        assert_eq!(calls.lock().unwrap().len(), 6);
        server.abort();
    }

    #[tokio::test]
    async fn leaderboard_member_names_stop_waiting_for_a_slow_discord() {
        let app = Router::new().fallback(get(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Json(serde_json::json!({"nick":"Too late"}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let entries = vec![LeaderboardEntry {
            user_id: "1".into(),
            xp: 42,
            opted_out: false,
        }];
        let names = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            leaderboard_member_names(&base, "fixture-token", "10", &entries),
        )
        .await
        .unwrap();
        assert!(names.is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn leaderboard_preview_requires_a_valid_session() {
        for credential in [None, Some("Bearer invalid")] {
            let mut request = Request::builder().uri("/api/leaderboard");
            if let Some(value) = credential {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = router(state(Store::open(":memory:").unwrap()))
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn leaderboard_preview_is_scoped_ranked_and_opt_out_aware() {
        let store = Store::open(":memory:").unwrap();
        store.add_xp("guild-a", "hidden", 999).unwrap();
        store.add_xp("guild-a", "member-b", 42).unwrap();
        store.add_xp("guild-a", "member-a", 42).unwrap();
        store.add_xp("guild-a", "member-c", 10).unwrap();
        store.add_xp("guild-b", "other-guild", 9999).unwrap();
        for (key, value) in [
            ("feature.community.leaderboard", "true"),
            ("community.leaderboard.max_entries", "2"),
            ("community.leaderboard.public", "false"),
            ("community.leaderboard.optout.hidden", "true"),
        ] {
            store.set_setting("guild-a", key, value).unwrap();
        }
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/leaderboard?guildId=guild-b&limit=9999")
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "guildId": "guild-a", "enabled": true, "public": false, "maxEntries": 2,
                "entries": [
                    {"userId": "member-a", "xp": 42, "rank": 1},
                    {"userId": "member-b", "xp": 42, "rank": 2}
                ]
            })
        );
        assert_eq!(store.top_levels("guild-a", 1).unwrap()[0].xp, 999);
    }

    #[tokio::test]
    async fn leaderboard_preview_defaults_and_disabled_state_are_explicit() {
        let store = Store::open(":memory:").unwrap();
        store.add_xp("guild-a", "member", 42).unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .uri("/api/leaderboard")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "guildId": "guild-a", "enabled": false, "public": true,
                "maxEntries": 10, "entries": []
            })
        );
    }

    #[tokio::test]
    async fn leaderboard_simulation_uses_runtime_ordering_and_opt_outs() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let body = serde_json::json!({
            "config": {"maxEntries": 1, "public": false},
            "leaderboardEntries": [
                {"userId": "private", "xp": 999, "optedOut": true},
                {"userId": "alice", "xp": 42},
                {"userId": "bob", "xp": 10}
            ]
        });
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/community.leaderboard/simulate")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let response: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(response["result"]["would_apply"], true);
        let effects = response["adapterEffects"].as_array().unwrap();
        let preview = effects[0].as_str().unwrap();
        assert!(preview.contains("private XP leaderboard"));
        assert!(preview.contains("alice"));
        assert!(!preview.contains("999"));
        assert!(preview.contains("Excluded 1 member"));
    }

    #[tokio::test]
    async fn stats_member_counter_preview_uses_the_requested_fixture_without_mutation() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let response = router(state(store.clone())).oneshot(
            Request::builder().method("POST")
                .uri("/api/config/features/insights.stats/simulate")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::json!({
                    "config": {"channelId": "123456789012345678", "nameTemplate": "📊 Members: {members}"},
                    "channel_id": "123456789012345678", "statsMembers": 42
                }).to_string())).unwrap()
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert!(
            body["adapterEffects"][0]
                .as_str()
                .unwrap()
                .contains("Members: 42")
        );
        assert!(
            store
                .get_feature_setting("guild-a", "insights.stats")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_feature_setting("guild-b", "insights.stats")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn feature_toggle_cannot_bypass_publish_preflight() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"support.tickets","enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(
            store
                .get_feature_setting("guild-a", "support.tickets")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_setting("guild-a", "feature.support.tickets")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn feature_repair_republishes_current_revision_atomically() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features/utility.help")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false,"config":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let initial = store
            .get_feature_setting("guild-a", "utility.help")
            .unwrap()
            .unwrap();
        assert_eq!(initial.revision, 1);

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/utility.help/repair")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["repaired"], true);
        assert_eq!(body["rolledBackFrom"], serde_json::Value::Null);
        assert_eq!(body["revision"], 2);
        assert_eq!(
            store
                .get_feature_setting("guild-a", "utility.help")
                .unwrap()
                .unwrap()
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn anti_spam_preflight_reports_missing_permissions() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preflight")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "operation": "protection.antispam.publish",
                            "enabled": true,
                            "config": {"timeoutSeconds": 60}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["ok"], false);
        assert!(
            body["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["path"] == "permissions.moderate_members")
        );
        assert!(
            body["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["path"] == "permissions.send_messages")
        );
    }

    #[tokio::test]
    async fn anti_spam_preflight_requires_manage_messages_only_when_deletion_is_enabled() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();

        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preflight")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "operation": "protection.antispam.publish",
                            "enabled": true,
                            "config": {"timeoutSeconds": 0, "deleteMessage": true}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let issues = body["issues"].as_array().unwrap();
        assert!(
            issues
                .iter()
                .any(|issue| issue["path"] == "permissions.bot_manage_messages")
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue["path"] == "permissions.moderate_members")
        );
    }

    #[tokio::test]
    async fn anti_scam_preflight_allows_monitoring_without_moderation_permissions() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();

        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preflight")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "operation": "protection.antiscam.publish",
                            "enabled": true,
                            "config": {
                                "alertOnly": true,
                                "deleteMessage": true,
                                "timeoutSeconds": 300
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let issues = body["issues"].as_array().unwrap();
        assert!(
            !issues
                .iter()
                .any(|issue| issue["path"] == "permissions.bot_manage_messages")
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue["path"] == "permissions.bot_moderate_members")
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue["path"] == "permissions.bot_send_messages")
        );
    }

    #[tokio::test]
    async fn protection_simulations_use_real_policy_inputs() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();

        let cases = [
            (
                "protection.antiscam",
                serde_json::json!({
                    "config": {"blockedKeywords":["free nitro"], "alertOnly":false},
                    "content": "Claim your free Nitro now",
                    "channel_id": "general"
                }),
                "timeout",
            ),
            (
                "protection.join_gate",
                serde_json::json!({
                    "config": {"minimumAccountDays":7, "requireAvatar":true, "blockedNamePatterns":["raid"]},
                    "account_age_days": 1,
                    "has_avatar": false,
                    "display_name": "raid account"
                }),
                "join-gate",
            ),
            (
                "community.starboard",
                serde_json::json!({"config":{"threshold":5}, "reaction_count":3}),
                "below",
            ),
            (
                "community.role_panels",
                serde_json::json!({
                    "config": {
                        "roleIds": ["111111111111111111", "222222222222222222"],
                        "selectionMode": "unique",
                        "removeOnUnselect": true
                    },
                    "selectedRoleIds": ["111111111111111111"],
                    "clickedRoleId": "222222222222222222"
                }),
                "assign role 222222222222222222",
            ),
            (
                "utility.temp_channels",
                serde_json::json!({
                    "config": {"nameTemplate":"{user} lounge", "maxActive":2},
                    "userName": "Rexy",
                    "activeTempRooms": 2
                }),
                "active_limit_reached",
            ),
        ];
        for (key, payload, expected) in cases {
            let response = router(state(store.clone()))
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/config/features/{key}/simulate"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{key}");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                    .unwrap();
            assert!(
                body["result"]["effects"][0]
                    .as_str()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains(expected),
                "{key}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn blocked_provider_simulation_never_claims_runtime_application() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/social.instagram/simulate")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "config": {
                                "username": "creator",
                                "targetChannelId": "123456789012345678"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["ok"], false);
        assert!(
            body["result"]["effects"][0]
                .as_str()
                .unwrap()
                .contains("Meta app")
        );
        assert!(
            !body["result"]["effects"][0]
                .as_str()
                .unwrap()
                .contains("Apply runtime setting")
        );
    }

    #[tokio::test]
    async fn beta_provider_simulation_never_claims_runtime_application_without_client() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/social.rss/simulate")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "config": {
                                "feedUrl": "https://example.com/feed.xml",
                                "targetChannelId": "123456789012345678",
                                "intervalSeconds": 300,
                                "messageTemplate": "{title}"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["ok"], false);
        assert!(
            body["result"]["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| {
                    issue["code"] == "provider_not_ready" && issue["path"] == "feature.provider"
                })
        );
    }

    #[test]
    fn every_subscription_provider_requires_a_live_runtime_client_before_enable() {
        for key in [
            "social.youtube",
            "social.rss",
            "social.podcasts",
            "social.twitch",
            "social.bluesky",
            "social.tiktok",
            "social.instagram",
            "social.kick",
        ] {
            assert!(
                provider_needs_runtime_ready(key),
                "{key} must be guarded by provider readiness before it can be enabled"
            );
        }
    }

    #[test]
    fn preflight_accepts_canonical_dependency_keys_and_panel_labels() {
        for (key, label, bit) in [
            ("send_messages", "Send Messages", 11),
            ("read_message_history", "Read Message History", 16),
            ("add_reactions", "Add Reactions", 6),
            ("change_nickname", "Change Nickname", 26),
            ("manage_roles", "Manage Roles", 28),
            ("use_application_commands", "Use Application Commands", 31),
        ] {
            assert_eq!(dependency_permission(key), Some((bit, label)));
            assert_eq!(dependency_permission(label), Some((bit, label)));
        }
        assert!(dependency_requires_role_management("manage_roles"));
        assert!(dependency_requires_role_management("Manage Roles"));
        assert!(!dependency_requires_role_management("Manage Messages"));
        assert_eq!(
            internal_feature_dependency("levels"),
            Some("community.levels")
        );
        assert_eq!(internal_feature_dependency("scheduler"), None);
    }

    #[test]
    fn published_gateway_dependencies_map_to_runtime_intents() {
        for (dependency, intent) in [
            ("message_content", "MESSAGE_CONTENT"),
            ("message_content_intent", "MESSAGE_CONTENT"),
            ("guild_members", "GUILD_MEMBERS"),
            ("guild_members_intent", "GUILD_MEMBERS"),
            ("voice_states", "GUILD_VOICE_STATES"),
            ("interactions", "GUILDS"),
            ("message_events", "GUILD_MESSAGES"),
        ] {
            assert_eq!(runtime_gateway_intent(dependency), Some(intent));
        }
        assert_eq!(runtime_gateway_intent("unknown_dependency"), None);
    }

    #[tokio::test]
    async fn rss_publish_returns_provider_precondition_before_touching_store() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        grant_premium(&store, &session);
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/config/features/social.rss")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "enabled": true,
                            "config": {
                                "feedUrl": "https://example.com/feed.xml",
                                "targetChannelId": "123456789012345678",
                                "intervalSeconds": 300,
                                "messageTemplate": "{title}"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(
            store
                .get_feature_setting("guild-a", "social.rss")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn anti_spam_detail_exposes_runtime_schema_and_defaults() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .uri("/api/config/features/protection.antispam")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["schema"]["source"], "anti_spam_adapter_v1");
        assert_eq!(body["defaults"]["floodCount"], 6);
        assert_eq!(body["defaults"]["maxLinks"], 5);
        assert_eq!(body["defaults"]["deleteMessage"], false);
        assert!(
            body["schema"]["sections"][1]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["kind"] == "channels")
        );
        assert!(
            body["schema"]["sections"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|section| section["fields"].as_array().unwrap())
                .any(|field| field["key"] == "deleteMessage")
        );
    }

    #[tokio::test]
    async fn anti_spam_health_and_feature_preflight_are_available_under_feature_route() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/config/features/protection.antispam/health")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["status"], "disabled");
        assert_eq!(body["adapter"], "anti_spam_adapter_v1");
        assert_eq!(body["operational"], true);

        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/features/protection.antispam/preflight")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"enabled": false, "config": {"floodCount": 6}})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
            panic!(
                "feature preflight returned {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["operation"], "protection.antispam.publish");
        assert_eq!(body["guildId"], "guild-a");
    }

    #[tokio::test]
    async fn enabled_feature_health_includes_live_discord_preflight() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        // The user has a managed guild but no moderation permissions. The
        // health endpoint must surface that runtime dependency instead of
        // calling a valid JSON revision operational.
        store
            .replace_session_guilds(
                session.session_id,
                &[("guild-a".into(), "Alpha".into(), Some("0".into()))],
            )
            .unwrap();
        store
            .publish_feature_setting(
                "guild-a",
                "management.moderation",
                true,
                &serde_json::json!({"requireReason": true, "maxPurge": 100}).to_string(),
                None,
                "user-1",
                &[],
            )
            .unwrap();

        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .uri("/api/config/features/management.moderation/health")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["preflight"]["ok"], false);
        assert_eq!(body["status"], "misconfigured");
        assert_eq!(body["operational"], false);
        assert!(body["issues"].as_array().unwrap().iter().any(|issue| {
            issue["code"] == "missing_permission" || issue["code"] == "discord_context_unavailable"
        }));
    }

    #[tokio::test]
    async fn session_guild_switch_requires_a_managed_guild() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        store
            .replace_session_guilds(
                session.session_id,
                &[
                    ("guild-a".into(), "Alpha".into(), Some("32".into())),
                    ("guild-b".into(), "Beta".into(), Some("32".into())),
                ],
            )
            .unwrap();
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/switch")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"guild_id":"guild-b"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-b");
        assert!(store.load_session(session.session_id).unwrap().is_none());
    }

    #[test]
    fn all_curated_backgrounds_pass_rank_card_validation() {
        assert_eq!(RANK_CARD_BACKGROUND_PRESETS.len(), 16);
        for (id, _) in RANK_CARD_BACKGROUND_PRESETS {
            let config = RankCardConfig {
                background_preset: Some((*id).into()),
                ..RankCardConfig::default()
            };
            assert!(valid_rank_card_config(&config), "preset {id}");
        }
        assert!(!valid_rank_card_preset(Some("untrusted-background")));
    }

    #[tokio::test]
    async fn rank_card_config_is_guild_scoped_and_validated() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        store.save_session(&session).unwrap();
        grant_premium(&store, &session);

        let config = serde_json::json!({
            "font": "poppins",
            "primary_color": "#123ABC",
            "text_color": "#F4F7FB",
            "background_color": "#101725",
            "overlay_opacity": 0.42,
            "background_preset": "neon-rain",
            "avatar_ring_color": "#123ABC",
            "avatar_ring_width": 6
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/studio/rank-card")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(config.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/studio/rank-card")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["config"]["primary_color"], "#123ABC");

        let invalid = serde_json::json!({
            "primary_color": "#123ABC",
            "background_color": "#101725",
            "text_color": "#F4F7FB",
            "avatar_ring_color": "#8EE5D2",
            "background_url": "https://cdn.example.test/rank.png"
        });
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/studio/rank-card")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(invalid.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authenticated_api_isolates_guild_data_and_import_target() {
        let store = Store::open(":memory:").unwrap();
        store
            .record_case("guild-a", "warn", "user-a", "mod", "a", None)
            .unwrap();
        store
            .record_case("guild-b", "warn", "user-b", "mod", "b", None)
            .unwrap();
        store.open_ticket("guild-a", "user-a", "channel-a").unwrap();
        store.open_ticket("guild-b", "user-b", "channel-b").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let app = router(state(store.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/cases")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["cases"].as_array().unwrap().len(), 1);
        assert_eq!(body["cases"][0]["guild_id"], "guild-a");
        assert!(!body.to_string().contains("guild-b"));

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/audit")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert!(
            !body["events"][0]["correlation_id"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        assert_eq!(body["events"][0]["actor_id"], "mod");
        assert!(!body.to_string().contains("guild-b"));

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/tickets")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["tickets"].as_array().unwrap().len(), 1);
        assert_eq!(body["tickets"][0]["guild_id"], "guild-a");
        assert!(!body.to_string().contains("channel-b"));

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/permissions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["permissions"].as_array().unwrap().len() >= 8);

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/security/health")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["score"], 35);
        assert!(
            body["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["id"] == "security.anti_nuke.enabled")
        );

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/privacy/receipt")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert!(
            body["notPersistedByDefault"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "Discord tokens")
        );

        store
            .set_setting("guild-a", "support.panel.1", "{}")
            .unwrap();
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/quotas")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["usage"]["panels"], 1);
        assert_eq!(body["limits"]["panels"], 1);

        let brand = serde_json::json!({
            "primary_color": "#123ABC",
            "secondary_color": "#0A0B0C",
            "logo_url": "https://cdn.example.test/logo.png",
            "font": "inter"
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/studio/brand")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(brand.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/studio/brand")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["brand"]["primary_color"], "#123ABC");

        grant_premium(&store, &session);
        let template_input = serde_json::json!({
            "name": "Gaming onboarding",
            "description": "Safe defaults for a gaming community",
            "modules": ["core", "security", "community"],
            "config": {"welcome": {"enabled": true}, "security": {"shadow": true}}
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/studio/templates")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(template_input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let template_id = body["template"]["id"].as_str().unwrap().to_string();
        assert_eq!(body["template"]["version"], 1);

        let updated = serde_json::json!({
            "name": "Gaming onboarding v2",
            "description": "Updated safe defaults",
            "modules": ["core", "security"],
            "config": {"welcome": {"enabled": false}}
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/studio/templates/{template_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(updated.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["template"]["version"], 2);

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri(format!("/api/studio/templates/{template_id}/revisions"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["revisions"].as_array().unwrap().len(), 2);
        assert_eq!(body["revisions"][0]["revision"], 2);

        let stale_rollback = serde_json::json!({
            "revision": 1,
            "expectedVersion": 1
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/studio/templates/{template_id}/rollback"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(stale_rollback.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let rollback = serde_json::json!({
            "revision": 1,
            "expectedVersion": 2
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/studio/templates/{template_id}/rollback"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(rollback.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["template"]["version"], 3);
        assert_eq!(body["template"]["name"], "Gaming onboarding");
        assert_eq!(body["restoredRevision"], 1);

        // A second panel tab must not overwrite the newer template revision.
        let stale_update = serde_json::json!({
            "name": "Stale edit",
            "description": "Must be rejected",
            "modules": ["core"],
            "config": {"welcome": {"enabled": true}},
            "expectedVersion": 1
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/studio/templates/{template_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(stale_update.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "template_revision_conflict");

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri(format!("/api/studio/templates/{template_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["template"]["version"], 3);
        assert_eq!(body["template"]["name"], "Gaming onboarding");

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/studio/templates")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["templates"].as_array().unwrap().len(), 1);
        assert!(!body.to_string().contains("guild-b"));

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/studio/templates/{template_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let import = serde_json::json!({
            "version": 1,
            "guildId": "guild-b",
            "settings": [{"key": "welcome.channel", "value": "123"}],
            "tags": [],
            "workflows": []
        });
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config/import")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(import.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            store.get_setting("guild-a", "welcome.channel").unwrap(),
            Some("123".into())
        );
        assert!(
            store
                .get_setting("guild-b", "welcome.channel")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn api_enforces_premium_workflow_quota() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        grant_premium(&store, &session);
        store
            .set_setting("guild-a", "feature.management.workflows", "true")
            .unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        for index in 0..25 {
            store
                .create_workflow(
                    "guild-a",
                    &format!("workflow-{index}"),
                    "message",
                    "hello",
                    "reply",
                    "Hi",
                )
                .unwrap();
        }
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/workflows")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "workflow-4",
                            "trigger": "message",
                            "condition": "hello",
                            "action": "reply",
                            "payload": "Hi"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn api_creates_unicode_reaction_workflows() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        grant_premium(&store, &session);
        store
            .set_setting("guild-a", "feature.management.workflows", "true")
            .unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/workflows")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "thank-you-reaction",
                            "trigger": "message",
                            "condition": "thanks",
                            "action": "react",
                            "payload": "✅"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let workflow = store
            .active_workflows("guild-a", "message")
            .unwrap()
            .into_iter()
            .next()
            .expect("stored reaction workflow");
        assert_eq!(workflow.action, "react");
        assert_eq!(workflow.payload, "✅");

        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/workflows/{}", workflow.id))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            store
                .active_workflows("guild-a", "message")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn workflow_endpoint_reports_the_enabled_state_and_effective_limits() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        grant_premium(&store, &session);
        for (key, value) in [
            ("feature.management.workflows", "true"),
            ("management.workflows.max_workflows", "4"),
            ("management.workflows.max_reply_length", "240"),
        ] {
            store.set_setting("guild-a", key, value).unwrap();
        }
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .uri("/api/workflows")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["enabled"], true);
        assert_eq!(body["planLimit"], 25);
        assert_eq!(body["maxWorkflows"], 4);
        assert_eq!(body["maxReplyLength"], 240);
    }

    #[tokio::test]
    async fn cookie_mutations_require_configured_panel_origin() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let mut api_state = state(store);
        api_state.allowed_origin = Some("http://127.0.0.1:4173".into());
        let body = serde_json::json!({
            "primary_color": "#123ABC",
            "secondary_color": "#0A0B0C",
            "logo_url": null,
            "font": "system"
        })
        .to_string();

        let health = router(api_state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .header(header::ORIGIN, "http://127.0.0.1:4173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(
            health
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://127.0.0.1:4173"
        );
        assert_eq!(
            health
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );

        let response = router(api_state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/studio/brand")
                    .header(header::COOKIE, format!("{COOKIE}={token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = router(api_state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/studio/brand")
                    .header(header::COOKIE, format!("{COOKIE}={token}"))
                    .header(header::ORIGIN, "http://127.0.0.1:4173")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oauth_start_binds_verifier_without_exposing_the_verifier() {
        let store = Store::open(":memory:").unwrap();
        let verifier = "a".repeat(64);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let response = router(state(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/oauth/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "guild_id": "guild-a",
                            "code_challenge": challenge,
                            "code_verifier": verifier
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());

        let mismatch = router(state(Store::open(":memory:").unwrap()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/oauth/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "guild_id": "guild-a",
                            "code_challenge": challenge,
                            "code_verifier": "b".repeat(64)
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);

        let get_response = router(state(Store::open(":memory:").unwrap()))
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/oauth/start?guild_id=guild-a&code_challenge={challenge}&code_verifier={verifier}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn install_start_uses_the_registered_api_callback() {
        let response = router(state(Store::open(":memory:").unwrap()))
            .oneshot(
                Request::builder()
                    .uri("/api/install/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let authorization = url::Url::parse(location).unwrap();
        let parameter = |name: &str| {
            authorization
                .query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .unwrap()
        };
        assert_eq!(parameter("client_id"), "client");
        assert_eq!(parameter("redirect_uri"), "https://example.test/callback");
        assert_eq!(parameter("permissions"), HELPER_INSTALL_PERMISSIONS);
        let permissions = parameter("permissions").parse::<u64>().unwrap();
        for bit in [10_u8, 11, 14, 16] {
            assert_ne!(
                permissions & (1_u64 << bit),
                0,
                "base permission bit {bit} is missing"
            );
        }
        for bit in [1_u8, 2, 3, 4, 5, 7, 13, 28, 40] {
            assert_eq!(
                permissions & (1_u64 << bit),
                0,
                "sensitive permission bit {bit} leaked into the base install"
            );
        }
        assert_eq!(parameter("integration_type"), "0");
        assert_eq!(
            parameter("scope"),
            "bot applications.commands identify guilds"
        );
        assert!(parameter("state").contains('.'));
        assert!(parameter("code_challenge").len() >= 43);
    }

    #[test]
    fn discord_guild_rate_limit_is_preserved_for_clients() {
        let (status, code) = discord_guilds_error(StatusCode::TOO_MANY_REQUESTS);

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(code, "discord_rate_limited");
    }

    #[test]
    fn install_callback_requires_a_discord_snowflake() {
        assert!(is_discord_snowflake("123456789012345678"));
        assert!(!is_discord_snowflake("guild-a"));
        assert!(!is_discord_snowflake("1234567890123456"));
        assert!(!is_discord_snowflake("12345678901234567890123"));
    }

    #[test]
    fn session_signature_binds_guild_claim() {
        let original = claims("guild-a");
        let token = sign_session(&original, "test-session-secret-with-at-least-32-bytes");
        assert_eq!(
            verify_session(&token, "test-session-secret-with-at-least-32-bytes")
                .unwrap()
                .guild_id,
            "guild-a"
        );
        let mut parts = token.split('.');
        let payload = URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap();
        let signature = parts.next().unwrap();
        let tampered = String::from_utf8(payload)
            .unwrap()
            .replace("guild-a", "guild-b");
        let forged = format!("{}.{}", URL_SAFE_NO_PAD.encode(tampered), signature);
        assert!(verify_session(&forged, "test-session-secret-with-at-least-32-bytes").is_none());
    }

    #[test]
    fn authentication_rechecks_persisted_session_lifetime_and_revocation() {
        let store = Store::open(":memory:").unwrap();
        let api_state = state(store);
        let active = claims("guild-a");
        api_state.store.save_session(&active).unwrap();
        let active_token = sign_session(&active, &api_state.session_secret);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {active_token}")).unwrap(),
        );

        assert!(authenticate(&api_state, &headers).is_some());
        api_state.store.revoke_session(active.session_id).unwrap();
        assert!(authenticate(&api_state, &headers).is_none());

        let mut idle = claims("guild-a");
        idle.last_seen_at = Utc::now() - Duration::minutes(IDLE_MINUTES + 1);
        api_state.store.save_session(&idle).unwrap();
        let idle_token = sign_session(&idle, &api_state.session_secret);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {idle_token}")).unwrap(),
        );
        assert!(authenticate(&api_state, &headers).is_none());
    }

    #[test]
    fn pkce_verifier_accepts_only_rfc7636_unreserved_values() {
        assert!(is_valid_pkce_verifier(&"a".repeat(43)));
        assert!(is_valid_pkce_verifier(&"~._-".repeat(16)));
        assert!(!is_valid_pkce_verifier(&"a".repeat(42)));
        assert!(!is_valid_pkce_verifier(&format!("{}!", "a".repeat(42))));
        assert!(!is_valid_pkce_verifier(&format!("{}é", "a".repeat(42))));
    }

    #[tokio::test]
    async fn twitch_eventsub_verifies_hmac_and_deduplicates_notifications() {
        let store = Store::open(":memory:").unwrap();
        store
            .create_twitch_subscription(
                "guild-a",
                "creator",
                "12345",
                "123456789012345",
                "{broadcaster} {url}",
                "",
                true,
                "user-1",
            )
            .unwrap();
        let mut api_state = state(store.clone());
        api_state.twitch = TwitchClient::new(
            "client-id",
            "client-secret",
            "https://api.vozen.org/rust/api/providers/twitch/eventsub",
            "eventsub-secret-1234567890",
        );
        let message_id = "message-1";
        let timestamp = Utc::now().to_rfc3339();
        let body = br#"{"subscription":{"type":"stream.online"},"event":{"broadcaster_user_id":"12345","id":"stream-1","started_at":"2026-08-02T00:00:00Z"}}"#;
        let mut mac = HmacSha256::new_from_slice(b"eventsub-secret-1234567890").unwrap();
        mac.update(message_id.as_bytes());
        mac.update(timestamp.as_bytes());
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let response = router(api_state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/providers/twitch/eventsub")
                    .header("Twitch-Eventsub-Message-Id", message_id)
                    .header("Twitch-Eventsub-Message-Timestamp", &timestamp)
                    .header("Twitch-Eventsub-Message-Signature", &signature)
                    .header("Twitch-Eventsub-Message-Type", "notification")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let record = store
            .twitch_subscriptions("guild-a")
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(record.pending_event_id.as_deref(), Some(message_id));
        let duplicate = router(api_state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/providers/twitch/eventsub")
                    .header("Twitch-Eventsub-Message-Id", message_id)
                    .header("Twitch-Eventsub-Message-Timestamp", &timestamp)
                    .header("Twitch-Eventsub-Message-Signature", &signature)
                    .header("Twitch-Eventsub-Message-Type", "notification")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            store.twitch_subscriptions("guild-a").unwrap()[0]
                .pending_event_id
                .as_deref(),
            Some(message_id)
        );
    }
    #[tokio::test]
    async fn shop_routes_bind_guild_enforce_csrf_and_preserve_order_history() {
        let store = Store::open(":memory:").unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let mut test_state = state(store.clone());
        test_state.allowed_origin = Some("https://vozen.org".into());
        let app = router(test_state);
        let body = serde_json::json!({"name":"Physical item","price":80,"delivery":"manual","roleId":null});
        for (authenticated, origin, guild, price, expected) in [
            (false, true, "guild-a", 80, StatusCode::UNAUTHORIZED),
            (true, false, "guild-a", 80, StatusCode::FORBIDDEN),
            (true, true, "guild-b", 80, StatusCode::CONFLICT),
            (true, true, "guild-a", 0, StatusCode::BAD_REQUEST),
            (true, true, "guild-a", 80, StatusCode::OK),
        ] {
            let mut value = body.clone();
            value["price"] = serde_json::json!(price);
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("/api/economy/products?guildId={guild}"))
                .header(header::CONTENT_TYPE, "application/json");
            if authenticated {
                request = request.header(header::COOKIE, format!("vh_session={token}"));
            }
            if origin {
                request = request.header(header::ORIGIN, "https://vozen.org");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(value.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        for (origin, guild, channel, expected) in [
            (false, "guild-a", "", StatusCode::FORBIDDEN),
            (true, "guild-b", "", StatusCode::CONFLICT),
            (true, "guild-a", "bad", StatusCode::BAD_REQUEST),
            (true, "guild-a", "", StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .method("PUT")
                .uri(format!("/api/economy/notifications?guildId={guild}"))
                .header(header::COOKIE, format!("vh_session={token}"))
                .header(header::CONTENT_TYPE, "application/json");
            if origin {
                request = request.header(header::ORIGIN, "https://vozen.org");
            }
            let response = app
                .clone()
                .oneshot(
                    request
                        .body(Body::from(
                            serde_json::json!({"channelId":channel}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/economy/channel?guildId=guild-b")
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .header(header::ORIGIN, "https://vozen.org")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"shop-orders"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let product = store.shop_products("guild-a").unwrap().remove(0);
        assert!(store.shop_products("guild-b").unwrap().is_empty());
        store.claim_daily("guild-a", "member", 100).unwrap();
        let order = store
            .buy_shop_product(
                "guild-a",
                "member",
                "Display Name",
                product.id,
                product.version,
                "purchase",
            )
            .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/economy/shop?guildId=guild-a")
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let result: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 100000).await.unwrap()).unwrap();
        assert_eq!(result["orders"][0]["displayName"], "Display Name");
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/economy/orders/{}?guildId=guild-a", order.id))
                        .header(header::COOKIE, format!("vh_session={token}"))
                        .header(header::ORIGIN, "https://vozen.org")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"status":"refunded"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(
            store.economy_account("guild-a", "member").unwrap().balance,
            100
        );
    }
    #[tokio::test]
    async fn activity_feed_requires_auth_and_filters_the_selected_guild_only() {
        let store = Store::open(":memory:").unwrap();
        let unauthorized = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/activity/feed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        store
            .record_activity(
                "guild-a",
                "member_join",
                "member",
                Some("Readable name"),
                None,
                "{}",
            )
            .unwrap();
        store
            .record_activity(
                "guild-b",
                "member_join",
                "hidden",
                Some("Private other guild"),
                None,
                "{}",
            )
            .unwrap();
        store
            .record_case("guild-a", "ban", "banned", "mod", "reason", None)
            .unwrap();
        let session = claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let response = router(state(store.clone()))
            .oneshot(
                Request::builder()
                    .uri("/api/activity/feed?category=joins&guildId=guild-b&limit=1")
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1000000).await.unwrap())
                .unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["memberName"], "Readable name");
        assert!(!body.to_string().contains("Private other guild"));
        for query in ["category=invalid", "before=1:9:1", "before=invalid"] {
            let response = router(state(store.clone()))
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/activity/feed?{query}"))
                        .header(header::COOKIE, format!("vh_session={token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
