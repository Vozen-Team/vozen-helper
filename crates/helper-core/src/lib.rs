//! Pure configuration and policy primitives. No Discord or HTTP side effects.

pub mod member_counter;

use anyhow::{Context, Result};
use helper_contracts::{
    AntiSpamDecision, AntiSpamObservation, AntiSpamPolicy, FeatureAdapterDescriptor,
    FeatureMaturity, Plan, RANK_CARD_BACKGROUND_PRESETS, RankCardConfig, ValidationIssue,
    is_valid_workflow_reaction,
};
use serde::Deserialize;
use std::{collections::HashSet, env, net::IpAddr, path::PathBuf, str::FromStr};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub discord_token: String,
    pub discord_application_id: u64,
    pub database_url: PathBuf,
    pub bind_addr: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_redirect_uri: String,
    pub oauth_success_redirect: String,
    pub trusted_vozen_oauth_client_id: Option<String>,
    pub private_tracker_client_id: Option<String>,
    pub private_tracker_owner_id: Option<String>,
    pub allow_legacy_session: bool,
    pub session_secret: String,
    pub entitlement_url: Option<String>,
    pub entitlement_secret: Option<String>,
    /// Optional current Top.gg v1 token for aggregate server-count publishing.
    /// The runtime treats an absent token as an observable disabled integration.
    pub topgg_token: Option<String>,
    pub environment: String,
    pub api_only: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();
        let required = |name: &str| -> Result<String> {
            env::var(name).with_context(|| format!("missing required environment variable {name}"))
        };
        let discord_application_id = required("DISCORD_APPLICATION_ID")?
            .parse::<u64>()
            .context("DISCORD_APPLICATION_ID must be an integer")?;
        let bind_addr = env::var("HELPER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3101".into());
        bind_addr
            .parse::<std::net::SocketAddr>()
            .context("HELPER_BIND_ADDR must be host:port")?;
        let environment = env::var("NODE_ENV").unwrap_or_else(|_| "production".into());
        let (entitlement_url, entitlement_secret) = resolve_entitlement_settings(
            &environment,
            optional_env("VOZEN_ENTITLEMENT_URL"),
            optional_env("VOZEN_ENTITLEMENT_SECRET"),
        )?;
        Ok(Self {
            discord_token: required("DISCORD_TOKEN")?,
            discord_application_id,
            database_url: PathBuf::from(
                env::var("HELPER_DATABASE_URL")
                    .unwrap_or_else(|_| "data/vozen-helper.sqlite".into()),
            ),
            bind_addr,
            oauth_client_id: required("DISCORD_OAUTH_CLIENT_ID")?,
            oauth_client_secret: required("DISCORD_OAUTH_CLIENT_SECRET")?,
            oauth_redirect_uri: required("DISCORD_OAUTH_REDIRECT_URI")?,
            oauth_success_redirect: env::var("HELPER_OAUTH_SUCCESS_REDIRECT")
                .unwrap_or_else(|_| "https://vozen.org/panel/helper-tracker/".into()),
            trusted_vozen_oauth_client_id: trusted_vozen_oauth_client_id(),
            private_tracker_client_id: optional_env("HELPER_PRIVATE_TRACKER_CLIENT_ID"),
            private_tracker_owner_id: optional_env("HELPER_PRIVATE_TRACKER_OWNER_ID"),
            allow_legacy_session: env::var("HELPER_ALLOW_LEGACY_SESSION")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            session_secret: required("HELPER_SESSION_SECRET")?,
            entitlement_url,
            entitlement_secret,
            topgg_token: optional_env("HELPER_TOPGG_TOKEN"),
            environment,
            api_only: env::var("HELPER_API_ONLY")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.discord_token.len() < 20 {
            anyhow::bail!("DISCORD_TOKEN is unexpectedly short");
        }
        if self.session_secret.len() < 32 {
            anyhow::bail!("HELPER_SESSION_SECRET must be at least 32 bytes");
        }
        if self.oauth_redirect_uri.starts_with("http://") && self.environment == "production" {
            anyhow::bail!("OAuth redirect URI must use HTTPS in production");
        }
        if self.oauth_success_redirect.starts_with("http://") && self.environment == "production" {
            anyhow::bail!("OAuth success redirect must use HTTPS in production");
        }
        if self.private_tracker_client_id.is_some() != self.private_tracker_owner_id.is_some() {
            anyhow::bail!(
                "HELPER_PRIVATE_TRACKER_CLIENT_ID and HELPER_PRIVATE_TRACKER_OWNER_ID must be configured together"
            );
        }
        Ok(())
    }
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The entitlement client is authenticated.  Accepting only half of its
/// configuration silently disabled server Premium and made paid features look
/// locked, so treat URL and shared secret as one atomic setting.
fn resolve_entitlement_settings(
    environment: &str,
    url: Option<String>,
    secret: Option<String>,
) -> Result<(Option<String>, Option<String>)> {
    match (url, secret) {
        (None, None) if !environment.eq_ignore_ascii_case("production") => Ok((None, None)),
        (Some(url), Some(secret)) => Ok((Some(url), Some(secret))),
        (None, None) => anyhow::bail!(
            "VOZEN_ENTITLEMENT_URL and VOZEN_ENTITLEMENT_SECRET are required in production"
        ),
        _ => anyhow::bail!(
            "VOZEN_ENTITLEMENT_URL and VOZEN_ENTITLEMENT_SECRET must be configured together"
        ),
    }
}

fn trusted_vozen_oauth_client_id() -> Option<String> {
    resolve_trusted_vozen_oauth_client_id(
        optional_env("VOZEN_ECOSYSTEM_OAUTH_CLIENT_ID"),
        optional_env("VOZEN_OAUTH_CLIENT_ID"),
    )
}

fn resolve_trusted_vozen_oauth_client_id(
    ecosystem_client_id: Option<String>,
    legacy_client_id: Option<String>,
) -> Option<String> {
    ecosystem_client_id.or(legacy_client_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Core,
    Studio,
    Security,
    Support,
    Events,
    Community,
    Automate,
    Insights,
}

/// Canonical allow-list shared by validation and migration code. The API
/// supplies copy and category metadata, but no request may publish a key that
/// is not present in this list.
pub const FEATURE_KEYS: &[&str] = &[
    "protection.antispam",
    "protection.antiscam",
    "protection.anti_raid",
    "protection.join_gate",
    "community.levels",
    "community.leaderboard",
    "community.starboard",
    "community.suggestions",
    "community.giveaways",
    "support.tickets",
    "support.welcome",
    "support.welcome_channel",
    "management.nickname",
    "management.workflows",
    "management.polls",
    "insights.stats",
    "studio.rank_card",
    "management.moderation",
    "management.custom_commands",
    "management.audit",
    "management.privacy",
    "management.templates",
    "community.role_panels",
    "community.events",
    "community.achievements",
    "management.invite_tracker",
    "utility.help",
    "utility.reminders",
    "utility.emojis",
    "utility.embeds",
    "utility.search",
    "utility.temp_channels",
    "social.twitch",
    "social.youtube",
    "social.instagram",
    "social.tiktok",
    "social.rss",
    "social.podcasts",
    "social.kick",
    "social.bluesky",
    "community.birthdays",
    "community.economy",
    "growth.monetization",
    "web3.crypto_stats",
    "web3.crypto_queries",
    "web3.gas_tracker",
    "web3.gating",
];

pub fn is_known_feature(key: &str) -> bool {
    FEATURE_KEYS.contains(&key)
}

fn valid_discord_id(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|id| id != 0)
}

/// Parse the JSON feature representation into the bounded anti-spam policy
/// shared by the API and gateway.
pub fn anti_spam_policy_from_json(value: &serde_json::Value) -> AntiSpamPolicy {
    let mut policy = AntiSpamPolicy::default();
    let Some(object) = value.as_object() else {
        return policy;
    };
    let number = |name: &str| object.get(name).and_then(serde_json::Value::as_u64);
    if let Some(value) = number("floodCount") {
        policy.flood_count = value.clamp(3, 30) as u32;
    }
    if let Some(value) = number("windowSeconds") {
        policy.window_seconds = value.clamp(3, 60);
    }
    if let Some(value) = number("duplicateLimit") {
        policy.duplicate_limit = value.clamp(2, 12) as u32;
    }
    if let Some(value) = number("mentionLimit") {
        policy.mention_limit = value.clamp(1, 30) as u32;
    }
    if let Some(value) = number("maxLinks") {
        policy.max_links = value.clamp(1, 20) as u32;
    }
    if let Some(value) = number("capsPercent") {
        policy.caps_percent = value.clamp(50, 100) as u32;
    }
    if let Some(value) = number("capsMinLetters") {
        policy.caps_min_letters = value.clamp(4, 100) as u32;
    }
    if let Some(value) = number("timeoutSeconds") {
        policy.timeout_seconds = value.min(86_400);
    }
    if let Some(value) = object
        .get("ignoredChannels")
        .and_then(serde_json::Value::as_array)
    {
        policy.ignored_channels = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = object
        .get("ignoredRoles")
        .and_then(serde_json::Value::as_array)
    {
        policy.ignored_roles = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = object.get("alertOnly").and_then(serde_json::Value::as_bool) {
        policy.alert_only = value;
    }
    if let Some(value) = object
        .get("deleteMessage")
        .and_then(serde_json::Value::as_bool)
    {
        policy.delete_message = value;
    }
    policy
}

/// Convert the bounded fixture accepted by the API into the observation used
/// by the Discord gateway.  Both camelCase (panel payloads) and snake_case
/// (Rust fixtures) are accepted so the simulation contract remains stable
/// across clients without duplicating the decision logic.
pub fn anti_spam_observation_from_json(value: &serde_json::Value) -> AntiSpamObservation {
    let object = value.as_object();
    let string = |camel: &str, snake: &str, fallback: &str| {
        object
            .and_then(|values| values.get(camel).or_else(|| values.get(snake)))
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(fallback)
            .to_owned()
    };
    let number = |camel: &str, snake: &str, fallback: u32| {
        object
            .and_then(|values| values.get(camel).or_else(|| values.get(snake)))
            .and_then(serde_json::Value::as_u64)
            .map(|value| value.min(u32::MAX as u64) as u32)
            .unwrap_or(fallback)
    };
    let roles = object
        .and_then(|values| values.get("roleIds").or_else(|| values.get("role_ids")))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .take(100)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    AntiSpamObservation {
        channel_id: string("channelId", "channel_id", "preview-channel"),
        role_ids: roles,
        message_count: number("messageCount", "message_count", 6),
        duplicate_count: number("duplicateCount", "duplicate_count", 3),
        mention_count: number("mentionCount", "mention_count", 5),
        link_count: number("linkCount", "link_count", 0),
        uppercase_letters: number("uppercaseLetters", "uppercase_letters", 0),
        letter_count: number("letterCount", "letter_count", 0),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScamPolicy {
    pub block_invites: bool,
    pub blocked_domains: Vec<String>,
    pub blocked_keywords: Vec<String>,
    pub ignored_channels: Vec<String>,
    pub ignored_roles: Vec<String>,
    pub alert_only: bool,
    /// Keep enforcement reversible: administrators can timeout a member
    /// without automatically deleting the original message.
    pub delete_message: bool,
    pub timeout_seconds: u64,
}

impl Default for ScamPolicy {
    fn default() -> Self {
        Self {
            block_invites: true,
            blocked_domains: Vec::new(),
            blocked_keywords: vec![
                "free nitro".into(),
                "steam gift".into(),
                "claim your prize".into(),
                "verify your wallet".into(),
            ],
            ignored_channels: Vec::new(),
            ignored_roles: Vec::new(),
            alert_only: false,
            // Preserve the existing anti-scam behaviour unless an
            // administrator explicitly opts out in the dashboard.
            delete_message: true,
            timeout_seconds: 300,
        }
    }
}

pub fn scam_policy_from_json(value: &serde_json::Value) -> ScamPolicy {
    let mut policy = ScamPolicy::default();
    let Some(object) = value.as_object() else {
        return policy;
    };
    if let Some(value) = object
        .get("blockInvites")
        .and_then(serde_json::Value::as_bool)
    {
        policy.block_invites = value;
    }
    if let Some(value) = object
        .get("blockedDomains")
        .and_then(serde_json::Value::as_array)
    {
        policy.blocked_domains = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|domain| domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .take(100)
            .collect();
    }
    if let Some(value) = object
        .get("blockedKeywords")
        .and_then(serde_json::Value::as_array)
    {
        policy.blocked_keywords = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|keyword| keyword.trim().to_ascii_lowercase())
            .filter(|keyword| !keyword.is_empty())
            .take(100)
            .collect();
    }
    if let Some(value) = object
        .get("ignoredChannels")
        .and_then(serde_json::Value::as_array)
    {
        policy.ignored_channels = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .take(100)
            .collect();
    }
    if let Some(value) = object
        .get("ignoredRoles")
        .and_then(serde_json::Value::as_array)
    {
        policy.ignored_roles = value
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .take(100)
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = object.get("alertOnly").and_then(serde_json::Value::as_bool) {
        policy.alert_only = value;
    }
    if let Some(value) = object
        .get("deleteMessage")
        .and_then(serde_json::Value::as_bool)
    {
        policy.delete_message = value;
    }
    if let Some(value) = object
        .get("timeoutSeconds")
        .and_then(serde_json::Value::as_u64)
    {
        policy.timeout_seconds = value.clamp(0, 86_400);
    }
    policy
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScamDecision {
    pub ignored: bool,
    pub matched: Vec<String>,
    pub should_act: bool,
    pub should_delete: bool,
    pub timeout_seconds: u64,
    pub reason: String,
}

pub fn evaluate_scam(policy: &ScamPolicy, channel_id: &str, content: &str) -> ScamDecision {
    evaluate_scam_with_roles(policy, channel_id, &[], content)
}

/// Evaluate scam policy with the member's roles. Keeping this pure makes the
/// API simulator and the Discord gateway share exactly the same exemptions
/// and matching rules.
pub fn evaluate_scam_with_roles(
    policy: &ScamPolicy,
    channel_id: &str,
    role_ids: &[String],
    content: &str,
) -> ScamDecision {
    if policy.ignored_channels.iter().any(|id| id == channel_id)
        || role_ids
            .iter()
            .any(|role| policy.ignored_roles.iter().any(|ignored| ignored == role))
    {
        return ScamDecision {
            ignored: true,
            matched: Vec::new(),
            should_act: false,
            should_delete: false,
            timeout_seconds: 0,
            reason: "ignored_channel".into(),
        };
    }
    let lower = content.to_ascii_lowercase();
    let mut matched = Vec::new();
    if policy.block_invites && contains_invite_link(&lower) {
        matched.push("discord_invite".into());
    }
    for domain in &policy.blocked_domains {
        if contains_blocked_domain(&lower, domain) {
            matched.push(format!("domain:{domain}"));
        }
    }
    for keyword in &policy.blocked_keywords {
        if lower.contains(keyword) {
            matched.push(format!("keyword:{keyword}"));
        }
    }
    let should_act = !matched.is_empty() && !policy.alert_only;
    ScamDecision {
        ignored: false,
        matched,
        should_act,
        should_delete: should_act && policy.delete_message,
        timeout_seconds: if should_act {
            policy.timeout_seconds
        } else {
            0
        },
        reason: if should_act {
            "blocked_scam_pattern".into()
        } else {
            "scam_pattern_monitoring".into()
        },
    }
}

fn contains_invite_link(content: &str) -> bool {
    content.split_whitespace().any(|token| {
        let host = normalize_host(token);
        (host == "discord.gg" && token.contains("discord.gg/"))
            || (host == "discord.com" && token.contains("discord.com/invite/"))
    })
}

/// Match a blocked host without treating `example.com.evil.test` as
/// `example.com`. Subdomains of a blocked domain remain blocked. Inputs are
/// intentionally ASCII-bounded so look-alike Unicode hosts cannot silently
/// bypass an administrator's domain list.
fn contains_blocked_domain(content: &str, configured: &str) -> bool {
    let domain = normalize_host(configured);
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    content.split_whitespace().any(|token| {
        let host = normalize_host(token);
        !host.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
    })
}

fn normalize_host(value: &str) -> String {
    let trimmed = value
        .trim()
        .trim_matches(|character: char| "<>[](){}\"'`,;!?".contains(character));
    let trimmed = ["https://", "http://"]
        .iter()
        .find_map(|scheme| trimmed.find(scheme).map(|start| &trimmed[start..]))
        .unwrap_or(trimmed);
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let without_www = authority.strip_prefix("www.").unwrap_or(authority);
    let host = without_www
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty()
        || !host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
    {
        return String::new();
    }
    host
}

/// Bounded anti-raid policy shared by the API simulator and the Discord
/// member-join handler.  The gateway is responsible for counting joins in a
/// time window; this pure evaluator decides what that count means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiRaidPolicy {
    pub join_threshold: u32,
    pub window_seconds: u64,
    pub incident_minutes: u64,
    pub verification: String,
    pub alert_only: bool,
    /// When enabled, an armed incident temporarily enables the join gate.
    /// Discord does not expose a safe global "pause invites" switch; the
    /// gate is the bounded equivalent that can be restored after expiry.
    pub pause_invites: bool,
}

impl Default for AntiRaidPolicy {
    fn default() -> Self {
        Self {
            join_threshold: 10,
            window_seconds: 10,
            incident_minutes: 10,
            verification: "high".into(),
            alert_only: false,
            pause_invites: true,
        }
    }
}

pub fn anti_raid_policy_from_json(value: &serde_json::Value) -> AntiRaidPolicy {
    let mut policy = AntiRaidPolicy::default();
    let Some(object) = value.as_object() else {
        return policy;
    };
    if let Some(value) = object
        .get("joinThreshold")
        .and_then(serde_json::Value::as_u64)
    {
        policy.join_threshold = value.clamp(2, 100) as u32;
    }
    if let Some(value) = object
        .get("windowSeconds")
        .and_then(serde_json::Value::as_u64)
    {
        policy.window_seconds = value.clamp(3, 60);
    }
    if let Some(value) = object
        .get("incidentMinutes")
        .and_then(serde_json::Value::as_u64)
    {
        policy.incident_minutes = value.clamp(1, 120);
    }
    if let Some(value) = object
        .get("verification")
        .and_then(serde_json::Value::as_str)
        && matches!(value, "medium" | "high" | "very_high")
    {
        policy.verification = value.into();
    }
    if let Some(value) = object.get("alertOnly").and_then(serde_json::Value::as_bool) {
        policy.alert_only = value;
    }
    if let Some(value) = object
        .get("pauseInvites")
        .and_then(serde_json::Value::as_bool)
    {
        policy.pause_invites = value;
    }
    policy
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiRaidDecision {
    pub joins: u32,
    pub armed: bool,
    pub shadow_mode: bool,
    pub should_contain: bool,
    pub incident_minutes: u64,
    pub reason: String,
}

pub fn evaluate_anti_raid(
    policy: &AntiRaidPolicy,
    joins: u32,
    shadow_mode: bool,
) -> AntiRaidDecision {
    let joins = joins.min(100_000);
    let armed = joins >= policy.join_threshold;
    let shadow_mode = shadow_mode || policy.alert_only;
    let should_contain = armed && !shadow_mode && policy.pause_invites;
    AntiRaidDecision {
        joins,
        armed,
        shadow_mode,
        should_contain,
        incident_minutes: policy.incident_minutes,
        reason: if armed {
            if shadow_mode {
                "join_burst_detected_shadow".into()
            } else if policy.pause_invites {
                "join_burst_detected_contain".into()
            } else {
                "join_burst_detected_alert".into()
            }
        } else {
            "join_burst_below_threshold".into()
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinGatePolicy {
    pub minimum_account_days: i64,
    pub require_avatar: bool,
    pub blocked_name_patterns: Vec<String>,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinGateObservation {
    pub account_age_days: i64,
    pub has_avatar: bool,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinGateDecision {
    pub blocked: bool,
    pub reasons: Vec<String>,
    pub action: String,
}

/// Decide whether a member needs verification.  Name matching is deliberately
/// case-insensitive and bounded by the adapter's validation limits.
pub fn evaluate_join_gate(
    policy: &JoinGatePolicy,
    observation: &JoinGateObservation,
) -> JoinGateDecision {
    let account_age_days = observation.account_age_days.clamp(0, 3650);
    let minimum_account_days = policy.minimum_account_days.clamp(0, 365);
    let display_name = observation.display_name.to_ascii_lowercase();
    let mut reasons = Vec::new();
    if account_age_days < minimum_account_days {
        reasons.push(format!(
            "account age {account_age_days}d < {minimum_account_days}d"
        ));
    }
    if policy.require_avatar && !observation.has_avatar {
        reasons.push("profile avatar is required".into());
    }
    if let Some(pattern) = policy
        .blocked_name_patterns
        .iter()
        .map(|pattern| pattern.trim().to_ascii_lowercase())
        .filter(|pattern| !pattern.is_empty())
        .take(20)
        .find(|pattern| display_name.contains(pattern))
    {
        reasons.push(format!("display name matches `{pattern}`"));
    }
    JoinGateDecision {
        blocked: !reasons.is_empty(),
        reasons,
        action: if policy.action == "alert" {
            "alert".into()
        } else {
            "quarantine".into()
        },
    }
}

/// Configuration and bounded input for the XP leaderboard.  Keeping this
/// evaluator in core means the API preview and the Discord command cannot
/// disagree about visibility, opt-outs or ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderboardPolicy {
    pub max_entries: u32,
    pub public: bool,
}

impl Default for LeaderboardPolicy {
    fn default() -> Self {
        Self {
            max_entries: 10,
            public: true,
        }
    }
}

pub fn leaderboard_policy_from_json(value: &serde_json::Value) -> LeaderboardPolicy {
    let mut policy = LeaderboardPolicy::default();
    let Some(object) = value.as_object() else {
        return policy;
    };
    if let Some(value) = object.get("maxEntries").and_then(serde_json::Value::as_u64) {
        policy.max_entries = value.clamp(1, 100) as u32;
    }
    if let Some(value) = object.get("public").and_then(serde_json::Value::as_bool) {
        policy.public = value;
    }
    policy
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaderboardEntry {
    #[serde(rename = "userId", alias = "user_id")]
    pub user_id: String,
    pub xp: i64,
    #[serde(default, rename = "optedOut", alias = "opted_out")]
    pub opted_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderboardDecision {
    pub public: bool,
    pub entries: Vec<LeaderboardEntry>,
    pub excluded_opt_outs: u32,
    pub truncated: bool,
}

/// Sort and bound leaderboard rows while excluding members who opted out.
/// IDs and XP are clamped so a malformed preview or legacy row cannot create
/// an unbounded response.  The same function is used by the gateway and API.
pub fn evaluate_leaderboard(
    policy: &LeaderboardPolicy,
    entries: impl IntoIterator<Item = LeaderboardEntry>,
) -> LeaderboardDecision {
    let mut excluded_opt_outs = 0;
    let mut entries: Vec<_> = entries
        .into_iter()
        .filter_map(|mut entry| {
            entry.user_id = entry.user_id.trim().chars().take(64).collect();
            if entry.user_id.is_empty() {
                return None;
            }
            entry.xp = entry.xp.clamp(0, i64::MAX);
            if entry.opted_out {
                excluded_opt_outs += 1;
                None
            } else {
                Some(entry)
            }
        })
        .take(1_000)
        .collect();
    entries.sort_by(|left, right| {
        right
            .xp
            .cmp(&left.xp)
            .then_with(|| left.user_id.cmp(&right.user_id))
    });
    let max_entries = policy.max_entries.clamp(1, 100) as usize;
    let truncated = entries.len() > max_entries;
    entries.truncate(max_entries);
    LeaderboardDecision {
        public: policy.public,
        entries,
        excluded_opt_outs,
        truncated,
    }
}

/// Bounded observation used by the XP runtime and dashboard preview.  The
/// evaluator deliberately contains no store or Discord calls so a preview of
/// an XP award cannot drift from what the gateway actually awards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelsDecision {
    pub allowed: bool,
    pub source: String,
    pub amount: i64,
    pub before_xp: i64,
    pub after_xp: i64,
    pub before_level: i64,
    pub after_level: i64,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Evaluate one message or voice XP event using the canonical levels config.
/// Message amounts are deterministic per event id; voice amounts are bounded
/// to one day so malformed fixtures or gateway input cannot inflate XP.
pub fn evaluate_levels(
    config: &serde_json::Value,
    source: &str,
    channel_id: &str,
    event_id: &str,
    cooldown_ready: bool,
    duration_minutes: u64,
    before_xp: i64,
) -> LevelsDecision {
    let object = config.as_object();
    let source = source.trim().to_ascii_lowercase();
    let before_xp = before_xp.max(0);
    let before_level = before_xp / 100 + 1;
    let ignored = object
        .and_then(|values| values.get("ignoredChannels"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|channels| {
            channels.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|candidate| candidate.trim() == channel_id.trim())
            })
        });
    let reject = |reason_code: &'static str, explanation: String| LevelsDecision {
        allowed: false,
        source: source.clone(),
        amount: 0,
        before_xp,
        after_xp: before_xp,
        before_level,
        after_level: before_level,
        reason_code,
        explanation,
    };
    if ignored {
        return reject(
            "channel_ignored",
            format!(
                "Channel `{}` is excluded from XP awards.",
                channel_id.trim()
            ),
        );
    }
    let amount = match source.as_str() {
        "message" => {
            if !cooldown_ready {
                return reject(
                    "cooldown_active",
                    "This member is still within the configured XP cooldown.".into(),
                );
            }
            let minimum = object
                .and_then(|values| values.get("xpMin"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(15)
                .clamp(1, 1_000);
            let maximum = object
                .and_then(|values| values.get("xpMax"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(30)
                .clamp(minimum, 2_000);
            let span = (maximum - minimum + 1) as u64;
            let stable = event_id.bytes().fold(0_u64, |total, byte| {
                total.wrapping_mul(33).wrapping_add(byte as u64)
            });
            minimum + (stable % span) as i64
        }
        "voice" => {
            if !object
                .and_then(|values| values.get("voiceXpEnabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return reject(
                    "voice_xp_disabled",
                    "Voice XP is disabled for this server.".into(),
                );
            }
            let per_minute = object
                .and_then(|values| values.get("voiceXpPerMinute"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(2)
                .clamp(0, 30);
            duration_minutes.min(24 * 60) as i64 * per_minute
        }
        _ => {
            return reject(
                "unsupported_source",
                "Only message and voice XP are supported.".into(),
            );
        }
    };
    if amount <= 0 {
        return reject(
            "no_xp_awarded",
            "This event does not produce any XP with the current settings.".into(),
        );
    }
    let after_xp = before_xp.saturating_add(amount);
    let after_level = after_xp / 100 + 1;
    LevelsDecision {
        allowed: true,
        source: source.clone(),
        amount,
        before_xp,
        after_xp,
        before_level,
        after_level,
        reason_code: "xp_awarded",
        explanation: format!(
            "Award {amount} XP from this {} event (level {} → {}).",
            if source == "voice" {
                "voice"
            } else {
                "message"
            },
            before_level,
            after_level
        ),
    }
}

/// Parse the bounded `leaderboardEntries` fixture accepted by the simulation
/// endpoint. Invalid rows are ignored just like rows without a Discord user
/// in the runtime store.
pub fn leaderboard_entries_from_json(value: &serde_json::Value) -> Vec<LeaderboardEntry> {
    value
        .get("leaderboardEntries")
        .or_else(|| value.get("leaderboard_entries"))
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| serde_json::from_value::<LeaderboardEntry>(row.clone()).ok())
                .take(1_000)
                .collect()
        })
        .unwrap_or_default()
}

/// Bounded policy shared by workflow simulation and the Discord message
/// handler.  Keeping this in the pure core crate prevents the panel from
/// previewing a different reply than the bot actually sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowPolicy {
    pub max_reply_length: usize,
    pub allow_mentions: bool,
}

impl Default for WorkflowPolicy {
    fn default() -> Self {
        Self {
            max_reply_length: 1_000,
            allow_mentions: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowObservation {
    pub enabled: bool,
    pub trigger: String,
    pub condition: String,
    pub action: String,
    pub payload: String,
    pub message_content: String,
    pub user_mention: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowDecision {
    pub matched: bool,
    pub should_run: bool,
    pub reply: Option<String>,
    pub reaction: Option<String>,
    pub reason: String,
}

/// Evaluate one bounded message workflow. The supported actions are a
/// bounded reply or a short Unicode reaction; unsupported actions are
/// reported as a non-match rather than silently being treated as successful.
pub fn evaluate_workflow(
    policy: &WorkflowPolicy,
    observation: &WorkflowObservation,
) -> WorkflowDecision {
    let content = observation.message_content.trim();
    if !observation.enabled {
        return WorkflowDecision {
            matched: false,
            should_run: false,
            reply: None,
            reaction: None,
            reason: "disabled".into(),
        };
    }
    if observation.trigger != "message" {
        return WorkflowDecision {
            matched: false,
            should_run: false,
            reply: None,
            reaction: None,
            reason: "unsupported_trigger".into(),
        };
    }
    if !observation.condition.trim().is_empty()
        && !content
            .to_lowercase()
            .contains(&observation.condition.to_lowercase())
    {
        return WorkflowDecision {
            matched: false,
            should_run: false,
            reply: None,
            reaction: None,
            reason: "condition_not_met".into(),
        };
    }
    let (reply, reaction) = match observation.action.as_str() {
        "reply" => {
            let mut reply = observation
                .payload
                .replace("{user}", &observation.user_mention)
                .replace("{message}", &truncate_chars(content, 500));
            if !policy.allow_mentions {
                reply = reply
                    .replace("@everyone", "@\u{200b}everyone")
                    .replace("@here", "@\u{200b}here");
            }
            (
                Some(truncate_chars(
                    &reply,
                    policy.max_reply_length.clamp(1, 1_500),
                )),
                None,
            )
        }
        "react" if is_valid_workflow_reaction(&observation.payload) => {
            (None, Some(observation.payload.trim().to_string()))
        }
        "react" => {
            return WorkflowDecision {
                matched: true,
                should_run: false,
                reply: None,
                reaction: None,
                reason: "invalid_reaction".into(),
            };
        }
        _ => {
            return WorkflowDecision {
                matched: true,
                should_run: false,
                reply: None,
                reaction: None,
                reason: "unsupported_action".into(),
            };
        }
    };
    WorkflowDecision {
        matched: true,
        should_run: true,
        reply,
        reaction,
        reason: "matched".into(),
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

/// Add the greeting emoji to the legacy default without rewriting custom copy.
pub fn render_welcome_message(template: &str, member: &str, server: &str) -> String {
    let template = if template == "Welcome {member} to {server}!" {
        "👋 Welcome {member} to {server}!"
    } else {
        template
    };
    render_member_message(template, member, server)
}

/// Render bounded member/server variables, suppress mass mentions and keep the
/// result within Discord's message limit, including for legacy settings.
pub fn render_member_message(template: &str, member: &str, server: &str) -> String {
    let rendered = template
        .replace("{member}", member)
        .replace("{server}", server)
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here");
    truncate_chars(
        &rendered
            .chars()
            .filter(|character| !character.is_control())
            .collect::<String>(),
        2_000,
    )
}

/// Render a reusable Studio template using the same bounded rules as the
/// Discord gateway. Only the template's `config` object is considered, and
/// only string content fields can reach Discord. Invalid, empty, oversized or
/// control-character content falls back to the caller-provided message.
pub fn render_bounded_template_message(
    template: &serde_json::Value,
    slot: &str,
    fallback: &str,
) -> String {
    let config = template
        .get("config")
        .and_then(serde_json::Value::as_object);
    let candidate = config.and_then(|object| {
        object
            .get(slot)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                object
                    .get(&format!("{slot}Message"))
                    .and_then(serde_json::Value::as_str)
            })
            .or_else(|| object.get("content").and_then(serde_json::Value::as_str))
            .or_else(|| object.get("message").and_then(serde_json::Value::as_str))
    });
    let Some(message) = candidate else {
        return fallback.to_owned();
    };
    if message.trim().is_empty()
        || message.chars().count() > 2_000
        || message.chars().any(char::is_control)
    {
        return fallback.to_owned();
    }
    message
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AchievementPolicy {
    pub first_threshold: i64,
    pub regular_threshold: i64,
    pub pillar_threshold: i64,
}

impl Default for AchievementPolicy {
    fn default() -> Self {
        Self {
            first_threshold: 100,
            regular_threshold: 1_000,
            pillar_threshold: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AchievementUnlock {
    pub key: &'static str,
    pub label: &'static str,
    pub threshold: i64,
}

/// Return the milestones reached by the supplied XP balance.  The runtime
/// persists each returned key idempotently; the API uses the same pure result
/// for its preview.
pub fn evaluate_achievements(policy: &AchievementPolicy, xp: i64) -> Vec<AchievementUnlock> {
    let xp = xp.max(0);
    [
        (
            "first_steps",
            "First steps",
            policy.first_threshold.clamp(1, 1_000_000),
        ),
        (
            "regular",
            "Regular",
            policy.regular_threshold.clamp(1, 1_000_000),
        ),
        (
            "community_pillar",
            "Community pillar",
            policy.pillar_threshold.clamp(1, 1_000_000),
        ),
    ]
    .into_iter()
    .filter(|(_, _, threshold)| xp >= *threshold)
    .map(|(key, label, threshold)| AchievementUnlock {
        key,
        label,
        threshold,
    })
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationPolicy {
    pub require_reason: bool,
    pub max_purge: u64,
}

impl Default for ModerationPolicy {
    fn default() -> Self {
        Self {
            require_reason: true,
            max_purge: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationObservation {
    pub action: String,
    pub reason: String,
    pub requested_count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationDecision {
    pub allowed: bool,
    pub effective_count: Option<u64>,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Evaluate the bounded safety envelope used by manual moderation commands.
/// This function has no Discord or store dependency, so API simulations and
/// production command handlers cannot drift apart on reasons or purge limits.
pub fn evaluate_moderation(
    policy: &ModerationPolicy,
    observation: &ModerationObservation,
) -> ModerationDecision {
    let action = observation.action.trim().to_ascii_lowercase();
    let supported = [
        "warn", "kick", "ban", "timeout", "tempban", "softban", "purge",
    ];
    if !supported.contains(&action.as_str()) {
        return ModerationDecision {
            allowed: false,
            effective_count: None,
            reason_code: "unsupported_action",
            explanation: format!("The moderation action `{action}` is not supported."),
        };
    }

    if action == "purge" {
        let Some(requested) = observation.requested_count else {
            return ModerationDecision {
                allowed: false,
                effective_count: None,
                reason_code: "count_required",
                explanation: "Choose how many messages to purge.".into(),
            };
        };
        if requested <= 0 {
            return ModerationDecision {
                allowed: false,
                effective_count: None,
                reason_code: "invalid_count",
                explanation: "The purge count must be at least 1.".into(),
            };
        }
        let maximum = policy.max_purge.clamp(1, 100);
        let effective = (requested as u64).min(maximum);
        let explanation = if requested as u64 > maximum {
            format!("Purge is limited to {maximum} messages by this server's policy.")
        } else {
            format!("Purge up to {effective} message(s).")
        };
        return ModerationDecision {
            allowed: true,
            effective_count: Some(effective),
            reason_code: if requested as u64 > maximum {
                "count_clamped"
            } else {
                "allowed"
            },
            explanation,
        };
    }

    if policy.require_reason && observation.reason.trim().is_empty() {
        return ModerationDecision {
            allowed: false,
            effective_count: None,
            reason_code: "reason_required",
            explanation: "Provide a reason so the action can be audited.".into(),
        };
    }

    ModerationDecision {
        allowed: true,
        effective_count: None,
        reason_code: "allowed",
        explanation: format!("The `{action}` action is allowed by the server policy."),
    }
}

/// Every configurable feature will eventually implement this contract. The
/// first adapter is intentionally small: it proves that the API and gateway
/// can consume one canonical schema/defaults/validator without pulling UI
/// concerns into the Discord crate.
pub trait FeatureAdapter: Sync {
    fn descriptor(&self) -> FeatureAdapterDescriptor;
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue>;
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)>;

    /// Produce a bounded, side-effect-free preview from the same projection
    /// that is published to the runtime.  The helper below is deliberately
    /// keyed by the adapter descriptor rather than by an HTTP route, so every
    /// feature gets a meaningful runtime action even when its configuration is
    /// currently just a feature gate.
    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let descriptor = self.descriptor();
        let projection = self.runtime_projection(config);
        simulate_feature_effect(&descriptor.key, config, fixture, &projection)
    }
}

fn fixture_string<'a>(
    fixture: &'a serde_json::Value,
    camel: &str,
    snake: &str,
    fallback: &'a str,
) -> &'a str {
    fixture
        .get(camel)
        .or_else(|| fixture.get(snake))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
}

fn fixture_u64(fixture: &serde_json::Value, camel: &str, snake: &str, fallback: u64) -> u64 {
    fixture
        .get(camel)
        .or_else(|| fixture.get(snake))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(fallback)
}

fn fixture_bool(fixture: &serde_json::Value, camel: &str, snake: &str, fallback: bool) -> bool {
    fixture
        .get(camel)
        .or_else(|| fixture.get(snake))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(fallback)
}

fn fixture_strings(fixture: &serde_json::Value, camel: &str, snake: &str) -> Vec<String> {
    fixture
        .get(camel)
        .or_else(|| fixture.get(snake))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .take(100)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketDecision {
    pub allowed: bool,
    pub max_open: u32,
    pub open_tickets: u32,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Keep the per-member ticket limit in one pure evaluator so the dashboard
/// simulation and the Discord component cannot disagree about whether a new
/// private channel may be opened.
pub fn evaluate_tickets(config: &serde_json::Value, open_tickets: u32) -> TicketDecision {
    let max_open = config
        .get("maxOpen")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1)
        .clamp(1, 10) as u32;
    if open_tickets >= max_open {
        return TicketDecision {
            allowed: false,
            max_open,
            open_tickets,
            reason_code: "max_open_reached",
            explanation: format!(
                "This member already has {open_tickets}/{max_open} open ticket(s)."
            ),
        };
    }
    TicketDecision {
        allowed: true,
        max_open,
        open_tickets,
        reason_code: "ticket_slot_available",
        explanation: format!(
            "A new private ticket may be opened ({open_tickets}/{max_open} currently open)."
        ),
    }
}

/// Describe the observable operation represented by a feature publication.
/// This is intentionally pure and bounded: it never calls Discord or an
/// external provider.  The Discord handlers consume the same projected
/// setting keys and the API uses this function for its preview, so the panel
/// cannot claim that it only "saved JSON".
fn simulate_feature_effect(
    key: &str,
    config: &serde_json::Value,
    fixture: &serde_json::Value,
    projection: &[(String, String)],
) -> Vec<String> {
    let channel = fixture
        .get("channelId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("the selected channel");
    let content = fixture
        .get("content")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("the preview event");
    let object = config.as_object();
    let effect = match key {
        "community.leaderboard" => format!(
            "Read the XP ledger and publish a {} leaderboard for {channel}.",
            if object
                .and_then(|values| values.get("public"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                "public"
            } else {
                "private"
            }
        ),
        "community.achievements" =>
            "Evaluate the member's XP/message milestones and grant each eligible reward once.".into(),
        "community.birthdays" =>
            "Run the timezone-aware birthday job and send the configured message without exposing a birth year.".into(),
        "management.nickname" =>
            "Apply the Helper nickname after a fresh Manage Nicknames and hierarchy preflight.".into(),
        "management.moderation" =>
            "Route the moderation action through policy, hierarchy checks, an idempotency key and an audit record.".into(),
        "management.audit" =>
            "Route the selected Discord events to the configured log destination and enforce retention.".into(),
        "management.privacy" =>
            "Create a guild-scoped export or erasure receipt while preserving required moderation evidence.".into(),
        "management.templates" =>
            "Render the selected template with approved variables and Discord size/mention limits before publishing.".into(),
        "management.custom_commands" =>
            "Resolve the saved response with bounded variables; user-provided code is never executed.".into(),
        "utility.help" =>
            "Return the enabled modules, command examples and the dashboard link for this server.".into(),
        "utility.reminders" =>
            "Create an idempotent reminder job with the configured timezone, recurrence and delivery channel.".into(),
        "utility.emojis" =>
            "Read the server emoji inventory, apply the configured filters and return a bounded result set.".into(),
        "utility.embeds" =>
            "Render the bounded embed preview with mentions disabled, then publish only after preflight.".into(),
        "utility.search" =>
            "Query only the enabled approved providers and return a rate-limited result set; arbitrary URLs are not fetched.".into(),
        "utility.temp_channels" => {
            let template = object
                .and_then(|values| values.get("nameTemplate"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("{user}'s room");
            let maximum = object
                .and_then(|values| values.get("maxActive"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(10);
            format!("Create a temporary voice room named `{template}` (up to {maximum} active rooms) and clean it up after a full disconnect.")
        }
        "insights.stats" =>
            "Update the configured statistics channel from the latest guild counters and expose freshness/health.".into(),
        "community.economy" =>
            "Append an idempotent economy ledger entry and derive the member balance from the ledger.".into(),
        "community.role_panels" =>
            "Publish bounded role-panel components after checking every role's manageability and hierarchy.".into(),
        "community.events" =>
            "Create or update the scheduled event, persist registrations and enqueue the configured reminders.".into(),
        "community.suggestions" => {
            let mode = object
                .and_then(|values| values.get("voteMode"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("up_down");
            let cooldown = object
                .and_then(|values| values.get("cooldownHours"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(24)
                .clamp(0, 720);
            let staff = object
                .and_then(|values| values.get("staffChannel"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!(" and notify staff in <#{value}>"))
                .unwrap_or_default();
            format!(
                "Create the suggestion with {mode} voting, enforce a {cooldown}-hour member cooldown{staff}, and keep every state transition auditable."
            )
        }
        "community.giveaways" =>
            "Create an idempotent giveaway job with bounded winners, role requirements and a replay-safe draw.".into(),
        "management.polls" =>
            "Publish the poll interaction and persist each vote with duplicate protection and a closing job.".into(),
        "support.tickets" =>
            "Create a private ticket channel with the configured team overwrites, claim/SLA state and transcript policy.".into(),
        "support.welcome" =>
            "Send the welcome message/DM and apply the configured auto-role on member join, with a safe fallback channel.".into(),
        "support.welcome_channel" =>
            "Publish the guided welcome panel with rules, first steps and bounded confirmation components.".into(),
        "studio.rank_card" =>
            "Render the XP card using only curated backgrounds, colours and the member's current XP snapshot.".into(),
        "social.youtube" | "social.rss" | "social.podcasts" | "social.twitch" | "social.bluesky"
        | "social.instagram" | "social.tiktok" | "social.kick" =>
            "Validate the subscription, enqueue a deduplicated provider job and deliver the rendered alert to the selected channel.".into(),
        "web3.crypto_stats" | "web3.crypto_queries" | "web3.gas_tracker" =>
            "Query the configured read-only provider with bounded caching, freshness metadata and rate-limit handling.".into(),
        "growth.monetization" =>
            "Create or update the server's Connect capability only after onboarding, webhook and compliance checks.".into(),
        "web3.gating" =>
            "Verify a single-use SIWE nonce and reconcile only the configured ERC-20/721/1155 role rules.".into(),
        "protection.antispam" | "protection.antiscam" | "protection.anti_raid" | "protection.join_gate" =>
            format!("Evaluate `{content}` against the configured protection policy, then apply only the allow-listed action after preflight."),
        _ if projection.is_empty() =>
            "Enable the feature's Discord event/command handler and record the publication in the audit stream.".into(),
        _ => format!(
            "Publish the validated settings ({}) to the feature's Discord runtime consumer and record an audit event.",
            projection.len()
        ),
    };
    let mut effects = vec![effect];
    // Keep the exact projected keys visible in the preview.  This is useful
    // for operators and, more importantly, proves that the effect is tied to
    // the same persisted values consumed by the runtime.
    effects.extend(
        projection
            .iter()
            .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
    );
    effects
}

/// Adapter for modules whose Discord behaviour is already command/interaction
/// driven and therefore has no additional server-side knobs yet.  An empty
/// schema is intentional: the panel can publish the feature toggle without
/// inventing controls that the runtime would ignore.
#[derive(Debug, Clone, Copy)]
pub struct ToggleOnlyAdapter {
    pub key: &'static str,
    pub source: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub dependencies: &'static [&'static str],
}

/// Adapter for provider subscriptions whose persistence and workers live in
/// the API/modules crates.  The subscription editor still belongs to the
/// canonical feature registry so production never falls back to a blank
/// toggle-only form.
#[derive(Debug, Clone, Copy)]
pub struct AlertSubscriptionAdapter {
    pub key: &'static str,
    pub source: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub source_key: &'static str,
    pub source_label: &'static str,
    pub source_help: &'static str,
    pub default_template: &'static str,
    pub dependencies: &'static [&'static str],
}

impl FeatureAdapter for AlertSubscriptionAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: self.source.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": self.source,
                "sections": [{
                    "title": self.title,
                    "description": self.description,
                    "fields": [
                        {"key": self.source_key, "label": self.source_label, "kind": "text", "help": self.source_help},
                        {"key": "targetChannelId", "label": "Discord channel", "kind": "channel"},
                        {"key": "intervalSeconds", "label": "Polling interval (seconds)", "kind": "number", "min": 900, "max": 86400},
                        {"key": "messageTemplate", "label": "Alert message", "kind": "textarea", "advanced": true},
                        {"key": "mention", "label": "Optional mention", "kind": "text", "advanced": true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                self.source_key: "",
                "targetChannelId": "",
                "intervalSeconds": 900,
                "messageTemplate": self.default_template,
                "mention": ""
            }),
            dependencies: self
                .dependencies
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Alert configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        let source = object
            .get(self.source_key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if source.is_empty() || source.chars().count() > 100 {
            issues.push(ValidationIssue {
                path: self.source_key.into(),
                code: "required".into(),
                message: format!(
                    "{} must be provided and at most 100 characters.",
                    self.source_label
                ),
                severity: "error".into(),
            });
        }
        let channel = object
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if channel.is_empty() || !valid_discord_id(channel) {
            issues.push(ValidationIssue {
                path: "targetChannelId".into(),
                code: "invalid_discord_id".into(),
                message: "Choose a real Discord channel for alerts.".into(),
                severity: "error".into(),
            });
        }
        if let Some(interval) = object
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            && !(900..=86_400).contains(&interval)
        {
            issues.push(ValidationIssue {
                path: "intervalSeconds".into(),
                code: "out_of_range".into(),
                message: "The polling interval must be between 900 and 86400 seconds.".into(),
                severity: "error".into(),
            });
        }
        if let Some(template) = object.get("messageTemplate")
            && (!template.is_string()
                || template
                    .as_str()
                    .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 1_800))
        {
            issues.push(ValidationIssue {
                path: "messageTemplate".into(),
                code: "invalid_template".into(),
                message: "The alert message must be non-empty and at most 1800 characters.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let prefix = self.key.replace('.', "_");
        let mut projection = Vec::new();
        for field in [
            self.source_key,
            "targetChannelId",
            "intervalSeconds",
            "messageTemplate",
            "mention",
        ] {
            if let Some(value) = object.get(field) {
                let value = value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_i64().map(|number| number.to_string()));
                if let Some(value) = value {
                    projection.push((format!("{prefix}.{field}"), value));
                }
            }
        }
        projection
    }
}

/// Configuration for interaction-driven community modules.  Keeping these
/// schemas in the core registry prevents the panel from inventing controls
/// that the Discord handlers do not understand.
#[derive(Debug, Clone, Copy)]
pub struct CommunityInteractionAdapter {
    pub key: &'static str,
    pub source: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub schema: &'static str,
    pub defaults: &'static str,
    pub dependencies: &'static [&'static str],
    pub projection: fn(&serde_json::Value) -> Vec<(String, String)>,
}

/// The pure selection decision used by role-panel previews and component
/// interactions.  Discord-specific checks (managed roles, hierarchy and
/// permissions) happen at the gateway boundary; this value only describes
/// the bounded state transition once those checks have passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePanelObservation {
    pub panel_role_ids: Vec<u64>,
    pub selected_role_ids: Vec<u64>,
    pub clicked_role_id: u64,
    pub selection_mode: String,
    pub remove_on_unselect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePanelDecision {
    pub allowed: bool,
    pub assign_clicked: bool,
    pub remove_role_ids: Vec<u64>,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// The bounded poll publication decision shared by the dashboard preview and
/// the Discord `/poll` command.  Keeping the duration, destination and
/// choice limits here prevents a valid-looking panel setting from drifting
/// away from what the command actually publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollDecision {
    pub allowed: bool,
    pub question: String,
    pub options: Vec<String>,
    pub channel_id: String,
    pub duration_ms: i64,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_poll(
    config: &serde_json::Value,
    question: &str,
    options: &[String],
    duration_override_ms: Option<i64>,
    command_channel_id: &str,
) -> PollDecision {
    let object = config.as_object();
    let question = question.trim();
    if question.is_empty() {
        return PollDecision {
            allowed: false,
            question: String::new(),
            options: Vec::new(),
            channel_id: String::new(),
            duration_ms: 0,
            reason_code: "question_required",
            explanation: "A poll needs a question.".into(),
        };
    }
    if question.chars().count() > 256 {
        return PollDecision {
            allowed: false,
            question: question.chars().take(256).collect(),
            options: Vec::new(),
            channel_id: String::new(),
            duration_ms: 0,
            reason_code: "question_too_long",
            explanation: "The poll question must be 256 characters or fewer.".into(),
        };
    }
    let options = options
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if options.len() < 2 {
        return PollDecision {
            allowed: false,
            question: question.into(),
            options,
            channel_id: String::new(),
            duration_ms: 0,
            reason_code: "options_required",
            explanation: "A poll needs at least two non-empty options.".into(),
        };
    }
    if options.len() > 5 {
        return PollDecision {
            allowed: false,
            question: question.into(),
            options,
            channel_id: String::new(),
            duration_ms: 0,
            reason_code: "too_many_options",
            explanation: "A poll can have at most five options.".into(),
        };
    }
    if let Some(value) = options
        .iter()
        .find(|value| value.chars().count() > 70)
        .cloned()
    {
        return PollDecision {
            allowed: false,
            question: question.into(),
            options,
            channel_id: String::new(),
            duration_ms: 0,
            reason_code: "option_too_long",
            explanation: format!("Poll option `{value}` must be 70 characters or fewer."),
        };
    }
    let channel_id = object
        .and_then(|values| values.get("channel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_discord_id(value))
        .unwrap_or(command_channel_id)
        .to_owned();
    let default_hours = object
        .and_then(|values| values.get("defaultDurationHours"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(24)
        .clamp(1, 168);
    if duration_override_ms.is_some_and(|value| !(60_000..=168 * 3_600_000).contains(&value)) {
        return PollDecision {
            allowed: false,
            question: question.into(),
            options,
            channel_id,
            duration_ms: 0,
            reason_code: "invalid_duration",
            explanation: "A poll must last between one minute and seven days.".into(),
        };
    }
    let duration_ms = duration_override_ms.unwrap_or(default_hours * 3_600_000);
    PollDecision {
        allowed: true,
        question: question.into(),
        options,
        channel_id,
        duration_ms,
        reason_code: "poll_ready",
        explanation: "The poll is within Discord's bounded question, option and duration limits."
            .into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GiveawayDecision {
    pub allowed: bool,
    pub prize: String,
    pub winners: u64,
    pub duration_ms: i64,
    pub required_role_id: Option<String>,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// The bounded decision used when creating a native Discord scheduled event.
/// Both dashboard previews and the gateway command use this value so defaults
/// such as capacity, destination and reminders cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDecision {
    pub allowed: bool,
    pub name: String,
    pub location: String,
    pub description: String,
    pub start_unix: i64,
    pub end_unix: i64,
    pub capacity: Option<i64>,
    pub announcement_channel_id: Option<String>,
    pub reminders: bool,
    pub reminder_hours: i64,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Validate and resolve event defaults without talking to Discord.  The
/// caller still performs the Discord permission/hierarchy preflight, while
/// this pure decision owns all bounded input and scheduling rules.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_event(
    config: &serde_json::Value,
    name: &str,
    location: &str,
    description: &str,
    start_unix: i64,
    end_unix: i64,
    capacity_override: Option<i64>,
    now_unix: i64,
) -> EventDecision {
    let object = config.as_object();
    let name = name.trim().to_owned();
    let location = location.trim().to_owned();
    let description = description.trim().to_owned();
    let empty = || EventDecision {
        allowed: false,
        name: name.clone(),
        location: location.clone(),
        description: description.clone(),
        start_unix,
        end_unix,
        capacity: None,
        announcement_channel_id: None,
        reminders: false,
        reminder_hours: 1,
        reason_code: "invalid_event",
        explanation: String::new(),
    };
    if !(1..=100).contains(&name.chars().count()) {
        let mut decision = empty();
        decision.reason_code = "invalid_name";
        decision.explanation = "The event name must be between 1 and 100 characters.".into();
        return decision;
    }
    if !(1..=100).contains(&location.chars().count()) {
        let mut decision = empty();
        decision.reason_code = "invalid_location";
        decision.explanation = "The event location must be between 1 and 100 characters.".into();
        return decision;
    }
    if description.chars().count() > 1_000 {
        let mut decision = empty();
        decision.reason_code = "description_too_long";
        decision.explanation = "The event description must be 1,000 characters or fewer.".into();
        return decision;
    }
    if start_unix <= now_unix {
        let mut decision = empty();
        decision.reason_code = "start_must_be_in_future";
        decision.explanation = "The event start must be in the future.".into();
        return decision;
    }
    if end_unix <= start_unix {
        let mut decision = empty();
        decision.reason_code = "end_must_follow_start";
        decision.explanation = "The event end must be after its start.".into();
        return decision;
    }
    if end_unix.saturating_sub(start_unix) > 365 * 86_400 {
        let mut decision = empty();
        decision.reason_code = "event_too_long";
        decision.explanation = "The event cannot last longer than 365 days.".into();
        return decision;
    }
    let capacity = capacity_override
        .or_else(|| {
            object
                .and_then(|values| values.get("defaultCapacity"))
                .and_then(serde_json::Value::as_i64)
        })
        .unwrap_or(0);
    if !(0..=100_000).contains(&capacity) {
        let mut decision = empty();
        decision.reason_code = "invalid_capacity";
        decision.explanation = "Capacity must be between 1 and 100,000, or 0 for unlimited.".into();
        return decision;
    }
    let announcement_channel_id = object
        .and_then(|values| values.get("announcementChannel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned);
    if announcement_channel_id
        .as_deref()
        .is_some_and(|value| !valid_discord_id(value))
    {
        let mut decision = empty();
        decision.reason_code = "invalid_announcement_channel";
        decision.explanation = "Choose a valid Discord announcement channel.".into();
        return decision;
    }
    let reminders = object
        .and_then(|values| values.get("reminders"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let reminder_hours = object
        .and_then(|values| values.get("reminderHours"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1);
    if !(1..=168).contains(&reminder_hours) {
        let mut decision = empty();
        decision.reason_code = "invalid_reminder_hours";
        decision.explanation = "Reminder time must be between 1 and 168 hours.".into();
        return decision;
    }
    EventDecision {
        allowed: true,
        name,
        location,
        description,
        start_unix,
        end_unix,
        capacity: (capacity > 0).then_some(capacity),
        announcement_channel_id,
        reminders,
        reminder_hours,
        reason_code: "event_ready",
        explanation: "The event satisfies Discord's bounded name, schedule and capacity limits."
            .into(),
    }
}

/// Bound giveaway creation before a durable draw is scheduled.  The API
/// preview and the Discord command use the same prize, winner, duration and
/// eligibility rules.
pub fn evaluate_giveaway(
    config: &serde_json::Value,
    prize: &str,
    winners_override: Option<i64>,
    duration_override_ms: Option<i64>,
    required_role_override: Option<&str>,
) -> GiveawayDecision {
    let prize = prize.trim();
    if prize.is_empty() {
        return GiveawayDecision {
            allowed: false,
            prize: String::new(),
            winners: 0,
            duration_ms: 0,
            required_role_id: None,
            reason_code: "prize_required",
            explanation: "A giveaway needs a prize description.".into(),
        };
    }
    if prize.chars().count() > 200 {
        return GiveawayDecision {
            allowed: false,
            prize: prize.chars().take(200).collect(),
            winners: 0,
            duration_ms: 0,
            required_role_id: None,
            reason_code: "prize_too_long",
            explanation: "The giveaway prize must be 200 characters or fewer.".into(),
        };
    }
    let object = config.as_object();
    let winners = winners_override
        .or_else(|| {
            object
                .and_then(|values| values.get("defaultWinners"))
                .and_then(serde_json::Value::as_i64)
        })
        .unwrap_or(1)
        .clamp(1, 20);
    let default_hours = object
        .and_then(|values| values.get("defaultDurationHours"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(24)
        .clamp(1, 168);
    if duration_override_ms.is_some_and(|value| !(60_000..=168 * 3_600_000).contains(&value)) {
        return GiveawayDecision {
            allowed: false,
            prize: prize.into(),
            winners: winners as u64,
            duration_ms: 0,
            required_role_id: None,
            reason_code: "invalid_duration",
            explanation: "Giveaway duration must be between 1 minute and 7 days.".into(),
        };
    }
    let duration_ms = duration_override_ms.unwrap_or(default_hours * 3_600_000);
    let required_role = required_role_override
        .or_else(|| {
            object
                .and_then(|values| values.get("requiredRole"))
                .and_then(serde_json::Value::as_str)
        })
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned);
    if required_role
        .as_deref()
        .is_some_and(|value| !valid_discord_id(value))
    {
        return GiveawayDecision {
            allowed: false,
            prize: prize.into(),
            winners: winners as u64,
            duration_ms,
            required_role_id: required_role,
            reason_code: "invalid_required_role",
            explanation: "The required giveaway role must be a valid Discord role ID.".into(),
        };
    }
    GiveawayDecision {
        allowed: true,
        prize: prize.into(),
        winners: winners as u64,
        duration_ms,
        required_role_id: required_role,
        reason_code: "giveaway_ready",
        explanation: "The giveaway is within bounded prize, winner and duration limits.".into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestionDecision {
    pub allowed: bool,
    pub text: String,
    pub vote_mode: String,
    pub anonymous: bool,
    pub channel_id: String,
    pub staff_channel_id: Option<String>,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Normalize the suggestion publication contract shared by the API preview
/// and `/suggest`. Cooldowns and role membership remain gateway/store checks,
/// while message bounds, destinations and voting mode are pure decisions.
pub fn evaluate_suggestion(
    config: &serde_json::Value,
    text: &str,
    command_channel_id: &str,
) -> SuggestionDecision {
    let text = text.trim();
    if !(3..=1_000).contains(&text.chars().count()) {
        return SuggestionDecision {
            allowed: false,
            text: text.into(),
            vote_mode: String::new(),
            anonymous: false,
            channel_id: String::new(),
            staff_channel_id: None,
            reason_code: "text_length_invalid",
            explanation: "A suggestion must contain between 3 and 1000 characters.".into(),
        };
    }
    let object = config.as_object();
    let vote_mode = object
        .and_then(|values| values.get("voteMode"))
        .and_then(serde_json::Value::as_str)
        .filter(|mode| matches!(*mode, "up_down" | "up_only"))
        .unwrap_or("up_down")
        .to_owned();
    let channel_id = object
        .and_then(|values| values.get("channel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_discord_id(value))
        .unwrap_or(command_channel_id)
        .to_owned();
    let staff_channel_id = object
        .and_then(|values| values.get("staffChannel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned);
    if staff_channel_id
        .as_deref()
        .is_some_and(|value| !valid_discord_id(value))
    {
        return SuggestionDecision {
            allowed: false,
            text: text.into(),
            vote_mode,
            anonymous: object
                .and_then(|values| values.get("anonymous"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            channel_id,
            staff_channel_id,
            reason_code: "invalid_staff_channel",
            explanation: "The staff notification destination must be a valid Discord channel ID."
                .into(),
        };
    }
    SuggestionDecision {
        allowed: true,
        text: text.into(),
        vote_mode,
        anonymous: object
            .and_then(|values| values.get("anonymous"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        channel_id,
        staff_channel_id,
        reason_code: "suggestion_ready",
        explanation:
            "The suggestion is ready for publication with bounded voting and destinations.".into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BirthdayDecision {
    pub allowed: bool,
    pub message: String,
    pub channel_id: String,
    pub timezone: String,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Validate the privacy-preserving birthday delivery contract. Only day and
/// month are accepted; the year is deliberately absent from the decision.
pub fn evaluate_birthday(
    config: &serde_json::Value,
    member_id: &str,
    month: u32,
    day: u32,
) -> BirthdayDecision {
    let object = config.as_object();
    let valid_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => (1..=31).contains(&day),
        4 | 6 | 9 | 11 => (1..=30).contains(&day),
        2 => (1..=29).contains(&day),
        _ => false,
    };
    if !valid_day {
        return BirthdayDecision {
            allowed: false,
            message: String::new(),
            channel_id: String::new(),
            timezone: String::new(),
            reason_code: "invalid_date",
            explanation: "Choose a real calendar day and month for the birthday.".into(),
        };
    }
    let channel_id = object
        .and_then(|values| values.get("channel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_discord_id(value))
        .unwrap_or_default()
        .to_owned();
    if channel_id.is_empty() {
        return BirthdayDecision {
            allowed: false,
            message: String::new(),
            channel_id,
            timezone: String::new(),
            reason_code: "channel_required",
            explanation: "Choose a real announcement channel before enabling birthdays.".into(),
        };
    }
    let message = object
        .and_then(|values| values.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Happy birthday, {user}! 🎉")
        .trim();
    if !(1..=1_000).contains(&message.chars().count()) {
        return BirthdayDecision {
            allowed: false,
            message: message.into(),
            channel_id,
            timezone: String::new(),
            reason_code: "message_length_invalid",
            explanation: "The birthday message must contain between 1 and 1000 characters.".into(),
        };
    }
    let timezone = object
        .and_then(|values| values.get("timezone"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| parse_utc_offset_minutes(value).is_some())
        .unwrap_or("UTC")
        .to_owned();
    BirthdayDecision {
        allowed: true,
        message: truncate_chars(
            &message.replace("{user}", &format!("<@{member_id}>")),
            2_000,
        ),
        channel_id,
        timezone,
        reason_code: "birthday_ready",
        explanation:
            "Birthday delivery is bounded to the configured channel, timezone and day/month.".into(),
    }
}

/// Evaluate a single role-panel click without touching Discord.  Keeping
/// this transition in `helper-core` means the API preview and the Serenity
/// interaction handler cannot drift on unique/multiple or toggle-off rules.
pub fn evaluate_role_panel(observation: &RolePanelObservation) -> RolePanelDecision {
    let clicked_is_panel_role = observation
        .panel_role_ids
        .contains(&observation.clicked_role_id);
    if !clicked_is_panel_role {
        return RolePanelDecision {
            allowed: false,
            assign_clicked: false,
            remove_role_ids: Vec::new(),
            reason_code: "role_not_in_panel",
            explanation: "The clicked role is not part of this role panel.".into(),
        };
    }

    let selected = observation
        .selected_role_ids
        .iter()
        .copied()
        .filter(|role_id| observation.panel_role_ids.contains(role_id))
        .collect::<Vec<_>>();
    if selected.contains(&observation.clicked_role_id) {
        if !observation.remove_on_unselect {
            return RolePanelDecision {
                allowed: true,
                assign_clicked: false,
                remove_role_ids: Vec::new(),
                reason_code: "role_kept",
                explanation: "This panel keeps selected roles assigned when toggled.".into(),
            };
        }
        return RolePanelDecision {
            allowed: true,
            assign_clicked: false,
            remove_role_ids: vec![observation.clicked_role_id],
            reason_code: "role_removed",
            explanation: "Remove the selected role because toggle-off is enabled.".into(),
        };
    }

    let remove_role_ids = if observation.selection_mode == "unique" {
        selected
            .into_iter()
            .filter(|role_id| *role_id != observation.clicked_role_id)
            .collect()
    } else {
        Vec::new()
    };
    RolePanelDecision {
        allowed: true,
        assign_clicked: true,
        remove_role_ids,
        reason_code: if observation.selection_mode == "unique" {
            "role_assigned_unique"
        } else {
            "role_assigned"
        },
        explanation: if observation.selection_mode == "unique" {
            "Assign the clicked role and remove other selected roles from this panel.".into()
        } else {
            "Assign the clicked role without removing other selections.".into()
        },
    }
}

fn project_suggestions(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    if let Some(value) = object.get("channel").and_then(serde_json::Value::as_str) {
        pairs.push(("community.suggestions.channel_id".into(), value.into()));
    }
    if let Some(value) = object.get("anonymous").and_then(serde_json::Value::as_bool) {
        pairs.push(("community.suggestions.anonymous".into(), value.to_string()));
    }
    if let Some(value) = object
        .get("requiredRole")
        .and_then(serde_json::Value::as_str)
    {
        pairs.push(("community.suggestions.required_role".into(), value.into()));
    }
    if let Some(value) = object
        .get("voteMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "up_down" || *mode == "up_only")
    {
        pairs.push(("community.suggestions.vote_mode".into(), value.into()));
    }
    if let Some(value) = object
        .get("cooldownHours")
        .and_then(serde_json::Value::as_i64)
        .filter(|hours| (0..=720).contains(hours))
    {
        pairs.push((
            "community.suggestions.cooldown_hours".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("staffChannel")
        .and_then(serde_json::Value::as_str)
    {
        pairs.push((
            "community.suggestions.staff_channel_id".into(),
            value.into(),
        ));
    }
    pairs
}

fn project_giveaways(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    if let Some(value) = object
        .get("defaultDurationHours")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "community.giveaways.default_duration_hours".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("defaultWinners")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "community.giveaways.default_winners".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("requiredRole")
        .and_then(serde_json::Value::as_str)
    {
        pairs.push(("community.giveaways.required_role".into(), value.into()));
    }
    pairs
}

fn project_polls(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    if let Some(value) = object
        .get("defaultDurationHours")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "management.polls.default_duration_hours".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object.get("channel").and_then(serde_json::Value::as_str) {
        pairs.push(("management.polls.channel_id".into(), value.into()));
    }
    pairs
}

fn project_events(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    if let Some(value) = object
        .get("defaultDurationHours")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "community.events.default_duration_hours".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("defaultCapacity")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "community.events.default_capacity".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("announcementChannel")
        .and_then(serde_json::Value::as_str)
    {
        pairs.push((
            "community.events.announcement_channel_id".into(),
            value.into(),
        ));
    }
    if let Some(value) = object.get("reminders").and_then(serde_json::Value::as_bool) {
        pairs.push(("community.events.reminders".into(), value.to_string()));
    }
    if let Some(value) = object
        .get("reminderHours")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push(("community.events.reminder_hours".into(), value.to_string()));
    }
    pairs
}

fn project_role_panels(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (field, key) in [
        ("channel", "community.role_panels.channel_id"),
        ("panelTitle", "community.role_panels.title"),
        ("panelDescription", "community.role_panels.description"),
    ] {
        if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
            pairs.push((key.into(), value.into()));
        }
    }
    if let Some(value) = object.get("maxRoles").and_then(serde_json::Value::as_i64) {
        pairs.push(("community.role_panels.max_roles".into(), value.to_string()));
    }
    if let Some(value) = object
        .get("removeOnUnselect")
        .and_then(serde_json::Value::as_bool)
    {
        pairs.push((
            "community.role_panels.remove_on_unselect".into(),
            value.to_string(),
        ));
    }
    if let Some(value) = object
        .get("selectionMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "multiple" || *mode == "unique")
    {
        pairs.push(("community.role_panels.selection_mode".into(), value.into()));
    }
    if let Some(values) = object.get("roleIds").and_then(serde_json::Value::as_array) {
        let ids = values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter(|value| valid_discord_id(value))
            .take(5)
            .collect::<Vec<_>>();
        if !ids.is_empty() {
            pairs.push(("community.role_panels.role_ids".into(), ids.join(",")));
        }
    }
    pairs
}

fn validate_interaction_config(config: &serde_json::Value, key: &str) -> Vec<ValidationIssue> {
    let Some(object) = config.as_object() else {
        return vec![ValidationIssue {
            path: "config".into(),
            code: "object_required".into(),
            message: "The configuration must be an object.".into(),
            severity: "error".into(),
        }];
    };
    let mut issues = Vec::new();
    for field in [
        "channel",
        "requiredRole",
        "announcementChannel",
        "staffChannel",
    ] {
        if object.get(field).is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|text| !text.trim().is_empty() && !valid_discord_id(text))
        }) {
            issues.push(ValidationIssue {
                path: field.into(),
                code: "invalid_discord_id".into(),
                message: "Choose a valid Discord channel or role.".into(),
                severity: "error".into(),
            });
        }
    }
    for field in ["anonymous", "removeOnUnselect", "reminders"] {
        if object.get(field).is_some_and(|value| !value.is_boolean()) {
            issues.push(ValidationIssue {
                path: field.into(),
                code: "boolean_required".into(),
                message: "This option must be true or false.".into(),
                severity: "error".into(),
            });
        }
    }
    for (field, min, max) in [
        (
            "defaultDurationHours",
            1_i64,
            if key == "community.events" {
                8760_i64
            } else {
                168_i64
            },
        ),
        ("defaultWinners", 1_i64, 20_i64),
        ("defaultCapacity", 0_i64, 100_000_i64),
        ("maxRoles", 1_i64, 5_i64),
        ("cooldownHours", 0_i64, 720_i64),
        ("reminderHours", 1_i64, 168_i64),
    ] {
        if let Some(value) = object.get(field) {
            if value.as_i64().is_none() {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "integer_required".into(),
                    message: "This value must be an integer.".into(),
                    severity: "error".into(),
                });
            } else if !value
                .as_i64()
                .is_some_and(|number| (min..=max).contains(&number))
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: format!("Value must be between {min} and {max}."),
                    severity: "error".into(),
                });
            }
        }
    }
    if key == "community.suggestions"
        && let Some(value) = object.get("voteMode")
        && !value
            .as_str()
            .is_some_and(|mode| mode == "up_down" || mode == "up_only")
    {
        issues.push(ValidationIssue {
            path: "voteMode".into(),
            code: "invalid_vote_mode".into(),
            message: "Choose support/against voting or support-only voting.".into(),
            severity: "error".into(),
        });
    }
    if key == "community.role_panels" {
        for (field, max) in [("panelTitle", 80_usize), ("panelDescription", 1_000_usize)] {
            if let Some(value) = object.get(field)
                && (value.as_str().is_none()
                    || value
                        .as_str()
                        .is_some_and(|text| text.chars().count() > max))
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_text".into(),
                    message: format!("Text must be at most {max} characters."),
                    severity: "error".into(),
                });
            }
        }
        if let Some(values) = object.get("roleIds") {
            let valid = values.as_array().is_some_and(|items| {
                !items.is_empty()
                    && items.len() <= 5
                    && items
                        .iter()
                        .all(|value| value.as_str().is_some_and(valid_discord_id))
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "roleIds".into(),
                    code: "invalid_role_ids".into(),
                    message: "Choose between one and five valid Discord roles.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("selectionMode") {
            let valid = value
                .as_str()
                .is_some_and(|mode| mode == "multiple" || mode == "unique");
            if !valid {
                issues.push(ValidationIssue {
                    path: "selectionMode".into(),
                    code: "invalid_selection_mode".into(),
                    message: "Choose multiple roles or one role at a time.".into(),
                    severity: "error".into(),
                });
            }
        }
    }
    issues
}

impl FeatureAdapter for CommunityInteractionAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: self.source.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::from_str(self.schema)
                .expect("community adapter schema is valid JSON"),
            defaults: serde_json::from_str(self.defaults)
                .expect("community adapter defaults are valid JSON"),
            dependencies: self
                .dependencies
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        validate_interaction_config(config, self.key)
    }
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        (self.projection)(config)
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        if self.key == "community.birthdays" {
            let member_id = fixture_string(fixture, "memberId", "member_id", "1234567890");
            let month = fixture_u64(fixture, "month", "month", 1) as u32;
            let day = fixture_u64(fixture, "day", "day", 1) as u32;
            let decision = evaluate_birthday(config, member_id, month, day);
            let mut effects = if !decision.allowed {
                vec![format!(
                    "Birthday delivery rejected ({}): {}",
                    decision.reason_code, decision.explanation
                )]
            } else {
                vec![format!(
                    "Announce birthday in <#{}> using {}: {}",
                    decision.channel_id, decision.timezone, decision.message
                )]
            };
            effects.extend(
                self.runtime_projection(config)
                    .into_iter()
                    .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
            );
            return effects;
        }
        if self.key == "community.suggestions" {
            let text = fixture_string(
                fixture,
                "content",
                "content",
                "A bounded suggestion preview.",
            );
            let decision = evaluate_suggestion(
                config,
                text,
                fixture_string(fixture, "channelId", "channel_id", "preview-channel"),
            );
            let mut effects = if !decision.allowed {
                vec![format!(
                    "Suggestion rejected ({}): {}",
                    decision.reason_code, decision.explanation
                )]
            } else {
                let audience = if decision.anonymous {
                    "anonymously"
                } else {
                    "with the author"
                };
                let staff = decision
                    .staff_channel_id
                    .as_deref()
                    .map(|value| format!(" and notify staff in <#{value}>"))
                    .unwrap_or_default();
                let cooldown = config
                    .get("cooldownHours")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(24)
                    .clamp(0, 720);
                vec![format!(
                    "Publish suggestion {audience} in <#{}> with {} voting and a {cooldown}-hour member cooldown{staff}.",
                    decision.channel_id, decision.vote_mode
                )]
            };
            effects.extend(
                self.runtime_projection(config)
                    .into_iter()
                    .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
            );
            return effects;
        }
        if self.key == "management.polls" {
            let question = fixture_string(fixture, "question", "question", "Preview poll");
            let options = fixture_strings(fixture, "options", "options");
            let options = if options.is_empty() {
                vec!["Option one".into(), "Option two".into()]
            } else {
                options
            };
            let duration_override_ms = fixture
                .get("durationMs")
                .or_else(|| fixture.get("duration_ms"))
                .and_then(serde_json::Value::as_i64);
            let channel_id = fixture_string(fixture, "channelId", "channel_id", "preview-channel");
            let decision =
                evaluate_poll(config, question, &options, duration_override_ms, channel_id);
            let mut effects = if !decision.allowed {
                vec![format!(
                    "Poll rejected ({}): {}",
                    decision.reason_code, decision.explanation
                )]
            } else {
                vec![format!(
                    "Publish poll `{}` with {} options in <#{}> for {} hour(s).",
                    decision.question,
                    decision.options.len(),
                    decision.channel_id,
                    decision.duration_ms / 3_600_000
                )]
            };
            effects.extend(
                self.runtime_projection(config)
                    .into_iter()
                    .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
            );
            return effects;
        }
        if self.key == "community.giveaways" {
            let prize = fixture_string(fixture, "prize", "prize", "Preview prize");
            let winners = fixture
                .get("winners")
                .or_else(|| fixture.get("winnerCount"))
                .and_then(serde_json::Value::as_i64);
            let duration_override_ms = fixture
                .get("durationMs")
                .or_else(|| fixture.get("duration_ms"))
                .and_then(serde_json::Value::as_i64);
            let required_role = fixture
                .get("requiredRole")
                .or_else(|| fixture.get("required_role"))
                .and_then(serde_json::Value::as_str);
            let decision =
                evaluate_giveaway(config, prize, winners, duration_override_ms, required_role);
            let mut effects = if !decision.allowed {
                vec![format!(
                    "Giveaway rejected ({}): {}",
                    decision.reason_code, decision.explanation
                )]
            } else {
                let role = decision
                    .required_role_id
                    .as_deref()
                    .map(|value| format!(" requiring <@&{value}>"))
                    .unwrap_or_default();
                vec![format!(
                    "Create giveaway `{}` with {} winner(s) for {} hour(s){} and schedule an idempotent draw.",
                    decision.prize,
                    decision.winners,
                    decision.duration_ms / 3_600_000,
                    role
                )]
            };
            effects.extend(
                self.runtime_projection(config)
                    .into_iter()
                    .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
            );
            return effects;
        }
        if self.key == "community.events" {
            let now_unix = fixture_u64(fixture, "nowUnix", "now_unix", 1_700_000_000) as i64;
            let start_unix = fixture_u64(
                fixture,
                "startUnix",
                "start_unix",
                (now_unix as u64).saturating_add(3_600),
            ) as i64;
            let end_unix = fixture_u64(
                fixture,
                "endUnix",
                "end_unix",
                (start_unix as u64).saturating_add(7_200),
            ) as i64;
            let capacity_override = fixture
                .get("capacity")
                .or_else(|| fixture.get("capacityOverride"))
                .and_then(serde_json::Value::as_i64);
            let decision = evaluate_event(
                config,
                fixture_string(fixture, "name", "name", "Preview event"),
                fixture_string(fixture, "location", "location", "Preview room"),
                fixture_string(
                    fixture,
                    "description",
                    "description",
                    "A bounded event preview.",
                ),
                start_unix,
                end_unix,
                capacity_override,
                now_unix,
            );
            let mut effects = if !decision.allowed {
                vec![format!(
                    "Event rejected ({}): {}",
                    decision.reason_code, decision.explanation
                )]
            } else {
                let capacity = decision
                    .capacity
                    .map(|value| format!(" with capacity {value}"))
                    .unwrap_or_default();
                let reminder = if decision.reminders {
                    format!(" and a {}-hour reminder", decision.reminder_hours)
                } else {
                    String::from(" with reminders disabled")
                };
                let announcement = decision
                    .announcement_channel_id
                    .as_deref()
                    .map(|value| format!("; announce in <#{value}>"))
                    .unwrap_or_default();
                vec![format!(
                    "Create native Discord event `{}` from <t:{}:F> to <t:{}:F>{capacity}{reminder}{announcement}.",
                    decision.name, decision.start_unix, decision.end_unix
                )]
            };
            effects.extend(
                self.runtime_projection(config)
                    .into_iter()
                    .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
            );
            return effects;
        }
        if self.key != "community.role_panels" {
            let descriptor = self.descriptor();
            return simulate_feature_effect(
                &descriptor.key,
                config,
                fixture,
                &self.runtime_projection(config),
            );
        }

        let panel_role_ids = config
            .get("roleIds")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|value| value.parse::<u64>().ok().filter(|id| *id != 0))
                    .take(5)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let selected_role_ids = fixture
            .get("selectedRoleIds")
            .or_else(|| fixture.get("selected_role_ids"))
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|value| value.parse::<u64>().ok().filter(|id| *id != 0))
                    .take(5)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let clicked_role_id = fixture
            .get("clickedRoleId")
            .or_else(|| fixture.get("clicked_role_id"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok().filter(|id| *id != 0))
            .or_else(|| panel_role_ids.first().copied())
            .unwrap_or_default();
        let selection_mode = config
            .get("selectionMode")
            .and_then(serde_json::Value::as_str)
            .filter(|mode| matches!(*mode, "multiple" | "unique"))
            .unwrap_or("multiple")
            .to_owned();
        let remove_on_unselect = config
            .get("removeOnUnselect")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let decision = evaluate_role_panel(&RolePanelObservation {
            panel_role_ids,
            selected_role_ids,
            clicked_role_id,
            selection_mode,
            remove_on_unselect,
        });
        let mut effects = if !decision.allowed {
            vec![format!(
                "Role-panel click rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        } else if decision.assign_clicked {
            let removed = if decision.remove_role_ids.is_empty() {
                String::new()
            } else {
                format!(
                    " Remove first: {}.",
                    decision
                        .remove_role_ids
                        .iter()
                        .map(|role_id| role_id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            vec![format!("Assign role {}.{}", clicked_role_id, removed)]
        } else if decision.remove_role_ids.is_empty() {
            vec![format!(
                "Keep role {} assigned because toggle-off is disabled.",
                clicked_role_id
            )]
        } else {
            vec![format!("Remove role {}.", clicked_role_id)]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Settings for temporary voice rooms.  The command already creates and
/// cleans up rooms in the Discord runtime; exposing these bounded controls
/// makes the dashboard publish the same values that command handler reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct TempChannelsAdapter;

impl TempChannelsAdapter {
    pub const KEY: &'static str = "utility.temp_channels";
    pub const SOURCE: &'static str = "temp_channels_adapter_v2";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempChannelDecision {
    pub allowed: bool,
    pub room_name: String,
    pub active_rooms: u64,
    pub max_active: u64,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Bound temporary-channel creation before it reaches Discord.  The command
/// and the API preview share the same cap and template rendering rules.
pub fn evaluate_temp_channel(
    template: &str,
    display_name: &str,
    active_rooms: u64,
    max_active: u64,
) -> TempChannelDecision {
    let max_active = max_active.clamp(1, 50);
    if active_rooms >= max_active {
        return TempChannelDecision {
            allowed: false,
            room_name: String::new(),
            active_rooms,
            max_active,
            reason_code: "active_limit_reached",
            explanation: format!(
                "The server already has {active_rooms} active temporary rooms (limit {max_active})."
            ),
        };
    }
    let display_name = display_name.trim();
    let fallback_name = if display_name.is_empty() {
        "member's room".to_owned()
    } else {
        format!("{display_name}'s room")
    };
    let room_name = template
        .replace(
            "{user}",
            if display_name.is_empty() {
                "member"
            } else {
                display_name
            },
        )
        .chars()
        .filter(|character| !character.is_control())
        .take(100)
        .collect::<String>();
    let room_name = if room_name.trim().is_empty() {
        fallback_name
    } else {
        room_name
    };
    TempChannelDecision {
        allowed: true,
        room_name,
        active_rooms,
        max_active,
        reason_code: "room_allowed",
        explanation: "The temporary room is below the configured active-room limit.".into(),
    }
}

impl FeatureAdapter for TempChannelsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Temporary voice rooms",
                    "description": "Create bounded rooms with a predictable name and optional category.",
                    "fields": [
                        {"key":"categoryId","label":"Category (optional)","kind":"category","help":"New rooms are created inside this category when selected."},
                        {"key":"nameTemplate","label":"Room name template","kind":"text","min":1,"max":80,"help":"Use {user} for the member display name."},
                        {"key":"maxActive","label":"Maximum active rooms","kind":"number","min":1,"max":50}
                    ]
                }]
            }),
            defaults: serde_json::json!({"categoryId":"", "nameTemplate":"{user}'s room", "maxActive": 10}),
            dependencies: vec!["manage_channels".into(), "voice_states".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("categoryId")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "categoryId".into(),
                code: "invalid_category_id".into(),
                message: "Choose a valid Discord category.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("nameTemplate") {
            let valid = value.as_str().is_some_and(|text| {
                let count = text.chars().count();
                (1..=80).contains(&count) && !text.chars().any(char::is_control)
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "nameTemplate".into(),
                    code: "invalid_template".into(),
                    message: "The room name must be 1-80 characters without control characters."
                        .into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("maxActive") {
            if let Some(value) = value.as_i64() {
                if !(1..=50).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "maxActive".into(),
                        code: "out_of_range".into(),
                        message: "Maximum active rooms must be between 1 and 50.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "maxActive".into(),
                    code: "integer_required".into(),
                    message: "Maximum active rooms must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        if let Some(value) = object.get("categoryId").and_then(serde_json::Value::as_str) {
            pairs.push(("utility.temp_channels.category_id".into(), value.into()));
        }
        if let Some(value) = object
            .get("nameTemplate")
            .and_then(serde_json::Value::as_str)
        {
            pairs.push(("utility.temp_channels.name_template".into(), value.into()));
        }
        if let Some(value) = object.get("maxActive").and_then(serde_json::Value::as_i64) {
            pairs.push(("utility.temp_channels.max_active".into(), value.to_string()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let template = config
            .get("nameTemplate")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("{user}'s room");
        let display_name = fixture
            .get("userName")
            .or_else(|| fixture.get("user_name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Preview member");
        let active_rooms = fixture
            .get("activeTempRooms")
            .or_else(|| fixture.get("active_temp_rooms"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let max_active = config
            .get("maxActive")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(10);
        let decision = evaluate_temp_channel(template, display_name, active_rooms, max_active);
        let mut effects = if decision.allowed {
            vec![format!(
                "Create the temporary voice room `{}` ({}/{} active rooms).",
                decision.room_name, decision.active_rooms, decision.max_active
            )]
        } else {
            vec![format!(
                "Temporary room rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Decision returned by the bounded custom-command evaluator.  The same
/// parser, guards and renderer are used by the API preview and gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomCommandDecision {
    pub allowed: bool,
    pub command_name: String,
    pub args: String,
    pub response: String,
    pub reason_code: &'static str,
    pub explanation: String,
}

fn parse_custom_command_input(content: &str, prefix: &str) -> Option<(String, String)> {
    let prefix = prefix.trim();
    if prefix.is_empty() || !content.starts_with(prefix) {
        return None;
    }
    let remainder = content[prefix.len()..].trim_start();
    let mut parts = remainder.splitn(2, char::is_whitespace);
    let name = parts.next()?.trim().to_lowercase();
    if name.is_empty()
        || name.len() > 32
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return None;
    }
    Some((
        name,
        parts
            .next()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(512)
            .collect(),
    ))
}

/// Evaluate a saved response without Discord or store access. `tag_content`
/// is `None` when the named tag does not exist in the guild.
pub fn evaluate_custom_command(
    config: &serde_json::Value,
    content: &str,
    channel_id: &str,
    actor_is_staff: bool,
    tag_content: Option<&str>,
    user_id: &str,
    server_name: &str,
) -> CustomCommandDecision {
    let prefix = config
        .get("triggerPrefix")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("!");
    let Some((command_name, args)) = parse_custom_command_input(content, prefix) else {
        return CustomCommandDecision {
            allowed: false,
            command_name: String::new(),
            args: String::new(),
            response: String::new(),
            reason_code: "not_a_custom_command",
            explanation: "The message does not use the configured command prefix.".into(),
        };
    };
    let ignored = config
        .get("ignoredChannels")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|channels| {
            channels.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|candidate| candidate.trim() == channel_id)
            })
        });
    if ignored {
        return CustomCommandDecision {
            allowed: false,
            command_name,
            args,
            response: String::new(),
            reason_code: "channel_ignored",
            explanation: "Custom commands are disabled in this channel.".into(),
        };
    }
    if config
        .get("staffOnly")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && !actor_is_staff
    {
        return CustomCommandDecision {
            allowed: false,
            command_name,
            args,
            response: String::new(),
            reason_code: "staff_only",
            explanation: "Only server staff can use custom commands in this server.".into(),
        };
    }
    let Some(tag_content) = tag_content else {
        return CustomCommandDecision {
            allowed: false,
            command_name,
            args,
            response: String::new(),
            reason_code: "tag_not_found",
            explanation: "No saved response exists for this command.".into(),
        };
    };
    let max_chars = config
        .get("maxResponseLength")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1_000)
        .clamp(1, 2_000) as usize;
    let response = tag_content
        .replace("{user}", &format!("<@{user_id}>"))
        .replace("{channel}", &format!("<#{}>", channel_id))
        .replace("{server}", server_name)
        .replace("{args}", &args)
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here")
        .chars()
        .take(max_chars)
        .collect::<String>();
    if response.trim().is_empty() {
        return CustomCommandDecision {
            allowed: false,
            command_name,
            args,
            response,
            reason_code: "empty_response",
            explanation: "The saved response is empty after rendering.".into(),
        };
    }
    CustomCommandDecision {
        allowed: true,
        command_name,
        args,
        response,
        reason_code: "custom_command_ready",
        explanation: "The saved response can be sent with broadcast mentions disabled.".into(),
    }
}

/// Adapter for the tag-backed custom command module.  Tags are the bounded,
/// user-authored responses exposed by `/tag` and `/tag-set`; the adapter keeps
/// the limits in the same source of truth as the runtime instead of leaving
/// them as hard-coded command constants.
#[derive(Debug, Clone, Copy, Default)]
pub struct CustomCommandsAdapter;

impl CustomCommandsAdapter {
    pub const KEY: &'static str = "management.custom_commands";
    pub const SOURCE: &'static str = "custom_commands_adapter_v2";
}

impl FeatureAdapter for CustomCommandsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Custom command behaviour",
                    "description": "Saved responses are deliberately bounded and never execute code.",
                    "fields": [
                        {"key":"triggerPrefix","label":"Command prefix","kind":"text","maxLength":3,"help":"The character(s) members type before a saved command, for example !rules."},
                        {"key":"ignoredChannels","label":"Ignored channels","kind":"channels","advanced":true,"help":"Commands are not answered in these channels."},
                        {"key":"staffOnly","label":"Staff-only commands","kind":"toggle","advanced":true,"help":"Only members with Manage Server or Administrator can invoke saved commands."},
                        {"key":"maxTags","label":"Maximum saved commands","kind":"number","min":1,"max":100,"help":"The maximum number of saved responses this server can keep."},
                        {"key":"maxResponseLength","label":"Maximum response length","kind":"number","min":1,"max":2000,"help":"Responses longer than this are rejected before they can be sent."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"triggerPrefix":"!","ignoredChannels":[],"staffOnly":false,"maxTags": 100, "maxResponseLength": 1000}),
            dependencies: vec!["message_content".into(), "send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("triggerPrefix") {
            let valid = value.as_str().is_some_and(|prefix| {
                let trimmed = prefix.trim();
                !trimmed.is_empty()
                    && trimmed.len() <= 3
                    && trimmed.chars().all(|character| {
                        !character.is_whitespace()
                            && !character.is_control()
                            && !matches!(character, '@' | '#' | ':' | '`')
                    })
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "triggerPrefix".into(),
                    code: "invalid_prefix".into(),
                    message: "Command prefix must be 1-3 visible non-space characters and cannot use mention syntax.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("ignoredChannels") {
            let valid = value.as_array().is_some_and(|channels| {
                channels.len() <= 50
                    && channels.iter().all(|channel| {
                        channel.as_str().is_some_and(|id| {
                            valid_discord_id(id.trim()) && id.chars().count() <= 20
                        })
                    })
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "ignoredChannels".into(),
                    code: "invalid_channels".into(),
                    message: "Ignored channels must contain at most 50 Discord channel IDs.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("staffOnly")
            && !value.is_boolean()
        {
            issues.push(ValidationIssue {
                path: "staffOnly".into(),
                code: "boolean_required".into(),
                message: "Staff-only commands must be a boolean.".into(),
                severity: "error".into(),
            });
        }
        for (field, min, max, label) in [
            ("maxTags", 1_i64, 100_i64, "Maximum saved commands"),
            (
                "maxResponseLength",
                1_i64,
                2_000_i64,
                "Maximum response length",
            ),
        ] {
            if let Some(value) = object.get(field) {
                if let Some(value) = value.as_i64() {
                    if !(min..=max).contains(&value) {
                        issues.push(ValidationIssue {
                            path: field.into(),
                            code: "out_of_range".into(),
                            message: format!("{label} must be between {min} and {max}."),
                            severity: "error".into(),
                        });
                    }
                } else {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "integer_required".into(),
                        message: format!("{label} must be an integer."),
                        severity: "error".into(),
                    });
                }
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object
            .get("triggerPrefix")
            .and_then(serde_json::Value::as_str)
        {
            projection.push((
                "management.custom_commands.trigger_prefix".into(),
                value.trim().to_string(),
            ));
        }
        if let Some(values) = object
            .get("ignoredChannels")
            .and_then(serde_json::Value::as_array)
        {
            let channels = values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            projection.push((
                "management.custom_commands.ignored_channels".into(),
                channels,
            ));
        }
        if let Some(value) = object.get("staffOnly").and_then(serde_json::Value::as_bool) {
            projection.push((
                "management.custom_commands.staff_only".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object.get("maxTags").and_then(serde_json::Value::as_i64) {
            projection.push((
                "management.custom_commands.max_tags".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("maxResponseLength")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "management.custom_commands.max_response_length".into(),
                value.to_string(),
            ));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let content = fixture
            .get("content")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("!rules");
        let channel_id = fixture
            .get("channelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("preview-channel");
        let actor_is_staff = fixture
            .get("actorIsStaff")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let decision = evaluate_custom_command(
            config,
            content,
            channel_id,
            actor_is_staff,
            fixture
                .get("tagContent")
                .or_else(|| fixture.get("template"))
                .and_then(serde_json::Value::as_str),
            fixture
                .get("userId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("preview-user"),
            fixture
                .get("serverName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Preview server"),
        );
        let mut effects = if decision.allowed {
            vec![format!(
                "Send custom command `{}` with {} characters and broadcast mentions disabled.",
                decision.command_name,
                decision.response.chars().count()
            )]
        } else {
            vec![format!(
                "Custom command rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDecision {
    pub should_contain: bool,
    pub shadow_mode: bool,
    pub threshold: i64,
    pub window_seconds: i64,
    pub incident_minutes: i64,
    pub log_channel_id: Option<String>,
    pub include_content: bool,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Resolve the destructive-action guard from the same bounded policy exposed
/// by the dashboard. `destructive_actions` is the number observed in the
/// current window; the Discord gateway supplies the real count after its
/// in-memory burst latch fires.
pub fn evaluate_audit(config: &serde_json::Value, destructive_actions: i64) -> AuditDecision {
    let object = config.as_object();
    let threshold = object
        .and_then(|values| values.get("threshold"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(3)
        .clamp(2, 25);
    let window_seconds = object
        .and_then(|values| values.get("windowSeconds"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(10)
        .clamp(3, 60);
    let incident_minutes = object
        .and_then(|values| values.get("incidentMinutes"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(10)
        .clamp(1, 120);
    let shadow_mode = object
        .and_then(|values| values.get("shadowMode"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let include_content = object
        .and_then(|values| values.get("includeContent"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let log_channel_id = object
        .and_then(|values| values.get("logChannel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned);
    if log_channel_id
        .as_deref()
        .is_some_and(|value| !valid_discord_id(value))
    {
        return AuditDecision {
            should_contain: false,
            shadow_mode,
            threshold,
            window_seconds,
            incident_minutes,
            log_channel_id: None,
            include_content,
            reason_code: "invalid_log_channel",
            explanation: "Choose a valid Discord audit log channel.".into(),
        };
    }
    if destructive_actions < threshold {
        return AuditDecision {
            should_contain: false,
            shadow_mode,
            threshold,
            window_seconds,
            incident_minutes,
            log_channel_id,
            include_content,
            reason_code: "below_threshold",
            explanation: format!(
                "The current window has {destructive_actions}/{threshold} destructive actions."
            ),
        };
    }
    AuditDecision {
        should_contain: !shadow_mode,
        shadow_mode,
        threshold,
        window_seconds,
        incident_minutes,
        log_channel_id,
        include_content,
        reason_code: if shadow_mode {
            "shadow_alert"
        } else {
            "containment_required"
        },
        explanation: if shadow_mode {
            format!(
                "The threshold was reached in {window_seconds}s; record and alert without containment."
            )
        } else {
            format!(
                "The threshold was reached in {window_seconds}s; enable the join gate for review."
            )
        },
    }
}

/// The audit feature controls the existing destructive-action guard and its
/// shadow mode.  Keeping these projections here makes the panel toggle and
/// the `/anti-nuke` command operate on the same persisted settings.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditAdapter;

impl AuditAdapter {
    pub const KEY: &'static str = "management.audit";
    pub const SOURCE: &'static str = "audit_adapter_v1";
}

impl FeatureAdapter for AuditAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Destructive action protection",
                    "description": "Record audit events and contain repeated destructive changes.",
                    "fields": [
                        {"key":"threshold","label":"Actions before containment","kind":"number","min":2,"max":25},
                        {"key":"windowSeconds","label":"Detection window (seconds)","kind":"number","min":3,"max":60},
                        {"key":"incidentMinutes","label":"Containment duration (minutes)","kind":"number","min":1,"max":120,"help":"The join gate restores its earlier state when this temporary containment expires."},
                        {"key":"shadowMode","label":"Shadow mode","kind":"toggle","help":"Record and alert without automatic containment."},
                        {"key":"logChannel","label":"Audit log channel (optional)","kind":"channel","advanced":true},
                        {"key":"includeContent","label":"Include cached message content","kind":"toggle","advanced":true,"help":"Off by default. Discord may not provide content for every edit/delete event."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"threshold": 3, "windowSeconds": 10, "incidentMinutes": 10, "shadowMode": false, "logChannel": "", "includeContent": false}),
            dependencies: vec!["view_audit_log".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for (field, min, max, label) in [
            ("threshold", 2_i64, 25_i64, "Threshold"),
            ("windowSeconds", 3_i64, 60_i64, "Window"),
            ("incidentMinutes", 1_i64, 120_i64, "Containment duration"),
        ] {
            if let Some(value) = object.get(field) {
                if let Some(value) = value.as_i64() {
                    if !(min..=max).contains(&value) {
                        issues.push(ValidationIssue {
                            path: field.into(),
                            code: "out_of_range".into(),
                            message: format!("{label} must be between {min} and {max}."),
                            severity: "error".into(),
                        });
                    }
                } else {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "integer_required".into(),
                        message: format!("{label} must be an integer."),
                        severity: "error".into(),
                    });
                }
            }
        }
        if object
            .get("shadowMode")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "shadowMode".into(),
                code: "boolean_required".into(),
                message: "Shadow mode must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if object.get("logChannel").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|raw| raw.is_empty() || valid_discord_id(raw))
        }) {
            issues.push(ValidationIssue {
                path: "logChannel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel or leave it empty.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("includeContent")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "includeContent".into(),
                code: "boolean_required".into(),
                message: "Content logging must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object.get("threshold").and_then(serde_json::Value::as_i64) {
            projection.push(("security.anti_nuke.actions".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("windowSeconds")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "security.anti_nuke.window_seconds".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("incidentMinutes")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "security.anti_nuke.incident_minutes".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("shadowMode")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("security.shadow_mode".into(), value.to_string()));
        }
        if let Some(value) = object.get("logChannel").and_then(serde_json::Value::as_str) {
            projection.push(("management.audit.log_channel".into(), value.into()));
        }
        if let Some(value) = object
            .get("includeContent")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("management.audit.include_content".into(), value.to_string()));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let actions = fixture_u64(fixture, "destructiveActions", "destructive_actions", 3) as i64;
        let decision = evaluate_audit(config, actions);
        let mut effects = if decision.reason_code == "invalid_log_channel" {
            vec![format!(
                "Audit simulation rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        } else if decision.should_contain {
            vec![format!(
                "Contain the executor after {} destructive actions in {}s by enabling the join gate for {} minutes and recording an audit case.",
                decision.threshold, decision.window_seconds, decision.incident_minutes
            )]
        } else if decision.shadow_mode && actions >= decision.threshold {
            vec![format!(
                "Alert only after {} destructive actions in {}s; no containment is applied in shadow mode.",
                decision.threshold, decision.window_seconds
            )]
        } else {
            vec![decision.explanation]
        };
        effects.push(format!(
            "Audit content persistence is {}.",
            if decision.include_content {
                "enabled for cached content"
            } else {
                "metadata-only"
            }
        ));
        if let Some(channel_id) = decision.log_channel_id {
            effects.push(format!("Audit alerts route to <#{channel_id}>."));
        }
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Import/export already exists in the durable store.  This adapter exposes
/// the capability with no invented JSON controls; the API gates those routes
/// by this feature toggle and keeps resource mapping/validation server-side.
#[derive(Debug, Clone, Copy, Default)]
pub struct TemplatesAdapter;

impl TemplatesAdapter {
    pub const KEY: &'static str = "management.templates";
    pub const SOURCE: &'static str = "templates_adapter_v1";
}

impl FeatureAdapter for TemplatesAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({"version": FEATURE_SCHEMA_VERSION, "source": Self::SOURCE, "sections": [{"title":"Portable templates", "description":"Save and transfer validated server configuration without copying secrets.", "fields": []}]}),
            defaults: serde_json::json!({}),
            dependencies: vec!["manager_session".into()],
        }
    }
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        if config.is_object() {
            Vec::new()
        } else {
            vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }]
        }
    }
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        // Templates are consumed by the import/export endpoints rather than a
        // Discord event handler.  Still publish an explicit, guild-scoped
        // policy so the adapter cannot appear configured while the module is
        // silently disabled.
        let enabled = config.is_object();
        vec![("management.templates.enabled".into(), enabled.to_string())]
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let slot = fixture_string(fixture, "slot", "slot", "content");
        let fallback = fixture_string(
            fixture,
            "fallback",
            "fallback",
            "Template preview unavailable.",
        );
        let template = fixture.get("template").unwrap_or(config);
        let rendered = render_bounded_template_message(template, slot, fallback);
        let used_fallback = rendered == fallback;
        let mut effects = vec![format!("Render the bounded `{slot}` template: {rendered}")];
        if used_fallback {
            effects.push(
                "The template was missing or outside safe Discord limits; the fallback will be used."
                    .into(),
            );
        }
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BirthdaysAdapter;

impl BirthdaysAdapter {
    pub const KEY: &'static str = "community.birthdays";
    pub const SOURCE: &'static str = "birthdays_adapter_v1";
}

impl FeatureAdapter for BirthdaysAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Birthday announcements",
                    "description": "Store only day and month and announce birthdays once per year.",
                    "fields": [
                        {"key":"channel","label":"Announcement channel","kind":"channel"},
                        {"key":"message","label":"Announcement message","kind":"text","min":1,"max":1000,"help":"Use {user} for the member mention."},
                        {"key":"timezone","label":"Announcement timezone","kind":"select","options":[["UTC","UTC"],["UTC-05:00","UTC-05:00"],["UTC+01:00","UTC+01:00"],["UTC+02:00","UTC+02:00"],["UTC+05:30","UTC+05:30"],["UTC+08:00","UTC+08:00"]],"help":"The local day used to decide when a birthday announcement is sent."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"channel":"", "message":"Happy birthday, {user}! 🎉", "timezone":"UTC"}),
            dependencies: vec![
                "guild_members".into(),
                "send_messages".into(),
                "scheduler".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if !object
            .get("channel")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| valid_discord_id(value.trim()))
        {
            issues.push(ValidationIssue {
                path: "channel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a real Discord announcement channel.".into(),
                severity: "error".into(),
            });
        }
        if let Some(message) = object.get("message") {
            if let Some(message) = message.as_str() {
                if !(1..=1000).contains(&message.chars().count()) {
                    issues.push(ValidationIssue {
                        path: "message".into(),
                        code: "out_of_range".into(),
                        message: "Birthday message must be between 1 and 1000 characters.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "message".into(),
                    code: "string_required".into(),
                    message: "Birthday message must be text.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(timezone) = object.get("timezone") {
            let valid = timezone
                .as_str()
                .and_then(parse_utc_offset_minutes)
                .is_some();
            if !valid {
                issues.push(ValidationIssue {
                    path: "timezone".into(),
                    code: "invalid_timezone".into(),
                    message:
                        "Birthday timezone must be UTC or a fixed offset between -14:00 and +14:00."
                            .into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let member_id = fixture_string(fixture, "memberId", "member_id", "1234567890");
        let month = fixture_u64(fixture, "month", "month", 1) as u32;
        let day = fixture_u64(fixture, "day", "day", 1) as u32;
        let decision = evaluate_birthday(config, member_id, month, day);
        let mut effects = if !decision.allowed {
            vec![format!(
                "Birthday delivery rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        } else {
            vec![format!(
                "Announce birthday in <#{}> using {}: {}",
                decision.channel_id, decision.timezone, decision.message
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object.get("channel").and_then(serde_json::Value::as_str) {
            projection.push(("community.birthdays.channel_id".into(), value.into()));
        }
        if let Some(value) = object.get("message").and_then(serde_json::Value::as_str) {
            projection.push(("community.birthdays.message".into(), value.into()));
        }
        if let Some(value) = object
            .get("timezone")
            .and_then(serde_json::Value::as_str)
            .filter(|value| parse_utc_offset_minutes(value).is_some())
        {
            projection.push(("community.birthdays.timezone".into(), value.into()));
        }
        projection
    }
}

impl FeatureAdapter for ToggleOnlyAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: self.source.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            // Provider integrations have their own subscription builders in
            // the API.  Do not expose an empty generic section that suggests
            // a toggle is enough to configure delivery.
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": self.source,
                "sections": [],
                "notes": [{"title": self.title, "description": self.description}]
            }),
            defaults: serde_json::json!({}),
            dependencies: self
                .dependencies
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        if config.is_object() {
            Vec::new()
        } else {
            vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }]
        }
    }

    fn runtime_projection(&self, _config: &serde_json::Value) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// The XP card has a dedicated editor and renderer, but it still participates
/// in the common adapter contract.  Keeping its schema and projection here
/// prevents the specialised endpoint from becoming a second, invisible
/// configuration source.
#[derive(Debug, Clone, Copy, Default)]
pub struct RankCardAdapter;

impl RankCardAdapter {
    pub const KEY: &'static str = "studio.rank_card";
    pub const SOURCE: &'static str = "rank_card_adapter_v2";

    fn valid_hex(value: &str) -> bool {
        value.len() == 7
            && value.starts_with('#')
            && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
    }

    fn valid_config(config: &RankCardConfig) -> bool {
        matches!(
            config.font.as_str(),
            "system" | "inter" | "roboto" | "poppins" | "space_grotesk" | "lexend"
        ) && Self::valid_hex(&config.primary_color)
            && Self::valid_hex(&config.text_color)
            && Self::valid_hex(&config.background_color)
            && Self::valid_hex(&config.avatar_ring_color)
            && config.overlay_opacity.is_finite()
            && (0.0..=0.85).contains(&config.overlay_opacity)
            && config.avatar_ring_width <= 8
            && config.background_preset.as_deref().is_none_or(|preset| {
                RANK_CARD_BACKGROUND_PRESETS
                    .iter()
                    .any(|(id, _)| *id == preset)
            })
            && config.background_url.is_none()
            && config.background_data.is_none()
    }
}

impl FeatureAdapter for RankCardAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "XP card appearance",
                    "description": "Choose curated backgrounds and colours for the XP card rendered by /rank.",
                    "fields": [
                        {"key":"font","label":"Font","kind":"select","options":["system","inter","roboto","poppins","space_grotesk","lexend"]},
                        {"key":"primaryColor","label":"Primary colour","kind":"color"},
                        {"key":"textColor","label":"Text colour","kind":"color"},
                        {"key":"backgroundColor","label":"Background colour","kind":"color"},
                        {"key":"overlayOpacity","label":"Overlay opacity","kind":"number","min":0,"max":0.85},
                        {"key":"backgroundPreset","label":"Curated background","kind":"select","advanced":true},
                        {"key":"avatarRingColor","label":"Avatar ring colour","kind":"color","advanced":true},
                        {"key":"avatarRingWidth","label":"Avatar ring width","kind":"number","min":0,"max":8,"advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::to_value(RankCardConfig::default())
                .expect("rank card defaults serialize"),
            dependencies: vec!["attach_files".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        match serde_json::from_value::<RankCardConfig>(config.clone()) {
            Ok(parsed) if Self::valid_config(&parsed) => Vec::new(),
            Ok(parsed) => vec![ValidationIssue {
                path: "config".into(),
                code: "invalid_rank_card".into(),
                message: if parsed.background_url.is_some() || parsed.background_data.is_some() {
                    "XP card backgrounds must use one of the curated presets; custom images are not accepted.".into()
                } else {
                    "Use a supported font, hexadecimal colours, an opacity between 0 and 0.85, and a curated background.".into()
                },
                severity: "error".into(),
            }],
            Err(_) => vec![ValidationIssue {
                path: "config".into(),
                code: "invalid_rank_card".into(),
                message: "XP card configuration must match the supported appearance fields.".into(),
                severity: "error".into(),
            }],
        }
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        serde_json::to_string(config)
            .ok()
            .map(|value| vec![("community.rank_card".into(), value)])
            .unwrap_or_default()
    }
}

/// Shared schema for feed-backed alert surfaces.  RSS and podcast feeds are
/// validated and published through the same store/provider path, but each has
/// its own catalog key and user-facing copy.
#[derive(Debug, Clone, Copy)]
pub struct FeedAdapter {
    pub key: &'static str,
    pub source: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub dependencies: &'static [&'static str],
}

impl FeatureAdapter for FeedAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: self.source.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": self.source,
                "sections": [{
                    "title": self.title,
                    "description": self.description,
                    "fields": [
                        {"key":"feedUrl","label":"Public feed URL","kind":"text"},
                        {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                        {"key":"intervalSeconds","label":"Polling interval (seconds)","kind":"number","min":300,"max":86400},
                        {"key":"messageTemplate","label":"Alert message","kind":"textarea","advanced":true},
                        {"key":"mention","label":"Optional mention","kind":"text","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "feedUrl": "",
                "targetChannelId": "",
                "intervalSeconds": 900,
                "messageTemplate": "New update from {feed}: **{title}**\\n{url}",
                "mention": ""
            }),
            dependencies: self
                .dependencies
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Feed configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        let feed_url = object
            .get("feedUrl")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if feed_url.is_empty() {
            issues.push(ValidationIssue {
                path: "feedUrl".into(),
                code: "required".into(),
                message: "Choose a public RSS or Atom feed URL.".into(),
                severity: "error".into(),
            });
        } else if feed_url.chars().count() > 2_000
            || !feed_url.starts_with("https://") && !feed_url.starts_with("http://")
        {
            issues.push(ValidationIssue {
                path: "feedUrl".into(),
                code: "invalid_url".into(),
                message:
                    "The feed URL must use http:// or https:// and be at most 2000 characters."
                        .into(),
                severity: "error".into(),
            });
        }
        let target_channel = object
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if target_channel.is_empty() || !valid_discord_id(target_channel) {
            issues.push(ValidationIssue {
                path: "targetChannelId".into(),
                code: "invalid_discord_id".into(),
                message: "Choose a real Discord channel for alerts.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("messageTemplate")
            && (!value.is_string()
                || value
                    .as_str()
                    .is_some_and(|value| value.chars().count() > 2_000))
        {
            issues.push(ValidationIssue {
                path: "messageTemplate".into(),
                code: "too_long".into(),
                message: "Alert messages must be text and at most 2000 characters.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("mention")
            && (!value.is_string()
                || value.as_str().is_some_and(|mention| {
                    !mention.trim().is_empty()
                        && mention.trim() != "@here"
                        && mention.trim() != "@everyone"
                        && !mention.trim().starts_with("<@&")
                }))
        {
            issues.push(ValidationIssue {
                path: "mention".into(),
                code: "invalid_mention".into(),
                message: "Mention must be empty, @here, @everyone or a role mention.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("intervalSeconds")
            .is_some_and(|value| value.as_i64().is_none())
        {
            issues.push(ValidationIssue {
                path: "intervalSeconds".into(),
                code: "integer_required".into(),
                message: "Polling interval must be an integer in seconds.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("feedUrl")
            .is_some_and(|value| value.as_str().is_none())
        {
            issues.push(ValidationIssue {
                path: "feedUrl".into(),
                code: "string_required".into(),
                message: "Feed URL must be text.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("targetChannelId")
            .is_some_and(|value| value.as_str().is_none())
        {
            issues.push(ValidationIssue {
                path: "targetChannelId".into(),
                code: "string_required".into(),
                message: "Discord channel ID must be text.".into(),
                severity: "error".into(),
            });
        }
        /*
         * Keep provider validation bounded here as well as in the provider
         * client. This means a saved beta feature cannot look healthy when
         * its subscription is only a half-filled JSON object.
         */
        if let Some(value) = object.get("intervalSeconds")
            && value
                .as_i64()
                .is_some_and(|value| !(300..=86_400).contains(&value))
        {
            issues.push(ValidationIssue {
                path: "intervalSeconds".into(),
                code: "out_of_range".into(),
                message: "Polling interval must be between 300 and 86400 seconds.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        for (field, key) in [
            ("feedUrl", "social.feed.url"),
            ("targetChannelId", "social.feed.target_channel_id"),
            ("messageTemplate", "social.feed.message_template"),
            ("mention", "social.feed.mention"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                projection.push((key.into(), value.into()));
            }
        }
        if let Some(value) = object
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push(("social.feed.interval_seconds".into(), value.to_string()));
        }
        projection
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BlueskyAdapter;

impl BlueskyAdapter {
    pub const KEY: &'static str = "social.bluesky";
    pub const SOURCE: &'static str = "bluesky_public_feed_v1";
}

impl FeatureAdapter for BlueskyAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Bluesky alerts",
                    "description": "Poll a public profile through the official Bluesky AppView API and post new updates in Discord.",
                    "fields": [
                        {"key":"sourceHandle","label":"Bluesky handle","kind":"text","help":"For example: vozen.org or @vozen.org."},
                        {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                        {"key":"intervalSeconds","label":"Polling interval (seconds)","kind":"number","min":300,"max":86400},
                        {"key":"messageTemplate","label":"Alert message","kind":"textarea","advanced":true},
                        {"key":"mention","label":"Optional mention","kind":"text","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "sourceHandle": "",
                "targetChannelId": "",
                "intervalSeconds": 900,
                "messageTemplate": "New Bluesky post from {handle}: **{text}**\\n{url}",
                "mention": ""
            }),
            dependencies: vec!["Bluesky public AppView API".into(), "Send Messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Bluesky alert configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        let handle = object
            .get("sourceHandle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if handle.is_empty()
            || handle.len() > 253
            || !handle.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@')
            })
        {
            issues.push(ValidationIssue {
                path: "sourceHandle".into(),
                code: "invalid_handle".into(),
                message: "Use a valid public Bluesky handle, such as vozen.org.".into(),
                severity: "error".into(),
            });
        }
        let target = object
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if target.is_empty() || !valid_discord_id(target) {
            issues.push(ValidationIssue {
                path: "targetChannelId".into(),
                code: "invalid_discord_id".into(),
                message: "Choose a real Discord channel for alerts.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
            && !(300..=86_400).contains(&value)
        {
            issues.push(ValidationIssue {
                path: "intervalSeconds".into(),
                code: "out_of_range".into(),
                message: "Polling interval must be between 300 and 86400 seconds.".into(),
                severity: "error".into(),
            });
        }
        if object.get("messageTemplate").is_some_and(|value| {
            value
                .as_str()
                .is_none_or(|text| text.trim().is_empty() || text.chars().count() > 1_800)
        }) {
            issues.push(ValidationIssue {
                path: "messageTemplate".into(),
                code: "invalid_template".into(),
                message: "Alert messages must be non-empty and at most 1800 characters.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("mention").and_then(serde_json::Value::as_str)
            && !value.trim().is_empty()
            && value.trim() != "@here"
            && value.trim() != "@everyone"
            && !(value.trim().starts_with("<@&") && value.trim().ends_with('>'))
        {
            issues.push(ValidationIssue {
                path: "mention".into(),
                code: "invalid_mention".into(),
                message: "Mention must be empty, @here, @everyone or a role mention.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        for (field, key) in [
            ("sourceHandle", "social.bluesky.handle"),
            ("targetChannelId", "social.bluesky.target_channel_id"),
            ("messageTemplate", "social.bluesky.message_template"),
            ("mention", "social.bluesky.mention"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                projection.push((key.into(), value.into()));
            }
        }
        if let Some(value) = object
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push(("social.bluesky.interval_seconds".into(), value.to_string()));
        }
        projection
    }
}

/// Contract for integrations whose runtime is deliberately gated by an
/// external provider account, app review, commercial agreement or operator
/// secret.  Keeping these adapters in the registry means the panel can show
/// a real schema, validation and exact dependency checklist instead of a
/// misleading empty form.  The maturity remains `Blocked` until the
/// provider-specific gate is satisfied.
#[derive(Debug, Clone, Copy)]
pub struct ExternalProviderAdapter {
    pub key: &'static str,
    pub source: &'static str,
    pub schema: &'static str,
    pub defaults: &'static str,
    pub dependencies: &'static [&'static str],
}

fn is_eth_address(value: &str) -> bool {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    body.is_some_and(|text| text.len() == 40 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

impl FeatureAdapter for ExternalProviderAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: self.source.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::from_str(self.schema).expect("external schema is valid JSON"),
            defaults: serde_json::from_str(self.defaults)
                .expect("external defaults are valid JSON"),
            dependencies: self
                .dependencies
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The integration configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("targetChannelId")
            && !value
                .as_str()
                .is_some_and(|text| text.trim().is_empty() || valid_discord_id(text.trim()))
        {
            issues.push(ValidationIssue {
                path: "targetChannelId".into(),
                code: "invalid_discord_id".into(),
                message: "Choose a real Discord channel.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("targetRoleId")
            && !value
                .as_str()
                .is_some_and(|text| text.trim().is_empty() || valid_discord_id(text.trim()))
        {
            issues.push(ValidationIssue {
                path: "targetRoleId".into(),
                code: "invalid_discord_id".into(),
                message: "Choose a real Discord role.".into(),
                severity: "error".into(),
            });
        }
        for field in ["sourceHandle", "username", "account", "collectionSlug"] {
            if let Some(value) = object.get(field)
                && let Some(text) = value.as_str()
                && !text.trim().is_empty()
                && (!(2..=100).contains(&text.trim().chars().count())
                    || text
                        .trim()
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace()))
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_source_identifier".into(),
                    message: "Use the provider's identifier, not a URL or arbitrary text.".into(),
                    severity: "error".into(),
                });
            }
        }
        let minimum_interval = 300;
        if let Some(value) = object.get("intervalSeconds")
            && (!value.is_i64()
                || !value
                    .as_i64()
                    .is_some_and(|seconds| (minimum_interval..=86_400).contains(&seconds)))
        {
            issues.push(ValidationIssue {
                path: "intervalSeconds".into(),
                code: "out_of_range".into(),
                message: format!(
                    "Polling intervals must be between {minimum_interval} and 86400 seconds."
                ),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("messageTemplate")
            && !value
                .as_str()
                .is_some_and(|text| !text.trim().is_empty() && text.chars().count() <= 1_800)
        {
            issues.push(ValidationIssue {
                path: "messageTemplate".into(),
                code: "invalid_template".into(),
                message: "Alert messages must be at most 1800 characters.".into(),
                severity: "error".into(),
            });
        }
        if self.key == "growth.monetization" {
            if let Some(value) = object.get("productName")
                && (!value.is_string()
                    || value
                        .as_str()
                        .is_some_and(|name| name.trim().is_empty() || name.chars().count() > 80))
            {
                issues.push(ValidationIssue {
                    path: "productName".into(),
                    code: "invalid_product_name".into(),
                    message: "Product name must contain 1 to 80 characters.".into(),
                    severity: "error".into(),
                });
            }
            if let Some(value) = object.get("priceCents")
                && (!value.is_i64()
                    || !value
                        .as_i64()
                        .is_some_and(|cents| (0..=10_000_000).contains(&cents)))
            {
                issues.push(ValidationIssue {
                    path: "priceCents".into(),
                    code: "invalid_price".into(),
                    message: "Prices must be integer cents between 0 and 10000000.".into(),
                    severity: "error".into(),
                });
            }
        }
        if self.key == "web3.gating"
            && let Some(value) = object.get("chain")
            && !value
                .as_str()
                .is_some_and(|chain| matches!(chain, "ethereum" | "polygon" | "arbitrum" | "base"))
        {
            issues.push(ValidationIssue {
                path: "chain".into(),
                code: "unsupported_chain".into(),
                message: "Choose one of the supported read-only chains.".into(),
                severity: "error".into(),
            });
        }
        if self.key == "web3.gating" {
            if let Some(value) = object.get("contractAddress")
                && let Some(address) = value.as_str()
                && !address.trim().is_empty()
                && !is_eth_address(address.trim())
            {
                issues.push(ValidationIssue {
                    path: "contractAddress".into(),
                    code: "invalid_contract_address".into(),
                    message: "Use a 0x-prefixed Ethereum contract address.".into(),
                    severity: "error".into(),
                });
            }
            if let Some(value) = object.get("targetRoleId")
                && let Some(role) = value.as_str()
                && !role.trim().is_empty()
                && !valid_discord_id(role.trim())
            {
                issues.push(ValidationIssue {
                    path: "targetRoleId".into(),
                    code: "invalid_discord_id".into(),
                    message: "Choose a real Discord role.".into(),
                    severity: "error".into(),
                });
            }
            let asset_type = object
                .get("assetType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("erc721");
            if !matches!(asset_type, "erc20" | "erc721" | "erc1155") {
                issues.push(ValidationIssue {
                    path: "assetType".into(),
                    code: "invalid_asset_type".into(),
                    message: "Choose ERC-20, ERC-721 or ERC-1155.".into(),
                    severity: "error".into(),
                });
            }
            let minimum = object
                .get("minimumBalance")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if minimum.is_empty()
                || minimum.len() > 39
                || !minimum.bytes().all(|byte| byte.is_ascii_digit())
            {
                issues.push(ValidationIssue {
                    path: "minimumBalance".into(),
                    code: "invalid_uint".into(),
                    message: "Minimum balance must be a non-negative decimal integer.".into(),
                    severity: "error".into(),
                });
            }
            if asset_type == "erc1155" {
                let token_id = object
                    .get("tokenId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if token_id.is_empty() || token_id.len() > 78 {
                    issues.push(ValidationIssue {
                        path: "tokenId".into(),
                        code: "token_id_required".into(),
                        message: "ERC-1155 gating requires a bounded token ID.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let prefix = self.key.replace('.', "_");
        let mut projection = Vec::new();
        for (field, suffix) in [
            ("productName", "product_name"),
            ("sourceHandle", "source_handle"),
            ("username", "username"),
            ("account", "account"),
            ("collectionSlug", "collection_slug"),
            ("targetChannelId", "target_channel_id"),
            ("targetRoleId", "target_role_id"),
            ("messageTemplate", "message_template"),
            ("mention", "mention"),
            ("chain", "chain"),
            ("contractAddress", "contract_address"),
            ("minimumBalance", "minimum_balance"),
            ("assetType", "asset_type"),
            ("tokenId", "token_id"),
            ("currency", "currency"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                projection.push((format!("{prefix}.{suffix}"), value.into()));
            }
        }
        for (field, suffix) in [
            ("intervalSeconds", "interval_seconds"),
            ("priceCents", "price_cents"),
            ("trialDays", "trial_days"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64) {
                projection.push((format!("{prefix}.{suffix}"), value.to_string()));
            }
        }
        projection
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CryptoAdapter {
    pub key: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub stats: bool,
}

impl FeatureAdapter for CryptoAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        let mut fields = vec![
            serde_json::json!({
                "key": "coinIds",
                "label": "CoinGecko IDs",
                "kind": "text",
                "help": "Comma-separated IDs such as bitcoin, ethereum or solana."
            }),
            serde_json::json!({
                "key": "currency",
                "label": "Currency",
                "kind": "text",
                "help": "Three to ten lowercase letters, for example usd or eur."
            }),
        ];
        if self.stats {
            fields.extend([
                serde_json::json!({"key":"targetChannelId","label":"Discord channel","kind":"channel"}),
                serde_json::json!({"key":"intervalSeconds","label":"Update interval (seconds)","kind":"number","min":300,"max":86400}),
                serde_json::json!({"key":"messageTemplate","label":"Statistics message","kind":"textarea","advanced":true}),
            ]);
        } else {
            fields.push(serde_json::json!({
                "key": "maxResults",
                "label": "Maximum results",
                "kind": "number",
                "min": 1,
                "max": 10,
                "advanced": true
            }));
        }
        FeatureAdapterDescriptor {
            key: self.key.into(),
            source: "coingecko_simple_price_v1".into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": "coingecko_simple_price_v1",
                "sections": [{
                    "title": self.title,
                    "description": self.description,
                    "fields": fields
                }]
            }),
            defaults: if self.stats {
                serde_json::json!({
                    "coinIds": "bitcoin",
                    "currency": "usd",
                    "targetChannelId": "",
                    "intervalSeconds": 900,
                    "messageTemplate": "Crypto update: {coins}"
                })
            } else {
                serde_json::json!({
                    "coinIds": "bitcoin",
                    "currency": "usd",
                    "maxResults": 5
                })
            },
            dependencies: vec![
                "CoinGecko public API".into(),
                if self.stats {
                    "Send Messages".into()
                } else {
                    "Use Application Commands".into()
                },
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Crypto configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        let coins = object
            .get("coinIds")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let coin_list = coins
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if coin_list.is_empty() || coin_list.len() > 20 {
            issues.push(ValidationIssue {
                path: "coinIds".into(),
                code: "invalid_coin_ids".into(),
                message: "Choose between one and twenty CoinGecko IDs.".into(),
                severity: "error".into(),
            });
        } else if coin_list.iter().any(|coin| {
            !(1..=64).contains(&coin.len())
                || !coin
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || coin.starts_with('-')
                || coin.ends_with('-')
        }) {
            issues.push(ValidationIssue {
                path: "coinIds".into(),
                code: "invalid_coin_id".into(),
                message: "Coin IDs may contain only letters, numbers and hyphens.".into(),
                severity: "error".into(),
            });
        }
        let currency = object
            .get("currency")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if !(3..=10).contains(&currency.len())
            || !currency.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            issues.push(ValidationIssue {
                path: "currency".into(),
                code: "invalid_currency".into(),
                message: "Currency must use three to ten lowercase letters, such as usd.".into(),
                severity: "error".into(),
            });
        }
        if self.stats {
            let target = object
                .get("targetChannelId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim();
            if target.is_empty() || !valid_discord_id(target) {
                issues.push(ValidationIssue {
                    path: "targetChannelId".into(),
                    code: "invalid_discord_id".into(),
                    message: "Choose a real Discord channel for statistics.".into(),
                    severity: "error".into(),
                });
            }
            if let Some(interval) = object
                .get("intervalSeconds")
                .and_then(serde_json::Value::as_i64)
                && !(300..=86_400).contains(&interval)
            {
                issues.push(ValidationIssue {
                    path: "intervalSeconds".into(),
                    code: "out_of_range".into(),
                    message: "Update interval must be between 300 and 86400 seconds.".into(),
                    severity: "error".into(),
                });
            }
            if object.get("messageTemplate").is_some_and(|value| {
                value.as_str().is_none_or(|template| {
                    template.trim().is_empty() || template.chars().count() > 1_800
                })
            }) {
                issues.push(ValidationIssue {
                    path: "messageTemplate".into(),
                    code: "invalid_template".into(),
                    message: "Statistics messages must be non-empty and at most 1800 characters."
                        .into(),
                    severity: "error".into(),
                });
            }
        } else if let Some(max_results) =
            object.get("maxResults").and_then(serde_json::Value::as_i64)
            && !(1..=10).contains(&max_results)
        {
            issues.push(ValidationIssue {
                path: "maxResults".into(),
                code: "out_of_range".into(),
                message: "Maximum results must be between 1 and 10.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let prefix = self.key.replace('.', "_");
        let mut projection = Vec::new();
        if let Some(coins) = object.get("coinIds").and_then(serde_json::Value::as_str) {
            projection.push((
                format!("{prefix}.coin_ids"),
                coins.trim().to_ascii_lowercase(),
            ));
        }
        if let Some(currency) = object.get("currency").and_then(serde_json::Value::as_str) {
            projection.push((
                format!("{prefix}.currency"),
                currency.trim().to_ascii_lowercase(),
            ));
        }
        if let Some(max_results) = object.get("maxResults").and_then(serde_json::Value::as_i64) {
            projection.push((format!("{prefix}.max_results"), max_results.to_string()));
        }
        if let Some(channel) = object
            .get("targetChannelId")
            .and_then(serde_json::Value::as_str)
        {
            projection.push((format!("{prefix}.target_channel_id"), channel.to_string()));
        }
        if let Some(interval) = object
            .get("intervalSeconds")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((format!("{prefix}.interval_seconds"), interval.to_string()));
        }
        if let Some(template) = object
            .get("messageTemplate")
            .and_then(serde_json::Value::as_str)
        {
            projection.push((format!("{prefix}.message_template"), template.to_string()));
        }
        projection
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GasAdapter;

impl FeatureAdapter for GasAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: "web3.gas_tracker".into(),
            source: "operator_rpc_gas_v1".into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": "operator_rpc_gas_v1",
                "sections": [{
                    "title": "Gas tracker",
                    "description": "Publish read-only gas prices from an operator-approved RPC endpoint.",
                    "fields": [
                        {"key":"network","label":"Network","kind":"select","options":["ethereum","polygon","arbitrum","base"]},
                        {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                        {"key":"intervalSeconds","label":"Update interval (seconds)","kind":"number","min":300,"max":86400},
                        {"key":"messageTemplate","label":"Statistics message","kind":"textarea","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "network": "ethereum",
                "targetChannelId": "",
                "intervalSeconds": 900,
                "messageTemplate": "{network} gas: {gasPriceGwei} Gwei (block {blockNumber})"
            }),
            dependencies: vec!["Operator-approved HTTPS RPC".into(), "Send Messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Gas tracker configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        let network = object
            .get("network")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "ethereum" | "polygon" | "arbitrum" | "base"
        ) {
            issues.push(ValidationIssue {
                path: "network".into(),
                code: "unsupported_network".into(),
                message: "Choose ethereum, polygon, arbitrum or base.".into(),
                severity: "error".into(),
            });
        }
        validate_channel_and_schedule(object, &mut issues, "gas");
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        project_gas(config)
    }
}

fn validate_channel_and_schedule(
    object: &serde_json::Map<String, serde_json::Value>,
    issues: &mut Vec<ValidationIssue>,
    label: &str,
) {
    let target = object
        .get("targetChannelId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    if target.is_empty() || !valid_discord_id(target) {
        issues.push(ValidationIssue {
            path: "targetChannelId".into(),
            code: "invalid_discord_id".into(),
            message: format!("Choose a real Discord channel for {label} updates."),
            severity: "error".into(),
        });
    }
    if let Some(interval) = object
        .get("intervalSeconds")
        .and_then(serde_json::Value::as_i64)
        && !(300..=86_400).contains(&interval)
    {
        issues.push(ValidationIssue {
            path: "intervalSeconds".into(),
            code: "out_of_range".into(),
            message: "Update interval must be between 300 and 86400 seconds.".into(),
            severity: "error".into(),
        });
    }
    if object.get("messageTemplate").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|template| template.trim().is_empty() || template.chars().count() > 1_800)
    }) {
        issues.push(ValidationIssue {
            path: "messageTemplate".into(),
            code: "invalid_template".into(),
            message: "Messages must be non-empty and at most 1800 characters.".into(),
            severity: "error".into(),
        });
    }
}

fn project_gas(config: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = config.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (field, key) in [
        ("network", "web3.gas_tracker.network"),
        ("targetChannelId", "web3.gas_tracker.target_channel_id"),
        ("messageTemplate", "web3.gas_tracker.message_template"),
    ] {
        if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
            pairs.push((key.into(), value.to_string()));
        }
    }
    if let Some(value) = object
        .get("intervalSeconds")
        .and_then(serde_json::Value::as_i64)
    {
        pairs.push((
            "web3.gas_tracker.interval_seconds".into(),
            value.to_string(),
        ));
    }
    pairs
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TicketsAdapter;

impl TicketsAdapter {
    pub const KEY: &'static str = "support.tickets";
    pub const SOURCE: &'static str = "tickets_adapter_v1";
}

impl FeatureAdapter for TicketsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Support workflow",
                    "description": "Choose the real category, support role, transcript channel and SLA used by ticket interactions.",
                    "fields": [
                        {"key":"panelChannel","label":"Ticket panel channel","kind":"channel","help":"The public channel for the Open ticket button. Saving publishes or updates the panel in this channel; private tickets are created in the category below. Existing panels in other channels are kept."},
                        {"key":"categoryId","label":"Ticket category","kind":"category","help":"New ticket channels are created inside this category."},
                        {"key":"staffRole","label":"Staff role to notify","kind":"role","help":"The opening message @mentions this role. Its members can view, claim, close and reopen tickets. Make the role mentionable or allow the bot to mention roles. Personal Discord notification settings still apply."},
                        {"key":"transcriptChannel","label":"Transcript channel","kind":"channel","help":"Closed ticket transcripts are sent here."},
                        {"key":"maxOpen","label":"Open tickets per member","kind":"number","min":1,"max":10,"help":"Limit the number of simultaneous tickets one member can open."},
                        {"key":"panelTitle","label":"Panel title","kind":"text","min":1,"max":100},
                        {"key":"panelDescription","label":"Panel description","kind":"textarea","min":1,"max":1000},
                        {"key":"closeAfterHours","label":"SLA reminder (hours)","kind":"number","min":1,"max":168,"help":"The Helper records an overdue ticket job after this period."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"panelChannel":"","categoryId":"","staffRole":"","transcriptChannel":"","maxOpen":1,"panelTitle":"Need support?","panelDescription":"Open a private ticket and the support team will help you." ,"closeAfterHours":1}),
            dependencies: vec![
                "manage_channels".into(),
                "send_messages".into(),
                "manage_roles".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in [
            "panelChannel",
            "categoryId",
            "staffRole",
            "transcriptChannel",
        ] {
            if let Some(value) = object.get(field)
                && !(value
                    .as_str()
                    .is_some_and(|raw| raw.is_empty() || valid_discord_id(raw)))
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_discord_id".into(),
                    message: "Choose a real Discord category, role or channel.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("closeAfterHours")
            && !value
                .as_i64()
                .is_some_and(|hours| (1..=168).contains(&hours))
        {
            issues.push(ValidationIssue {
                path: "closeAfterHours".into(),
                code: "out_of_range".into(),
                message: "The SLA must be between 1 and 168 hours.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("maxOpen")
            && !value
                .as_i64()
                .is_some_and(|count| (1..=10).contains(&count))
        {
            issues.push(ValidationIssue {
                path: "maxOpen".into(),
                code: "out_of_range".into(),
                message: "Open tickets per member must be between 1 and 10.".into(),
                severity: "error".into(),
            });
        }
        for (field, max, message) in [
            (
                "panelTitle",
                100_usize,
                "The panel title must contain 1-100 characters.",
            ),
            (
                "panelDescription",
                1_000_usize,
                "The panel description must contain 1-1000 characters.",
            ),
        ] {
            if let Some(value) = object.get(field)
                && !value.as_str().is_some_and(|text| {
                    let length = text.chars().count();
                    (1..=max).contains(&length) && !text.chars().any(char::is_control)
                })
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_text".into(),
                    message: message.into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        if let Some(value) = object.get("categoryId").and_then(serde_json::Value::as_str) {
            pairs.push(("support.ticket.category_id".into(), value.into()));
        }
        if let Some(value) = object.get("staffRole").and_then(serde_json::Value::as_str) {
            pairs.push(("support.ticket.staff_role_id".into(), value.into()));
        }
        if let Some(value) = object
            .get("transcriptChannel")
            .and_then(serde_json::Value::as_str)
        {
            pairs.push(("support.ticket.transcript_channel_id".into(), value.into()));
        }
        if let Some(value) = object
            .get("closeAfterHours")
            .and_then(serde_json::Value::as_i64)
        {
            pairs.push((
                "support.ticket.sla_ms".into(),
                value.clamp(1, 168).saturating_mul(3_600_000).to_string(),
            ));
        }
        if let Some(value) = object.get("maxOpen").and_then(serde_json::Value::as_i64) {
            pairs.push(("support.ticket.max_open".into(), value.to_string()));
        }
        for (field, setting) in [
            ("panelChannel", "support.ticket.panel_channel_id"),
            ("panelTitle", "support.ticket.panel_title"),
            ("panelDescription", "support.ticket.panel_description"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                pairs.push((setting.into(), value.into()));
            }
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let open_tickets = fixture_u64(fixture, "openTickets", "open_tickets", 0) as u32;
        let decision = evaluate_tickets(config, open_tickets);
        let mut effects = if decision.allowed {
            vec![format!(
                "Create a private ticket channel ({}/{} open slots used).",
                decision.open_tickets, decision.max_open
            )]
        } else {
            vec![format!(
                "Ticket opening rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WelcomeAdapter;

impl WelcomeAdapter {
    pub const KEY: &'static str = "support.welcome";
    pub const SOURCE: &'static str = "welcome_adapter_v1";
}

impl FeatureAdapter for WelcomeAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Welcome message",
                    "description": "Configure the channel, message, optional DM and real auto-role used on member join.",
                    "fields": [
                        {"key":"channel","label":"Welcome channel","kind":"channel"},
                        {"key":"message","label":"Public message","kind":"textarea","maxLength":2000,"help":"Variables: {member} and {server}."},
                        {"key":"delaySeconds","label":"Delay before sending (seconds)","kind":"number","min":0,"max":300,"advanced":true},
                        {"key":"sendDm","label":"Send a direct message","kind":"toggle"},
                        {"key":"guideEnabled","label":"Add orientation buttons","kind":"toggle","help":"Link directly to the configured rules, introductions and channels destinations. Buttons without a destination are hidden. The optional help step shows command guidance."},
                        {"key":"steps","label":"Guided steps","kind":"tags","max":4,"help":"Choose from rules, introductions, channels and help.","advanced":true},
                        {"key":"rulesChannel","label":"Rules channel (optional)","kind":"channel","help":"Open this channel directly. Leave empty to hide Read the rules.","advanced":true},
                        {"key":"introductionsChannel","label":"Introductions channel (optional)","kind":"channel","help":"Open this channel directly. Leave empty to hide Introduce yourself.","advanced":true},
                        {"key":"channelsChannel","label":"Channels guide (optional)","kind":"channel","help":"Open this channel directly. Leave empty to hide Explore channels.","advanced":true},
                        {"key":"dmMessage","label":"Direct message","kind":"textarea","maxLength":2000,"advanced":true},
                        {"key":"autoRole","label":"Automatic role","kind":"role","advanced":true},
                        {"key":"farewellChannel","label":"Farewell channel","kind":"channel","advanced":true},
                        {"key":"farewellMessage","label":"Farewell message","kind":"textarea","maxLength":2000,"advanced":true},
                        {"key":"templateId","label":"Reusable message template","kind":"select","options":[["","No template"]],"help":"Optional: choose a template created in Models and importação.","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({"channel":"","message":"👋 Welcome {member} to {server}!","delaySeconds":0,"sendDm":false,"dmMessage":"Hello {member}, welcome to {server}!","autoRole":"","farewellChannel":"","farewellMessage":"Goodbye {member}. We hope to see you again!","templateId":"","guideEnabled":false,"steps":["rules","introductions","channels"],"rulesChannel":"","introductionsChannel":"","channelsChannel":""}),
            dependencies: vec![
                "guild_members_intent".into(),
                "send_messages".into(),
                "manage_roles".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in ["channel", "autoRole", "farewellChannel"] {
            if object.get(field).is_some_and(|value| {
                !value
                    .as_str()
                    .is_some_and(|raw| raw.is_empty() || valid_discord_id(raw))
            }) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_discord_id".into(),
                    message: "Choose a real Discord resource.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues.extend(
            WelcomeChannelAdapter
                .validate(config)
                .into_iter()
                .filter(|issue| {
                    matches!(
                        issue.path.as_str(),
                        "steps" | "rulesChannel" | "introductionsChannel" | "channelsChannel"
                    )
                }),
        );
        if object
            .get("guideEnabled")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "guideEnabled".into(),
                code: "boolean_required".into(),
                message: "Orientation buttons must be enabled or disabled.".into(),
                severity: "error".into(),
            });
        }
        for field in ["message", "dmMessage", "farewellMessage"] {
            if object.get(field).is_some_and(|value| {
                !value.as_str().is_some_and(|raw| {
                    raw.chars().count() <= 2_000 && !raw.chars().any(char::is_control)
                })
            }) {
                issues.push(ValidationIssue { path: field.into(), code: "invalid_message".into(), message: "Messages must be at most 2000 characters and contain no control characters.".into(), severity: "error".into() });
            }
        }
        if object.get("templateId").is_some_and(|value| {
            !value.as_str().is_some_and(|raw| {
                raw.is_empty()
                    || ((1..=64).contains(&raw.len())
                        && raw.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        }))
            })
        }) {
            issues.push(ValidationIssue {
                path: "templateId".into(),
                code: "invalid_template_id".into(),
                message: "Choose a template from this guild.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("sendDm")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "sendDm".into(),
                code: "boolean_required".into(),
                message: "Send DM must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("delaySeconds")
            .is_some_and(|value| !value.as_i64().is_some_and(|raw| (0..=300).contains(&raw)))
        {
            issues.push(ValidationIssue {
                path: "delaySeconds".into(),
                code: "out_of_range".into(),
                message: "The welcome delay must be between 0 and 300 seconds.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for (field, key) in [
            ("channel", "support.welcome.channel_id"),
            ("message", "support.welcome.message"),
            ("dmMessage", "support.welcome.dm_message"),
            ("autoRole", "support.welcome.auto_role"),
            ("farewellChannel", "support.welcome.farewell_channel_id"),
            ("farewellMessage", "support.welcome.farewell_message"),
            ("templateId", "support.welcome.template_id"),
            ("rulesChannel", "support.welcome_channel.rules_channel"),
            (
                "introductionsChannel",
                "support.welcome_channel.introductions_channel",
            ),
            (
                "channelsChannel",
                "support.welcome_channel.channels_channel",
            ),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                pairs.push((key.into(), value.into()));
            }
        }
        if let Some(value) = object.get("sendDm").and_then(serde_json::Value::as_bool) {
            pairs.push(("support.welcome.send_dm".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("guideEnabled")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("support.welcome.guide_enabled".into(), value.to_string()));
        }
        if let Some(steps) = object.get("steps").and_then(serde_json::Value::as_array) {
            pairs.push((
                "support.welcome_channel.steps".into(),
                steps
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(value) = object
            .get("delaySeconds")
            .and_then(serde_json::Value::as_i64)
        {
            pairs.push(("support.welcome.delay_seconds".into(), value.to_string()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let member = fixture_string(fixture, "member", "member", "<@member>");
        let server = fixture_string(fixture, "server", "server", "this server");
        let message = config
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("👋 Welcome {member} to {server}!");
        let rendered = render_welcome_message(message, member, server);
        let delay = config
            .get("delaySeconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0)
            .clamp(0, 300);
        let mut effects = vec![format!(
            "Send the welcome message `{rendered}` after {delay} second(s)."
        )];
        if config["guideEnabled"].as_bool() == Some(true) {
            effects.push("Attach orientation buttons for the configured destinations to that same message; hide destination buttons without a channel. Do not send a second public welcome.".into());
        }
        if config
            .get("sendDm")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            let dm = config
                .get("dmMessage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Hello {member}, welcome to {server}!");
            effects.push(format!(
                "Send a direct message `{}`.",
                render_member_message(dm, member, server)
            ));
        }
        if let Some(role) = config
            .get("autoRole")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            effects.push(format!("Assign the configured automatic role `{role}`."));
        }
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AntiSpamAdapter;

#[derive(Debug, Clone, Copy, Default)]
pub struct NicknameAdapter;

impl NicknameAdapter {
    pub const KEY: &'static str = "management.nickname";
    pub const SOURCE: &'static str = "nickname_adapter_v1";

    fn schema() -> serde_json::Value {
        serde_json::json!({
            "version": FEATURE_SCHEMA_VERSION,
            "source": Self::SOURCE,
            "sections": [{
                "title": "Helper identity",
                "description": "Choose the display name the Helper uses in this server.",
                "fields": [{
                    "key": "nickname",
                    "label": "Server nickname",
                    "kind": "text",
                    "min": 0,
                    "max": 32,
                    "help": "Discord allows up to 32 characters. Leave it empty when disabling to restore the default name."
                }]
            }]
        })
    }

    fn defaults() -> serde_json::Value {
        serde_json::json!({"nickname": ""})
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicknameDecision {
    pub allowed: bool,
    pub nickname: String,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Validate the exact nickname mutation used by the API preview and the
/// Discord worker. Empty text is intentional: it restores Discord's default
/// display name when the feature is disabled or cleared.
pub fn evaluate_nickname(config: &serde_json::Value) -> NicknameDecision {
    let nickname = config
        .get("nickname")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(64)
        .collect::<String>();
    if nickname.chars().count() > 32 || nickname.chars().any(char::is_control) {
        return NicknameDecision {
            allowed: false,
            nickname,
            reason_code: "invalid_nickname",
            explanation:
                "The nickname must be at most 32 characters and cannot contain control characters."
                    .into(),
        };
    }
    NicknameDecision {
        allowed: true,
        nickname: nickname.clone(),
        reason_code: if nickname.is_empty() {
            "restore_default"
        } else {
            "nickname_ready"
        },
        explanation: if nickname.is_empty() {
            "The Helper nickname will be cleared and Discord's default name restored.".into()
        } else {
            format!("Apply `{nickname}` as the Helper's server nickname after preflight.")
        },
    }
}

impl FeatureAdapter for NicknameAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: Self::schema(),
            defaults: Self::defaults(),
            dependencies: vec!["change_nickname".into(), "manage_nicknames".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let Some(value) = object.get("nickname").and_then(serde_json::Value::as_str) else {
            return vec![ValidationIssue {
                path: "nickname".into(),
                code: "required".into(),
                message: "Enter the Helper nickname.".into(),
                severity: "error".into(),
            }];
        };
        if value.chars().count() > 32 || value.chars().any(char::is_control) {
            return vec![ValidationIssue {
                path: "nickname".into(),
                code: "invalid_nickname".into(),
                message: "The nickname must be at most 32 characters and cannot contain control characters.".into(),
                severity: "error".into(),
            }];
        }
        Vec::new()
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        config
            .get("nickname")
            .and_then(serde_json::Value::as_str)
            .map(|value| vec![("identity.nickname".into(), value.to_owned())])
            .unwrap_or_default()
    }

    fn simulate(&self, config: &serde_json::Value, _fixture: &serde_json::Value) -> Vec<String> {
        let decision = evaluate_nickname(config);
        let mut effects = vec![if decision.allowed {
            decision.explanation
        } else {
            format!(
                "Nickname rejected ({}): {}",
                decision.reason_code, decision.explanation
            )
        }];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReminderAdapter;

/// Parse the fixed UTC offsets supported by the reminder scheduler.
///
/// The panel deliberately offers a bounded list instead of arbitrary IANA
/// names: this keeps scheduling deterministic across the API, gateway and
/// tests without pulling a timezone database into the bot process.  Values
/// such as `UTC+01`, `UTC+01:30`, `UTC-05:00` and `UTC` are accepted.
pub fn parse_utc_offset_minutes(raw: &str) -> Option<i32> {
    let value = raw.trim();
    if value.eq_ignore_ascii_case("UTC") || value.eq_ignore_ascii_case("GMT") {
        return Some(0);
    }
    let suffix = value
        .strip_prefix("UTC")
        .or_else(|| value.strip_prefix("GMT"))?;
    let (sign, digits) = match suffix.as_bytes().first().copied()? {
        b'+' => (1_i32, &suffix[1..]),
        b'-' => (-1_i32, &suffix[1..]),
        _ => return None,
    };
    let (hours, minutes) = if let Some((hours, minutes)) = digits.split_once(':') {
        (hours.parse::<i32>().ok()?, minutes.parse::<i32>().ok()?)
    } else {
        (digits.parse::<i32>().ok()?, 0)
    };
    if !(0..=14).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }
    if hours == 14 && minutes != 0 {
        return None;
    }
    Some(sign * (hours * 60 + minutes))
}

impl ReminderAdapter {
    pub const KEY: &'static str = "utility.reminders";
    pub const SOURCE: &'static str = "reminders_adapter_v1";

    fn schema() -> serde_json::Value {
        serde_json::json!({
            "version": FEATURE_SCHEMA_VERSION,
            "source": Self::SOURCE,
            "sections": [{
                "title": "Reminder limits",
                "description": "Keep reminders useful and bounded for every member.",
                "fields": [
                    {"key":"maxDelayHours","label":"Maximum delay (hours)","kind":"number","min":1,"max":8760,"help":"The longest time a member can schedule a reminder."},
                    {"key":"maxTextLength","label":"Maximum message length","kind":"number","min":50,"max":500,"help":"Longer text is rejected before a job is created."},
                    {"key":"timezone","label":"Reminder timezone","kind":"select","options":[["UTC","UTC"],["UTC-05:00","UTC-05:00"],["UTC+01:00","UTC+01:00"],["UTC+02:00","UTC+02:00"],["UTC+05:30","UTC+05:30"],["UTC+08:00","UTC+08:00"]],"help":"Used when a reminder time is written as HH:MM, such as 09:30."},
                    {"key":"notifyUser","label":"Mention the member when it fires","kind":"toggle","help":"Turn off to post a quiet reminder without a mention."},
                    {"key":"allowRecurring","label":"Allow recurring reminders","kind":"toggle","help":"Members can choose a bounded daily or weekly reminder."},
                    {"key":"maxRecurrences","label":"Maximum repeats","kind":"number","min":1,"max":52,"help":"Limits how many times a recurring reminder is re-created."}
                ]
            }]
        })
    }

    fn defaults() -> serde_json::Value {
        serde_json::json!({"maxDelayHours": 168, "maxTextLength": 500, "timezone": "UTC", "notifyUser": true, "allowRecurring": false, "maxRecurrences": 12})
    }
}

/// Runtime policy shared by the reminder command and the dashboard
/// simulation. Keeping the bounds here prevents a saved setting from being
/// interpreted differently by the scheduler and by the preview endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReminderPolicy {
    pub max_delay_hours: u64,
    pub max_text_length: usize,
    pub timezone: String,
    pub notify_user: bool,
    pub allow_recurring: bool,
    pub max_recurrences: u64,
}

impl Default for ReminderPolicy {
    fn default() -> Self {
        Self {
            max_delay_hours: 168,
            max_text_length: 500,
            timezone: "UTC".into(),
            notify_user: true,
            allow_recurring: false,
            max_recurrences: 12,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReminderObservation {
    pub delay_ms: i64,
    pub text: String,
    pub repeat: Option<String>,
    pub timezone: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReminderDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
    pub explanation: String,
    pub delay_ms: i64,
    pub repeat: Option<String>,
    pub remaining: u64,
}

pub fn reminder_policy_from_json(config: &serde_json::Value) -> ReminderPolicy {
    let object = config.as_object();
    ReminderPolicy {
        max_delay_hours: object
            .and_then(|value| value.get("maxDelayHours"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(168)
            .clamp(1, 8_760),
        max_text_length: object
            .and_then(|value| value.get("maxTextLength"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(500)
            .clamp(50, 500) as usize,
        timezone: object
            .and_then(|value| value.get("timezone"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UTC")
            .to_owned(),
        notify_user: object
            .and_then(|value| value.get("notifyUser"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        allow_recurring: object
            .and_then(|value| value.get("allowRecurring"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        max_recurrences: object
            .and_then(|value| value.get("maxRecurrences"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(12)
            .clamp(1, 52),
    }
}

/// Evaluate one reminder request. This is deliberately pure and bounded so
/// that `POST .../simulate` and the Discord slash command cannot drift apart.
pub fn evaluate_reminder(
    policy: &ReminderPolicy,
    observation: &ReminderObservation,
) -> ReminderDecision {
    let max_delay_ms = policy
        .max_delay_hours
        .saturating_mul(3_600_000)
        .min(i64::MAX as u64) as i64;
    let reject = |reason_code: &'static str, explanation: String| ReminderDecision {
        allowed: false,
        reason_code,
        explanation,
        delay_ms: observation.delay_ms,
        repeat: observation.repeat.clone(),
        remaining: policy.max_recurrences,
    };
    if parse_utc_offset_minutes(&observation.timezone).is_none() {
        return reject(
            "invalid_timezone",
            "The reminder timezone must be UTC or a fixed offset between -14:00 and +14:00.".into(),
        );
    }
    if observation.delay_ms <= 0 {
        return reject(
            "invalid_delay",
            "The reminder time must be in the future.".into(),
        );
    }
    if observation.delay_ms > max_delay_ms {
        return reject(
            "delay_exceeds_limit",
            format!(
                "The reminder is beyond the configured {} hour limit.",
                policy.max_delay_hours
            ),
        );
    }
    if observation.text.chars().count() > policy.max_text_length {
        return reject(
            "text_exceeds_limit",
            format!(
                "The reminder is longer than the configured {} character limit.",
                policy.max_text_length
            ),
        );
    }
    if let Some(repeat) = observation.repeat.as_deref() {
        if !policy.allow_recurring {
            return reject(
                "recurring_disabled",
                "Recurring reminders are disabled in this server's dashboard.".into(),
            );
        }
        if !matches!(repeat, "daily" | "weekly") {
            return reject(
                "invalid_repeat",
                "Choose daily or weekly for a recurring reminder.".into(),
            );
        }
    }
    ReminderDecision {
        allowed: true,
        reason_code: "accepted",
        explanation: "The reminder is within the server limits and can be scheduled.".into(),
        delay_ms: observation.delay_ms,
        repeat: observation.repeat.clone(),
        remaining: if observation.repeat.is_some() {
            policy.max_recurrences
        } else {
            0
        },
    }
}

impl FeatureAdapter for ReminderAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: Self::schema(),
            defaults: Self::defaults(),
            dependencies: vec!["scheduler".into(), "send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for (field, min, max) in [
            ("maxDelayHours", 1_i64, 8_760_i64),
            ("maxTextLength", 50, 500),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64)
                && !(min..=max).contains(&value)
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: format!("The value must be between {min} and {max}."),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("maxDelayHours")
            .is_some_and(|value| !value.is_i64())
        {
            issues.push(ValidationIssue {
                path: "maxDelayHours".into(),
                code: "integer_required".into(),
                message: "Maximum delay must be an integer.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("maxTextLength")
            .is_some_and(|value| !value.is_i64())
        {
            issues.push(ValidationIssue {
                path: "maxTextLength".into(),
                code: "integer_required".into(),
                message: "Maximum message length must be an integer.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("notifyUser")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "notifyUser".into(),
                code: "boolean_required".into(),
                message: "Mention preference must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("timezone") {
            let valid = value.as_str().and_then(parse_utc_offset_minutes).is_some();
            if !valid {
                issues.push(ValidationIssue {
                    path: "timezone".into(),
                    code: "invalid_timezone".into(),
                    message: "Use UTC or a fixed offset from UTC between -14:00 and +14:00.".into(),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("allowRecurring")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "allowRecurring".into(),
                code: "boolean_required".into(),
                message: "Recurring reminder preference must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("maxRecurrences") {
            if let Some(value) = value.as_i64() {
                if !(1..=52).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "maxRecurrences".into(),
                        code: "out_of_range".into(),
                        message: "The value must be between 1 and 52.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "maxRecurrences".into(),
                    code: "integer_required".into(),
                    message: "Maximum repeats must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object
            .get("maxDelayHours")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "utility.reminders.max_delay_hours".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("maxTextLength")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "utility.reminders.max_text_length".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object.get("timezone").and_then(serde_json::Value::as_str)
            && parse_utc_offset_minutes(value).is_some()
        {
            projection.push(("utility.reminders.timezone".into(), value.to_owned()));
        }
        if let Some(value) = object
            .get("notifyUser")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.reminders.notify_user".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("allowRecurring")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push((
                "utility.reminders.allow_recurring".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("maxRecurrences")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "utility.reminders.max_recurrences".into(),
                value.to_string(),
            ));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = reminder_policy_from_json(config);
        let observation = ReminderObservation {
            delay_ms: fixture
                .get("delayMs")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(600_000),
            text: fixture
                .get("reminderText")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Preview reminder")
                .to_owned(),
            repeat: fixture
                .get("repeat")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            timezone: fixture
                .get("timezone")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(policy.timezone.as_str())
                .to_owned(),
        };
        let decision = evaluate_reminder(&policy, &observation);
        let mut effects = if decision.allowed {
            let mention = if policy.notify_user {
                " with a member mention"
            } else {
                " quietly"
            };
            let recurrence = decision
                .repeat
                .as_deref()
                .map(|repeat| format!(" and repeat {repeat} up to {} time(s)", decision.remaining))
                .unwrap_or_default();
            vec![format!(
                "Schedule the bounded reminder{}{} (delay: {} ms).",
                mention, recurrence, decision.delay_ms
            )]
        } else {
            vec![format!(
                "Reminder rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LeaderboardAdapter;

impl LeaderboardAdapter {
    pub const KEY: &'static str = "community.leaderboard";
    pub const SOURCE: &'static str = "leaderboard_adapter_v1";

    fn descriptor_schema() -> serde_json::Value {
        serde_json::json!({
            "version": FEATURE_SCHEMA_VERSION,
            "source": Self::SOURCE,
            "sections": [{
                "title": "Leaderboard privacy",
                "description": "Control how many members appear in the XP leaderboard.",
                "fields": [
                    {"key":"maxEntries","label":"Members shown","kind":"number","min":1,"max":100,"help":"Keep the public result concise and predictable."},
                    {"key":"public","label":"Show the leaderboard publicly","kind":"toggle","help":"When disabled, only the requesting member sees the result."}
                ]
            }]
        })
    }

    fn defaults() -> serde_json::Value {
        serde_json::json!({"maxEntries": 10, "public": true})
    }
}

impl FeatureAdapter for LeaderboardAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: Self::descriptor_schema(),
            defaults: Self::defaults(),
            dependencies: vec!["levels".into(), "send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("maxEntries") {
            if let Some(value) = value.as_i64() {
                if !(1..=100).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "maxEntries".into(),
                        code: "out_of_range".into(),
                        message: "Members shown must be between 1 and 100.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "maxEntries".into(),
                    code: "integer_required".into(),
                    message: "Members shown must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("public")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "public".into(),
                code: "boolean_required".into(),
                message: "Public visibility must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object.get("maxEntries").and_then(serde_json::Value::as_i64) {
            projection.push((
                "community.leaderboard.max_entries".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object.get("public").and_then(serde_json::Value::as_bool) {
            projection.push(("community.leaderboard.public".into(), value.to_string()));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = leaderboard_policy_from_json(config);
        let entries = leaderboard_entries_from_json(fixture);
        let decision = evaluate_leaderboard(&policy, entries);
        let visibility = if decision.public { "public" } else { "private" };
        let listed = decision
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| format!("{}. {} — {} XP", index + 1, entry.user_id, entry.xp))
            .collect::<Vec<_>>();
        let mut effect = format!(
            "Render a {visibility} XP leaderboard with up to {} members.",
            policy.max_entries
        );
        if !listed.is_empty() {
            effect.push_str(&format!(" Preview: {}.", listed.join("; ")));
        } else {
            effect.push_str(" Preview contains no eligible members.");
        }
        if decision.excluded_opt_outs > 0 {
            effect.push_str(&format!(
                " Excluded {} member(s) who opted out.",
                decision.excluded_opt_outs
            ));
        }
        if decision.truncated {
            effect.push_str(" Additional eligible members are hidden by the configured limit.");
        }
        let mut effects = vec![effect];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WorkflowAdapter;

impl WorkflowAdapter {
    pub const KEY: &'static str = "management.workflows";
    pub const SOURCE: &'static str = "workflows_adapter_v1";

    fn schema() -> serde_json::Value {
        serde_json::json!({
            "version": FEATURE_SCHEMA_VERSION,
            "source": Self::SOURCE,
            "sections": [{
                "title": "Automation safety limits",
                "description": "Bounded message automations keep your server responsive.",
                "fields": [
                    {"key":"maxWorkflows","label":"Maximum workflows","kind":"number","min":1,"max":100,"help":"The maximum number of active and paused workflows stored for this server."},
                    {"key":"maxReplyLength","label":"Maximum reply length","kind":"number","min":1,"max":1500,"help":"Longer generated replies are rejected before they can be sent."},
                    {"key":"allowMentions","label":"Allow mentions in replies","kind":"toggle","help":"When disabled, everyone/here mentions are neutralised."}
                ]
            }]
        })
    }

    fn defaults() -> serde_json::Value {
        serde_json::json!({"maxWorkflows": 10, "maxReplyLength": 1000, "allowMentions": false})
    }
}

impl FeatureAdapter for WorkflowAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: Self::schema(),
            defaults: Self::defaults(),
            dependencies: vec!["message_content".into(), "send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for (field, min, max, label) in [
            ("maxWorkflows", 1_i64, 100_i64, "Maximum workflows"),
            ("maxReplyLength", 1_i64, 1_500_i64, "Maximum reply length"),
        ] {
            if let Some(value) = object.get(field) {
                if let Some(value) = value.as_i64() {
                    if !(min..=max).contains(&value) {
                        issues.push(ValidationIssue {
                            path: field.into(),
                            code: "out_of_range".into(),
                            message: format!("{label} must be between {min} and {max}."),
                            severity: "error".into(),
                        });
                    }
                } else {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "integer_required".into(),
                        message: format!("{label} must be an integer."),
                        severity: "error".into(),
                    });
                }
            }
        }
        if object
            .get("allowMentions")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "allowMentions".into(),
                code: "boolean_required".into(),
                message: "Mention permission must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object
            .get("maxWorkflows")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "management.workflows.max_workflows".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("maxReplyLength")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "management.workflows.max_reply_length".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("allowMentions")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push((
                "management.workflows.allow_mentions".into(),
                value.to_string(),
            ));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = WorkflowPolicy {
            max_reply_length: config
                .get("maxReplyLength")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1_000)
                .clamp(1, 1_500) as usize,
            allow_mentions: config
                .get("allowMentions")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        };
        let workflow = fixture.get("workflow").unwrap_or(fixture);
        let decision = evaluate_workflow(
            &policy,
            &WorkflowObservation {
                enabled: fixture_bool(workflow, "enabled", "enabled", true),
                trigger: fixture_string(workflow, "trigger", "trigger", "message").into(),
                condition: fixture_string(workflow, "condition", "condition", "").into(),
                action: fixture_string(workflow, "action", "action", "reply").into(),
                payload: fixture_string(workflow, "payload", "payload", "Thanks {user}: {message}")
                    .into(),
                message_content: fixture_string(
                    fixture,
                    "messageContent",
                    "message_content",
                    "hello preview",
                )
                .into(),
                user_mention: fixture_string(
                    fixture,
                    "userMention",
                    "user_mention",
                    "<@preview-user>",
                )
                .into(),
            },
        );
        let mut effects = if let Some(reply) = decision.reply {
            vec![format!(
                "Workflow matched and would send this bounded reply: {reply}"
            )]
        } else if let Some(reaction) = decision.reaction {
            vec![format!("Workflow matched and would react with: {reaction}")]
        } else {
            vec![format!(
                "Workflow would not send a reply ({}).",
                decision.reason
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PrivacyAdapter;

impl PrivacyAdapter {
    pub const KEY: &'static str = "management.privacy";
    pub const SOURCE: &'static str = "privacy_adapter_v1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyDecision {
    pub allowed: bool,
    pub action: String,
    pub max_export_bytes: usize,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_privacy(config: &serde_json::Value, action: &str) -> PrivacyDecision {
    let object = config.as_object();
    let action = action.trim().to_ascii_lowercase();
    let max_export_bytes = object
        .and_then(|value| value.get("maxExportBytes"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1_000_000)
        .clamp(65_536, 10_000_000) as usize;
    let allowed = match action.as_str() {
        "export" | "data" => object
            .and_then(|value| value.get("allowMemberExport"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "erase" => object
            .and_then(|value| value.get("allowMemberErase"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        _ => false,
    };
    let normalized_action = if action == "data" {
        "export".to_owned()
    } else {
        action.clone()
    };
    if !matches!(normalized_action.as_str(), "export" | "erase") {
        return PrivacyDecision {
            allowed: false,
            action: normalized_action,
            max_export_bytes,
            reason_code: "unknown_action",
            explanation: "Choose export or erase for the privacy preview.".into(),
        };
    }
    if !allowed {
        return PrivacyDecision {
            allowed: false,
            action: normalized_action.clone(),
            max_export_bytes,
            reason_code: "action_disabled",
            explanation: format!(
                "Member {} is disabled by this server's privacy policy.",
                if normalized_action == "export" {
                    "exports"
                } else {
                    "erasure"
                }
            ),
        };
    }
    PrivacyDecision {
        allowed: true,
        action: normalized_action.clone(),
        max_export_bytes,
        reason_code: "allowed",
        explanation: if normalized_action == "export" {
            format!(
                "Create a private JSON export up to {max_export_bytes} bytes; moderation evidence remains retained."
            )
        } else {
            "Erase voluntary member data while retaining required moderation evidence.".into()
        },
    }
}

impl FeatureAdapter for PrivacyAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Member data controls",
                    "description": "Choose which self-service privacy requests members can make.",
                    "fields": [
                        {"key":"allowMemberExport","label":"Allow member exports","kind":"toggle","help":"Members can request their own JSON export through /privacy data."},
                        {"key":"allowMemberErase","label":"Allow member erasure","kind":"toggle","help":"Voluntary profile data is erased; moderation audit records stay retained."},
                        {"key":"maxExportBytes","label":"Maximum export size","kind":"number","min":65536,"max":10000000,"help":"Protects DMs and storage from oversized exports."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"allowMemberExport": true, "allowMemberErase": true, "maxExportBytes": 1000000}),
            dependencies: vec!["direct_messages".into(), "manager_session".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in ["allowMemberExport", "allowMemberErase"] {
            if object.get(field).is_some_and(|value| !value.is_boolean()) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "boolean_required".into(),
                    message: "This privacy option must be true or false.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("maxExportBytes") {
            if let Some(value) = value.as_i64() {
                if !(65_536..=10_000_000).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "maxExportBytes".into(),
                        code: "out_of_range".into(),
                        message: "Export size must be between 65536 and 10000000 bytes.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "maxExportBytes".into(),
                    code: "integer_required".into(),
                    message: "Export size must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        for (field, key) in [
            (
                "allowMemberExport",
                "management.privacy.allow_member_export",
            ),
            ("allowMemberErase", "management.privacy.allow_member_erase"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_bool) {
                projection.push((key.into(), value.to_string()));
            }
        }
        if let Some(value) = object
            .get("maxExportBytes")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "management.privacy.max_export_bytes".into(),
                value.to_string(),
            ));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let action = fixture_string(fixture, "privacyAction", "privacy_action", "export");
        let decision = evaluate_privacy(config, action);
        let mut effects = vec![if decision.allowed {
            decision.explanation
        } else {
            format!(
                "Privacy request rejected ({}): {}",
                decision.reason_code, decision.explanation
            )
        }];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StatsAdapter;

impl StatsAdapter {
    pub const KEY: &'static str = "insights.stats";
    pub const SOURCE: &'static str = "stats_adapter_v1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsDecision {
    pub allowed: bool,
    pub channel_id: Option<String>,
    pub window_days: i64,
    pub name: String,
    pub messages: i64,
    pub joins: i64,
    pub leaves: i64,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Build the exact bounded channel-name mutation used by the stats worker.
/// Keeping the template expansion here makes the dashboard preview useful
/// even before a guild has a live statistics channel.
pub fn evaluate_stats(
    config: &serde_json::Value,
    channel_id: Option<&str>,
    messages: i64,
    joins: i64,
    leaves: i64,
) -> StatsDecision {
    evaluate_stats_with_members(config, channel_id, messages, joins, leaves, None)
}

/// A contagem de membros vem do Discord, não da soma de entradas e saídas.
pub fn evaluate_stats_with_members(
    config: &serde_json::Value,
    channel_id: Option<&str>,
    messages: i64,
    joins: i64,
    leaves: i64,
    members: Option<u64>,
) -> StatsDecision {
    let object = config.as_object();
    let window_days = object
        .and_then(|value| value.get("windowDays"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(7)
        .clamp(1, 30);
    let channel_id = channel_id
        .or_else(|| object.and_then(|value| value.get("channelId"))?.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let Some(channel_id) = channel_id else {
        return StatsDecision {
            allowed: false,
            channel_id: None,
            window_days,
            name: String::new(),
            messages,
            joins,
            leaves,
            reason_code: "channel_required",
            explanation: "Choose a real Discord channel before enabling live statistics.".into(),
        };
    };
    if !valid_discord_id(&channel_id) {
        return StatsDecision {
            allowed: false,
            channel_id: Some(channel_id),
            window_days,
            name: String::new(),
            messages,
            joins,
            leaves,
            reason_code: "invalid_channel",
            explanation: "The statistics channel must be a Discord channel ID.".into(),
        };
    }
    let template = object
        .and_then(|value| value.get("nameTemplate"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("messages-{messages}");
    let Some(template) = member_counter::render_member_count(template, members) else {
        return StatsDecision {
            allowed: false,
            channel_id: Some(channel_id),
            window_days,
            name: String::new(),
            messages,
            joins,
            leaves,
            reason_code: "member_count_unavailable",
            explanation: "Discord member count is unavailable; keep the existing channel name."
                .into(),
        };
    };
    let name = template
        .replace("{messages}", &messages.to_string())
        .replace("{joins}", &joins.to_string())
        .replace("{leaves}", &leaves.to_string())
        .replace("{days}", &window_days.to_string())
        .chars()
        .filter(|character| !character.is_control())
        .take(100)
        .collect::<String>();
    if name.trim().is_empty() {
        return StatsDecision {
            allowed: false,
            channel_id: Some(channel_id),
            window_days,
            name,
            messages,
            joins,
            leaves,
            reason_code: "empty_name",
            explanation: "The statistics template produced an empty channel name.".into(),
        };
    }
    StatsDecision {
        allowed: true,
        channel_id: Some(channel_id),
        window_days,
        name: name.clone(),
        messages,
        joins,
        leaves,
        reason_code: "channel_update_ready",
        explanation: format!("Rename the statistics channel to `{name}`."),
    }
}

impl FeatureAdapter for StatsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Server statistics",
                    "description": "Control the period, visibility and optional live counter channel for server statistics.",
                    "fields": [
                        {"key":"windowDays","label":"Reporting window (days)","kind":"number","min":1,"max":30,"help":"Number of recent daily snapshots included."},
                        {"key":"public","label":"Show publicly","kind":"toggle","help":"When disabled, only the requesting member sees the summary."},
                        {"key":"channelId","label":"Live counter channel (optional)","kind":"channel","help":"Automatically rename an existing channel with the current member total or activity counters. No webhook is needed."},
                        {"key":"intervalMinutes","label":"Counter refresh (minutes)","kind":"number","min":5,"max":1440,"advanced":true,"help":"Member counters refresh at most once every 10 minutes to respect Discord limits."},
                        {"key":"nameTemplate","label":"Channel name template","kind":"text","max":100,"help":"Use {members} (or {count}) for the current total, including bots. Also supports {messages}, {joins}, {leaves} and {days}. Example: 📊 Members: {members}"}
                    ]
                }]
            }),
            defaults: serde_json::json!({"windowDays": 7, "public": false, "channelId": "", "intervalMinutes": 15, "nameTemplate": "messages-{messages}"}),
            dependencies: vec![
                "message_events".into(),
                "scheduler".into(),
                "manage_channels".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("windowDays") {
            if let Some(value) = value.as_i64() {
                if !(1..=30).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "windowDays".into(),
                        code: "out_of_range".into(),
                        message: "Reporting window must be between 1 and 30 days.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "windowDays".into(),
                    code: "integer_required".into(),
                    message: "Reporting window must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("public")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "public".into(),
                code: "boolean_required".into(),
                message: "Public visibility must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("channelId")
            && (!value.is_string()
                || value
                    .as_str()
                    .is_some_and(|value| !value.is_empty() && !valid_discord_id(value)))
        {
            issues.push(ValidationIssue {
                path: "channelId".into(),
                code: "channel_id_required".into(),
                message: "Live counter channel must be a Discord channel ID or empty.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("intervalMinutes")
            && !value
                .as_i64()
                .is_some_and(|value| (5..=1_440).contains(&value))
        {
            issues.push(ValidationIssue {
                path: "intervalMinutes".into(),
                code: "out_of_range".into(),
                message: "Counter refresh must be between 5 and 1440 minutes.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("nameTemplate")
            && (!value.is_string()
                || value.as_str().is_some_and(|value| {
                    value.trim().is_empty() || value.chars().count() > 100 || !value.contains('{')
                }))
        {
            issues.push(ValidationIssue {
                path: "nameTemplate".into(),
                code: "invalid_template".into(),
                message: "Channel name template must be non-empty, at most 100 characters and contain a placeholder.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut projection = Vec::new();
        if let Some(value) = object.get("windowDays").and_then(serde_json::Value::as_i64) {
            projection.push(("insights.stats.window_days".into(), value.to_string()));
        }
        if let Some(value) = object.get("public").and_then(serde_json::Value::as_bool) {
            projection.push(("insights.stats.public".into(), value.to_string()));
        }
        if let Some(value) = object.get("channelId").and_then(serde_json::Value::as_str) {
            projection.push(("insights.stats.channel_id".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("intervalMinutes")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "insights.stats.interval_minutes".into(),
                value.clamp(5, 1_440).to_string(),
            ));
        }
        if let Some(value) = object
            .get("nameTemplate")
            .and_then(serde_json::Value::as_str)
        {
            projection.push(("insights.stats.name_template".into(), value.to_string()));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let channel = fixture
            .get("channelId")
            .or_else(|| fixture.get("channel_id"))
            .and_then(serde_json::Value::as_str)
            .or_else(|| config.get("channelId").and_then(serde_json::Value::as_str));
        let messages = fixture
            .get("statsMessages")
            .or_else(|| fixture.get("stats_messages"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(128)
            .max(0);
        let joins = fixture
            .get("statsJoins")
            .or_else(|| fixture.get("stats_joins"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(12)
            .max(0);
        let leaves = fixture
            .get("statsLeaves")
            .or_else(|| fixture.get("stats_leaves"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(3)
            .max(0);
        let members = fixture
            .get("statsMembers")
            .or_else(|| fixture.get("stats_members"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(26);
        let decision =
            evaluate_stats_with_members(config, channel, messages, joins, leaves, Some(members));
        let mut effects = vec![if decision.allowed {
            format!(
                "{} ({}, {} joins, {} leaves over {} days).",
                decision.explanation,
                decision.messages,
                decision.joins,
                decision.leaves,
                decision.window_days
            )
        } else {
            format!(
                "Statistics preview rejected ({}): {}",
                decision.reason_code, decision.explanation
            )
        }];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HelpAdapter;

impl HelpAdapter {
    pub const KEY: &'static str = "utility.help";
    pub const SOURCE: &'static str = "help_adapter_v1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpDecision {
    pub show_modules: bool,
    pub show_dashboard: bool,
    pub explanation: String,
}

pub fn evaluate_help(config: &serde_json::Value) -> HelpDecision {
    let show_modules = config
        .get("showModules")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let show_dashboard = config
        .get("showDashboard")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let mut parts = vec!["Return the enabled Vozen Helper modules and commands.".to_owned()];
    if show_modules {
        parts.push("Include the module summary.".into());
    }
    if show_dashboard {
        parts.push("Include the dashboard link.".into());
    }
    HelpDecision {
        show_modules,
        show_dashboard,
        explanation: parts.join(" "),
    }
}

impl FeatureAdapter for HelpAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Help message",
                    "description": "Choose the links and module list shown by /help.",
                    "fields": [
                        {"key":"showModules","label":"Show module list","kind":"toggle","help":"Include the enabled module summary in the response."},
                        {"key":"showDashboard","label":"Include dashboard link","kind":"toggle","help":"Append the dashboard URL for server managers."}
                    ]
                }]
            }),
            defaults: serde_json::json!({"showModules": true, "showDashboard": true}),
            dependencies: vec!["send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        ["showModules", "showDashboard"]
            .into_iter()
            .filter(|field| object.get(*field).is_some_and(|value| !value.is_boolean()))
            .map(|field| ValidationIssue {
                path: field.into(),
                code: "boolean_required".into(),
                message: "This help option must be true or false.".into(),
                severity: "error".into(),
            })
            .collect()
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        [
            ("showModules", "utility.help.show_modules"),
            ("showDashboard", "utility.help.show_dashboard"),
        ]
        .into_iter()
        .filter_map(|(field, key)| {
            object
                .get(field)
                .and_then(serde_json::Value::as_bool)
                .map(|value| (key.into(), value.to_string()))
        })
        .collect()
    }

    fn simulate(&self, config: &serde_json::Value, _fixture: &serde_json::Value) -> Vec<String> {
        let decision = evaluate_help(config);
        let mut effects = vec![decision.explanation];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Controls the safety envelope for manual moderation commands.  The command
/// handlers read the projected values before touching Discord, so the panel
/// can no longer expose limits that are ignored by the runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModerationAdapter;

impl ModerationAdapter {
    pub const KEY: &'static str = "management.moderation";
    pub const SOURCE: &'static str = "moderation_adapter_v1";
}

impl FeatureAdapter for ModerationAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Moderation safety",
                    "description": "Set guardrails used by manual moderation commands.",
                    "fields": [
                        {"key":"requireReason","label":"Require a reason","kind":"toggle","help":"Reject destructive actions without a useful reason."},
                        {"key":"maxPurge","label":"Maximum purge count","kind":"number","min":1,"max":100,"help":"Upper bound for one purge command."},
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "requireReason": true,
                "maxPurge": 100
            }),
            dependencies: vec!["moderate_members".into(), "manage_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in ["requireReason"] {
            if object.get(field).is_some_and(|value| !value.is_boolean()) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "boolean_required".into(),
                    message: "This option must be true or false.".into(),
                    severity: "error".into(),
                });
            }
        }
        for (field, min, max) in [("maxPurge", 1_i64, 100_i64)] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64)
                && !(min..=max).contains(&value)
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: format!("The value must be between {min} and {max}."),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for (field, setting) in [("requireReason", "management.moderation.require_reason")] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_bool) {
                pairs.push((setting.into(), value.to_string()));
            }
        }
        for (field, setting) in [("maxPurge", "management.moderation.max_purge")] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64) {
                pairs.push((setting.into(), value.to_string()));
            }
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = ModerationPolicy {
            require_reason: config
                .get("requireReason")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true),
            max_purge: config
                .get("maxPurge")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(100)
                .clamp(1, 100) as u64,
        };
        let action = fixture_string(fixture, "action", "action", "purge");
        let reason = fixture_string(fixture, "reason", "reason", "");
        let requested_count = fixture
            .get("requestedCount")
            .or_else(|| fixture.get("requested_count"))
            .and_then(serde_json::Value::as_i64);
        let decision = evaluate_moderation(
            &policy,
            &ModerationObservation {
                action: action.to_owned(),
                reason: reason.to_owned(),
                requested_count,
            },
        );
        let mut effects = if decision.allowed {
            if let Some(count) = decision.effective_count {
                vec![format!(
                    "Allow `{action}` with an effective limit of {count} message(s)."
                )]
            } else {
                vec![format!(
                    "Allow `{action}` after the configured safety checks."
                )]
            }
        } else {
            vec![format!("Block `{action}`: {}", decision.explanation)]
        };
        effects.push(format!("Decision code: `{}`.", decision.reason_code));
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AntiScamAdapter;

impl AntiScamAdapter {
    pub const KEY: &'static str = "protection.antiscam";
    pub const SOURCE: &'static str = "anti_scam_adapter_v1";
}

impl FeatureAdapter for AntiScamAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Scam protection",
                    "description": "Detect invite scams, suspicious domains and common social-engineering phrases.",
                    "fields": [
                        {"key":"blockInvites","label":"Block unsolicited Discord invites","kind":"toggle"},
                        {"key":"blockedDomains","label":"Blocked domains","kind":"tags","max":100,"advanced":true},
                        {"key":"blockedKeywords","label":"Blocked phrases","kind":"tags","max":100,"advanced":true},
                        {"key":"ignoredChannels","label":"Ignored channels","kind":"channels","max":100,"advanced":true},
                        {"key":"ignoredRoles","label":"Ignored roles","kind":"roles","max":100,"advanced":true},
                        {"key":"logChannel","label":"Log channel","kind":"channel","advanced":true},
                        {"key":"timeoutSeconds","label":"Timeout (seconds)","kind":"number","min":0,"max":86400,"advanced":true},
                        {"key":"deleteMessage","label":"Delete matched messages","kind":"toggle","advanced":true},
                        {"key":"alertOnly","label":"Monitor only","kind":"toggle","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "blockInvites": true,
                "blockedDomains": [],
                "blockedKeywords": ["free nitro", "steam gift", "claim your prize", "verify your wallet"],
                "ignoredChannels": [],
                "ignoredRoles": [],
                "logChannel": "",
                "timeoutSeconds": 300,
                "deleteMessage": true,
                "alertOnly": false
            }),
            // Message deletion and timeouts are optional controls. Their
            // exact Discord permissions are checked against the published
            // configuration by the API preflight, rather than shown as an
            // unconditional requirement in the panel.
            dependencies: vec!["message_content_intent".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in ["blockInvites", "alertOnly", "deleteMessage"] {
            if object.get(field).is_some_and(|value| !value.is_boolean()) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "boolean_required".into(),
                    message: "This option must be true or false.".into(),
                    severity: "error".into(),
                });
            }
        }
        for (field, max, allow_url) in [
            ("blockedDomains", 100_usize, true),
            ("blockedKeywords", 100, false),
            ("ignoredChannels", 100, false),
            ("ignoredRoles", 100, false),
        ] {
            if let Some(value) = object.get(field) {
                let valid = value.as_array().is_some_and(|items| {
                    items.len() <= max
                        && items.iter().all(|item| {
                            item.as_str().is_some_and(|text| {
                                let text = text.trim();
                                !text.is_empty()
                                    && text.chars().count() <= 200
                                    && !text.chars().any(char::is_control)
                                    && (!allow_url || !text.contains('/'))
                            })
                        })
                });
                if !valid {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "invalid_list".into(),
                        message: "Use a bounded list of non-empty values.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        for field in ["ignoredChannels", "ignoredRoles"] {
            if let Some(value) = object.get(field) {
                let valid_ids = value.as_array().is_some_and(|items| {
                    items
                        .iter()
                        .all(|item| item.as_str().is_some_and(|id| valid_discord_id(id.trim())))
                });
                if !valid_ids {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "invalid_discord_ids".into(),
                        message: "Choose valid Discord channel or role IDs.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        if let Some(value) = object
            .get("timeoutSeconds")
            .and_then(serde_json::Value::as_i64)
            && !(0..=86_400).contains(&value)
        {
            issues.push(ValidationIssue {
                path: "timeoutSeconds".into(),
                code: "out_of_range".into(),
                message: "Timeout must be between 0 and 86400 seconds.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("logChannel")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "logChannel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel for protection logs.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        if let Some(value) = object
            .get("blockInvites")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("security.antiscam.block_invites".into(), value.to_string()));
        }
        if let Some(value) = object.get("alertOnly").and_then(serde_json::Value::as_bool) {
            pairs.push(("security.antiscam.alert_only".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("deleteMessage")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("security.antiscam.delete_message".into(), value.to_string()));
        }
        if let Some(value) = object.get("logChannel").and_then(serde_json::Value::as_str) {
            pairs.push(("security.antiscam.log_channel".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("timeoutSeconds")
            .and_then(serde_json::Value::as_i64)
        {
            pairs.push((
                "security.antiscam.timeout_seconds".into(),
                value.to_string(),
            ));
        }
        for (field, setting) in [
            ("blockedDomains", "security.antiscam.blocked_domains"),
            ("blockedKeywords", "security.antiscam.blocked_keywords"),
            ("ignoredChannels", "security.antiscam.ignored_channels"),
            ("ignoredRoles", "security.antiscam.ignored_roles"),
        ] {
            if let Some(values) = object.get(field).and_then(serde_json::Value::as_array) {
                pairs.push((
                    setting.into(),
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ));
            }
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let channel_id = fixture_string(fixture, "channelId", "channel_id", "preview-channel");
        let role_ids = fixture
            .get("roleIds")
            .or_else(|| fixture.get("role_ids"))
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .take(100)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let content = fixture_string(
            fixture,
            "content",
            "content",
            "Claim your free Nitro at https://discord.gg/example",
        );
        let decision = evaluate_scam_with_roles(
            &scam_policy_from_json(config),
            channel_id,
            &role_ids,
            content,
        );
        let mut effects = if decision.ignored {
            vec!["Ignore the message because this channel is exempt.".into()]
        } else if decision.matched.is_empty() {
            vec!["No scam pattern matched; keep the message.".into()]
        } else if decision.should_act {
            vec![format!(
                "Match {} and apply the configured action (timeout: {}s; {}).",
                decision.matched.join(", "),
                decision.timeout_seconds,
                if decision.should_delete {
                    "delete the matching message"
                } else {
                    "keep the matching message"
                }
            )]
        } else {
            vec![format!(
                "Match {} in monitor-only mode; do not modify the message.",
                decision.matched.join(", ")
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WelcomeChannelAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeChannelDecision {
    pub allowed: bool,
    pub message: String,
    pub steps: Vec<String>,
    pub reason_code: &'static str,
    pub explanation: String,
}

/// Resolve the guided welcome payload used after a member joins. The Discord
/// handler supplies any template-expanded message, so this function remains
/// deterministic for both legacy settings and API previews.
pub fn evaluate_welcome_channel(
    config: &serde_json::Value,
    member: &str,
    server: &str,
) -> WelcomeChannelDecision {
    let channel_id = config
        .get("channelId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    if !valid_discord_id(channel_id) || channel_id == "0" {
        return WelcomeChannelDecision {
            allowed: false,
            message: String::new(),
            steps: Vec::new(),
            reason_code: "missing_channel",
            explanation: "Choose a valid welcome channel before publishing the guide.".into(),
        };
    }
    let template = config
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let message = render_member_message(template, member, server);
    if message.trim().is_empty() {
        return WelcomeChannelDecision {
            allowed: false,
            message,
            steps: Vec::new(),
            reason_code: "empty_message",
            explanation: "The guided welcome message cannot be empty.".into(),
        };
    }
    let steps = config
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|step| matches!(*step, "rules" | "introductions" | "channels" | "help"))
                .map(str::to_owned)
                .take(4)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if steps.is_empty() {
        return WelcomeChannelDecision {
            allowed: false,
            message,
            steps,
            reason_code: "no_steps",
            explanation: "Choose at least one guided welcome step.".into(),
        };
    }
    WelcomeChannelDecision {
        allowed: true,
        message,
        steps,
        reason_code: "welcome_channel_ready",
        explanation: "The guided welcome message and bounded steps can be published.".into(),
    }
}

impl WelcomeChannelAdapter {
    pub const KEY: &'static str = "support.welcome_channel";
    pub const SOURCE: &'static str = "welcome_channel_adapter_v1";
}

impl FeatureAdapter for WelcomeChannelAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Guided welcome channel",
                    "description": "Post the first steps and server rules when a new member arrives.",
                    "fields": [
                        {"key":"channelId","label":"Welcome channel","kind":"channel"},
                        {"key":"message","label":"Guide message","kind":"textarea","min":1,"max":2000,"help":"Use {member} and {server} as placeholders."},
                        {"key":"steps","label":"Guided steps","kind":"tags","max":4,"help":"Choose from rules, introductions, channels and help."},
                        {"key":"rulesChannel","label":"Rules channel (optional)","kind":"channel","advanced":true},
                        {"key":"introductionsChannel","label":"Introductions channel (optional)","kind":"channel","advanced":true},
                        {"key":"channelsChannel","label":"Channels guide (optional)","kind":"channel","advanced":true},
                        {"key":"templateId","label":"Reusable guide template","kind":"select","options":[["","No template"]],"help":"Optional: choose a template created in Models and importação.","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "channelId": "",
                "message": "Welcome {member}! Start with the rules, introduce yourself and check the server channels.",
                "steps": ["rules", "introductions", "channels"],
                "rulesChannel": "",
                "introductionsChannel": "",
                "channelsChannel": "",
                "templateId": ""
            }),
            dependencies: vec!["send_messages".into(), "view_channel".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if !object
            .get("channelId")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.is_empty() || valid_discord_id(value))
        {
            issues.push(ValidationIssue {
                path: "channelId".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel.".into(),
                severity: "error".into(),
            });
        }
        if object.get("templateId").is_some_and(|value| {
            !value.as_str().is_some_and(|raw| {
                raw.is_empty()
                    || ((1..=64).contains(&raw.len())
                        && raw.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        }))
            })
        }) {
            issues.push(ValidationIssue {
                path: "templateId".into(),
                code: "invalid_template_id".into(),
                message: "Choose a template from this guild.".into(),
                severity: "error".into(),
            });
        }
        if !object
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty() && value.chars().count() <= 2_000)
        {
            issues.push(ValidationIssue {
                path: "message".into(),
                code: "invalid_message".into(),
                message: "The guide message must contain 1-2000 characters.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("steps") {
            let valid = value.as_array().is_some_and(|steps| {
                (1..=4).contains(&steps.len())
                    && steps.iter().all(|step| {
                        step.as_str().is_some_and(|step| {
                            matches!(step, "rules" | "introductions" | "channels" | "help")
                        })
                    })
                    && steps
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        == steps.len()
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "steps".into(),
                    code: "invalid_steps".into(),
                    message: "Choose one to four unique steps from rules, introductions, channels and help.".into(),
                    severity: "error".into(),
                });
            }
        }
        for field in ["rulesChannel", "introductionsChannel", "channelsChannel"] {
            if object.get(field).is_some_and(|value| {
                !value
                    .as_str()
                    .is_some_and(|raw| raw.is_empty() || valid_discord_id(raw))
            }) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "invalid_channel_id".into(),
                    message: "Choose a valid Discord channel or leave it empty.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        if let Some(value) = object.get("channelId").and_then(serde_json::Value::as_str) {
            pairs.push(("support.welcome_channel.channel_id".into(), value.into()));
        }
        if let Some(value) = object.get("message").and_then(serde_json::Value::as_str) {
            pairs.push(("support.welcome_channel.message".into(), value.into()));
        }
        if let Some(values) = object.get("steps").and_then(serde_json::Value::as_array) {
            pairs.push((
                "support.welcome_channel.steps".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        for (field, setting) in [
            ("rulesChannel", "support.welcome_channel.rules_channel"),
            (
                "introductionsChannel",
                "support.welcome_channel.introductions_channel",
            ),
            (
                "channelsChannel",
                "support.welcome_channel.channels_channel",
            ),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                pairs.push((setting.into(), value.into()));
            }
        }
        if let Some(value) = object.get("templateId").and_then(serde_json::Value::as_str) {
            pairs.push(("support.welcome_channel.template_id".into(), value.into()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let decision = evaluate_welcome_channel(
            config,
            fixture
                .get("memberMention")
                .or_else(|| fixture.get("displayName"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<@preview-user>"),
            fixture
                .get("serverName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("this server"),
        );
        let mut effects = if decision.allowed {
            vec![format!(
                "Publish the guided welcome message with {} step button(s), mentions disabled.",
                decision.steps.len()
            )]
        } else {
            vec![format!(
                "Guided welcome rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LevelsAdapter;

impl LevelsAdapter {
    pub const KEY: &'static str = "community.levels";
    pub const SOURCE: &'static str = "levels_adapter_v1";
}

impl FeatureAdapter for LevelsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "XP progression",
                    "description": "Tune message XP and level-up announcements.",
                    "fields": [
                        {"key":"xpMin","label":"Minimum XP per message","kind":"number","min":1,"max":1000},
                        {"key":"xpMax","label":"Maximum XP per message","kind":"number","min":1,"max":2000},
                        {"key":"cooldownSeconds","label":"XP cooldown (seconds)","kind":"number","min":0,"max":3600},
                        {"key":"voiceXpEnabled","label":"Award XP in voice channels","kind":"toggle","advanced":true},
                        {"key":"voiceXpPerMinute","label":"Voice XP per minute","kind":"number","min":0,"max":30,"advanced":true},
                        {"key":"ignoredChannels","label":"Channels that do not award XP","kind":"channels","max":100,"advanced":true},
                        {"key":"levelRoles","label":"Level role rewards (level=role ID)","kind":"tags","max":50,"advanced":true},
                        {"key":"stackRoles","label":"Keep previous level roles","kind":"toggle","advanced":true},
                        {"key":"announceChannel","label":"Level-up channel","kind":"channel","advanced":true},
                        {"key":"announceTemplate","label":"Level-up message","kind":"text","max":1000,"advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "bannerEnabled": true,
                "xpMin": 15,
                "xpMax": 30,
                "cooldownSeconds": 60,
                "voiceXpEnabled": false,
                "voiceXpPerMinute": 2,
                "ignoredChannels": [],
                "levelRoles": [],
                "stackRoles": true,
                "announceChannel": "",
                "announceTemplate": "{member} reached level {level}!"
            }),
            dependencies: vec![
                "message_content_intent".into(),
                "send_messages".into(),
                "embed_links".into(),
                "attach_files".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if object
            .get("bannerEnabled")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "bannerEnabled".into(),
                code: "boolean_required".into(),
                message: "Choose whether to show level-up banners.".into(),
                severity: "error".into(),
            });
        }
        if let Some(card) = object.get("rankCard") {
            issues.extend(RankCardAdapter.validate(card).into_iter().map(|mut issue| {
                issue.path = format!("rankCard.{}", issue.path);
                issue
            }));
        }
        for (field, min, max) in [
            ("xpMin", 1_i64, 1_000_i64),
            ("xpMax", 1, 2_000),
            ("cooldownSeconds", 0, 3_600),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64)
                && !(min..=max).contains(&value)
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: format!("The value must be between {min} and {max}."),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("xpMin")
            .and_then(serde_json::Value::as_i64)
            .zip(object.get("xpMax").and_then(serde_json::Value::as_i64))
            .is_some_and(|(min, max)| max < min)
        {
            issues.push(ValidationIssue {
                path: "xpMax".into(),
                code: "must_be_at_least_minimum".into(),
                message: "Maximum XP must be at least minimum XP.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("announceChannel")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "announceChannel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("announceTemplate")
            && !value
                .as_str()
                .is_some_and(|text| !text.trim().is_empty() && text.chars().count() <= 1_000)
        {
            issues.push(ValidationIssue {
                path: "announceTemplate".into(),
                code: "invalid_template".into(),
                message: "The announcement must contain 1-1000 characters.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("voiceXpEnabled")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "voiceXpEnabled".into(),
                code: "boolean_required".into(),
                message: "Voice XP enabled must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("voiceXpPerMinute") {
            if let Some(value) = value.as_i64() {
                if !(0..=30).contains(&value) {
                    issues.push(ValidationIssue {
                        path: "voiceXpPerMinute".into(),
                        code: "out_of_range".into(),
                        message: "Voice XP per minute must be between 0 and 30.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "voiceXpPerMinute".into(),
                    code: "integer_required".into(),
                    message: "Voice XP per minute must be an integer.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("ignoredChannels") {
            if let Some(values) = value.as_array() {
                if values.len() > 100
                    || values
                        .iter()
                        .any(|item| !item.as_str().is_some_and(valid_discord_id))
                {
                    issues.push(ValidationIssue {
                        path: "ignoredChannels".into(),
                        code: "invalid_channel_ids".into(),
                        message: "Ignored channels must contain at most 100 Discord channel IDs."
                            .into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "ignoredChannels".into(),
                    code: "array_required".into(),
                    message: "Ignored channels must be an array.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("levelRoles") {
            if let Some(values) = value.as_array() {
                if values.len() > 50
                    || values.iter().any(|item| {
                        let Some(entry) = item.as_str() else {
                            return true;
                        };
                        let mut parts = entry.split('=');
                        let level = parts
                            .next()
                            .and_then(|part| part.trim().parse::<u32>().ok());
                        let role = parts.next().and_then(|part| {
                            valid_discord_id(part.trim())
                                .then(|| part.trim().parse::<u64>().ok())
                                .flatten()
                        });
                        level.is_none() || role.is_none() || parts.next().is_some()
                    })
                {
                    issues.push(ValidationIssue {
                        path: "levelRoles".into(),
                        code: "invalid_level_roles".into(),
                        message: "Rewards must use level=role ID, with at most 50 entries.".into(),
                        severity: "error".into(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    path: "levelRoles".into(),
                    code: "array_required".into(),
                    message: "Level rewards must be an array.".into(),
                    severity: "error".into(),
                });
            }
        }
        if object
            .get("stackRoles")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "stackRoles".into(),
                code: "boolean_required".into(),
                message: "Stack roles must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        // bannerEnabled is retained in the config for old clients, but is no
        // longer projected: Discord always includes the level-up card.
        if let Some(card) = object.get("rankCard") {
            pairs.push(("community.rank_card".into(), card.to_string()));
        }
        for (field, setting) in [
            ("xpMin", "community.levels.xp_min"),
            ("xpMax", "community.levels.xp_max"),
            ("cooldownSeconds", "community.levels.cooldown_seconds"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64) {
                pairs.push((setting.into(), value.to_string()));
            }
        }
        for (field, setting) in [
            ("announceChannel", "community.levels.announce_channel"),
            ("announceTemplate", "community.levels.announce_template"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                pairs.push((setting.into(), value.into()));
            }
        }
        if let Some(value) = object
            .get("voiceXpEnabled")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push((
                "community.levels.voice_xp_enabled".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object
            .get("voiceXpPerMinute")
            .and_then(serde_json::Value::as_i64)
        {
            pairs.push((
                "community.levels.voice_xp_per_minute".into(),
                value.to_string(),
            ));
        }
        if let Some(values) = object
            .get("ignoredChannels")
            .and_then(serde_json::Value::as_array)
        {
            pairs.push((
                "community.levels.ignored_channels".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(values) = object
            .get("levelRoles")
            .and_then(serde_json::Value::as_array)
        {
            pairs.push((
                "community.levels.level_roles".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(value) = object
            .get("stackRoles")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("community.levels.stack_roles".into(), value.to_string()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let source = fixture_string(fixture, "source", "source", "message");
        let channel_id = fixture_string(fixture, "channelId", "channel_id", "preview-channel");
        let event_id = fixture_string(fixture, "eventId", "event_id", "preview-event");
        let cooldown_ready = fixture_bool(fixture, "cooldownReady", "cooldown_ready", true);
        let duration_minutes = fixture_u64(fixture, "durationMinutes", "duration_minutes", 5);
        let before_xp = fixture
            .get("currentXp")
            .or_else(|| fixture.get("current_xp"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let decision = evaluate_levels(
            config,
            source,
            channel_id,
            event_id,
            cooldown_ready,
            duration_minutes,
            before_xp,
        );
        let mut effects = if decision.allowed {
            let level_note = if decision.after_level > decision.before_level {
                format!(" Level up to {}.", decision.after_level)
            } else {
                String::new()
            };
            vec![format!("{}{}", decision.explanation, level_note)]
        } else {
            vec![format!(
                "XP award rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StarboardAdapter;

impl StarboardAdapter {
    pub const KEY: &'static str = "community.starboard";
    pub const SOURCE: &'static str = "starboard_adapter_v1";
}

impl FeatureAdapter for StarboardAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Starboard",
                    "description": "Choose the channel and reaction score required to feature a message.",
                    "fields": [
                        {"key":"channel","label":"Starboard channel","kind":"channel"},
                        {"key":"threshold","label":"Stars required","kind":"number","min":1,"max":100},
                        {"key":"emoji","label":"Reaction emoji","kind":"text","min":1,"max":32},
                        {"key":"allowSelfStar","label":"Allow authors to star their own message","kind":"toggle","advanced":true},
                        {"key":"includeImages","label":"Include image attachments","kind":"toggle","advanced":true},
                        {"key":"ignoredChannels","label":"Ignored channels","kind":"channels","max":100,"advanced":true},
                        {"key":"ignoredRoles","label":"Ignored member roles","kind":"roles","max":100,"advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "channel": "",
                "threshold": 3,
                "emoji": "⭐",
                "allowSelfStar": false,
                "includeImages": true,
                "ignoredChannels": [],
                "ignoredRoles": []
            }),
            dependencies: vec![
                "read_message_history".into(),
                "add_reactions".into(),
                "send_messages".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("threshold").and_then(serde_json::Value::as_i64)
            && !(1..=100).contains(&value)
        {
            issues.push(ValidationIssue {
                path: "threshold".into(),
                code: "out_of_range".into(),
                message: "Stars required must be between 1 and 100.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("channel")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "channel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel.".into(),
                severity: "error".into(),
            });
        }
        for field in ["ignoredChannels", "ignoredRoles"] {
            if let Some(value) = object.get(field) {
                let valid = value.as_array().is_some_and(|items| {
                    items.len() <= 100
                        && items.iter().all(|item| {
                            item.as_str().is_some_and(|text| {
                                !text.trim().is_empty() && valid_discord_id(text)
                            })
                        })
                });
                if !valid {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "invalid_discord_ids".into(),
                        message: "Choose up to 100 valid Discord IDs.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for (field, setting) in [
            ("channel", "community.starboard.channel_id"),
            ("emoji", "community.starboard.emoji"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                pairs.push((setting.into(), value.into()));
            }
        }
        if let Some(value) = object.get("threshold").and_then(serde_json::Value::as_i64) {
            pairs.push(("community.starboard.threshold".into(), value.to_string()));
        }
        for (field, setting) in [
            ("allowSelfStar", "community.starboard.allow_self_star"),
            ("includeImages", "community.starboard.include_images"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_bool) {
                pairs.push((setting.into(), value.to_string()));
            }
        }
        if let Some(values) = object
            .get("ignoredChannels")
            .and_then(serde_json::Value::as_array)
        {
            pairs.push((
                "community.starboard.ignored_channels".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(values) = object
            .get("ignoredRoles")
            .and_then(serde_json::Value::as_array)
        {
            pairs.push((
                "community.starboard.ignored_roles".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = starboard_policy_from_json(config);
        let reactor_ids = {
            let values = fixture_strings(fixture, "reactorIds", "reactor_ids");
            if values.is_empty() {
                (0..fixture_u64(fixture, "reactionCount", "reaction_count", 5))
                    .take(100)
                    .map(|index| format!("preview-reactor-{index}"))
                    .collect()
            } else {
                values
            }
        };
        let decision = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: fixture_string(
                    fixture,
                    "channelId",
                    "channel_id",
                    "preview-channel",
                )
                .to_owned(),
                author_id: fixture_string(fixture, "authorId", "author_id", "preview-author")
                    .to_owned(),
                reactor_ids,
                author_role_ids: fixture_strings(fixture, "authorRoleIds", "author_role_ids"),
                has_attachments: fixture_bool(fixture, "hasAttachments", "has_attachments", false),
            },
        );
        let mut effects = if decision.should_publish {
            vec![format!(
                "Create or update the starboard mirror ({}/{} reactions). {}",
                decision.count, decision.threshold, decision.reason
            )]
        } else if decision.ignored {
            vec![format!("Do not mirror this message. {}", decision.reason)]
        } else {
            vec![format!(
                "Keep the original message below the board threshold ({}/{} reactions). {}",
                decision.count, decision.threshold, decision.reason
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Runtime policy for the starboard.  Both the Discord event handler and the
/// API simulator consume this type so a preview cannot disagree with the
/// reaction reconciliation performed by the bot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarboardPolicy {
    pub threshold: u64,
    pub allow_self_star: bool,
    pub include_images: bool,
    pub ignored_channels: Vec<String>,
    pub ignored_roles: Vec<String>,
}

impl Default for StarboardPolicy {
    fn default() -> Self {
        Self {
            threshold: 3,
            allow_self_star: false,
            include_images: true,
            ignored_channels: Vec::new(),
            ignored_roles: Vec::new(),
        }
    }
}

pub fn starboard_policy_from_json(config: &serde_json::Value) -> StarboardPolicy {
    let object = config.as_object();
    let ids = |field: &str| {
        object
            .and_then(|values| values.get(field))
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    StarboardPolicy {
        threshold: object
            .and_then(|values| values.get("threshold"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3)
            .clamp(1, 100),
        allow_self_star: object
            .and_then(|values| values.get("allowSelfStar"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        include_images: object
            .and_then(|values| values.get("includeImages"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        ignored_channels: ids("ignoredChannels"),
        ignored_roles: ids("ignoredRoles"),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StarboardObservation {
    pub source_channel_id: String,
    pub author_id: String,
    pub reactor_ids: Vec<String>,
    pub author_role_ids: Vec<String>,
    pub has_attachments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarboardDecision {
    pub ignored: bool,
    pub should_publish: bool,
    pub count: u64,
    pub threshold: u64,
    pub reason: String,
}

pub fn evaluate_starboard(
    policy: &StarboardPolicy,
    observation: &StarboardObservation,
) -> StarboardDecision {
    let ignored_channel = policy
        .ignored_channels
        .iter()
        .any(|value| value == &observation.source_channel_id);
    let ignored_role = policy.ignored_roles.iter().any(|ignored| {
        observation
            .author_role_ids
            .iter()
            .any(|role| role == ignored)
    });
    if ignored_channel || ignored_role {
        return StarboardDecision {
            ignored: true,
            should_publish: false,
            count: 0,
            threshold: policy.threshold,
            reason: if ignored_channel {
                "The source channel is ignored by the starboard policy.".into()
            } else {
                "The message author has an ignored role.".into()
            },
        };
    }
    if observation.has_attachments && !policy.include_images {
        return StarboardDecision {
            ignored: true,
            should_publish: false,
            count: 0,
            threshold: policy.threshold,
            reason: "Image attachments are disabled by the starboard policy.".into(),
        };
    }
    let mut reactors = HashSet::new();
    for reactor_id in &observation.reactor_ids {
        if policy.allow_self_star || reactor_id != &observation.author_id {
            reactors.insert(reactor_id);
        }
    }
    let count = reactors.len() as u64;
    StarboardDecision {
        ignored: false,
        should_publish: count >= policy.threshold,
        count,
        threshold: policy.threshold,
        reason: if count >= policy.threshold {
            "The message reached the configured star threshold.".into()
        } else {
            "The message is below the configured star threshold.".into()
        },
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AntiRaidAdapter;

impl AntiRaidAdapter {
    pub const KEY: &'static str = "protection.anti_raid";
    pub const SOURCE: &'static str = "anti_raid_adapter_v1";
}

impl FeatureAdapter for AntiRaidAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Join burst protection",
                    "description": "Enable the gate when too many members arrive in a short window.",
                    "fields": [
                        {"key":"joinThreshold","label":"Joins before containment","kind":"number","min":2,"max":100},
                        {"key":"windowSeconds","label":"Window (seconds)","kind":"number","min":3,"max":60},
                        {"key":"incidentMinutes","label":"Containment duration (minutes)","kind":"number","min":1,"max":120},
                        {"key":"verification","label":"Verification level","kind":"select","options":[["medium","Medium"],["high","High"],["very_high","Very high"]]},
                        {"key":"pauseInvites","label":"Pause invite entry during an incident","kind":"toggle","help":"Uses the join gate temporarily and restores it when containment expires."},
                        {"key":"alertChannel","label":"Alert channel","kind":"channel","advanced":true},
                        {"key":"alertOnly","label":"Monitor only","kind":"toggle","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "joinThreshold": 10,
                "windowSeconds": 10,
                "incidentMinutes": 10,
                "verification": "high",
                "pauseInvites": true,
                "alertChannel": "",
                "alertOnly": false
            }),
            dependencies: vec!["guild_members_intent".into(), "manage_roles".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for (field, min, max) in [
            ("joinThreshold", 2_i64, 100_i64),
            ("windowSeconds", 3, 60),
            ("incidentMinutes", 1, 120),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64)
                && !(min..=max).contains(&value)
            {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: format!("The value must be between {min} and {max}."),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("alertChannel")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "alertChannel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("alertOnly")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "alertOnly".into(),
                code: "boolean_required".into(),
                message: "Monitor only must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("pauseInvites")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "pauseInvites".into(),
                code: "boolean_required".into(),
                message: "Pause invite entry must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if object.get("verification").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|value| matches!(value, "medium" | "high" | "very_high"))
        }) {
            issues.push(ValidationIssue {
                path: "verification".into(),
                code: "invalid_choice".into(),
                message: "Choose medium, high or very high verification.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for (field, setting) in [
            ("joinThreshold", "security.anti_raid.joins"),
            ("windowSeconds", "security.anti_raid.window_seconds"),
            ("incidentMinutes", "security.anti_raid.incident_minutes"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64) {
                pairs.push((setting.into(), value.to_string()));
            }
        }
        if let Some(value) = object
            .get("alertChannel")
            .and_then(serde_json::Value::as_str)
        {
            pairs.push(("security.anti_raid.alert_channel".into(), value.into()));
        }
        if let Some(value) = object.get("alertOnly").and_then(serde_json::Value::as_bool) {
            pairs.push(("security.anti_raid.alert_only".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("pauseInvites")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("security.anti_raid.pause_invites".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("verification")
            .and_then(serde_json::Value::as_str)
        {
            pairs.push(("security.anti_raid.verification".into(), value.into()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = anti_raid_policy_from_json(config);
        let joins = fixture_u64(
            fixture,
            "joinCount",
            "join_count",
            policy.join_threshold as u64,
        );
        let decision = evaluate_anti_raid(&policy, joins as u32, policy.alert_only);
        let mut effects = if decision.armed {
            vec![format!(
                "{} ({}/{} joins in {}s; containment {} for {} minutes).",
                if decision.shadow_mode || !decision.should_contain {
                    "Monitor the burst without automatic containment"
                } else {
                    "Contain the join burst"
                },
                decision.joins,
                policy.join_threshold,
                policy.window_seconds,
                if decision.shadow_mode || !decision.should_contain {
                    "disabled"
                } else {
                    "enabled"
                },
                decision.incident_minutes
            )]
        } else {
            vec![format!(
                "Keep monitoring: {}/{} joins in the current {}s window.",
                decision.joins, policy.join_threshold, policy.window_seconds
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct JoinGateAdapter;

impl JoinGateAdapter {
    pub const KEY: &'static str = "protection.join_gate";
    pub const SOURCE: &'static str = "join_gate_adapter_v1";
}

impl FeatureAdapter for JoinGateAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Join verification",
                    "description": "Hold accounts below the configured age behind a verification role.",
                    "fields": [
                        {"key":"minimumAccountDays","label":"Minimum account age (days)","kind":"number","min":0,"max":365},
                        {"key":"requireAvatar","label":"Require a profile avatar","kind":"toggle"},
                        {"key":"action","label":"Action for suspicious accounts","kind":"select","options":[["quarantine","Quarantine"],["alert","Alert only"]]},
                        {"key":"verifiedRole","label":"Quarantine role","kind":"role"},
                        {"key":"autoRole","label":"Role for verified members","kind":"role"},
                        {"key":"blockedNamePatterns","label":"Blocked name patterns","kind":"tags","advanced":true},
                        {"key":"logChannel","label":"Log channel","kind":"channel","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({"minimumAccountDays": 0, "requireAvatar": false, "action": "quarantine", "verifiedRole": "", "autoRole": "", "blockedNamePatterns": [], "logChannel": ""}),
            dependencies: vec!["guild_members_intent".into(), "manage_roles".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object
            .get("minimumAccountDays")
            .and_then(serde_json::Value::as_i64)
            && !(0..=365).contains(&value)
        {
            issues.push(ValidationIssue {
                path: "minimumAccountDays".into(),
                code: "out_of_range".into(),
                message: "Account age must be between 0 and 365 days.".into(),
                severity: "error".into(),
            });
        }
        if let Some(value) = object.get("verifiedRole")
            && !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        {
            issues.push(ValidationIssue {
                path: "verifiedRole".into(),
                code: "invalid_role_id".into(),
                message: "Choose a valid Discord role.".into(),
                severity: "error".into(),
            });
        }
        if object.get("autoRole").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        }) {
            issues.push(ValidationIssue {
                path: "autoRole".into(),
                code: "invalid_role_id".into(),
                message: "Choose a valid Discord role.".into(),
                severity: "error".into(),
            });
        }
        if object.get("logChannel").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text))
        }) {
            issues.push(ValidationIssue {
                path: "logChannel".into(),
                code: "invalid_channel_id".into(),
                message: "Choose a valid Discord channel.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("requireAvatar")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "requireAvatar".into(),
                code: "boolean_required".into(),
                message: "Require avatar must be true or false.".into(),
                severity: "error".into(),
            });
        }
        if object.get("action").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|value| matches!(value, "quarantine" | "alert"))
        }) {
            issues.push(ValidationIssue {
                path: "action".into(),
                code: "invalid_choice".into(),
                message: "Choose quarantine or alert.".into(),
                severity: "error".into(),
            });
        }
        let action = object
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("quarantine");
        let quarantine_role = object
            .get("verifiedRole")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        let verified_role = object
            .get("autoRole")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        if action == "quarantine" && quarantine_role.is_none() {
            issues.push(ValidationIssue {
                path: "verifiedRole".into(),
                code: "quarantine_role_required".into(),
                message: "Choose a quarantine role before enabling the quarantine action.".into(),
                severity: "error".into(),
            });
        }
        if quarantine_role.is_some() && quarantine_role == verified_role {
            issues.push(ValidationIssue {
                path: "autoRole".into(),
                code: "join_gate_roles_must_differ".into(),
                message: "The verified member role must differ from the quarantine role.".into(),
                severity: "error".into(),
            });
        }
        if let Some(patterns) = object.get("blockedNamePatterns") {
            let valid = patterns.as_array().is_some_and(|values| {
                values.len() <= 20
                    && values.iter().all(|value| {
                        value.as_str().is_some_and(|pattern| {
                            let length = pattern.chars().count();
                            (1..=64).contains(&length) && !pattern.chars().any(char::is_control)
                        })
                    })
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "blockedNamePatterns".into(),
                    code: "invalid_patterns".into(),
                    message: "Use up to 20 name patterns, each 1-64 characters.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        if let Some(value) = object
            .get("minimumAccountDays")
            .and_then(serde_json::Value::as_i64)
        {
            pairs.push(("security.join_gate.min_age_days".into(), value.to_string()));
        }
        if let Some(value) = object
            .get("verifiedRole")
            .and_then(serde_json::Value::as_str)
        {
            pairs.push(("security.join_gate.role_id".into(), value.into()));
        }
        if let Some(value) = object
            .get("requireAvatar")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push((
                "security.join_gate.require_avatar".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = object.get("action").and_then(serde_json::Value::as_str) {
            pairs.push(("security.join_gate.action".into(), value.into()));
        }
        if let Some(value) = object.get("autoRole").and_then(serde_json::Value::as_str) {
            pairs.push(("security.join_gate.auto_role_id".into(), value.into()));
        }
        if let Some(value) = object.get("logChannel").and_then(serde_json::Value::as_str) {
            pairs.push(("security.join_gate.log_channel".into(), value.into()));
        }
        if let Some(values) = object
            .get("blockedNamePatterns")
            .and_then(serde_json::Value::as_array)
        {
            pairs.push((
                "security.join_gate.blocked_name_patterns".into(),
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let object = config.as_object();
        let policy = JoinGatePolicy {
            minimum_account_days: object
                .and_then(|values| values.get("minimumAccountDays"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            require_avatar: object
                .and_then(|values| values.get("requireAvatar"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            blocked_name_patterns: object
                .and_then(|values| values.get("blockedNamePatterns"))
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .take(20)
                        .collect()
                })
                .unwrap_or_default(),
            action: object
                .and_then(|values| values.get("action"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("quarantine")
                .to_owned(),
        };
        let decision = evaluate_join_gate(
            &policy,
            &JoinGateObservation {
                account_age_days: fixture_u64(fixture, "accountAgeDays", "account_age_days", 30)
                    as i64,
                has_avatar: fixture_bool(fixture, "hasAvatar", "has_avatar", true),
                display_name: fixture_string(
                    fixture,
                    "displayName",
                    "display_name",
                    "Preview member",
                )
                .to_owned(),
            },
        );
        let mut effects = if !decision.blocked {
            vec!["Allow the member and apply the configured auto-role, if any.".into()]
        } else {
            vec![format!(
                "Apply the {} join-gate action because {}.",
                decision.action,
                decision.reasons.join("; ")
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

impl AntiSpamAdapter {
    pub const KEY: &'static str = "protection.antispam";
    pub const SOURCE: &'static str = "anti_spam_adapter_v1";

    fn schema() -> serde_json::Value {
        serde_json::json!({
            "version": FEATURE_SCHEMA_VERSION,
            "source": Self::SOURCE,
            "sections": [
                {
                    "title": "Resposta automática",
                    "description": "Deteta flood, repetição, menções, excesso de links e caps com limites seguros.",
                    "fields": [
                        {"key":"floodCount","label":"Mensagens no intervalo","kind":"number","min":3,"max":30,"help":"Número de mensagens do mesmo membro antes de sinalizar."},
                        {"key":"windowSeconds","label":"Janela de tempo (segundos)","kind":"number","min":3,"max":60,"help":"As mensagens antigas saem automaticamente desta janela."},
                        {"key":"duplicateLimit","label":"Repetições iguais","kind":"number","min":2,"max":12,"help":"Quantas mensagens iguais acionam a regra."},
                        {"key":"maxLinks","label":"Limite de links por mensagem","kind":"number","min":1,"max":20,"help":"Quantos links numa mensagem acionam a regra."},
                        {"key":"timeoutSeconds","label":"Timeout inicial (segundos)","kind":"number","min":0,"max":86400,"help":"Usa 0 para apenas registar o incidente."},
                        {"key":"warningDelivery","label":"Enviar aviso por","kind":"select","options":[["chat","Apenas no chat"],["dm","Apenas por mensagem privada"],["both","Chat e mensagem privada"]],"help":"Escolhe onde o membro recebe o aviso automático. Se a mensagem privada estiver bloqueada, a moderação continua a funcionar."}
                    ]
                },
                {
                    "title": "Exceções e alertas",
                    "description": "Escolhe recursos reais do servidor para evitar falsos positivos e receber contexto.",
                    "fields": [
                        {"key":"mentionLimit","label":"Limite de menções por mensagem","kind":"number","min":1,"max":30,"advanced":true},
                        {"key":"capsPercent","label":"Percentagem máxima de maiúsculas","kind":"number","min":50,"max":100,"advanced":true},
                        {"key":"capsMinLetters","label":"Mínimo de letras para avaliar caps","kind":"number","min":4,"max":100,"advanced":true},
                        {"key":"ignoredChannels","label":"Canais ignorados","kind":"channels","help":"Mensagens nestes canais não entram no avaliador.","advanced":true},
                        {"key":"ignoredRoles","label":"Cargos ignorados","kind":"roles","help":"Membros com um destes cargos não entram no avaliador.","advanced":true},
                        {"key":"logChannel","label":"Canal de registo","kind":"channel","help":"O Helper publica aqui o motivo e o modo da decisão.","advanced":true},
                        {"key":"alertOnly","label":"Apenas alertar, sem aplicar castigo","kind":"toggle","help":"Mantém a deteção e auditoria, mas não aplica timeout.","advanced":true},
                        {"key":"deleteMessage","label":"Apagar a mensagem que acionou a regra","kind":"toggle","help":"Só apaga quando a ação estiver ativa; nunca no modo apenas alertar.","advanced":true}
                    ]
                }
            ]
        })
    }

    fn defaults() -> serde_json::Value {
        serde_json::json!({
            "floodCount": 6,
            "windowSeconds": 10,
            "duplicateLimit": 3,
            "timeoutSeconds": 60,
            "warningDelivery": "both",
            "mentionLimit": 5,
            "maxLinks": 5,
            "capsPercent": 80,
            "capsMinLetters": 8,
            "ignoredChannels": [],
            "ignoredRoles": [],
            "logChannel": "",
            "alertOnly": false,
            "deleteMessage": false
        })
    }
}

impl FeatureAdapter for AntiSpamAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: Self::schema(),
            defaults: Self::defaults(),
            dependencies: vec!["message_content_intent".into(), "moderate_members".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
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
        for (name, min, max) in [
            ("floodCount", 3_i64, 30_i64),
            ("windowSeconds", 3, 60),
            ("duplicateLimit", 2, 12),
            ("timeoutSeconds", 0, 86_400),
            ("mentionLimit", 1, 30),
            ("maxLinks", 1, 20),
            ("capsPercent", 50, 100),
            ("capsMinLetters", 4, 100),
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
        for (field, label) in [
            ("alertOnly", "Apenas alertar"),
            ("deleteMessage", "Apagar mensagem"),
        ] {
            if config.get(field).is_some_and(|value| !value.is_boolean()) {
                issues.push(ValidationIssue {
                    path: field.into(),
                    code: "boolean_required".into(),
                    message: format!("{label} tem de ser verdadeiro ou falso."),
                    severity: "error".into(),
                });
            }
        }
        for field in ["ignoredChannels", "ignoredRoles"] {
            if let Some(value) = config.get(field) {
                let valid = value.as_array().is_some_and(|items| {
                    items.len() <= 100
                        && items.iter().all(|item| {
                            item.as_str().is_some_and(|text| {
                                valid_discord_id(text.trim())
                                    && text.chars().count() <= 64
                                    && !text.chars().any(char::is_control)
                            })
                        })
                });
                if !valid {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "invalid_exemptions".into(),
                        message: "Indica no máximo 100 IDs ou nomes válidos.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        if let Some(value) = config.get("logChannel") {
            let valid = value
                .as_str()
                .is_some_and(|text| text.is_empty() || valid_discord_id(text));
            if !valid {
                issues.push(ValidationIssue {
                    path: "logChannel".into(),
                    code: "invalid_channel_id".into(),
                    message: "Escolhe um canal Discord válido para o registo.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = config.get("warningDelivery") {
            let valid = value
                .as_str()
                .is_some_and(|delivery| matches!(delivery, "chat" | "dm" | "both"));
            if !valid {
                issues.push(ValidationIssue {
                    path: "warningDelivery".into(),
                    code: "invalid_warning_delivery".into(),
                    message: "Escolhe aviso no chat, por mensagem privada ou nos dois.".into(),
                    severity: "error".into(),
                });
            }
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let Some(object) = config.as_object() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        let mut add = |name: &str, value: String| pairs.push((name.to_string(), value));
        for (field, setting) in [
            ("floodCount", "security.antispam.flood_count"),
            ("windowSeconds", "security.antispam.window_seconds"),
            ("duplicateLimit", "security.antispam.duplicate_limit"),
            ("timeoutSeconds", "security.antispam.timeout_seconds"),
            ("mentionLimit", "security.antispam.mention_limit"),
            ("maxLinks", "security.antispam.max_links"),
            ("capsPercent", "security.antispam.caps_percent"),
            ("capsMinLetters", "security.antispam.caps_min_letters"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_i64) {
                add(setting, value.to_string());
            }
        }
        if let Some(value) = object.get("logChannel").and_then(serde_json::Value::as_str) {
            add("security.antispam.log_channel", value.to_string());
        }
        if let Some(value) = object
            .get("warningDelivery")
            .and_then(serde_json::Value::as_str)
        {
            add("security.antispam.warning_delivery", value.to_string());
        }
        for (field, setting) in [
            ("ignoredChannels", "security.antispam.ignored_channels"),
            ("ignoredRoles", "security.antispam.ignored_roles"),
        ] {
            if let Some(values) = object.get(field).and_then(serde_json::Value::as_array) {
                add(
                    setting,
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
        }
        for (field, setting) in [
            ("alertOnly", "security.antispam.alert_only"),
            ("deleteMessage", "security.antispam.delete_message"),
        ] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_bool) {
                add(setting, value.to_string());
            }
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = anti_spam_policy_from_json(config);
        let observation = anti_spam_observation_from_json(fixture);
        let decision = evaluate_anti_spam(&policy, &observation);
        if decision.ignored {
            return vec!["Ignore the message because its channel or member role is exempt.".into()];
        }
        if decision.matched.is_empty() {
            return vec!["Record no match and leave the message unchanged.".into()];
        }
        let mode = if decision.should_act {
            "action"
        } else {
            "monitor-only"
        };
        let mut actions = Vec::new();
        if decision.should_delete {
            actions.push("delete the matching message".to_string());
        }
        if decision.should_act && decision.timeout_seconds > 0 {
            actions.push(format!(
                "apply a {} second timeout",
                decision.timeout_seconds
            ));
        }
        let action = if actions.is_empty() {
            String::new()
        } else {
            format!(" and {}", actions.join(" and "))
        };
        let mut effects = vec![format!(
            "Record {} in {mode} mode{action} ({} messages, {} duplicate(s), {} mention(s), {} link(s), {} uppercase letters out of {} letters).",
            decision.matched.join(", "),
            observation.message_count,
            observation.duplicate_count,
            observation.mention_count,
            observation.link_count,
            observation.uppercase_letters,
            observation.letter_count
        )];
        if let Some(channel) = config
            .get("logChannel")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            effects.push(format!("Publish the decision to log channel {channel}."));
        }
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(key, value)| format!("Runtime setting {key}={value}.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AchievementsAdapter;

impl AchievementsAdapter {
    pub const KEY: &'static str = "community.achievements";
    pub const SOURCE: &'static str = "achievements_adapter_v2";
}

impl FeatureAdapter for AchievementsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "XP milestones",
                    "description": "Choose the real XP thresholds used by the achievements command.",
                    "fields": [
                        {"key":"firstThreshold","label":"First steps threshold","kind":"number","min":1,"max":1000000},
                        {"key":"regularThreshold","label":"Regular threshold","kind":"number","min":1,"max":1000000},
                        {"key":"pillarThreshold","label":"Community pillar threshold","kind":"number","min":1,"max":1000000},
                        {"key":"firstRewardRole","label":"First steps reward role","kind":"role","advanced":true},
                        {"key":"regularRewardRole","label":"Regular reward role","kind":"role","advanced":true},
                        {"key":"pillarRewardRole","label":"Community pillar reward role","kind":"role","advanced":true}
                    ]
                }]
            }),
            defaults: serde_json::json!({"firstThreshold":100,"regularThreshold":1000,"pillarThreshold":10000,"firstRewardRole":"","regularRewardRole":"","pillarRewardRole":""}),
            dependencies: vec![
                "message_content".into(),
                "levels".into(),
                "send_messages".into(),
            ],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Achievement settings must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        for field in ["firstThreshold", "regularThreshold", "pillarThreshold"] {
            match object.get(field).and_then(serde_json::Value::as_i64) {
                Some(value) if (1..=1_000_000).contains(&value) => {}
                Some(_) => issues.push(ValidationIssue {
                    path: field.into(),
                    code: "out_of_range".into(),
                    message: "XP threshold must be between 1 and 1000000.".into(),
                    severity: "error".into(),
                }),
                None => issues.push(ValidationIssue {
                    path: field.into(),
                    code: "integer_required".into(),
                    message: "XP threshold must be an integer.".into(),
                    severity: "error".into(),
                }),
            }
        }
        for field in ["firstRewardRole", "regularRewardRole", "pillarRewardRole"] {
            if let Some(value) = object.get(field) {
                let valid = value
                    .as_str()
                    .is_some_and(|role| role.is_empty() || valid_discord_id(role.trim()));
                if !valid {
                    issues.push(ValidationIssue {
                        path: field.into(),
                        code: "role_id_invalid".into(),
                        message: "Reward roles must be empty or a Discord role ID.".into(),
                        severity: "error".into(),
                    });
                }
            }
        }
        if let (Some(first), Some(regular), Some(pillar)) = (
            object
                .get("firstThreshold")
                .and_then(serde_json::Value::as_i64),
            object
                .get("regularThreshold")
                .and_then(serde_json::Value::as_i64),
            object
                .get("pillarThreshold")
                .and_then(serde_json::Value::as_i64),
        ) && !(first <= regular && regular <= pillar)
        {
            issues.push(ValidationIssue {
                path: "thresholds".into(),
                code: "ordered_required".into(),
                message: "Milestones must be ordered from smallest to largest.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        [
            ("firstThreshold", "community.achievements.first_threshold"),
            (
                "regularThreshold",
                "community.achievements.regular_threshold",
            ),
            ("pillarThreshold", "community.achievements.pillar_threshold"),
        ]
        .into_iter()
        .filter_map(|(field, key)| {
            config
                .get(field)
                .and_then(serde_json::Value::as_i64)
                .map(|value| (key.into(), value.to_string()))
        })
        .chain(
            [
                (
                    "firstRewardRole",
                    "community.achievements.first_reward_role",
                ),
                (
                    "regularRewardRole",
                    "community.achievements.regular_reward_role",
                ),
                (
                    "pillarRewardRole",
                    "community.achievements.pillar_reward_role",
                ),
            ]
            .into_iter()
            .filter_map(|(field, key)| {
                config
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(|value| (key.into(), value.to_owned()))
            }),
        )
        .collect()
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let policy = AchievementPolicy {
            first_threshold: config
                .get("firstThreshold")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(100),
            regular_threshold: config
                .get("regularThreshold")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(1_000),
            pillar_threshold: config
                .get("pillarThreshold")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(10_000),
        };
        let xp = fixture
            .get("xp")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(1_250);
        let unlocked = evaluate_achievements(&policy, xp);
        let mut effects = if unlocked.is_empty() {
            vec![format!("No achievement is unlocked at {xp} XP.")]
        } else {
            vec![format!(
                "Unlock {} at {xp} XP: {}.",
                unlocked.len(),
                unlocked
                    .iter()
                    .map(|item| format!("{} ({} XP)", item.label, item.threshold))
                    .collect::<Vec<_>>()
                    .join(", ")
            )]
        };
        for milestone in unlocked {
            let role_key = match milestone.key {
                "first_steps" => "firstRewardRole",
                "regular" => "regularRewardRole",
                "community_pillar" => "pillarRewardRole",
                _ => continue,
            };
            if let Some(role) = config
                .get(role_key)
                .and_then(serde_json::Value::as_str)
                .filter(|role| !role.trim().is_empty())
            {
                effects.push(format!(
                    "Assign reward role `{role}` for {}.",
                    milestone.label
                ));
            }
        }
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InviteTrackerAdapter;

impl InviteTrackerAdapter {
    pub const KEY: &'static str = "management.invite_tracker";
    pub const SOURCE: &'static str = "invite_tracker_adapter_v2";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteTrackerDecision {
    pub allowed: bool,
    pub max_entries: usize,
    pub include_inviter: bool,
    pub shown_count: usize,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_invite_tracker(
    config: &serde_json::Value,
    available_count: u64,
) -> InviteTrackerDecision {
    let max_entries = config
        .get("maxEntries")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(10)
        .clamp(1, 50) as usize;
    let include_inviter = config
        .get("includeInviter")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let shown_count = (available_count.min(max_entries as u64)) as usize;
    InviteTrackerDecision {
        allowed: true,
        max_entries,
        include_inviter,
        shown_count,
        reason_code: if available_count == 0 {
            "empty"
        } else {
            "bounded"
        },
        explanation: if available_count == 0 {
            "No active invites are available to display; Manage Server is required for a live list."
                .into()
        } else {
            format!(
                "Display {shown_count} of {available_count} active invite(s){}.",
                if include_inviter {
                    " with inviter names"
                } else {
                    " without inviter names"
                }
            )
        },
    }
}

impl FeatureAdapter for InviteTrackerAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({"version":FEATURE_SCHEMA_VERSION,"source":Self::SOURCE,"sections":[{"title":"Invite overview","description":"Control the staff-facing invite list without scraping or storing invite tokens.","fields":[{"key":"maxEntries","label":"Invites shown","kind":"number","min":1,"max":50},{"key":"includeInviter","label":"Show inviter names","kind":"toggle"}]}]}),
            defaults: serde_json::json!({"maxEntries":10,"includeInviter":true}),
            dependencies: vec![
                "manage_guild".into(),
                "guild_invites".into(),
                "send_messages".into(),
            ],
        }
    }
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Invite tracker settings must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("maxEntries")
            && !value
                .as_i64()
                .is_some_and(|value| (1..=50).contains(&value))
        {
            issues.push(ValidationIssue {
                path: "maxEntries".into(),
                code: "out_of_range".into(),
                message: "Invites shown must be between 1 and 50.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("includeInviter")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "includeInviter".into(),
                code: "boolean_required".into(),
                message: "Include inviter names must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(value) = config.get("maxEntries").and_then(serde_json::Value::as_i64) {
            pairs.push((
                "management.invite_tracker.max_entries".into(),
                value.to_string(),
            ));
        }
        if let Some(value) = config
            .get("includeInviter")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push((
                "management.invite_tracker.include_inviter".into(),
                value.to_string(),
            ));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let available = fixture_u64(fixture, "inviteCount", "invite_count", 0);
        let decision = evaluate_invite_tracker(config, available);
        let mut effects = vec![decision.explanation];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EmojisAdapter;

impl EmojisAdapter {
    pub const KEY: &'static str = "utility.emojis";
    pub const SOURCE: &'static str = "emojis_adapter_v2";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojisDecision {
    pub allowed: bool,
    pub max_entries: usize,
    pub animated_only: bool,
    pub matching_count: usize,
    pub shown_count: usize,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_emojis(
    config: &serde_json::Value,
    total_count: u64,
    animated_count: u64,
) -> EmojisDecision {
    let max_entries = config
        .get("maxEntries")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(50)
        .clamp(1, 100) as usize;
    let animated_only = config
        .get("animatedOnly")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let matching_count = if animated_only {
        animated_count.min(total_count)
    } else {
        total_count
    } as usize;
    let shown_count = matching_count.min(max_entries);
    EmojisDecision {
        allowed: true,
        max_entries,
        animated_only,
        matching_count,
        shown_count,
        reason_code: if matching_count == 0 {
            "empty"
        } else {
            "bounded"
        },
        explanation: if matching_count == 0 {
            "No custom emojis match the current inventory filter.".into()
        } else {
            format!(
                "Display {shown_count} of {matching_count} matching custom emoji(ies){}.",
                if animated_only {
                    " (animated only)"
                } else {
                    ""
                }
            )
        },
    }
}

impl FeatureAdapter for EmojisAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({"version":FEATURE_SCHEMA_VERSION,"source":Self::SOURCE,"sections":[{"title":"Emoji inventory","description":"Choose how many custom emojis the staff command lists.","fields":[{"key":"maxEntries","label":"Emojis shown","kind":"number","min":1,"max":100},{"key":"animatedOnly","label":"Only animated emojis","kind":"toggle"}]}]}),
            defaults: serde_json::json!({"maxEntries":50,"animatedOnly":false}),
            dependencies: vec!["manage_expressions".into(), "send_messages".into()],
        }
    }
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "Emoji settings must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("maxEntries")
            && !value
                .as_i64()
                .is_some_and(|value| (1..=100).contains(&value))
        {
            issues.push(ValidationIssue {
                path: "maxEntries".into(),
                code: "out_of_range".into(),
                message: "Emojis shown must be between 1 and 100.".into(),
                severity: "error".into(),
            });
        }
        if object
            .get("animatedOnly")
            .is_some_and(|value| !value.is_boolean())
        {
            issues.push(ValidationIssue {
                path: "animatedOnly".into(),
                code: "boolean_required".into(),
                message: "Animated-only must be true or false.".into(),
                severity: "error".into(),
            });
        }
        issues
    }
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(value) = config.get("maxEntries").and_then(serde_json::Value::as_i64) {
            pairs.push(("utility.emojis.max_entries".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("animatedOnly")
            .and_then(serde_json::Value::as_bool)
        {
            pairs.push(("utility.emojis.animated_only".into(), value.to_string()));
        }
        pairs
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let total = fixture_u64(fixture, "emojiCount", "emoji_count", 0);
        let animated = fixture_u64(fixture, "animatedEmojiCount", "animated_emoji_count", 0);
        let decision = evaluate_emojis(config, total, animated);
        let mut effects = vec![decision.explanation];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

static ANTI_SPAM_ADAPTER: AntiSpamAdapter = AntiSpamAdapter;
static NICKNAME_ADAPTER: NicknameAdapter = NicknameAdapter;
static REMINDER_ADAPTER: ReminderAdapter = ReminderAdapter;
static LEADERBOARD_ADAPTER: LeaderboardAdapter = LeaderboardAdapter;
static WORKFLOW_ADAPTER: WorkflowAdapter = WorkflowAdapter;
static PRIVACY_ADAPTER: PrivacyAdapter = PrivacyAdapter;
static STATS_ADAPTER: StatsAdapter = StatsAdapter;
static HELP_ADAPTER: HelpAdapter = HelpAdapter;
static MODERATION_ADAPTER: ModerationAdapter = ModerationAdapter;
static ANTI_SCAM_ADAPTER: AntiScamAdapter = AntiScamAdapter;
static WELCOME_CHANNEL_ADAPTER: WelcomeChannelAdapter = WelcomeChannelAdapter;
static LEVELS_ADAPTER: LevelsAdapter = LevelsAdapter;
static STARBOARD_ADAPTER: StarboardAdapter = StarboardAdapter;
static ANTI_RAID_ADAPTER: AntiRaidAdapter = AntiRaidAdapter;
static JOIN_GATE_ADAPTER: JoinGateAdapter = JoinGateAdapter;
static TICKETS_ADAPTER: TicketsAdapter = TicketsAdapter;
static WELCOME_ADAPTER: WelcomeAdapter = WelcomeAdapter;
static SUGGESTIONS_ADAPTER: CommunityInteractionAdapter = CommunityInteractionAdapter {
    key: "community.suggestions",
    source: "suggestions_adapter_v2",
    title: "Suggestion workflow",
    description: "Route suggestions, control voting, cooldowns and staff notifications.",
    schema: r#"{"version":1,"source":"suggestions_adapter_v2","sections":[{"title":"Suggestion intake","description":"These options are applied to every new suggestion.","fields":[{"key":"channel","label":"Suggestion channel","kind":"channel"},{"key":"voteMode","label":"Voting mode","kind":"select","options":[["up_down","Support / against"],["up_only","Support only"]]},{"key":"anonymous","label":"Hide author in the public message","kind":"toggle"}]},{"title":"Moderation","description":"Control submission frequency and give staff a private notification channel.","fields":[{"key":"cooldownHours","label":"Cooldown per member (hours)","kind":"number","min":0,"max":720,"advanced":true},{"key":"requiredRole","label":"Required role (optional)","kind":"role","advanced":true},{"key":"staffChannel","label":"Staff notification channel (optional)","kind":"channel","advanced":true}]}]}"#,
    defaults: r#"{"channel":"","voteMode":"up_down","anonymous":false,"cooldownHours":24,"requiredRole":"","staffChannel":""}"#,
    dependencies: &["send_messages", "interactions"],
    projection: project_suggestions,
};
static GIVEAWAYS_ADAPTER: CommunityInteractionAdapter = CommunityInteractionAdapter {
    key: "community.giveaways",
    source: "giveaways_adapter_v2",
    title: "Giveaway workflow",
    description: "Set safe defaults for giveaway duration, winners and eligibility.",
    schema: r#"{"version":1,"source":"giveaways_adapter_v2","sections":[{"title":"Giveaway defaults","description":"Commands can still override these defaults when needed.","fields":[{"key":"defaultDurationHours","label":"Default duration (hours)","kind":"number","min":1,"max":168},{"key":"defaultWinners","label":"Default winners","kind":"number","min":1,"max":20},{"key":"requiredRole","label":"Required role (optional)","kind":"role"}]}]}"#,
    defaults: r#"{"defaultDurationHours":24,"defaultWinners":1,"requiredRole":""}"#,
    dependencies: &["send_messages", "scheduler", "interactions"],
    projection: project_giveaways,
};
static POLLS_ADAPTER: CommunityInteractionAdapter = CommunityInteractionAdapter {
    key: "management.polls",
    source: "polls_adapter_v2",
    title: "Poll workflow",
    description: "Set the default poll lifetime and route new polls to a real channel.",
    schema: r#"{"version":1,"source":"polls_adapter_v2","sections":[{"title":"Poll defaults","description":"The command uses these values when no override is provided.","fields":[{"key":"defaultDurationHours","label":"Default duration (hours)","kind":"number","min":1,"max":168},{"key":"channel","label":"Poll channel (optional)","kind":"channel"}]}]}"#,
    defaults: r#"{"defaultDurationHours":24,"channel":""}"#,
    dependencies: &["send_messages", "scheduler", "interactions"],
    projection: project_polls,
};
static EVENTS_ADAPTER: CommunityInteractionAdapter = CommunityInteractionAdapter {
    key: "community.events",
    source: "events_adapter_v2",
    title: "Discord events",
    description: "Set duration, capacity and optional start reminders for native events.",
    schema: r#"{"version":1,"source":"events_adapter_v2","sections":[{"title":"Event defaults","description":"These values are applied to new events created with the Helper.","fields":[{"key":"defaultDurationHours","label":"Default duration (hours)","kind":"number","min":1,"max":8760},{"key":"defaultCapacity","label":"Default capacity (0 = unlimited)","kind":"number","min":0,"max":100000},{"key":"announcementChannel","label":"Announcement channel (optional)","kind":"channel"}]},{"title":"Start reminder","description":"Post one reminder before each new event in the announcement channel.","fields":[{"key":"reminders","label":"Send start reminders","kind":"toggle"},{"key":"reminderHours","label":"Hours before start","kind":"number","min":1,"max":168,"advanced":true}]}]}"#,
    defaults: r#"{"defaultDurationHours":2,"defaultCapacity":0,"announcementChannel":"","reminders":true,"reminderHours":1}"#,
    dependencies: &["manage_events", "scheduler"],
    projection: project_events,
};
static ROLE_PANELS_ADAPTER: CommunityInteractionAdapter = CommunityInteractionAdapter {
    key: "community.role_panels",
    source: "role_panels_adapter_v2",
    title: "Role panel workflow",
    description: "Set safe defaults for role panels and enforce a bounded number of roles.",
    schema: r#"{"version":1,"source":"role_panels_adapter_v2","sections":[{"title":"Panel defaults","description":"The role panel command applies these values to newly published panels.","fields":[{"key":"channel","label":"Panel channel (optional)","kind":"channel"},{"key":"roleIds","label":"Panel roles","kind":"roles","max":5},{"key":"panelTitle","label":"Panel title","kind":"text","min":1,"max":80},{"key":"panelDescription","label":"Panel description","kind":"textarea","max":1000},{"key":"maxRoles","label":"Maximum roles","kind":"number","min":1,"max":5},{"key":"selectionMode","label":"Selection mode","kind":"select","options":[["multiple","Members can choose several roles"],["unique","Members can choose one role"]]},{"key":"removeOnUnselect","label":"Remove the role when toggled off","kind":"toggle"}]}]}"#,
    defaults: r#"{"channel":"","panelTitle":"Choose your roles","panelDescription":"Select the roles that fit you.","maxRoles":5,"selectionMode":"multiple","removeOnUnselect":true}"#,
    dependencies: &["manage_roles", "interactions"],
    projection: project_role_panels,
};
static CUSTOM_COMMANDS_ADAPTER: CustomCommandsAdapter = CustomCommandsAdapter;
static AUDIT_ADAPTER: AuditAdapter = AuditAdapter;
static TEMPLATES_ADAPTER: TemplatesAdapter = TemplatesAdapter;
static BIRTHDAYS_ADAPTER: BirthdaysAdapter = BirthdaysAdapter;
static EMOJIS_ADAPTER: EmojisAdapter = EmojisAdapter;
static ACHIEVEMENTS_ADAPTER: AchievementsAdapter = AchievementsAdapter;
static INVITE_TRACKER_ADAPTER: InviteTrackerAdapter = InviteTrackerAdapter;
static SEARCH_ADAPTER: SearchAdapter = SearchAdapter;

static TEMP_CHANNELS_ADAPTER: TempChannelsAdapter = TempChannelsAdapter;

static YOUTUBE_ADAPTER: AlertSubscriptionAdapter = AlertSubscriptionAdapter {
    key: "social.youtube",
    source: "youtube_data_api_v3_adapter_v1",
    title: "YouTube alerts",
    description: "Polls the official YouTube Data API and delivers deduplicated new-video alerts.",
    source_key: "sourceChannelId",
    source_label: "YouTube channel ID",
    source_help: "Use the channel ID, not a watch URL.",
    default_template: "New video from {channel}: **{title}**\\n{url}",
    dependencies: &["YOUTUBE_API_KEY", "send_messages", "embed_links"],
};
// XP card uses a dedicated endpoint and renderer, while its schema and
// projection remain owned by the same registry as every other feature.
static RANK_CARD_ADAPTER: RankCardAdapter = RankCardAdapter;
static RSS_ADAPTER: FeedAdapter = FeedAdapter {
    key: "social.rss",
    source: "rss_atom_adapter_v1",
    title: "RSS alerts",
    description: "Polls validated RSS and Atom feeds with SSRF protection and deduplication.",
    dependencies: &["outbound_https", "send_messages"],
};
static PODCASTS_ADAPTER: FeedAdapter = FeedAdapter {
    key: "social.podcasts",
    source: "podcast_rss_adapter_v1",
    title: "Podcast alerts",
    description: "Polls a public podcast RSS or Atom feed with the same SSRF protection and deduplication as RSS alerts.",
    dependencies: &["outbound_https", "send_messages"],
};
static TWITCH_ADAPTER: AlertSubscriptionAdapter = AlertSubscriptionAdapter {
    key: "social.twitch",
    source: "twitch_eventsub_adapter_v1",
    title: "Twitch alerts",
    description: "Uses the official Helix/EventSub API with signed webhook verification and deduplication.",
    source_key: "sourceLogin",
    source_label: "Twitch channel login",
    source_help: "Use the channel login, without a URL or @ prefix.",
    default_template: "{handle} is live: **{title}**\\n{url}",
    dependencies: &[
        "TWITCH_CLIENT_ID",
        "TWITCH_CLIENT_SECRET",
        "TWITCH_EVENTSUB_SECRET",
        "send_messages",
    ],
};

/// The bounded decision shared by the HTTP preview and the Discord `/embed`
/// command.  Keeping the rendered values here prevents a valid-looking draft
/// from diverging from what the runtime will actually publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbedDecision {
    pub allowed: bool,
    pub title: String,
    pub description: String,
    pub color: Option<String>,
    pub footer: String,
    pub reason_code: &'static str,
    pub explanation: String,
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

fn valid_embed_color(value: &str) -> bool {
    value.is_empty()
        || (value.len() == 7
            && value.starts_with('#')
            && value[1..]
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
}

/// Validate and render the same embed payload used by the production command.
/// Mentions are deliberately not part of the returned payload; the Discord
/// handler always disables them when publishing.
pub fn evaluate_embed(
    config: &serde_json::Value,
    title: &str,
    description: &str,
    requested_color: Option<&str>,
    requested_footer: Option<&str>,
) -> EmbedDecision {
    let max_description = config
        .get("maxDescription")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(2_000)
        .clamp(1, 4_000) as usize;
    let title = bounded_text(title, 256);
    let description = bounded_text(description, max_description);
    let configured_color = config
        .get("defaultColor")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    let color = requested_color
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(configured_color);
    if title.is_empty() || description.is_empty() {
        return EmbedDecision {
            allowed: false,
            title,
            description,
            color: None,
            footer: String::new(),
            reason_code: "title_description_required",
            explanation: "An embed needs a non-empty title and description.".into(),
        };
    }
    if !valid_embed_color(color) {
        return EmbedDecision {
            allowed: false,
            title,
            description,
            color: None,
            footer: String::new(),
            reason_code: "invalid_color",
            explanation: "Colour must be empty or a #RRGGBB value.".into(),
        };
    }
    let configured_footer = config
        .get("defaultFooter")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    let footer = requested_footer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(configured_footer);
    if footer.chars().count() > 2_048 {
        return EmbedDecision {
            allowed: false,
            title,
            description,
            color: None,
            footer: String::new(),
            reason_code: "footer_too_long",
            explanation: "Footer must be at most 2048 characters.".into(),
        };
    }
    EmbedDecision {
        allowed: true,
        title,
        description,
        color: (!color.is_empty()).then(|| color.to_owned()),
        footer: footer.to_owned(),
        reason_code: "embed_ready",
        explanation: "The bounded embed can be published with mentions disabled.".into(),
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EmbedsAdapter;

impl EmbedsAdapter {
    pub const KEY: &'static str = "utility.embeds";
    pub const SOURCE: &'static str = "embeds_adapter_v2";
}

impl FeatureAdapter for EmbedsAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({"version": FEATURE_SCHEMA_VERSION, "source": Self::SOURCE, "sections": [{"title":"Safe embed publishing", "description":"Publish a bounded embed from a slash command; mentions are disabled by default.", "fields":[{"key":"maxDescription","label":"Maximum description length","kind":"number","min":1,"max":4000},{"key":"defaultColor","label":"Default colour (hex)","kind":"text","maxLength":7,"placeholder":"#5865F2"},{"key":"defaultFooter","label":"Default footer","kind":"text","maxLength":2048}]}]}),
            defaults: serde_json::json!({"maxDescription": 2000, "defaultColor":"", "defaultFooter":""}),
            dependencies: vec!["send_messages".into(), "embed_links".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        match object.get("maxDescription") {
            Some(value)
                if value
                    .as_i64()
                    .is_some_and(|value| (1..=4000).contains(&value)) =>
            {
                Vec::new()
            }
            Some(value) if value.as_i64().is_some() => vec![ValidationIssue {
                path: "maxDescription".into(),
                code: "out_of_range".into(),
                message: "Maximum description length must be between 1 and 4000.".into(),
                severity: "error".into(),
            }],
            Some(_) => vec![ValidationIssue {
                path: "maxDescription".into(),
                code: "integer_required".into(),
                message: "Maximum description length must be an integer.".into(),
                severity: "error".into(),
            }],
            None => Vec::new(),
        }
        .into_iter()
        .for_each(|issue| issues.push(issue));
        if let Some(value) = object.get("defaultColor") {
            let valid = value.as_str().is_some_and(|color| {
                color.is_empty()
                    || (color.len() == 7
                        && color.starts_with('#')
                        && color[1..]
                            .chars()
                            .all(|character| character.is_ascii_hexdigit()))
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "defaultColor".into(),
                    code: "hex_color_required".into(),
                    message: "Default colour must be empty or a #RRGGBB value.".into(),
                    severity: "error".into(),
                });
            }
        }
        if let Some(value) = object.get("defaultFooter")
            && value
                .as_str()
                .is_none_or(|footer| footer.chars().count() > 2_048)
        {
            issues.push(ValidationIssue {
                path: "defaultFooter".into(),
                code: "text_too_long".into(),
                message: "Default footer must be at most 2048 characters.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let mut projection = config
            .get("maxDescription")
            .and_then(serde_json::Value::as_i64)
            .map(|value| vec![("utility.embeds.max_description".into(), value.to_string())])
            .unwrap_or_default();
        if let Some(color) = config
            .get("defaultColor")
            .and_then(serde_json::Value::as_str)
        {
            projection.push(("utility.embeds.default_color".into(), color.into()));
        }
        if let Some(footer) = config
            .get("defaultFooter")
            .and_then(serde_json::Value::as_str)
        {
            projection.push(("utility.embeds.default_footer".into(), footer.into()));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let title = fixture
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Preview embed");
        let description = fixture
            .get("description")
            .and_then(serde_json::Value::as_str)
            .or_else(|| fixture.get("content").and_then(serde_json::Value::as_str))
            .unwrap_or("Preview description");
        let requested_color = fixture.get("color").and_then(serde_json::Value::as_str);
        let requested_footer = fixture.get("footer").and_then(serde_json::Value::as_str);
        let decision = evaluate_embed(
            config,
            title,
            description,
            requested_color,
            requested_footer,
        );
        let mut effects = if decision.allowed {
            vec![format!(
                "Publish embed `{}` with {} characters, mentions disabled{}.",
                decision.title,
                decision.description.chars().count(),
                decision
                    .color
                    .as_deref()
                    .map(|color| format!(" and colour {color}"))
                    .unwrap_or_default()
            )]
        } else {
            vec![format!(
                "Embed rejected ({}): {}",
                decision.reason_code, decision.explanation
            )]
        };
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EconomyAdapter;

impl EconomyAdapter {
    pub const KEY: &'static str = "community.economy";
    pub const SOURCE: &'static str = "economy_adapter_v1";
}

/// The bounded economy decision shared by dashboard previews and Discord
/// commands. The store remains authoritative for the atomic ledger write and
/// cooldown race; this evaluator owns the amount, action and limits so the UI
/// cannot preview a reward different from the one the runtime requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomyDecision {
    pub allowed: bool,
    pub action: String,
    pub amount: i64,
    pub cooldown_ms: i64,
    pub resulting_balance: i64,
    pub currency_name: String,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_economy(
    config: &serde_json::Value,
    action: &str,
    current_balance: i64,
    cooldown_ready: bool,
) -> EconomyDecision {
    let object = config.as_object();
    let currency_name = object
        .and_then(|value| value.get("currencyName"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("credits")
        .chars()
        .take(24)
        .collect::<String>();
    let action = action.trim().to_ascii_lowercase();
    let (amount, cooldown_ms, requires_cooldown) = match action.as_str() {
        "balance" => (0_i64, 0_i64, false),
        "daily" => (
            object
                .and_then(|value| value.get("dailyReward"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(100)
                .clamp(1, 10_000),
            86_400_000,
            true,
        ),
        "work" => {
            let reward = object
                .and_then(|value| value.get("workReward"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(50)
                .clamp(1, 10_000);
            let cooldown = object
                .and_then(|value| value.get("workCooldownMinutes"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(60)
                .clamp(5, 1_440)
                .saturating_mul(60_000);
            (reward, cooldown, true)
        }
        "top" | "leaderboard" => (0_i64, 0_i64, false),
        _ => {
            return EconomyDecision {
                allowed: false,
                action,
                amount: 0,
                cooldown_ms: 0,
                resulting_balance: current_balance,
                currency_name,
                reason_code: "unknown_action",
                explanation: "Choose balance, daily, work or top for the economy preview.".into(),
            };
        }
    };
    if requires_cooldown && !cooldown_ready {
        return EconomyDecision {
            allowed: false,
            action: action.clone(),
            amount,
            cooldown_ms,
            resulting_balance: current_balance,
            currency_name: currency_name.clone(),
            reason_code: "cooldown_active",
            explanation: format!(
                "The `{}` reward is still on cooldown; no ledger entry will be created.",
                action
            ),
        };
    }
    EconomyDecision {
        allowed: true,
        action: action.clone(),
        amount,
        cooldown_ms,
        resulting_balance: current_balance.saturating_add(amount),
        currency_name: currency_name.clone(),
        reason_code: if amount > 0 {
            "reward_ready"
        } else {
            "read_only"
        },
        explanation: if amount > 0 {
            format!(
                "The `{action}` action may append {} {currency_name} to the ledger.",
                amount
            )
        } else {
            format!("The `{action}` action reads the current economy state without changing it.")
        },
    }
}

impl FeatureAdapter for EconomyAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({"version": FEATURE_SCHEMA_VERSION, "source": Self::SOURCE, "sections":[{"title":"Rewards", "description":"Bounded community rewards backed by an auditable balance ledger.", "fields":[{"key":"currencyName","label":"Currency name","kind":"text","maxLength":24},{"key":"dailyReward","label":"Daily reward","kind":"number","min":1,"max":10000},{"key":"workReward","label":"Work reward","kind":"number","min":1,"max":10000},{"key":"workCooldownMinutes","label":"Work cooldown (minutes)","kind":"number","min":5,"max":1440}]}]}),
            defaults: serde_json::json!({"currencyName":"credits","dailyReward":100,"workReward":50,"workCooldownMinutes":60}),
            dependencies: vec!["scheduler".into()],
        }
    }
    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("currencyName") {
            let valid = value.as_str().is_some_and(|name| {
                let trimmed = name.trim();
                !trimmed.is_empty() && trimmed.chars().count() <= 24
            });
            if !valid {
                issues.push(ValidationIssue {
                    path: "currencyName".into(),
                    code: "invalid_name".into(),
                    message: "Currency name must contain 1 to 24 characters.".into(),
                    severity: "error".into(),
                });
            }
        }
        for (path, min, max) in [
            ("dailyReward", 1_i64, 10_000_i64),
            ("workReward", 1_i64, 10_000_i64),
            ("workCooldownMinutes", 5_i64, 1_440_i64),
        ] {
            match object.get(path) {
                Some(value)
                    if value
                        .as_i64()
                        .is_some_and(|number| (min..=max).contains(&number)) => {}
                Some(value) if value.as_i64().is_some() => issues.push(ValidationIssue {
                    path: path.into(),
                    code: "out_of_range".into(),
                    message: format!("{path} must be between {min} and {max}."),
                    severity: "error".into(),
                }),
                Some(_) => issues.push(ValidationIssue {
                    path: path.into(),
                    code: "integer_required".into(),
                    message: format!("{path} must be an integer."),
                    severity: "error".into(),
                }),
                None => {}
            }
        }
        issues
    }
    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let mut projection = Vec::new();
        if let Some(value) = config
            .get("currencyName")
            .and_then(serde_json::Value::as_str)
        {
            projection.push((
                "community.economy.currency_name".into(),
                value.trim().to_string(),
            ));
        }
        if let Some(value) = config
            .get("dailyReward")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push(("community.economy.daily_reward".into(), value.to_string()));
        }
        if let Some(value) = config.get("workReward").and_then(serde_json::Value::as_i64) {
            projection.push(("community.economy.work_reward".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("workCooldownMinutes")
            .and_then(serde_json::Value::as_i64)
        {
            projection.push((
                "community.economy.work_cooldown_ms".into(),
                (value.saturating_mul(60_000)).to_string(),
            ));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let action = fixture_string(fixture, "economyAction", "economy_action", "daily");
        let current_balance = fixture
            .get("currentBalance")
            .or_else(|| fixture.get("current_balance"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let cooldown_ready = fixture_bool(
            fixture,
            "rewardCooldownReady",
            "reward_cooldown_ready",
            true,
        );
        let decision = evaluate_economy(config, action, current_balance, cooldown_ready);
        let mut effects = vec![if decision.allowed {
            format!(
                "{} Balance preview: {} {}.",
                decision.explanation, decision.resulting_balance, decision.currency_name
            )
        } else {
            format!(
                "Economy action rejected ({}): {}",
                decision.reason_code, decision.explanation
            )
        }];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}

/// Bounded search uses only providers with public, documented APIs.  The
/// adapter deliberately exposes the allow-list so the dashboard cannot turn
/// the feature into an arbitrary web proxy.
#[derive(Debug, Clone, Copy, Default)]
pub struct SearchAdapter;

impl SearchAdapter {
    pub const KEY: &'static str = "utility.search";
    pub const SOURCE: &'static str = "bounded_search_adapter_v1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDecision {
    pub allowed: bool,
    pub provider: String,
    pub max_results: usize,
    pub reason_code: &'static str,
    pub explanation: String,
}

pub fn evaluate_search(
    config: &serde_json::Value,
    provider: &str,
    query_len: usize,
) -> SearchDecision {
    let object = config.as_object();
    let provider = provider.trim().to_ascii_lowercase();
    let max_results = object
        .and_then(|value| value.get("maxResults"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(5)
        .clamp(1, 5) as usize;
    let enabled = match provider.as_str() {
        "wikipedia" => object
            .and_then(|value| value.get("allowWikipedia"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "anilist" => object
            .and_then(|value| value.get("allowAniList"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "bluesky" => object
            .and_then(|value| value.get("allowBluesky"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "youtube" => object
            .and_then(|value| value.get("allowYouTube"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        "twitch" => object
            .and_then(|value| value.get("allowTwitch"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        _ => false,
    };
    let (allowed, reason_code, explanation) = if provider.is_empty() {
        (
            false,
            "provider_required",
            "Choose one approved search provider.".to_owned(),
        )
    } else if query_len == 0 || query_len > 128 {
        (
            false,
            "query_out_of_range",
            "Search text must contain between 1 and 128 characters.".to_owned(),
        )
    } else if !matches!(
        provider.as_str(),
        "wikipedia" | "anilist" | "bluesky" | "youtube" | "twitch"
    ) {
        (
            false,
            "provider_not_approved",
            "Choose Wikipedia, AniList, Bluesky, YouTube or Twitch.".to_owned(),
        )
    } else if !enabled {
        (
            false,
            "provider_disabled",
            "That search provider is disabled in this server's settings.".to_owned(),
        )
    } else {
        (
            true,
            "provider_allowed",
            format!("Search {provider} with at most {max_results} bounded result(s)."),
        )
    };
    SearchDecision {
        allowed,
        provider,
        max_results,
        reason_code,
        explanation,
    }
}

impl FeatureAdapter for SearchAdapter {
    fn descriptor(&self) -> FeatureAdapterDescriptor {
        FeatureAdapterDescriptor {
            key: Self::KEY.into(),
            source: Self::SOURCE.into(),
            schema_version: FEATURE_SCHEMA_VERSION,
            schema: serde_json::json!({
                "version": FEATURE_SCHEMA_VERSION,
                "source": Self::SOURCE,
                "sections": [{
                    "title": "Approved search sources",
                    "description": "Search is limited to providers with documented APIs; arbitrary URLs are never fetched.",
                    "fields": [
                        {"key":"maxResults","label":"Results per search","kind":"number","min":1,"max":5},
                        {"key":"allowWikipedia","label":"Wikipedia","kind":"toggle"},
                        {"key":"allowAniList","label":"AniList","kind":"toggle"},
                        {"key":"allowBluesky","label":"Bluesky","kind":"toggle"},
                        {"key":"allowYouTube","label":"YouTube","kind":"toggle"},
                        {"key":"allowTwitch","label":"Twitch","kind":"toggle"}
                    ]
                }]
            }),
            defaults: serde_json::json!({
                "maxResults": 5,
                "allowWikipedia": true,
                "allowAniList": true,
                "allowBluesky": true,
                "allowYouTube": true,
                "allowTwitch": true
            }),
            dependencies: vec!["outbound_https".into(), "send_messages".into()],
        }
    }

    fn validate(&self, config: &serde_json::Value) -> Vec<ValidationIssue> {
        let Some(object) = config.as_object() else {
            return vec![ValidationIssue {
                path: "config".into(),
                code: "object_required".into(),
                message: "The configuration must be an object.".into(),
                severity: "error".into(),
            }];
        };
        let mut issues = Vec::new();
        if let Some(value) = object.get("maxResults")
            && !value.as_i64().is_some_and(|value| (1..=5).contains(&value))
        {
            issues.push(ValidationIssue {
                path: "maxResults".into(),
                code: "out_of_range".into(),
                message: "Results per search must be between 1 and 5.".into(),
                severity: "error".into(),
            });
        }
        for key in [
            "allowWikipedia",
            "allowAniList",
            "allowBluesky",
            "allowYouTube",
            "allowTwitch",
        ] {
            if object.get(key).is_some_and(|value| !value.is_boolean()) {
                issues.push(ValidationIssue {
                    path: key.into(),
                    code: "boolean_required".into(),
                    message: "Search provider switches must be true or false.".into(),
                    severity: "error".into(),
                });
            }
        }
        if [
            "allowWikipedia",
            "allowAniList",
            "allowBluesky",
            "allowYouTube",
            "allowTwitch",
        ]
        .iter()
        .all(|key| object.get(*key).and_then(serde_json::Value::as_bool) == Some(false))
        {
            issues.push(ValidationIssue {
                path: "providers".into(),
                code: "provider_required".into(),
                message: "Enable at least one approved search provider.".into(),
                severity: "error".into(),
            });
        }
        issues
    }

    fn runtime_projection(&self, config: &serde_json::Value) -> Vec<(String, String)> {
        let mut projection = Vec::new();
        if let Some(value) = config.get("maxResults").and_then(serde_json::Value::as_i64) {
            projection.push((
                "utility.search.max_results".into(),
                value.clamp(1, 5).to_string(),
            ));
        }
        if let Some(value) = config
            .get("allowWikipedia")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.search.allow_wikipedia".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("allowAniList")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.search.allow_anilist".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("allowBluesky")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.search.allow_bluesky".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("allowYouTube")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.search.allow_youtube".into(), value.to_string()));
        }
        if let Some(value) = config
            .get("allowTwitch")
            .and_then(serde_json::Value::as_bool)
        {
            projection.push(("utility.search.allow_twitch".into(), value.to_string()));
        }
        projection
    }

    fn simulate(&self, config: &serde_json::Value, fixture: &serde_json::Value) -> Vec<String> {
        let provider = fixture_string(fixture, "searchProvider", "search_provider", "wikipedia");
        let query = fixture_string(fixture, "searchQuery", "search_query", "preview");
        let decision = evaluate_search(config, provider, query.len());
        let mut effects = vec![if decision.allowed {
            decision.explanation
        } else {
            format!(
                "Search rejected ({}): {}",
                decision.reason_code, decision.explanation
            )
        }];
        effects.extend(
            self.runtime_projection(config)
                .into_iter()
                .map(|(setting, value)| format!("Runtime setting `{setting}` = `{value}`.")),
        );
        effects
    }
}
static EMBEDS_ADAPTER: EmbedsAdapter = EmbedsAdapter;
static ECONOMY_ADAPTER: EconomyAdapter = EconomyAdapter;
static BLUESKY_ADAPTER: BlueskyAdapter = BlueskyAdapter;
static INSTAGRAM_ADAPTER: ExternalProviderAdapter = ExternalProviderAdapter {
    key: "social.instagram",
    source: "meta_instagram_official_v1",
    schema: r#"{
        "version": 1,
        "source": "meta_instagram_official_v1",
        "sections": [{
            "title": "Instagram alerts",
            "description": "Notify a Discord channel about posts from a professional Instagram account authorised through Meta OAuth.",
            "fields": [
                {"key":"username","label":"Professional account","kind":"text","help":"The account must explicitly authorise Vozen through Meta OAuth."},
                {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                {"key":"intervalSeconds","label":"Check interval (seconds)","kind":"number","min":300,"max":86400},
                {"key":"messageTemplate","label":"Alert message","kind":"textarea","advanced":true},
                {"key":"mention","label":"Optional mention","kind":"text","advanced":true}
            ]
        }]
    }"#,
    defaults: r#"{
        "username":"",
        "targetChannelId":"",
        "intervalSeconds":900,
        "messageTemplate":"New Instagram post from @{username}: {url}",
        "mention":""
    }"#,
    dependencies: &[
        "Meta Instagram API app",
        "Professional account OAuth grant",
        "Meta App Review and deletion callbacks",
        "Send Messages",
    ],
};
static TIKTOK_ADAPTER: ExternalProviderAdapter = ExternalProviderAdapter {
    key: "social.tiktok",
    source: "tiktok_display_api_v1",
    schema: r#"{
        "version": 1,
        "source": "tiktok_display_api_v1",
        "sections": [{
            "title": "TikTok alerts",
            "description": "Notify a Discord channel about videos from a creator who authorises the Display API scopes.",
            "fields": [
                {"key":"username","label":"Creator username","kind":"text","help":"The creator must authorise the Vozen application."},
                {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                {"key":"intervalSeconds","label":"Check interval (seconds)","kind":"number","min":300,"max":86400},
                {"key":"messageTemplate","label":"Alert message","kind":"textarea","advanced":true},
                {"key":"mention","label":"Optional mention","kind":"text","advanced":true}
            ]
        }]
    }"#,
    defaults: r#"{
        "username":"",
        "targetChannelId":"",
        "intervalSeconds":900,
        "messageTemplate":"New TikTok video from @{username}: {url}",
        "mention":""
    }"#,
    dependencies: &[
        "TikTok Display API app",
        "TikTok App Review",
        "Creator OAuth grant",
        "Send Messages",
    ],
};
static KICK_ADAPTER: ExternalProviderAdapter = ExternalProviderAdapter {
    key: "social.kick",
    source: "kick_official_api_v1",
    schema: r#"{
        "version": 1,
        "source": "kick_official_api_v1",
        "sections": [{
            "title": "Kick alerts",
            "description": "Notify a Discord channel about streams through an approved Kick API application.",
            "fields": [
                {"key":"sourceHandle","label":"Kick channel","kind":"text","help":"Enter the channel slug, not a web URL."},
                {"key":"targetChannelId","label":"Discord channel","kind":"channel"},
                {"key":"intervalSeconds","label":"Check interval (seconds)","kind":"number","min":300,"max":86400},
                {"key":"messageTemplate","label":"Alert message","kind":"textarea","advanced":true},
                {"key":"mention","label":"Optional mention","kind":"text","advanced":true}
            ]
        }]
    }"#,
    defaults: r#"{
        "sourceHandle":"",
        "targetChannelId":"",
        "intervalSeconds":900,
        "messageTemplate":"{sourceHandle} is live on Kick: {url}",
        "mention":""
    }"#,
    dependencies: &[
        "Approved Kick developer application",
        "Official Kick API/webhook access",
        "Send Messages",
    ],
};
static MONETIZATION_ADAPTER: ExternalProviderAdapter = ExternalProviderAdapter {
    key: "growth.monetization",
    source: "stripe_connect_server_sales_v1",
    schema: r#"{
        "version": 1,
        "source": "stripe_connect_server_sales_v1",
        "sections": [{
            "title": "Server monetization",
            "description": "Offer a server subscription through Stripe Connect. Production requires legal, tax and support approval.",
            "fields": [
                {"key":"productName","label":"Product name","kind":"text","max":80},
                {"key":"targetRoleId","label":"Subscriber role","kind":"role"},
                {"key":"priceCents","label":"Monthly price (cents)","kind":"number","min":0,"max":10000000},
                {"key":"currency","label":"Currency","kind":"text","help":"ISO 4217 lowercase code, for example eur."},
                {"key":"trialDays","label":"Trial days","kind":"number","min":0,"max":30}
            ]
        }]
    }"#,
    defaults: r#"{
        "productName":"",
        "targetRoleId":"",
        "priceCents":0,
        "currency":"eur",
        "trialDays":0
    }"#,
    dependencies: &[
        "Stripe Connect account",
        "KYC, tax and refund policy",
        "Signed Stripe webhooks",
        "Support and chargeback process",
    ],
};
static WALLET_GATING_ADAPTER: ExternalProviderAdapter = ExternalProviderAdapter {
    key: "web3.gating",
    source: "siwe_read_only_role_gate_v1",
    schema: r#"{
        "version": 1,
        "source": "siwe_read_only_role_gate_v1",
        "sections": [{
            "title": "Wallet gating",
            "description": "Grant a Discord role after a one-time SIWE signature and read-only contract check.",
            "fields": [
                {"key":"chain","label":"Network","kind":"select","options":["ethereum","polygon","arbitrum","base"]},
                {"key":"contractAddress","label":"Contract address","kind":"text","help":"Only an approved contract is accepted; never enter a private key."},
                {"key":"assetType","label":"Token standard","kind":"select","options":["erc20","erc721","erc1155"]},
                {"key":"tokenId","label":"Token ID (ERC-1155)","kind":"text","advanced":true},
                {"key":"targetRoleId","label":"Holder role","kind":"role"},
                {"key":"minimumBalance","label":"Minimum balance","kind":"text"},
                {"key":"intervalSeconds","label":"Recheck interval (seconds)","kind":"number","min":900,"max":86400}
            ]
        }]
    }"#,
    defaults: r#"{
        "chain":"ethereum",
        "contractAddress":"",
        "assetType":"erc721",
        "tokenId":"",
        "targetRoleId":"",
        "minimumBalance":"1",
        "intervalSeconds":3600
    }"#,
    dependencies: &[
        "SIWE domain and session secret",
        "Operator-approved RPC endpoint",
        "Approved contract allow-list",
        "Manage Roles",
    ],
};
static CRYPTO_STATS_ADAPTER: CryptoAdapter = CryptoAdapter {
    key: "web3.crypto_stats",
    title: "Crypto statistics",
    description: "Publish bounded CoinGecko price updates to a Discord channel.",
    stats: true,
};
static CRYPTO_QUERIES_ADAPTER: CryptoAdapter = CryptoAdapter {
    key: "web3.crypto_queries",
    title: "Crypto queries",
    description: "Query read-only CoinGecko prices from an application command.",
    stats: false,
};
static GAS_TRACKER_ADAPTER: GasAdapter = GasAdapter;
pub fn feature_adapter(key: &str) -> Option<&'static dyn FeatureAdapter> {
    match key {
        AntiSpamAdapter::KEY => Some(&ANTI_SPAM_ADAPTER as &dyn FeatureAdapter),
        NicknameAdapter::KEY => Some(&NICKNAME_ADAPTER as &dyn FeatureAdapter),
        ReminderAdapter::KEY => Some(&REMINDER_ADAPTER as &dyn FeatureAdapter),
        LeaderboardAdapter::KEY => Some(&LEADERBOARD_ADAPTER as &dyn FeatureAdapter),
        WorkflowAdapter::KEY => Some(&WORKFLOW_ADAPTER as &dyn FeatureAdapter),
        PrivacyAdapter::KEY => Some(&PRIVACY_ADAPTER as &dyn FeatureAdapter),
        StatsAdapter::KEY => Some(&STATS_ADAPTER as &dyn FeatureAdapter),
        HelpAdapter::KEY => Some(&HELP_ADAPTER as &dyn FeatureAdapter),
        ModerationAdapter::KEY => Some(&MODERATION_ADAPTER as &dyn FeatureAdapter),
        AntiScamAdapter::KEY => Some(&ANTI_SCAM_ADAPTER as &dyn FeatureAdapter),
        WelcomeChannelAdapter::KEY => Some(&WELCOME_CHANNEL_ADAPTER as &dyn FeatureAdapter),
        LevelsAdapter::KEY => Some(&LEVELS_ADAPTER as &dyn FeatureAdapter),
        StarboardAdapter::KEY => Some(&STARBOARD_ADAPTER as &dyn FeatureAdapter),
        AntiRaidAdapter::KEY => Some(&ANTI_RAID_ADAPTER as &dyn FeatureAdapter),
        JoinGateAdapter::KEY => Some(&JOIN_GATE_ADAPTER as &dyn FeatureAdapter),
        TicketsAdapter::KEY => Some(&TICKETS_ADAPTER as &dyn FeatureAdapter),
        WelcomeAdapter::KEY => Some(&WELCOME_ADAPTER as &dyn FeatureAdapter),
        "community.suggestions" => Some(&SUGGESTIONS_ADAPTER as &dyn FeatureAdapter),
        "community.giveaways" => Some(&GIVEAWAYS_ADAPTER as &dyn FeatureAdapter),
        "management.polls" => Some(&POLLS_ADAPTER as &dyn FeatureAdapter),
        "community.events" => Some(&EVENTS_ADAPTER as &dyn FeatureAdapter),
        "community.role_panels" => Some(&ROLE_PANELS_ADAPTER as &dyn FeatureAdapter),
        CustomCommandsAdapter::KEY => Some(&CUSTOM_COMMANDS_ADAPTER as &dyn FeatureAdapter),
        AuditAdapter::KEY => Some(&AUDIT_ADAPTER as &dyn FeatureAdapter),
        TemplatesAdapter::KEY => Some(&TEMPLATES_ADAPTER as &dyn FeatureAdapter),
        BirthdaysAdapter::KEY => Some(&BIRTHDAYS_ADAPTER as &dyn FeatureAdapter),
        EmojisAdapter::KEY => Some(&EMOJIS_ADAPTER as &dyn FeatureAdapter),
        AchievementsAdapter::KEY => Some(&ACHIEVEMENTS_ADAPTER as &dyn FeatureAdapter),
        InviteTrackerAdapter::KEY => Some(&INVITE_TRACKER_ADAPTER as &dyn FeatureAdapter),
        SearchAdapter::KEY => Some(&SEARCH_ADAPTER as &dyn FeatureAdapter),
        "utility.temp_channels" => Some(&TEMP_CHANNELS_ADAPTER as &dyn FeatureAdapter),
        "social.youtube" => Some(&YOUTUBE_ADAPTER as &dyn FeatureAdapter),
        "social.rss" => Some(&RSS_ADAPTER as &dyn FeatureAdapter),
        "social.podcasts" => Some(&PODCASTS_ADAPTER as &dyn FeatureAdapter),
        "social.twitch" => Some(&TWITCH_ADAPTER as &dyn FeatureAdapter),
        BlueskyAdapter::KEY => Some(&BLUESKY_ADAPTER as &dyn FeatureAdapter),
        "social.instagram" => Some(&INSTAGRAM_ADAPTER as &dyn FeatureAdapter),
        "social.tiktok" => Some(&TIKTOK_ADAPTER as &dyn FeatureAdapter),
        "social.kick" => Some(&KICK_ADAPTER as &dyn FeatureAdapter),
        "growth.monetization" => Some(&MONETIZATION_ADAPTER as &dyn FeatureAdapter),
        "web3.gating" => Some(&WALLET_GATING_ADAPTER as &dyn FeatureAdapter),
        "studio.rank_card" => Some(&RANK_CARD_ADAPTER as &dyn FeatureAdapter),
        EmbedsAdapter::KEY => Some(&EMBEDS_ADAPTER as &dyn FeatureAdapter),
        EconomyAdapter::KEY => Some(&ECONOMY_ADAPTER as &dyn FeatureAdapter),
        "web3.crypto_stats" => Some(&CRYPTO_STATS_ADAPTER as &dyn FeatureAdapter),
        "web3.crypto_queries" => Some(&CRYPTO_QUERIES_ADAPTER as &dyn FeatureAdapter),
        "web3.gas_tracker" => Some(&GAS_TRACKER_ADAPTER as &dyn FeatureAdapter),
        _ => None,
    }
}

/// Evaluate one message observation without Discord side effects. This is the
/// sole place where anti-spam matching precedence is decided.
pub fn evaluate_anti_spam(
    policy: &AntiSpamPolicy,
    observation: &AntiSpamObservation,
) -> AntiSpamDecision {
    let ignored = policy
        .ignored_channels
        .iter()
        .any(|channel| channel == &observation.channel_id)
        || observation
            .role_ids
            .iter()
            .any(|role| policy.ignored_roles.iter().any(|ignored| ignored == role));
    if ignored {
        return AntiSpamDecision {
            ignored: true,
            matched: Vec::new(),
            should_act: false,
            should_delete: false,
            timeout_seconds: 0,
            reason: "channel_or_role_exempt".into(),
        };
    }
    let mut matched = Vec::new();
    if observation.message_count >= policy.flood_count {
        matched.push("flood".into());
    }
    if observation.duplicate_count >= policy.duplicate_limit {
        matched.push("duplicate".into());
    }
    if observation.mention_count >= policy.mention_limit {
        matched.push("mentions".into());
    }
    if observation.link_count >= policy.max_links {
        matched.push("links".into());
    }
    if observation.letter_count >= policy.caps_min_letters
        && (observation.uppercase_letters as u64).saturating_mul(100)
            >= (policy.caps_percent as u64).saturating_mul(observation.letter_count as u64)
    {
        matched.push("caps".into());
    }
    let should_act = !matched.is_empty() && !policy.alert_only;
    let reason = if matched.is_empty() {
        "no_match".into()
    } else {
        format!("matched:{}", matched.join(","))
    };
    AntiSpamDecision {
        ignored: false,
        matched,
        should_act,
        should_delete: should_act && policy.delete_message,
        timeout_seconds: if should_act {
            policy.timeout_seconds
        } else {
            0
        },
        reason,
    }
}

/// Canonical lifecycle policy for the feature catalogue.  Labels and copy are
/// intentionally kept in the API response for now, but the runtime state is
/// decided here so the panel cannot mark a stored JSON blob as operational.
pub fn feature_maturity(key: &str) -> FeatureMaturity {
    match key {
        // These adapters are wired to the current Rust runtime.
        "protection.antiscam"
        | "protection.anti_raid"
        | "protection.join_gate"
        | "protection.antispam"
        | "community.levels"
        | "community.starboard"
        | "community.suggestions"
        | "community.giveaways"
        | "community.role_panels"
        | "community.events"
        | "support.tickets"
        | "support.welcome"
        | "support.welcome_channel"
        | "management.polls"
        | "management.nickname"
        | "utility.reminders"
        | "community.leaderboard"
        | "management.workflows"
        | "management.privacy"
        | "insights.stats"
        | "utility.help"
        | "management.moderation"
        | "management.custom_commands"
        | "management.audit"
        | "management.templates"
        | "community.birthdays"
        | "community.achievements"
        | "management.invite_tracker"
        | "utility.emojis"
        | "utility.embeds"
        | "utility.search"
        | "utility.temp_channels"
        | "community.economy"
        | "studio.rank_card"
        // RSS and podcasts share the same public RSS/Atom transport, including
        // SSRF protection, bounded payloads, deduplication and test delivery.
        // Neither requires provider credentials to operate.
        | "social.rss"
        | "social.podcasts"
        | "social.bluesky"
        | "web3.crypto_stats"
        | "web3.crypto_queries" => FeatureMaturity::Operational,
        "social.youtube" | "social.twitch" | "web3.gas_tracker" => FeatureMaturity::Beta,
        // Providers without an approved adapter or credentials must never be
        // presented as configurable, even if a legacy setting exists.
        "social.instagram"
        | "social.tiktok"
        | "social.kick"
        | "growth.monetization"
        | "web3.gating" => FeatureMaturity::Blocked,
        _ => FeatureMaturity::Planned,
    }
}

pub fn feature_is_configurable(key: &str) -> bool {
    matches!(
        feature_maturity(key),
        FeatureMaturity::Operational | FeatureMaturity::Beta
    )
}

pub const FEATURE_SCHEMA_VERSION: u32 = 1;

pub fn quota_limit(plan: &Plan, key: &str) -> u64 {
    let free = match key {
        "panels" => 1,
        "forms" => 1,
        "role_panels" => 3,
        "workflows" => 3,
        "workflow_runs" => 500,
        "feeds" => 2,
        "templates" => 5,
        "analytics_days" => 30,
        "audit_days" => 30,
        "transcript_days" => 30,
        "personal_drafts" | "personal_views" | "personal_templates" => 5,
        _ => 0,
    };
    let paid = match key {
        "panels" => 10,
        "forms" => 25,
        "role_panels" => 25,
        "workflows" => 25,
        "workflow_runs" => 25_000,
        "feeds" => 25,
        "templates" => 100,
        "analytics_days" => 365,
        "audit_days" => 365,
        "transcript_days" => 365,
        "personal_drafts" | "personal_views" | "personal_templates" => 100,
        _ => 0,
    };
    match plan {
        Plan::Free => free,
        // Plus is user-scoped: it can unlock personal drafts, views and
        // templates, but must not increase a guild's operational quotas.
        Plan::Plus => match key {
            "personal_drafts" | "personal_views" | "personal_templates" => paid,
            _ => free,
        },
        Plan::Premium { .. } => paid,
    }
}

pub fn parse_ip(value: &str) -> Result<IpAddr> {
    IpAddr::from_str(value).context("invalid IP address")
}

#[cfg(test)]
mod tests {
    #[test]
    fn welcome_polish_is_limited_to_the_standard_greeting() {
        for greeting in [
            "Welcome {member} to {server}!",
            "👋 Welcome {member} to {server}!",
        ] {
            assert_eq!(
                super::render_welcome_message(greeting, "<@123>", "Community"),
                "👋 Welcome <@123> to Community!"
            );
        }
        for custom in [
            "Hello {member}!",
            "🎉 Welcome {member}!",
            "",
            &"a".repeat(2000),
        ] {
            assert_eq!(
                super::render_welcome_message(custom, "<@123>", "Community"),
                super::render_member_message(custom, "<@123>", "Community")
            );
        }
        let safe =
            super::render_welcome_message("Hello {member} @everyone @here", "<@123>", "Community");
        assert!(!safe.contains("@everyone"));
        assert!(!safe.contains("@here"));
    }
    #[test]
    fn suggestion_length_counts_unicode_characters() {
        let text = "é".repeat(1_000);
        let decision =
            super::evaluate_suggestion(&serde_json::json!({"channel": "123"}), &text, "123");
        assert!(decision.allowed);
        assert_eq!(decision.text.chars().count(), 1_000);
    }

    use super::*;

    #[test]
    fn entitlement_settings_must_be_configured_as_a_pair() {
        assert!(resolve_entitlement_settings("development", None, None).is_ok());
        assert!(
            resolve_entitlement_settings(
                "production",
                Some("http://127.0.0.1:3011/internal/v1/entitlements/resolve".into()),
                Some("service-secret".into()),
            )
            .is_ok()
        );
        assert!(
            resolve_entitlement_settings(
                "development",
                Some("http://127.0.0.1:3011/resolve".into()),
                None
            )
            .is_err()
        );
        assert!(
            resolve_entitlement_settings("development", None, Some("service-secret".into()))
                .is_err()
        );
        assert!(resolve_entitlement_settings("production", None, None).is_err());
    }

    #[test]
    fn every_adapter_handles_null_unicode_and_numeric_boundary_inputs() {
        let probes = [
            serde_json::Value::Null,
            serde_json::json!(false),
            serde_json::json!(0),
            serde_json::json!(i64::MIN),
            serde_json::json!(u64::MAX),
            serde_json::json!("🦀é\u{0000}"),
            serde_json::json!([null, "🦀é\u{0000}", 0]),
            serde_json::json!({}),
        ];
        for key in FEATURE_KEYS {
            let adapter = feature_adapter(key).unwrap();
            let descriptor = adapter.descriptor();
            for probe in &probes {
                adapter.validate(probe);
                adapter.runtime_projection(probe);
                adapter.simulate(probe, probe);
                for field in descriptor.defaults.as_object().unwrap().keys() {
                    let mut config = descriptor.defaults.clone();
                    config[field] = probe.clone();
                    adapter.validate(&config);
                    let projection = adapter.runtime_projection(&config);
                    let unique: HashSet<_> = projection.iter().map(|(key, _)| key).collect();
                    assert_eq!(
                        unique.len(),
                        projection.len(),
                        "{key}.{field}: duplicate projection"
                    );
                    adapter.simulate(&config, probe);
                }
            }
        }
    }

    #[test]
    fn catalogue_discord_id_fields_reject_zero() {
        for key in FEATURE_KEYS {
            let adapter = feature_adapter(key).unwrap();
            let descriptor = adapter.descriptor();
            for section in descriptor.schema["sections"]
                .as_array()
                .into_iter()
                .flatten()
            {
                for field in section["fields"].as_array().into_iter().flatten() {
                    let Some(name) = field["key"].as_str() else {
                        continue;
                    };
                    let value = match field["kind"].as_str() {
                        Some("channel" | "role") => serde_json::json!("0"),
                        Some("channels" | "roles") => serde_json::json!(["0"]),
                        _ => continue,
                    };
                    let mut config = descriptor.defaults.clone();
                    config[name] = value;
                    assert!(
                        adapter
                            .validate(&config)
                            .iter()
                            .any(|issue| issue.path == name),
                        "{key}.{name} accepts zero"
                    );
                }
            }
        }
    }

    #[test]
    fn reminders_count_unicode_characters_and_birthdays_bound_expanded_messages() {
        let policy = ReminderPolicy {
            max_text_length: 50,
            ..ReminderPolicy::default()
        };
        let mut observation = ReminderObservation {
            delay_ms: 1000,
            text: "🦀".repeat(50),
            repeat: None,
            timezone: "UTC".into(),
        };
        assert!(evaluate_reminder(&policy, &observation).allowed);
        observation.text.push('é');
        assert_eq!(
            evaluate_reminder(&policy, &observation).reason_code,
            "text_exceeds_limit"
        );
        let birthday = evaluate_birthday(
            &serde_json::json!({"channel":"123", "message":"{user}".repeat(166)}),
            "123456789012345678",
            9,
            7,
        );
        assert!(birthday.allowed);
        assert!(birthday.message.chars().count() <= 2000);
        assert!(!evaluate_birthday(&serde_json::json!({"channel":"0"}), "123", 9, 7).allowed);
        assert!(!evaluate_stats(&serde_json::json!({}), Some("0"), 0, 0, 0).allowed);
    }

    #[test]
    fn scam_policy_matches_markdown_links_and_userinfo_hosts() {
        let policy = scam_policy_from_json(
            &serde_json::json!({"blockedDomains":["bad.example"],"blockInvites":true}),
        );
        for content in [
            "[gift](https://bad.example/claim)",
            "https://trusted.example@bad.example/",
            "[join](https://discord.gg/raid)",
        ] {
            assert!(
                !evaluate_scam(&policy, "123", content).matched.is_empty(),
                "{content}"
            );
        }
        for content in [
            "https://bad.example.safe.example/",
            "https://bad.example@safe.example/",
        ] {
            assert!(
                evaluate_scam(&policy, "123", content).matched.is_empty(),
                "{content}"
            );
        }
    }
    use helper_contracts::Plan;

    #[test]
    fn quota_matrix_keeps_free_small_and_paid_bounded() {
        assert_eq!(quota_limit(&Plan::Free, "workflow_runs"), 500);
        assert_eq!(quota_limit(&Plan::Plus, "workflow_runs"), 500);
        assert_eq!(quota_limit(&Plan::Plus, "personal_drafts"), 100);
        assert_eq!(quota_limit(&Plan::Premium { guild_limit: 8 }, "panels"), 10);
    }

    #[test]
    fn unknown_quota_is_closed() {
        assert_eq!(quota_limit(&Plan::Free, "unknown"), 0);
    }

    #[test]
    fn ecosystem_oauth_client_takes_precedence_over_legacy_client() {
        assert_eq!(
            resolve_trusted_vozen_oauth_client_id(
                Some("1537738930722443364".into()),
                Some("1523826014935842997".into()),
            ),
            Some("1537738930722443364".into())
        );
        assert_eq!(
            resolve_trusted_vozen_oauth_client_id(None, Some("legacy".into())),
            Some("legacy".into())
        );
    }

    #[test]
    fn reminder_evaluator_applies_delay_length_and_repeat_policy() {
        let policy = ReminderPolicy {
            max_delay_hours: 1,
            max_text_length: 20,
            timezone: "UTC".into(),
            notify_user: true,
            allow_recurring: true,
            max_recurrences: 3,
        };
        let accepted = evaluate_reminder(
            &policy,
            &ReminderObservation {
                delay_ms: 30 * 60 * 1_000,
                text: "check the queue".into(),
                repeat: Some("daily".into()),
                timezone: "UTC".into(),
            },
        );
        assert!(accepted.allowed);
        assert_eq!(accepted.remaining, 3);

        let too_long = evaluate_reminder(
            &policy,
            &ReminderObservation {
                delay_ms: 1_000,
                text: "this reminder is deliberately too long".into(),
                repeat: None,
                timezone: "UTC".into(),
            },
        );
        assert_eq!(too_long.reason_code, "text_exceeds_limit");

        let invalid_repeat = evaluate_reminder(
            &policy,
            &ReminderObservation {
                delay_ms: 1_000,
                text: "short".into(),
                repeat: Some("hourly".into()),
                timezone: "UTC".into(),
            },
        );
        assert_eq!(invalid_repeat.reason_code, "invalid_repeat");
    }

    #[test]
    fn reminder_adapter_simulation_uses_runtime_evaluator() {
        let adapter = ReminderAdapter;
        let effects = adapter.simulate(
            &serde_json::json!({
                "maxDelayHours": 1,
                "maxTextLength": 20,
                "timezone": "UTC",
                "allowRecurring": false,
                "maxRecurrences": 3,
            }),
            &serde_json::json!({
                "delayMs": 120_000,
                "reminderText": "short",
                "repeat": "daily",
                "timezone": "UTC",
            }),
        );
        assert!(
            effects
                .iter()
                .any(|effect| effect.contains("recurring_disabled"))
        );
    }

    #[test]
    fn feature_registry_has_47_unique_keys_and_closed_unknowns() {
        let mut keys = FEATURE_KEYS.to_vec();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(FEATURE_KEYS.len(), 47);
        assert_eq!(keys.len(), 47);
        assert!(is_known_feature("community.leaderboard"));
        assert!(!is_known_feature("community.not_a_real_feature"));
    }

    #[test]
    fn leaderboard_evaluator_sorts_bounds_and_respects_opt_outs() {
        let policy = LeaderboardPolicy {
            max_entries: 2,
            public: false,
        };
        let decision = evaluate_leaderboard(
            &policy,
            vec![
                LeaderboardEntry {
                    user_id: "low".into(),
                    xp: 10,
                    opted_out: false,
                },
                LeaderboardEntry {
                    user_id: "private".into(),
                    xp: 999,
                    opted_out: true,
                },
                LeaderboardEntry {
                    user_id: "top".into(),
                    xp: 100,
                    opted_out: false,
                },
                LeaderboardEntry {
                    user_id: "middle".into(),
                    xp: 50,
                    opted_out: false,
                },
            ],
        );
        assert!(!decision.public);
        assert_eq!(decision.excluded_opt_outs, 1);
        assert!(decision.truncated);
        assert_eq!(
            decision
                .entries
                .iter()
                .map(|entry| entry.user_id.as_str())
                .collect::<Vec<_>>(),
            vec!["top", "middle"]
        );
    }

    #[test]
    fn workflow_evaluator_matches_condition_and_sanitizes_mentions() {
        let decision = evaluate_workflow(
            &WorkflowPolicy {
                max_reply_length: 80,
                allow_mentions: false,
            },
            &WorkflowObservation {
                enabled: true,
                trigger: "message".into(),
                condition: "hello".into(),
                action: "reply".into(),
                payload: "Hi {user}: {message} @everyone".into(),
                message_content: "HELLO from the community".into(),
                user_mention: "<@42>".into(),
            },
        );
        assert!(decision.matched);
        assert!(decision.should_run);
        let reply = decision.reply.expect("matched workflow reply");
        assert!(reply.contains("<@42>"));
        assert!(reply.contains("@\u{200b}everyone"));
        assert!(!reply.contains("@everyone"));
    }

    #[test]
    fn workflow_evaluator_runs_a_safe_unicode_reaction() {
        let decision = evaluate_workflow(
            &WorkflowPolicy::default(),
            &WorkflowObservation {
                enabled: true,
                trigger: "message".into(),
                condition: "thanks".into(),
                action: "react".into(),
                payload: "✅".into(),
                message_content: "Thanks for the help!".into(),
                user_mention: "<@42>".into(),
            },
        );

        assert!(decision.matched);
        assert!(decision.should_run);
        assert_eq!(decision.reply, None);
        assert_eq!(decision.reaction.as_deref(), Some("✅"));
        assert_eq!(decision.reason, "matched");
    }

    #[test]
    fn workflow_evaluator_rejects_custom_emoji_reactions() {
        let decision = evaluate_workflow(
            &WorkflowPolicy::default(),
            &WorkflowObservation {
                enabled: true,
                trigger: "message".into(),
                condition: String::new(),
                action: "react".into(),
                payload: "<:unsafe:123456789>".into(),
                message_content: "hello".into(),
                user_mention: "<@42>".into(),
            },
        );

        assert!(decision.matched);
        assert!(!decision.should_run);
        assert_eq!(decision.reaction, None);
        assert_eq!(decision.reason, "invalid_reaction");
    }

    #[test]
    fn workflow_adapter_simulation_uses_the_runtime_evaluator() {
        let adapter = feature_adapter("management.workflows").expect("workflow adapter");
        let effects = adapter.simulate(
            &serde_json::json!({"maxReplyLength": 20, "allowMentions": false}),
            &serde_json::json!({
                "workflow": {"condition":"ping", "action":"reply", "payload":"{user} ping @here"},
                "messageContent":"please PING",
                "userMention":"<@99>"
            }),
        );
        assert!(effects[0].contains("<@99> ping @\u{200b}here"));
        assert!(effects.iter().any(|effect| {
            effect.contains("management.workflows.max_reply_length") && effect.contains("20")
        }));
    }

    #[test]
    fn achievements_evaluator_returns_ordered_milestones() {
        let unlocked = evaluate_achievements(
            &AchievementPolicy {
                first_threshold: 100,
                regular_threshold: 500,
                pillar_threshold: 1_000,
            },
            600,
        );
        assert_eq!(
            unlocked.iter().map(|item| item.key).collect::<Vec<_>>(),
            vec!["first_steps", "regular"]
        );
    }

    #[test]
    fn achievements_adapter_simulation_uses_the_same_milestone_evaluator() {
        let adapter = feature_adapter("community.achievements").expect("achievements adapter");
        let effects = adapter.simulate(
            &serde_json::json!({
                "firstThreshold": 100,
                "regularThreshold": 500,
                "pillarThreshold": 1000,
                "firstRewardRole": "123456789012345678"
            }),
            &serde_json::json!({"xp": 600}),
        );
        assert!(effects[0].contains("First steps"));
        assert!(effects[0].contains("Regular"));
        assert!(!effects[0].contains("Community pillar"));
        assert!(
            effects
                .iter()
                .any(|effect| { effect.contains("Assign reward role `123456789012345678`") })
        );
    }

    #[test]
    fn leaderboard_adapter_simulation_uses_the_same_decision_contract() {
        let adapter = feature_adapter("community.leaderboard").expect("leaderboard adapter");
        let effects = adapter.simulate(
            &serde_json::json!({"maxEntries": 1, "public": true}),
            &serde_json::json!({
                "leaderboardEntries": [
                    {"userId": "opted-out", "xp": 999, "optedOut": true},
                    {"userId": "alice", "xp": 42}
                ]
            }),
        );
        assert!(effects[0].contains("public XP leaderboard"));
        assert!(effects[0].contains("alice"));
        assert!(effects[0].contains("Excluded 1 member"));
        assert!(effects.iter().any(|effect| {
            effect.contains("community.leaderboard.max_entries") && effect.contains("1")
        }));
    }

    #[test]
    fn every_internal_feature_has_an_adapter_and_external_features_stay_blocked() {
        let internal = [
            "protection.antispam",
            "protection.antiscam",
            "protection.anti_raid",
            "protection.join_gate",
            "community.levels",
            "community.leaderboard",
            "community.starboard",
            "community.suggestions",
            "community.giveaways",
            "support.tickets",
            "support.welcome",
            "support.welcome_channel",
            "management.nickname",
            "management.workflows",
            "management.polls",
            "insights.stats",
            "studio.rank_card",
            "management.moderation",
            "management.custom_commands",
            "management.audit",
            "management.privacy",
            "management.templates",
            "community.role_panels",
            "community.events",
            "community.achievements",
            "management.invite_tracker",
            "utility.help",
            "utility.reminders",
            "utility.emojis",
            "utility.embeds",
            "utility.search",
            "utility.temp_channels",
            "community.birthdays",
            "community.economy",
            "social.podcasts",
            "social.bluesky",
            "web3.crypto_stats",
            "web3.crypto_queries",
        ];
        for key in internal {
            assert!(feature_adapter(key).is_some(), "missing adapter for {key}");
            assert!(matches!(
                feature_maturity(key),
                FeatureMaturity::Operational | FeatureMaturity::Beta
            ));
        }
        for key in [
            "social.instagram",
            "social.tiktok",
            "social.kick",
            "growth.monetization",
            "web3.gating",
        ] {
            assert_eq!(feature_maturity(key), FeatureMaturity::Blocked);
            let adapter = feature_adapter(key).expect("blocked feature still has a contract");
            assert!(!adapter.descriptor().dependencies.is_empty());
            assert!(!adapter.descriptor().schema.as_object().unwrap().is_empty());
        }
        assert_eq!(feature_maturity("web3.gas_tracker"), FeatureMaturity::Beta);
    }

    #[test]
    fn rss_alerts_are_operational_without_provider_credentials() {
        let rss = feature_adapter("social.rss").expect("rss adapter");

        assert_eq!(feature_maturity("social.rss"), FeatureMaturity::Operational);
        assert_eq!(rss.descriptor().source, "rss_atom_adapter_v1");
        assert!(
            rss.descriptor()
                .dependencies
                .iter()
                .any(|dependency| dependency == "outbound_https")
        );
    }

    #[test]
    fn every_catalogue_key_has_a_runtime_adapter_or_an_explicit_blocker() {
        for key in FEATURE_KEYS {
            let maturity = feature_maturity(key);
            assert!(
                feature_adapter(key).is_some() || maturity == FeatureMaturity::Blocked,
                "{key} would otherwise be a silent no-op in the panel"
            );
        }
    }

    #[test]
    fn every_catalogue_adapter_has_a_bounded_preview_and_runtime_projection() {
        let fixture = serde_json::json!({
            "content": "preview message",
            "channelId": "123456789012345678",
            "reactionCount": 5,
            "joinCount": 10,
            "accountAgeDays": 30,
            "hasAvatar": true,
            "displayName": "Preview member"
        });

        for key in FEATURE_KEYS {
            let adapter = feature_adapter(key).expect("catalogue key must have an adapter");
            let descriptor = adapter.descriptor();
            assert_eq!(descriptor.key, *key, "adapter key drifted for {key}");
            assert_eq!(descriptor.schema_version, FEATURE_SCHEMA_VERSION);
            assert!(
                descriptor.schema.is_object(),
                "{key} must expose an object schema"
            );
            assert!(
                descriptor.defaults.is_object(),
                "{key} must expose object defaults"
            );

            // A preview is deliberately side-effect free, but it must still
            // explain what the runtime would do.  This catches adapters that
            // only persist JSON and would otherwise render a misleading
            // Configure button in the panel.
            let effects = adapter.simulate(&descriptor.defaults, &fixture);
            assert!(
                !effects.is_empty() && effects.iter().all(|effect| !effect.trim().is_empty()),
                "{key} has no usable runtime preview"
            );

            // Projection can be empty only for a toggle-only adapter.  Those
            // adapters are still covered by the non-empty simulate contract
            // above; configurable schemas must project at least one setting.
            if descriptor
                .schema
                .get("sections")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|sections| !sections.is_empty())
            {
                assert!(
                    !adapter.runtime_projection(&descriptor.defaults).is_empty(),
                    "{key} exposes fields but publishes no runtime projection"
                );
            }
        }
    }

    #[test]
    fn every_catalogue_preview_describes_an_actionable_runtime_decision() {
        let fixture = serde_json::json!({
            "content": "preview message",
            "channelId": "123456789012345678",
            "reactionCount": 5,
            "joinCount": 10,
            "accountAgeDays": 30,
            "hasAvatar": true,
            "displayName": "Preview member"
        });

        for key in FEATURE_KEYS {
            let adapter = feature_adapter(key).expect("catalogue key must have an adapter");
            let descriptor = adapter.descriptor();
            let effects = adapter.simulate(&descriptor.defaults, &fixture);
            assert!(
                effects.iter().all(|effect| {
                    !effect.contains("Validate and apply")
                        && !effect.contains("only persist")
                        && !effect.contains("guardar JSON")
                }),
                "{key} still exposes a generic persistence-only preview"
            );
            let projection = adapter.runtime_projection(&descriptor.defaults);
            if !projection.is_empty() {
                assert!(
                    effects
                        .iter()
                        .any(|effect| effect.contains("Runtime setting")),
                    "{key} preview does not expose the values consumed by the runtime"
                );
            }
        }
    }

    #[test]
    fn every_schema_field_changes_the_published_runtime_projection() {
        fn probe_value(
            kind: &str,
            current: Option<&serde_json::Value>,
            min: Option<i64>,
            max: Option<i64>,
        ) -> serde_json::Value {
            match current {
                Some(value) if value.is_boolean() => serde_json::json!(!value.as_bool().unwrap()),
                Some(value) if value.is_number() => {
                    let current = value.as_i64().unwrap_or_default();
                    let candidate = if min.is_none_or(|bound| current > bound) {
                        current.saturating_sub(1)
                    } else {
                        current.saturating_add(1)
                    };
                    let candidate = max.map_or(candidate, |bound| candidate.min(bound));
                    serde_json::json!(min.map_or(candidate, |bound| candidate.max(bound)))
                }
                Some(value) if value.is_array() => serde_json::json!(["123456789012345678"]),
                Some(value) if value.is_string() => {
                    serde_json::json!(format!("{}-probe", value.as_str().unwrap_or_default()))
                }
                Some(_) | None if kind == "toggle" => serde_json::json!(true),
                Some(_) | None if matches!(kind, "number" | "slider") => serde_json::json!(1),
                Some(_) | None if matches!(kind, "tags" | "channels" | "roles") => {
                    serde_json::json!(["123456789012345678"])
                }
                _ => serde_json::json!("probe"),
            }
        }

        for key in FEATURE_KEYS {
            let adapter = feature_adapter(key).expect("catalogue key must have an adapter");
            let descriptor = adapter.descriptor();
            let baseline = adapter.runtime_projection(&descriptor.defaults);
            let sections = descriptor.schema["sections"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for section in sections {
                for field in section["fields"].as_array().cloned().unwrap_or_default() {
                    let Some(field_key) = field["key"].as_str() else {
                        continue;
                    };
                    let kind = field["kind"].as_str().unwrap_or("text");
                    let min = field["min"].as_i64();
                    let max = field["max"].as_i64();
                    let mut candidate = descriptor.defaults.clone();
                    let object = candidate
                        .as_object_mut()
                        .expect("feature defaults must be a JSON object");
                    let current = object.get(field_key);
                    object.insert(field_key.into(), probe_value(kind, current, min, max));
                    let projected = adapter.runtime_projection(&candidate);
                    assert_ne!(
                        projected, baseline,
                        "{key}.{field_key} is exposed but does not change runtime projection"
                    );
                }
            }
        }
    }

    #[test]
    fn every_known_key_has_a_declared_lifecycle() {
        for key in FEATURE_KEYS {
            assert_ne!(
                feature_maturity(key),
                FeatureMaturity::Planned,
                "{key} must be operational, beta, or explicitly blocked"
            );
        }
    }

    #[test]
    fn anti_spam_evaluator_explains_matches_and_respects_alert_only() {
        let policy = anti_spam_policy_from_json(&serde_json::json!({
            "floodCount": 5,
            "windowSeconds": 12,
            "duplicateLimit": 2,
            "mentionLimit": 4,
            "timeoutSeconds": 90,
        }));
        let decision = evaluate_anti_spam(
            &policy,
            &AntiSpamObservation {
                channel_id: "general".into(),
                role_ids: vec![],
                message_count: 5,
                duplicate_count: 2,
                mention_count: 4,
                link_count: 0,
                uppercase_letters: 0,
                letter_count: 0,
            },
        );
        assert_eq!(decision.matched, vec!["flood", "duplicate", "mentions"]);
        assert!(decision.should_act);
        assert_eq!(decision.timeout_seconds, 90);
        assert!(decision.reason.contains("matched:flood,duplicate,mentions"));

        let monitor = AntiSpamPolicy {
            alert_only: true,
            ..policy
        };
        let decision = evaluate_anti_spam(
            &monitor,
            &AntiSpamObservation {
                channel_id: "general".into(),
                role_ids: vec![],
                message_count: 5,
                duplicate_count: 0,
                mention_count: 0,
                link_count: 0,
                uppercase_letters: 0,
                letter_count: 0,
            },
        );
        assert!(!decision.should_act);
        assert!(!decision.should_delete);
        assert_eq!(decision.timeout_seconds, 0);
        assert_eq!(decision.matched, vec!["flood"]);
    }

    #[test]
    fn anti_spam_detects_link_and_caps_bursts_and_can_delete_the_message() {
        let policy = anti_spam_policy_from_json(&serde_json::json!({
            "maxLinks": 3,
            "capsPercent": 75,
            "capsMinLetters": 8,
            "deleteMessage": true,
            "timeoutSeconds": 300,
        }));
        let decision = evaluate_anti_spam(
            &policy,
            &AntiSpamObservation {
                channel_id: "general".into(),
                role_ids: vec![],
                message_count: 1,
                duplicate_count: 1,
                mention_count: 0,
                link_count: 3,
                uppercase_letters: 9,
                letter_count: 10,
            },
        );

        assert_eq!(decision.matched, vec!["links", "caps"]);
        assert!(decision.should_act);
        assert!(decision.should_delete);
        assert_eq!(decision.timeout_seconds, 300);
    }

    #[test]
    fn anti_spam_exemptions_short_circuit_before_matching() {
        let policy = AntiSpamPolicy {
            ignored_channels: vec!["staff".into()],
            ignored_roles: vec!["trusted".into()],
            ..AntiSpamPolicy::default()
        };
        for (channel_id, role_ids) in [("staff", vec![]), ("general", vec!["trusted".into()])] {
            let decision = evaluate_anti_spam(
                &policy,
                &AntiSpamObservation {
                    channel_id: channel_id.into(),
                    role_ids,
                    message_count: 99,
                    duplicate_count: 99,
                    mention_count: 99,
                    link_count: 99,
                    uppercase_letters: 99,
                    letter_count: 99,
                },
            );
            assert!(decision.ignored);
            assert!(!decision.should_act);
            assert!(decision.matched.is_empty());
        }
    }

    #[test]
    fn anti_spam_adapter_is_the_single_schema_and_validation_source() {
        let adapter = feature_adapter("protection.antispam").expect("adapter registered");
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.source, "anti_spam_adapter_v1");
        assert_eq!(descriptor.defaults["floodCount"], 6);
        assert_eq!(descriptor.defaults["maxLinks"], 5);
        assert_eq!(descriptor.defaults["capsPercent"], 80);
        assert_eq!(descriptor.defaults["deleteMessage"], false);
        assert_eq!(descriptor.defaults["warningDelivery"], "both");
        assert!(descriptor.schema["sections"].as_array().unwrap().len() >= 2);
        let issues = adapter.validate(&serde_json::json!({
            "floodCount": 2,
            "maxLinks": 0,
            "capsPercent": 101,
            "capsMinLetters": 1,
            "deleteMessage": "yes",
            "ignoredChannels": [""],
            "logChannel": "not-a-discord-id",
            "warningDelivery": "nowhere",
            "alertOnly": "true"
        }));
        assert!(issues.iter().any(|issue| issue.path == "floodCount"));
        assert!(issues.iter().any(|issue| issue.path == "maxLinks"));
        assert!(issues.iter().any(|issue| issue.path == "capsPercent"));
        assert!(issues.iter().any(|issue| issue.path == "capsMinLetters"));
        assert!(issues.iter().any(|issue| issue.path == "deleteMessage"));
        assert!(issues.iter().any(|issue| issue.path == "ignoredChannels"));
        assert!(issues.iter().any(|issue| issue.path == "logChannel"));
        assert!(issues.iter().any(|issue| issue.path == "warningDelivery"));
        assert!(issues.iter().any(|issue| issue.path == "alertOnly"));
        let projection = adapter.runtime_projection(&serde_json::json!({
            "floodCount": 8,
            "maxLinks": 4,
            "capsPercent": 70,
            "capsMinLetters": 10,
            "deleteMessage": true,
            "warningDelivery": "dm",
            "ignoredChannels": ["123"],
            "alertOnly": true
        }));
        assert!(projection.contains(&("security.antispam.flood_count".into(), "8".into())));
        assert!(projection.contains(&("security.antispam.max_links".into(), "4".into())));
        assert!(projection.contains(&("security.antispam.caps_percent".into(), "70".into())));
        assert!(projection.contains(&("security.antispam.caps_min_letters".into(), "10".into())));
        assert!(projection.contains(&("security.antispam.delete_message".into(), "true".into())));
        assert!(projection.contains(&("security.antispam.warning_delivery".into(), "dm".into())));
        assert!(projection.contains(&("security.antispam.ignored_channels".into(), "123".into())));
        assert!(projection.contains(&("security.antispam.alert_only".into(), "true".into())));
        assert!(feature_adapter("community.levels").is_some());
    }

    #[test]
    fn anti_spam_adapter_preview_uses_camel_and_snake_case_fixtures() {
        let adapter = feature_adapter("protection.antispam").expect("adapter registered");
        let config = serde_json::json!({
            "floodCount": 4,
            "duplicateLimit": 2,
            "mentionLimit": 3,
            "timeoutSeconds": 90,
            "logChannel": "987654321098765432"
        });
        for fixture in [
            serde_json::json!({
                "channelId": "general",
                "roleIds": [],
                "messageCount": 4,
                "duplicateCount": 2,
                "mentionCount": 3
            }),
            serde_json::json!({
                "channel_id": "general",
                "role_ids": [],
                "message_count": 4,
                "duplicate_count": 2,
                "mention_count": 3
            }),
        ] {
            let effects = adapter.simulate(&config, &fixture);
            assert!(effects[0].contains("90 second timeout"));
            assert!(effects.iter().any(|effect| effect.contains("log channel")));
            assert!(
                effects
                    .iter()
                    .any(|effect| effect.contains("security.antispam.flood_count=4"))
            );
        }
    }

    #[test]
    fn protection_adapters_preview_the_same_policies_as_the_gateway() {
        let scam = feature_adapter("protection.antiscam").unwrap();
        let scam_effects = scam.simulate(
            &serde_json::json!({"blockedKeywords": ["free nitro"], "timeoutSeconds": 120}),
            &serde_json::json!({"channel_id": "general", "content": "free nitro"}),
        );
        assert!(scam_effects[0].contains("timeout: 120s"));

        let raid = feature_adapter("protection.anti_raid").unwrap();
        let raid_effects = raid.simulate(
            &serde_json::json!({"joinThreshold": 4, "windowSeconds": 12, "alertOnly": true}),
            &serde_json::json!({"join_count": 4}),
        );
        assert!(raid_effects[0].contains("Monitor the burst"));
        assert!(raid_effects[0].contains("4/4 joins in 12s"));

        let gate = feature_adapter("protection.join_gate").unwrap();
        let gate_effects = gate.simulate(
            &serde_json::json!({"minimumAccountDays": 7, "requireAvatar": true, "blockedNamePatterns": ["raid"]}),
            &serde_json::json!({"account_age_days": 1, "has_avatar": false, "display_name": "raid account"}),
        );
        assert!(gate_effects[0].contains("join-gate action"));

        let starboard = feature_adapter("community.starboard").unwrap();
        let starboard_effects = starboard.simulate(
            &serde_json::json!({"threshold": 5}),
            &serde_json::json!({"reaction_count": 3}),
        );
        assert!(starboard_effects[0].contains("below the board threshold (3/5"));

        let suggestions = feature_adapter("community.suggestions").unwrap();
        let suggestion_preview = suggestions.simulate(
            &serde_json::json!({
                "voteMode": "up_only",
                "cooldownHours": 12,
                "staffChannel": "456"
            }),
            &serde_json::json!({}),
        );
        assert!(suggestion_preview[0].contains("up_only voting"));
        assert!(suggestion_preview[0].contains("12-hour member cooldown"));
        assert!(suggestion_preview[0].contains("<#456>"));
        assert!(
            suggestions.descriptor().schema["sections"][1]["fields"]
                .as_array()
                .is_some_and(|fields| fields.iter().any(|field| field["key"] == "staffChannel"))
        );
        assert!(
            suggestions
                .validate(&serde_json::json!({"voteMode": "poll", "cooldownHours": 721}))
                .iter()
                .any(|issue| issue.path == "voteMode")
        );
        assert!(
            suggestions
                .runtime_projection(&serde_json::json!({
                    "channel": "123",
                    "voteMode": "up_only",
                    "cooldownHours": 12,
                    "staffChannel": "456"
                }))
                .contains(&("community.suggestions.vote_mode".into(), "up_only".into()))
        );

        let polls = feature_adapter("management.polls").expect("polls adapter");
        let poll_preview = polls.simulate(
            &serde_json::json!({"defaultDurationHours": 12, "channel": "789"}),
            &serde_json::json!({
                "question": "Where should we meet?",
                "options": ["Lobby", "Garden"],
                "durationMs": 3_600_000
            }),
        );
        assert!(poll_preview[0].contains("Publish poll"));
        assert!(poll_preview[0].contains("1 hour"));
        let rejected = polls.simulate(
            &serde_json::json!({"defaultDurationHours": 12}),
            &serde_json::json!({
                "question": "Only one choice",
                "options": ["Lobby"]
            }),
        );
        assert!(rejected[0].contains("options_required"));
        for duration in [0, 10_000, 168 * 3_600_000 + 1, i64::MAX] {
            let decision = evaluate_poll(
                &serde_json::json!({}),
                "Question",
                &["Yes".into(), "No".into()],
                Some(duration),
                "123",
            );
            assert!(!decision.allowed);
            assert_eq!(decision.reason_code, "invalid_duration");
        }
        for duration in [60_000, 168 * 3_600_000] {
            let decision = evaluate_poll(
                &serde_json::json!({}),
                "Question",
                &["Yes".into(), "No".into()],
                Some(duration),
                "123",
            );
            assert!(decision.allowed);
            assert_eq!(decision.duration_ms, duration);
        }

        let giveaways = feature_adapter("community.giveaways").expect("giveaways adapter");
        let giveaway_preview = giveaways.simulate(
            &serde_json::json!({"defaultDurationHours": 24, "defaultWinners": 2}),
            &serde_json::json!({
                "prize": "Community bundle",
                "winners": 3,
                "durationMs": 7_200_000,
                "requiredRole": "456"
            }),
        );
        assert!(giveaway_preview[0].contains("Create giveaway"));
        assert!(giveaway_preview[0].contains("3 winner(s)"));
        let rejected = giveaways.simulate(
            &serde_json::json!({"defaultDurationHours": 24}),
            &serde_json::json!({"prize": "No role", "requiredRole": "not-a-role"}),
        );
        assert!(rejected[0].contains("invalid_required_role"));
        let invalid_duration = evaluate_giveaway(
            &serde_json::json!({"defaultDurationHours": 24}),
            "Prize",
            None,
            Some(10_000),
            None,
        );
        assert!(!invalid_duration.allowed);
        assert_eq!(invalid_duration.reason_code, "invalid_duration");
        assert_eq!(invalid_duration.duration_ms, 0);

        let events = feature_adapter("community.events").expect("events adapter");
        let event_preview = events.simulate(
            &serde_json::json!({
                "defaultCapacity": 50,
                "announcementChannel": "789",
                "reminders": true,
                "reminderHours": 2
            }),
            &serde_json::json!({
                "name": "Community meetup",
                "location": "Main stage",
                "nowUnix": 1_700_000_000,
                "startUnix": 1_700_003_600,
                "endUnix": 1_700_010_800
            }),
        );
        assert!(event_preview[0].contains("Create native Discord event"));
        assert!(event_preview[0].contains("capacity 50"));
        assert!(event_preview[0].contains("2-hour reminder"));
        let rejected = events.simulate(
            &serde_json::json!({"announcementChannel": "not-a-channel"}),
            &serde_json::json!({
                "name": "Community meetup",
                "location": "Main stage",
                "nowUnix": 1_700_000_000,
                "startUnix": 1_700_003_600,
                "endUnix": 1_700_010_800
            }),
        );
        assert!(rejected[0].contains("invalid_announcement_channel"));

        let tickets = feature_adapter("support.tickets").expect("tickets adapter");
        let available = tickets.simulate(
            &serde_json::json!({"maxOpen": 2, "categoryId": "123"}),
            &serde_json::json!({"openTickets": 1}),
        );
        assert!(available[0].contains("Create a private ticket channel"));
        assert!(
            available
                .iter()
                .any(|effect| effect.contains("support.ticket.max_open"))
        );
        let full = tickets.simulate(
            &serde_json::json!({"maxOpen": 2}),
            &serde_json::json!({"openTickets": 2}),
        );
        assert!(full[0].contains("max_open_reached"));
    }

    #[test]
    fn existing_discord_modules_have_runtime_owned_panel_contracts() {
        let tickets = feature_adapter("support.tickets").expect("tickets adapter registered");
        assert_eq!(tickets.descriptor().source, "tickets_adapter_v1");
        let descriptor = tickets.descriptor();
        assert!(
            descriptor.schema["sections"][0]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["key"] == "panelChannel" && field["kind"] == "channel")
        );
        assert!(
            tickets
                .validate(&serde_json::json!({"panelChannel":"not-an-id"}))
                .iter()
                .any(|issue| issue.path == "panelChannel")
        );
        assert!(
            tickets
                .validate(&serde_json::json!({"panelChannel":"123"}))
                .is_empty()
        );
        let staff_field = descriptor.schema["sections"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["key"] == "staffRole")
            .unwrap();
        assert_eq!(staff_field["label"], "Staff role to notify");
        assert!(staff_field["help"].as_str().unwrap().contains("@mentions"));
        assert!(
            tickets
                .validate(&serde_json::json!({"closeAfterHours": 0}))
                .iter()
                .any(|issue| issue.path == "closeAfterHours")
        );
        assert!(
            tickets
                .runtime_projection(&serde_json::json!({
                    "categoryId": "789",
                    "staffRole": "123",
                    "transcriptChannel": "456",
                    "maxOpen": 3,
                    "panelTitle": "Support",
                    "panelDescription": "Open a ticket.",
                    "closeAfterHours": 2
                }))
                .contains(&("support.ticket.category_id".into(), "789".into()))
        );
        assert!(
            tickets
                .runtime_projection(&serde_json::json!({
                    "categoryId": "789",
                    "staffRole": "123",
                    "transcriptChannel": "456",
                    "maxOpen": 3,
                    "panelTitle": "Support",
                    "panelDescription": "Open a ticket.",
                    "closeAfterHours": 2
                }))
                .contains(&("support.ticket.sla_ms".into(), "7200000".into()))
        );
        assert!(
            tickets
                .runtime_projection(&serde_json::json!({"maxOpen": 3}))
                .contains(&("support.ticket.max_open".into(), "3".into()))
        );
        assert!(
            tickets
                .runtime_projection(&serde_json::json!({
                    "panelTitle": "Support",
                    "panelDescription": "Open a ticket."
                }))
                .contains(&("support.ticket.panel_title".into(), "Support".into()))
        );

        let welcome = feature_adapter("support.welcome").expect("welcome adapter registered");
        assert_eq!(welcome.descriptor().source, "welcome_adapter_v1");
        assert!(
            welcome
                .runtime_projection(&serde_json::json!({
                    "channel": "123",
                    "message": "Welcome {member}",
                    "sendDm": true,
                    "dmMessage": "Hello {member}",
                    "autoRole": "456",
                    "templateId": "welcome-1"
                }))
                .contains(&("support.welcome.send_dm".into(), "true".into()))
        );
        assert!(
            welcome
                .runtime_projection(&serde_json::json!({"templateId": "welcome-1"}))
                .contains(&("support.welcome.template_id".into(), "welcome-1".into()))
        );

        for key in [
            "community.suggestions",
            "community.giveaways",
            "management.polls",
            "community.events",
            "community.role_panels",
        ] {
            let adapter = feature_adapter(key).expect("community adapter registered");
            assert!(
                adapter.descriptor().schema["sections"][0]["fields"]
                    .as_array()
                    .is_some_and(|fields| !fields.is_empty())
            );
            assert!(adapter.validate(&serde_json::json!({})).is_empty());
        }
        let events = feature_adapter("community.events").expect("events adapter");
        assert_eq!(events.descriptor().defaults["defaultDurationHours"], 2);
        assert_eq!(events.descriptor().defaults["reminderHours"], 1);
        let event_projection = events.runtime_projection(&serde_json::json!({
            "defaultDurationHours": 4,
            "defaultCapacity": 25,
            "announcementChannel": "123",
            "reminders": true,
            "reminderHours": 2
        }));
        assert!(
            event_projection
                .contains(&("community.events.default_duration_hours".into(), "4".into()))
        );
        assert!(event_projection.contains(&("community.events.reminder_hours".into(), "2".into())));

        let temp = feature_adapter("utility.temp_channels").expect("temporary channels adapter");
        assert_eq!(temp.descriptor().source, "temp_channels_adapter_v2");
        assert!(
            temp.validate(&serde_json::json!({"maxActive": 0}))
                .iter()
                .any(|issue| issue.path == "maxActive")
        );
        assert!(temp
            .runtime_projection(&serde_json::json!({"categoryId": "123", "nameTemplate": "Room {user}", "maxActive": 4}))
            .contains(&("utility.temp_channels.max_active".into(), "4".into())));

        for key in [
            "social.youtube",
            "social.rss",
            "social.podcasts",
            "social.twitch",
        ] {
            let adapter = feature_adapter(key).expect("official provider adapter registered");
            assert!(adapter.descriptor().dependencies.len() >= 2);
        }
        let rss = feature_adapter("social.rss").expect("rss adapter");
        let feed_projection = rss.runtime_projection(&serde_json::json!({
            "feedUrl": "https://example.com/feed.xml",
            "targetChannelId": "123",
            "intervalSeconds": 600,
            "messageTemplate": "New: {title}",
            "mention": ""
        }));
        assert!(feed_projection.contains(&("social.feed.target_channel_id".into(), "123".into())));
        assert!(feed_projection.contains(&("social.feed.interval_seconds".into(), "600".into())));

        let youtube = feature_adapter("social.youtube").expect("youtube adapter");
        let youtube_descriptor = youtube.descriptor();
        let youtube_fields = youtube_descriptor.schema["sections"][0]["fields"]
            .as_array()
            .expect("youtube schema fields");
        assert!(
            youtube_fields
                .iter()
                .any(|field| field["key"] == "sourceChannelId")
        );
        assert!(
            youtube_fields
                .iter()
                .any(|field| field["key"] == "targetChannelId")
        );
        assert!(
            youtube
                .validate(&serde_json::json!({}))
                .iter()
                .any(|issue| issue.path == "sourceChannelId")
        );
        assert!(
            youtube
                .validate(&serde_json::json!({
                    "sourceChannelId": "UC123",
                    "targetChannelId": "123456789012345678",
                    "intervalSeconds": 900,
                    "messageTemplate": "New video: {title}"
                }))
                .is_empty()
        );

        let twitch = feature_adapter("social.twitch").expect("twitch adapter");
        let twitch_descriptor = twitch.descriptor();
        let twitch_fields = twitch_descriptor.schema["sections"][0]["fields"]
            .as_array()
            .expect("twitch schema fields");
        assert!(
            twitch_fields
                .iter()
                .any(|field| field["key"] == "sourceLogin")
        );
        assert!(
            twitch
                .runtime_projection(&serde_json::json!({
                    "sourceLogin": "vozen",
                    "targetChannelId": "987654321098765432",
                    "intervalSeconds": 1800
                }))
                .contains(&("social_twitch.sourceLogin".into(), "vozen".into()))
        );
    }

    #[test]
    fn custom_commands_audit_and_templates_have_real_contracts() {
        let custom = feature_adapter("management.custom_commands").expect("custom command adapter");
        assert_eq!(custom.descriptor().defaults["triggerPrefix"], "!");
        assert_eq!(custom.descriptor().defaults["maxTags"], 100);
        assert!(
            custom
                .validate(&serde_json::json!({"maxTags": 0}))
                .iter()
                .any(|issue| issue.path == "maxTags")
        );
        assert!(
            custom
                .validate(&serde_json::json!({"triggerPrefix": " @"}))
                .iter()
                .any(|issue| issue.path == "triggerPrefix")
        );
        assert!(
            custom
                .validate(&serde_json::json!({"ignoredChannels": ["not-a-channel"]}))
                .iter()
                .any(|issue| issue.path == "ignoredChannels")
        );
        assert!(
            custom
                .runtime_projection(&serde_json::json!({
                    "triggerPrefix": "?",
                    "ignoredChannels": ["123", "456"],
                    "staffOnly": true,
                    "maxTags": 12,
                    "maxResponseLength": 700
                }))
                .contains(&("management.custom_commands.max_tags".into(), "12".into()))
        );
        let projection = custom.runtime_projection(&serde_json::json!({
            "triggerPrefix": "?",
            "ignoredChannels": ["123", "456"],
            "staffOnly": true
        }));
        assert!(projection.contains(&(
            "management.custom_commands.trigger_prefix".into(),
            "?".into()
        )));
        assert!(projection.contains(&(
            "management.custom_commands.ignored_channels".into(),
            "123,456".into()
        )));
        assert!(projection.contains(&(
            "management.custom_commands.staff_only".into(),
            "true".into()
        )));
        let decision = evaluate_custom_command(
            &serde_json::json!({
                "triggerPrefix": "!",
                "staffOnly": true,
                "maxResponseLength": 80
            }),
            "!rules read this",
            "123",
            true,
            Some("Hello {user}: {args} @everyone"),
            "42",
            "Preview server",
        );
        assert!(decision.allowed);
        assert_eq!(decision.command_name, "rules");
        assert!(decision.response.contains("<@42>"));
        assert!(decision.response.contains("@\u{200b}everyone"));
        let preview = custom.simulate(
            &serde_json::json!({"triggerPrefix":"!", "maxResponseLength":80}),
            &serde_json::json!({
                "content":"!rules read this",
                "channelId":"123",
                "actorIsStaff":true,
                "tagContent":"Hello {user}: {args}",
                "userId":"42"
            }),
        );
        assert!(preview[0].contains("Send custom command `rules`"));

        let audit = feature_adapter("management.audit").expect("audit adapter");
        assert_eq!(audit.descriptor().defaults["threshold"], 3);
        assert_eq!(audit.descriptor().defaults["incidentMinutes"], 10);
        let audit_projection = audit.runtime_projection(&serde_json::json!({
            "threshold": 5,
            "windowSeconds": 20,
            "incidentMinutes": 15,
            "shadowMode": true,
            "logChannel": "123",
            "includeContent": true
        }));
        assert!(audit_projection.contains(&("security.anti_nuke.actions".into(), "5".into())));
        assert!(
            audit_projection.contains(&("security.anti_nuke.incident_minutes".into(), "15".into()))
        );
        assert!(audit_projection.contains(&("security.shadow_mode".into(), "true".into())));
        assert!(audit_projection.contains(&("management.audit.log_channel".into(), "123".into())));
        assert!(
            audit_projection.contains(&("management.audit.include_content".into(), "true".into()))
        );
        assert!(
            audit
                .validate(&serde_json::json!({"logChannel": "not-a-channel"}))
                .iter()
                .any(|issue| issue.path == "logChannel")
        );
        assert!(
            audit
                .validate(&serde_json::json!({"incidentMinutes": 0}))
                .iter()
                .any(|issue| issue.path == "incidentMinutes")
        );
        let shadow_preview = audit.simulate(
            &serde_json::json!({
                "threshold": 3,
                "windowSeconds": 10,
                "shadowMode": true,
                "logChannel": "789",
                "includeContent": false
            }),
            &serde_json::json!({"destructiveActions": 3}),
        );
        assert!(shadow_preview[0].contains("Alert only"));
        assert!(
            shadow_preview
                .iter()
                .any(|effect| effect.contains("<#789>"))
        );
        assert!(
            shadow_preview
                .iter()
                .any(|effect| effect.contains("metadata-only"))
        );
        let invalid_preview = audit.simulate(
            &serde_json::json!({"logChannel": "not-a-channel"}),
            &serde_json::json!({"destructiveActions": 3}),
        );
        assert!(invalid_preview[0].contains("invalid_log_channel"));

        let templates = feature_adapter("management.templates").expect("templates adapter");
        assert!(templates.validate(&serde_json::json!({})).is_empty());
        assert_eq!(
            feature_maturity("management.templates"),
            FeatureMaturity::Operational
        );
        let preview = templates.simulate(
            &serde_json::json!({}),
            &serde_json::json!({
                "slot": "welcome",
                "fallback": "Fallback",
                "template": {"config": {"content": "Hello @everyone"}}
            }),
        );
        assert!(
            preview
                .iter()
                .any(|effect| effect.contains("Hello @\u{200b}everyone"))
        );
        let rejected = templates.simulate(
            &serde_json::json!({}),
            &serde_json::json!({
                "slot": "welcome",
                "fallback": "Fallback",
                "template": {"config": {"content": "\u{0000}"}}
            }),
        );
        assert!(
            rejected
                .iter()
                .any(|effect| effect.contains("fallback will be used"))
        );

        let birthdays = feature_adapter("community.birthdays").expect("birthdays adapter");
        assert!(
            birthdays
                .runtime_projection(&serde_json::json!({"channel":"123", "message":"Happy {user}"}))
                .contains(&("community.birthdays.channel_id".into(), "123".into()))
        );
        assert!(
            birthdays
                .runtime_projection(&serde_json::json!({"timezone":"UTC+01:00"}))
                .contains(&("community.birthdays.timezone".into(), "UTC+01:00".into()))
        );
        assert!(
            birthdays
                .validate(&serde_json::json!({"message": ""}))
                .iter()
                .any(|issue| issue.path == "message")
        );
        assert!(
            birthdays
                .validate(&serde_json::json!({"timezone": "Europe/Lisbon"}))
                .iter()
                .any(|issue| issue.code == "invalid_timezone")
        );
        assert_eq!(birthdays.descriptor().defaults["timezone"], "UTC");
        assert_eq!(
            feature_maturity("community.birthdays"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn nickname_adapter_owns_schema_validation_and_projection() {
        let adapter = feature_adapter("management.nickname").expect("adapter registered");
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.source, "nickname_adapter_v1");
        assert_eq!(descriptor.defaults["nickname"], "");
        assert!(
            adapter
                .validate(&serde_json::json!({"nickname": "A\u{0007}"}))
                .iter()
                .any(|issue| issue.code == "invalid_nickname")
        );
        assert_eq!(
            adapter.runtime_projection(&serde_json::json!({"nickname": "Vozen Helper"})),
            vec![("identity.nickname".into(), "Vozen Helper".into())]
        );
        assert_eq!(
            feature_maturity("management.nickname"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn adapters_declare_permissions_required_by_their_discord_mutations() {
        let expectations = [
            ("management.audit", "view_audit_log"),
            ("support.welcome", "manage_roles"),
            ("insights.stats", "manage_channels"),
        ];
        for (key, dependency) in expectations {
            let descriptor = feature_adapter(key)
                .expect("adapter registered")
                .descriptor();
            assert!(
                descriptor
                    .dependencies
                    .iter()
                    .any(|value| value == dependency),
                "{key} must declare {dependency}"
            );
        }
    }

    #[test]
    fn reminder_adapter_projects_real_runtime_limits() {
        let adapter = feature_adapter("utility.reminders").expect("adapter registered");
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.source, "reminders_adapter_v1");
        assert_eq!(descriptor.defaults["maxDelayHours"], 168);
        assert_eq!(descriptor.defaults["timezone"], "UTC");
        assert!(adapter
            .validate(&serde_json::json!({"maxDelayHours": 0, "maxTextLength": 500, "notifyUser": true}))
            .iter()
            .any(|issue| issue.path == "maxDelayHours"));
        assert!(
            adapter
                .validate(&serde_json::json!({"timezone": "Europe/Lisbon"}))
                .iter()
                .any(|issue| issue.code == "invalid_timezone")
        );
        let projection = adapter.runtime_projection(&serde_json::json!({
            "maxDelayHours": 24,
            "maxTextLength": 240,
            "timezone": "UTC+01:00",
            "notifyUser": false,
            "allowRecurring": true,
            "maxRecurrences": 6
        }));
        assert!(projection.contains(&("utility.reminders.max_delay_hours".into(), "24".into())));
        assert!(projection.contains(&("utility.reminders.max_text_length".into(), "240".into())));
        assert!(projection.contains(&("utility.reminders.timezone".into(), "UTC+01:00".into())));
        assert!(projection.contains(&("utility.reminders.notify_user".into(), "false".into())));
        assert!(projection.contains(&("utility.reminders.allow_recurring".into(), "true".into())));
        assert!(projection.contains(&("utility.reminders.max_recurrences".into(), "6".into())));
        assert_eq!(
            feature_maturity("utility.reminders"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn reminder_timezones_are_bounded_fixed_offsets() {
        assert_eq!(parse_utc_offset_minutes("UTC"), Some(0));
        assert_eq!(parse_utc_offset_minutes("UTC+05:30"), Some(330));
        assert_eq!(parse_utc_offset_minutes("GMT-05"), Some(-300));
        assert_eq!(parse_utc_offset_minutes("UTC+14:30"), None);
        assert_eq!(parse_utc_offset_minutes("Europe/Lisbon"), None);
    }

    #[test]
    fn leaderboard_and_workflow_adapters_project_runtime_limits() {
        let leaderboard = feature_adapter("community.leaderboard").expect("leaderboard adapter");
        assert_eq!(leaderboard.descriptor().source, "leaderboard_adapter_v1");
        assert!(
            leaderboard
                .validate(&serde_json::json!({"maxEntries": 101, "public": true}))
                .iter()
                .any(|issue| issue.path == "maxEntries")
        );
        assert!(
            leaderboard
                .runtime_projection(&serde_json::json!({"maxEntries": 25, "public": false}))
                .contains(&("community.leaderboard.max_entries".into(), "25".into()))
        );
        assert_eq!(
            feature_maturity("community.leaderboard"),
            FeatureMaturity::Operational
        );

        let workflows = feature_adapter("management.workflows").expect("workflow adapter");
        assert_eq!(workflows.descriptor().source, "workflows_adapter_v1");
        assert!(workflows
            .validate(&serde_json::json!({"maxWorkflows": 10, "maxReplyLength": 0, "allowMentions": false}))
            .iter()
            .any(|issue| issue.path == "maxReplyLength"));
        assert!(
            workflows
                .runtime_projection(&serde_json::json!({
                    "maxWorkflows": 20,
                    "maxReplyLength": 750,
                    "allowMentions": true
                }))
                .contains(&("management.workflows.allow_mentions".into(), "true".into()))
        );
        assert_eq!(
            feature_maturity("management.workflows"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn moderation_adapter_projects_guardrails_used_by_commands() {
        let adapter = feature_adapter("management.moderation").expect("moderation adapter");
        assert_eq!(adapter.descriptor().source, "moderation_adapter_v1");
        assert!(
            adapter
                .validate(&serde_json::json!({"requireReason": true, "maxPurge": 0}))
                .iter()
                .any(|issue| issue.path == "maxPurge")
        );
        let projection = adapter.runtime_projection(&serde_json::json!({
            "requireReason": false,
            "maxPurge": 42
        }));
        assert!(projection.contains(&(
            "management.moderation.require_reason".into(),
            "false".into()
        )));
        assert!(projection.contains(&("management.moderation.max_purge".into(), "42".into())));
        assert_eq!(
            feature_maturity("management.moderation"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn moderation_evaluator_requires_reasons_and_clamps_purge() {
        let policy = ModerationPolicy {
            require_reason: true,
            max_purge: 12,
        };
        let missing_reason = evaluate_moderation(
            &policy,
            &ModerationObservation {
                action: "ban".into(),
                reason: " ".into(),
                requested_count: None,
            },
        );
        assert!(!missing_reason.allowed);
        assert_eq!(missing_reason.reason_code, "reason_required");

        let purge = evaluate_moderation(
            &policy,
            &ModerationObservation {
                action: "purge".into(),
                reason: String::new(),
                requested_count: Some(50),
            },
        );
        assert!(purge.allowed);
        assert_eq!(purge.effective_count, Some(12));
        assert_eq!(purge.reason_code, "count_clamped");
    }

    #[test]
    fn moderation_adapter_simulation_uses_runtime_evaluator() {
        let adapter = feature_adapter("management.moderation").expect("moderation adapter");
        let blocked = adapter.simulate(
            &serde_json::json!({"requireReason": true, "maxPurge": 12}),
            &serde_json::json!({"action": "ban", "reason": ""}),
        );
        assert!(
            blocked
                .iter()
                .any(|effect| effect.contains("reason_required"))
        );

        let clamped = adapter.simulate(
            &serde_json::json!({"requireReason": true, "maxPurge": 12}),
            &serde_json::json!({"action": "purge", "requestedCount": 50}),
        );
        assert!(
            clamped
                .iter()
                .any(|effect| effect.contains("effective limit of 12"))
        );
        assert!(
            clamped
                .iter()
                .any(|effect| effect.contains("count_clamped"))
        );
    }

    #[test]
    fn welcome_renderer_bounds_templates_and_mentions() {
        let rendered =
            render_member_message("Hello {member} in {server}: @everyone", "<@42>", "Vozen");
        assert_eq!(rendered, "Hello <@42> in Vozen: @\u{200b}everyone");
        assert!(
            render_member_message(&"x".repeat(2_500), "m", "s")
                .chars()
                .count()
                <= 2_000
        );
    }

    #[test]
    fn welcome_adapter_simulation_uses_rendered_runtime_message() {
        let adapter = feature_adapter("support.welcome").expect("welcome adapter");
        let effects = adapter.simulate(
            &serde_json::json!({
                "message": "Welcome {member} to {server}! @everyone",
                "sendDm": true,
                "dmMessage": "Read the rules, {member}.",
                "delaySeconds": 5,
                "autoRole": "123"
            }),
            &serde_json::json!({"member": "<@42>", "server": "Vozen"}),
        );
        assert!(
            effects
                .iter()
                .any(|effect| effect.contains("@\u{200b}everyone"))
        );
        assert!(
            effects
                .iter()
                .any(|effect| effect.contains("after 5 second(s)"))
        );
        assert!(
            effects
                .iter()
                .any(|effect| effect.contains("automatic role `123`"))
        );
    }

    #[test]
    fn scam_policy_is_bounded_and_explainable() {
        let adapter = feature_adapter("protection.antiscam").expect("anti-scam adapter");
        assert_eq!(adapter.descriptor().source, "anti_scam_adapter_v1");
        assert_eq!(
            adapter.descriptor().dependencies,
            vec!["message_content_intent"]
        );
        assert!(
            adapter
                .validate(&serde_json::json!({"blockedDomains": ["bad/domain"]}))
                .iter()
                .any(|issue| issue.path == "blockedDomains")
        );
        assert!(
            adapter
                .validate(&serde_json::json!({"ignoredRoles": ["staff"]}))
                .iter()
                .any(|issue| issue.path == "ignoredRoles")
        );
        let policy = scam_policy_from_json(&serde_json::json!({
            "blockInvites": true,
            "blockedDomains": ["example.invalid"],
            "blockedKeywords": ["free coins"],
            "ignoredRoles": ["777"],
            "timeoutSeconds": 60
        }));
        let decision = evaluate_scam(
            &policy,
            "123",
            "Claim your free coins at https://example.invalid now",
        );
        assert!(decision.should_act);
        assert!(
            decision
                .matched
                .iter()
                .any(|value| value.starts_with("domain:"))
        );
        assert_eq!(decision.timeout_seconds, 60);
        assert!(evaluate_scam(&policy, "123", "https://discord.gg/example").should_act);
        assert!(
            evaluate_scam(&policy, "123", "https://example.invalid.evil.test/landing")
                .matched
                .iter()
                .all(|value| !value.starts_with("domain:"))
        );
        assert!(
            evaluate_scam_with_roles(&policy, "123", &["777".into()], "https://example.invalid")
                .ignored
        );
        assert!(evaluate_scam(&policy, "123", "hello").matched.is_empty());
    }

    #[test]
    fn scam_policy_separates_alert_timeout_and_message_deletion() {
        let policy = ScamPolicy {
            timeout_seconds: 90,
            delete_message: false,
            ..ScamPolicy::default()
        };
        let decision = evaluate_scam(&policy, "123", "Claim your free nitro now");
        assert!(decision.should_act);
        assert!(!decision.should_delete);
        assert_eq!(decision.timeout_seconds, 90);

        let deleting = ScamPolicy {
            delete_message: true,
            ..policy.clone()
        };
        assert!(evaluate_scam(&deleting, "123", "Claim your free nitro now").should_delete);

        let monitor_only = ScamPolicy {
            alert_only: true,
            ..deleting
        };
        let monitor_decision = evaluate_scam(&monitor_only, "123", "Claim your free nitro now");
        assert!(!monitor_decision.should_act);
        assert!(!monitor_decision.should_delete);
        assert_eq!(monitor_decision.timeout_seconds, 0);
    }

    #[test]
    fn welcome_channel_adapter_projects_a_real_member_join_message() {
        let adapter = feature_adapter("support.welcome_channel").expect("welcome adapter");
        assert_eq!(adapter.descriptor().source, "welcome_channel_adapter_v1");
        assert!(
            adapter
                .validate(&serde_json::json!({"channelId": "not-an-id", "message": "Hi"}))
                .iter()
                .any(|issue| issue.path == "channelId")
        );
        assert!(
            adapter
                .runtime_projection(&serde_json::json!({
                    "channelId": "123",
                    "message": "Welcome {member}!"
                }))
                .contains(&("support.welcome_channel.channel_id".into(), "123".into()))
        );
        assert_eq!(
            feature_maturity("support.welcome_channel"),
            FeatureMaturity::Operational
        );
        assert!(
            adapter
                .validate(&serde_json::json!({
                    "channelId": "123",
                    "message": "Hi",
                    "steps": ["rules", "rules"]
                }))
                .iter()
                .any(|issue| issue.path == "steps")
        );
        let projection = adapter.runtime_projection(&serde_json::json!({
            "channelId": "123",
            "message": "Hi",
            "steps": ["rules", "help"],
            "rulesChannel": "456"
        }));
        assert!(
            projection.contains(&("support.welcome_channel.steps".into(), "rules,help".into()))
        );
        assert!(
            projection.contains(&("support.welcome_channel.rules_channel".into(), "456".into()))
        );
        let decision = evaluate_welcome_channel(
            &serde_json::json!({
                "channelId": "123",
                "message": "Welcome {member} to {server}! @everyone",
                "steps": ["rules", "help"]
            }),
            "<@42>",
            "Vozen",
        );
        assert!(decision.allowed);
        assert_eq!(decision.steps, vec!["rules", "help"]);
        assert!(decision.message.contains("@\u{200b}everyone"));
        let preview = adapter.simulate(
            &serde_json::json!({
                "channelId": "123",
                "message": "Welcome {member}!",
                "steps": ["rules"]
            }),
            &serde_json::json!({"memberMention": "<@42>"}),
        );
        assert!(preview[0].contains("step button(s)"));
    }

    #[test]
    fn unified_welcome_guide_is_optional_and_uses_one_public_message() {
        let adapter = feature_adapter("support.welcome").unwrap();
        let mut config = adapter.descriptor().defaults;
        assert_eq!(config["guideEnabled"], false);
        config["guideEnabled"] = serde_json::json!(true);
        assert!(adapter.validate(&config).is_empty());
        let effects = adapter.simulate(&config, &serde_json::json!({}));
        assert_eq!(
            effects
                .iter()
                .filter(|effect| effect.starts_with("Send the welcome message"))
                .count(),
            1
        );
        assert!(effects.iter().any(|effect| effect.contains("same message")));
        config["steps"] = serde_json::json!(["rules", "rules"]);
        assert!(
            adapter
                .validate(&config)
                .iter()
                .any(|issue| issue.path == "steps")
        );
        config["guideEnabled"] = serde_json::json!("yes");
        assert!(
            adapter
                .validate(&config)
                .iter()
                .any(|issue| issue.path == "guideEnabled")
        );
    }

    #[test]
    fn birthdays_adapter_preview_uses_the_scheduled_delivery_evaluator() {
        let adapter = feature_adapter("community.birthdays").expect("birthdays adapter");
        let config = serde_json::json!({
            "channel": "123",
            "message": "Happy birthday, {user}!",
            "timezone": "UTC+01:00"
        });
        assert_eq!(adapter.descriptor().source, "birthdays_adapter_v1");
        let preview = adapter.simulate(
            &config,
            &serde_json::json!({"memberId": "42", "month": 2, "day": 29}),
        );
        assert!(preview[0].contains("Announce birthday in <#123> using UTC+01:00"));
        assert!(preview[0].contains("<@42>"));
        assert!(preview.iter().any(|effect| effect.contains("channel_id")));

        let invalid = adapter.simulate(
            &config,
            &serde_json::json!({"memberId": "42", "month": 2, "day": 31}),
        );
        assert!(invalid[0].contains("invalid_date"));
        assert!(evaluate_birthday(&config, "42", 2, 29).allowed);
        assert!(!evaluate_birthday(&config, "42", 2, 31).allowed);
    }

    #[test]
    fn level_banners_are_mandatory_even_for_legacy_disabled_configs() {
        let levels = feature_adapter("community.levels").unwrap();
        let descriptor = levels.descriptor();
        assert_eq!(descriptor.defaults["bannerEnabled"], true);
        assert!(!descriptor.schema.to_string().contains("bannerEnabled"));
        assert!(descriptor.dependencies.contains(&"embed_links".into()));
        for config in [
            serde_json::json!({}),
            serde_json::json!({"bannerEnabled": false}),
            serde_json::json!({"bannerEnabled": true}),
        ] {
            assert!(
                !levels
                    .runtime_projection(&config)
                    .iter()
                    .any(|(key, _)| key == "community.levels.banner_enabled")
            );
        }
    }

    #[test]
    fn levels_and_starboard_adapters_cover_runtime_settings() {
        let levels = feature_adapter("community.levels").expect("levels adapter");
        assert_eq!(levels.descriptor().source, "levels_adapter_v1");
        assert!(
            levels
                .validate(&serde_json::json!({"xpMin": 40, "xpMax": 20}))
                .iter()
                .any(|issue| issue.path == "xpMax")
        );
        assert!(
            levels
                .runtime_projection(&serde_json::json!({"xpMin": 10, "xpMax": 25}))
                .contains(&("community.levels.xp_max".into(), "25".into()))
        );
        assert!(
            levels
                .validate(&serde_json::json!({"voiceXpEnabled": true, "voiceXpPerMinute": 31}))
                .iter()
                .any(|issue| issue.path == "voiceXpPerMinute")
        );
        assert!(
            levels
                .runtime_projection(&serde_json::json!({
                    "voiceXpEnabled": true,
                    "voiceXpPerMinute": 4
                }))
                .contains(&("community.levels.voice_xp_enabled".into(), "true".into()))
        );
        assert!(
            levels
                .runtime_projection(&serde_json::json!({
                    "voiceXpEnabled": true,
                    "voiceXpPerMinute": 4
                }))
                .contains(&("community.levels.voice_xp_per_minute".into(), "4".into()))
        );
        assert!(
            levels
                .validate(&serde_json::json!({"levelRoles": ["5=123"]}))
                .is_empty()
        );
        assert!(
            levels
                .runtime_projection(&serde_json::json!({
                    "ignoredChannels": ["456"],
                    "levelRoles": ["5=123"],
                    "stackRoles": false
                }))
                .contains(&("community.levels.ignored_channels".into(), "456".into()))
        );

        let starboard = feature_adapter("community.starboard").expect("starboard adapter");
        assert_eq!(starboard.descriptor().source, "starboard_adapter_v1");
        assert!(
            starboard
                .validate(&serde_json::json!({"threshold": 0}))
                .iter()
                .any(|issue| issue.path == "threshold")
        );
        assert!(
            starboard
                .runtime_projection(&serde_json::json!({
                    "channel": "123",
                    "threshold": 5,
                    "emoji": "⭐"
                }))
                .contains(&("community.starboard.threshold".into(), "5".into()))
        );
        assert!(
            starboard
                .runtime_projection(&serde_json::json!({"ignoredRoles": ["456"]}))
                .contains(&("community.starboard.ignored_roles".into(), "456".into()))
        );
    }

    #[test]
    fn levels_simulation_and_runtime_evaluator_share_cooldown_voice_and_exclusions() {
        let config = serde_json::json!({
            "xpMin": 10,
            "xpMax": 10,
            "voiceXpEnabled": true,
            "voiceXpPerMinute": 3,
            "ignoredChannels": ["999"]
        });
        let message = evaluate_levels(&config, "message", "123", "message-1", true, 0, 95);
        assert!(message.allowed);
        assert_eq!(message.amount, 10);
        assert_eq!(message.before_level, 1);
        assert_eq!(message.after_level, 2);
        let cooldown = evaluate_levels(&config, "message", "123", "message-2", false, 0, 0);
        assert_eq!(cooldown.reason_code, "cooldown_active");
        let ignored = evaluate_levels(&config, "message", "999", "message-3", true, 0, 0);
        assert_eq!(ignored.reason_code, "channel_ignored");
        let voice = evaluate_levels(&config, "voice", "123", "voice-1", true, 20, 0);
        assert!(voice.allowed);
        assert_eq!(voice.amount, 60);
        let preview = feature_adapter("community.levels")
            .expect("levels adapter")
            .simulate(
                &config,
                &serde_json::json!({
                    "source": "voice",
                    "channelId": "123",
                    "durationMinutes": 20,
                    "currentXp": 0
                }),
            );
        assert!(preview[0].contains("Award 60 XP"));
    }

    #[test]
    fn nickname_simulation_uses_the_same_bounded_mutation_contract() {
        let adapter = feature_adapter("management.nickname").expect("nickname adapter");
        let ready = evaluate_nickname(&serde_json::json!({"nickname": "Vozen Helper"}));
        assert!(ready.allowed);
        assert_eq!(ready.reason_code, "nickname_ready");
        let preview = adapter.simulate(
            &serde_json::json!({"nickname": "Vozen Helper"}),
            &serde_json::json!({}),
        );
        assert!(preview[0].contains("Apply `Vozen Helper`"));
        let invalid = evaluate_nickname(&serde_json::json!({"nickname": "bad\nname"}));
        assert!(!invalid.allowed);
        assert_eq!(invalid.reason_code, "invalid_nickname");
        let clear = evaluate_nickname(&serde_json::json!({"nickname": ""}));
        assert_eq!(clear.reason_code, "restore_default");
    }

    #[test]
    fn join_protection_adapters_project_real_gateway_limits() {
        let raid = feature_adapter("protection.anti_raid").expect("anti-raid adapter");
        assert_eq!(raid.descriptor().source, "anti_raid_adapter_v1");
        assert!(
            raid.runtime_projection(&serde_json::json!({
                "joinThreshold": 20,
                "windowSeconds": 15,
                "incidentMinutes": 30,
                "verification": "very_high",
                "pauseInvites": false,
                "alertOnly": true
            }))
            .contains(&("security.anti_raid.joins".into(), "20".into()))
        );
        assert!(
            raid.runtime_projection(
                &serde_json::json!({"incidentMinutes": 30, "verification": "very_high"})
            )
            .contains(&("security.anti_raid.incident_minutes".into(), "30".into()))
        );
        assert!(
            raid.runtime_projection(
                &serde_json::json!({"incidentMinutes": 30, "verification": "very_high"})
            )
            .contains(&("security.anti_raid.verification".into(), "very_high".into()))
        );
        assert!(
            raid.runtime_projection(&serde_json::json!({"pauseInvites": false}))
                .contains(&("security.anti_raid.pause_invites".into(), "false".into()))
        );
        let gate = feature_adapter("protection.join_gate").expect("join gate adapter");
        assert_eq!(gate.descriptor().source, "join_gate_adapter_v1");
        assert!(
            gate.validate(&serde_json::json!({"minimumAccountDays": 400}))
                .iter()
                .any(|issue| issue.path == "minimumAccountDays")
        );
        assert!(
            gate.validate(&serde_json::json!({"action": "quarantine"}))
                .iter()
                .any(|issue| issue.code == "quarantine_role_required")
        );
        assert!(
            gate.validate(&serde_json::json!({
                "action": "quarantine",
                "verifiedRole": "123",
                "autoRole": "123"
            }))
            .iter()
            .any(|issue| issue.code == "join_gate_roles_must_differ")
        );
        assert!(
            gate.runtime_projection(&serde_json::json!({
                "minimumAccountDays": 7,
                "verifiedRole": "123",
                "requireAvatar": true,
                "action": "quarantine",
                "autoRole": "456",
                "blockedNamePatterns": ["spam"],
                "logChannel": "789"
            }))
            .contains(&("security.join_gate.role_id".into(), "123".into()))
        );
        assert!(gate.runtime_projection(&serde_json::json!({"requireAvatar": true, "action": "alert", "autoRole": "456", "blockedNamePatterns": ["spam"], "logChannel": "789"})).contains(&("security.join_gate.require_avatar".into(), "true".into())));
    }

    #[test]
    fn privacy_stats_and_help_adapters_expose_bounded_runtime_options() {
        let privacy = feature_adapter("management.privacy").expect("privacy adapter");
        assert_eq!(privacy.descriptor().source, "privacy_adapter_v1");
        assert!(privacy
            .validate(&serde_json::json!({"maxExportBytes": 1, "allowMemberExport": true, "allowMemberErase": true}))
            .iter()
            .any(|issue| issue.path == "maxExportBytes"));
        assert!(
            privacy
                .runtime_projection(&serde_json::json!({
                    "maxExportBytes": 500_000,
                    "allowMemberExport": false,
                    "allowMemberErase": true
                }))
                .contains(&(
                    "management.privacy.allow_member_export".into(),
                    "false".into()
                ))
        );

        let stats = feature_adapter("insights.stats").expect("stats adapter");
        assert_eq!(stats.descriptor().source, "stats_adapter_v1");
        assert!(
            stats
                .validate(&serde_json::json!({
                    "windowDays": 31,
                    "public": false,
                    "channelId": "not-a-channel",
                    "intervalMinutes": 2,
                    "nameTemplate": ""
                }))
                .iter()
                .any(|issue| issue.path == "windowDays")
        );
        assert!(stats
            .validate(&serde_json::json!({"channelId": "123", "intervalMinutes": 15, "nameTemplate": "messages-{messages}"}))
            .is_empty());
        assert!(
            stats
                .runtime_projection(&serde_json::json!({
                    "channelId": "123",
                    "intervalMinutes": 30,
                    "nameTemplate": "msgs-{messages}"
                }))
                .contains(&("insights.stats.channel_id".into(), "123".into()))
        );
        assert_eq!(
            feature_maturity("insights.stats"),
            FeatureMaturity::Operational
        );

        let help = feature_adapter("utility.help").expect("help adapter");
        assert_eq!(help.descriptor().source, "help_adapter_v1");
        assert!(
            help.validate(&serde_json::json!({"showModules": "yes", "showDashboard": true}))
                .iter()
                .any(|issue| issue.path == "showModules")
        );
        assert_eq!(
            feature_maturity("utility.help"),
            FeatureMaturity::Operational
        );
    }

    #[test]
    fn achievements_invites_and_emojis_adapters_project_real_command_settings() {
        let achievements = feature_adapter("community.achievements").expect("achievements adapter");
        assert_eq!(achievements.descriptor().source, "achievements_adapter_v2");
        assert!(achievements
            .validate(&serde_json::json!({"firstThreshold": 1000, "regularThreshold": 100, "pillarThreshold": 10000}))
            .iter()
            .any(|issue| issue.code == "ordered_required"));
        assert!(achievements
            .runtime_projection(&serde_json::json!({"firstThreshold": 50, "regularThreshold": 500, "pillarThreshold": 5000}))
            .contains(&("community.achievements.regular_threshold".into(), "500".into())));

        let invites = feature_adapter("management.invite_tracker").expect("invite tracker adapter");
        assert_eq!(invites.descriptor().source, "invite_tracker_adapter_v2");
        assert!(
            invites
                .runtime_projection(&serde_json::json!({"maxEntries": 25, "includeInviter": false}))
                .contains(&(
                    "management.invite_tracker.include_inviter".into(),
                    "false".into()
                ))
        );

        let emojis = feature_adapter("utility.emojis").expect("emojis adapter");
        assert_eq!(emojis.descriptor().source, "emojis_adapter_v2");
        assert!(
            emojis
                .runtime_projection(&serde_json::json!({"maxEntries": 8, "animatedOnly": true}))
                .contains(&("utility.emojis.animated_only".into(), "true".into()))
        );
    }

    #[test]
    fn bounded_search_adapter_rejects_disabled_provider_set() {
        let search = feature_adapter("utility.search").expect("search adapter");
        assert_eq!(search.descriptor().source, "bounded_search_adapter_v1");
        assert!(
            search
                .validate(&serde_json::json!({
                    "maxResults": 5,
                    "allowWikipedia": false,
                    "allowAniList": false,
                    "allowBluesky": false,
                    "allowYouTube": false,
                    "allowTwitch": false
                }))
                .iter()
                .any(|issue| issue.code == "provider_required")
        );
        assert!(
            search
                .runtime_projection(&serde_json::json!({
                    "maxResults": 3,
                    "allowWikipedia": true,
                    "allowAniList": false,
                    "allowBluesky": true
                }))
                .contains(&("utility.search.max_results".into(), "3".into()))
        );
        assert!(
            search
                .runtime_projection(&serde_json::json!({
                    "maxResults": 3,
                    "allowWikipedia": false,
                    "allowAniList": false,
                    "allowBluesky": true
                }))
                .contains(&("utility.search.allow_bluesky".into(), "true".into()))
        );
    }

    #[test]
    fn gas_adapter_keeps_provider_boundary_explicit() {
        let gas = feature_adapter("web3.gas_tracker").expect("gas adapter");
        assert_eq!(gas.descriptor().source, "operator_rpc_gas_v1");
        assert!(
            gas.validate(&serde_json::json!({
                "network": "mainnet",
                "targetChannelId": "123",
                "intervalSeconds": 900
            }))
            .iter()
            .any(|issue| issue.path == "network")
        );
        assert!(
            gas.runtime_projection(&serde_json::json!({
                "network": "ethereum",
                "targetChannelId": "123",
                "intervalSeconds": 600
            }))
            .contains(&("web3.gas_tracker.network".into(), "ethereum".into()))
        );
    }

    #[test]
    fn anti_raid_evaluator_is_shared_and_respects_shadow_mode() {
        let policy = anti_raid_policy_from_json(&serde_json::json!({
            "joinThreshold": 5,
            "windowSeconds": 12,
            "incidentMinutes": 20,
            "alertOnly": false,
            "pauseInvites": true
        }));
        let below = evaluate_anti_raid(&policy, 4, false);
        assert!(!below.armed);
        assert_eq!(below.reason, "join_burst_below_threshold");

        let contained = evaluate_anti_raid(&policy, 5, false);
        assert!(contained.armed);
        assert!(!contained.shadow_mode);
        assert!(contained.should_contain);
        assert_eq!(contained.incident_minutes, 20);

        let shadow = evaluate_anti_raid(&policy, 5, true);
        assert!(shadow.armed);
        assert!(shadow.shadow_mode);
        assert!(!shadow.should_contain);
        assert_eq!(shadow.reason, "join_burst_detected_shadow");

        let alert_only = anti_raid_policy_from_json(&serde_json::json!({
            "joinThreshold": 5,
            "pauseInvites": false
        }));
        let alert = evaluate_anti_raid(&alert_only, 5, false);
        assert!(alert.armed);
        assert!(!alert.shadow_mode);
        assert!(!alert.should_contain);
        assert_eq!(alert.reason, "join_burst_detected_alert");
    }

    #[test]
    fn economy_simulation_uses_the_same_bounded_reward_evaluator() {
        let config = serde_json::json!({
            "currencyName": "coins",
            "dailyReward": 120,
            "workReward": 40,
            "workCooldownMinutes": 30
        });
        let ready = evaluate_economy(&config, "work", 10, true);
        assert!(ready.allowed);
        assert_eq!(ready.amount, 40);
        assert_eq!(ready.cooldown_ms, 1_800_000);
        assert_eq!(ready.resulting_balance, 50);

        let blocked = evaluate_economy(&config, "work", 10, false);
        assert!(!blocked.allowed);
        assert_eq!(blocked.reason_code, "cooldown_active");

        let adapter = feature_adapter("community.economy").expect("economy adapter");
        let effects = adapter.simulate(
            &config,
            &serde_json::json!({
                "economyAction": "work",
                "currentBalance": 10,
                "rewardCooldownReady": true
            }),
        );
        assert!(effects[0].contains("40 coins"));
        assert!(effects[0].contains("50 coins"));
    }

    #[test]
    fn stats_member_counter_uses_live_total_in_preview_and_runtime() {
        let config = serde_json::json!({
            "channelId": "123456789012345678", "nameTemplate": "📊 Members: {members}"
        });
        let decision = evaluate_stats_with_members(&config, None, 20, 4, 2, Some(26));
        assert!(decision.allowed);
        assert_eq!(decision.name, "📊 Members: 26");
        assert!(!evaluate_stats_with_members(&config, None, 20, 4, 2, None).allowed);
        let adapter = feature_adapter("insights.stats").expect("stats adapter");
        assert!(adapter.validate(&config).is_empty());
        assert!(
            adapter.simulate(&config, &serde_json::json!({"statsMembers": 26}))[0]
                .contains("Members: 26")
        );
        assert!(adapter.runtime_projection(&config).contains(&(
            "insights.stats.name_template".into(),
            "📊 Members: {members}".into()
        )));
    }

    #[test]
    fn stats_simulation_uses_the_same_channel_name_evaluator() {
        let config = serde_json::json!({
            "windowDays": 14,
            "channelId": "123456789012345678",
            "nameTemplate": "chat-{messages}-j{joins}-s{leaves}"
        });
        let decision = evaluate_stats(&config, Some("123456789012345678"), 20, 4, 2);
        assert!(decision.allowed);
        assert_eq!(decision.name, "chat-20-j4-s2");

        let adapter = feature_adapter("insights.stats").expect("stats adapter");
        let effects = adapter.simulate(
            &config,
            &serde_json::json!({
                "statsMessages": 20,
                "statsJoins": 4,
                "statsLeaves": 2
            }),
        );
        assert!(effects[0].contains("chat-20-j4-s2"));
        assert!(effects.iter().any(|effect| {
            effect.contains("insights.stats.window_days") && effect.contains("14")
        }));
    }

    #[test]
    fn join_gate_evaluator_explains_all_blocking_reasons() {
        let policy = JoinGatePolicy {
            minimum_account_days: 7,
            require_avatar: true,
            blocked_name_patterns: vec!["free nitro".into()],
            action: "quarantine".into(),
        };
        let decision = evaluate_join_gate(
            &policy,
            &JoinGateObservation {
                account_age_days: 1,
                has_avatar: false,
                display_name: "Free Nitro winner".into(),
            },
        );
        assert!(decision.blocked);
        assert_eq!(decision.action, "quarantine");
        assert_eq!(decision.reasons.len(), 3);

        let allowed = evaluate_join_gate(
            &policy,
            &JoinGateObservation {
                account_age_days: 30,
                has_avatar: true,
                display_name: "Community member".into(),
            },
        );
        assert!(!allowed.blocked);
        assert!(allowed.reasons.is_empty());
    }

    #[test]
    fn starboard_evaluator_matches_threshold_and_exemptions() {
        let policy = starboard_policy_from_json(&serde_json::json!({
            "threshold": 3,
            "allowSelfStar": false,
            "includeImages": false,
            "ignoredChannels": ["999"],
            "ignoredRoles": ["777"]
        }));
        let decision = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: "123".into(),
                author_id: "1".into(),
                reactor_ids: vec!["1".into(), "2".into(), "2".into(), "3".into(), "4".into()],
                author_role_ids: vec![],
                has_attachments: false,
            },
        );
        assert_eq!(decision.count, 3);
        assert!(decision.should_publish);
        assert!(!decision.ignored);

        let ignored = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: "999".into(),
                author_id: "1".into(),
                reactor_ids: vec!["2".into(), "3".into(), "4".into()],
                author_role_ids: vec![],
                has_attachments: false,
            },
        );
        assert!(ignored.ignored);
        assert!(!ignored.should_publish);

        let image = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: "123".into(),
                author_id: "1".into(),
                reactor_ids: vec!["2".into(), "3".into(), "4".into()],
                author_role_ids: vec![],
                has_attachments: true,
            },
        );
        assert!(image.ignored);
        assert!(image.reason.contains("attachments"));
    }

    #[test]
    fn role_panel_adapter_projects_web_selected_roles() {
        let adapter = feature_adapter("community.role_panels").expect("role panel adapter");
        let config = serde_json::json!({
            "channel": "123456789012345678",
            "roleIds": ["111111111111111111", "222222222222222222"],
            "panelTitle": "Pick your alerts",
            "panelDescription": "Choose what you want to receive.",
            "maxRoles": 2,
            "selectionMode": "unique",
            "removeOnUnselect": true
        });
        assert!(adapter.validate(&config).is_empty());
        assert!(adapter.runtime_projection(&config).contains(&(
            "community.role_panels.role_ids".into(),
            "111111111111111111,222222222222222222".into()
        )));
        assert!(adapter.runtime_projection(&config).contains(&(
            "community.role_panels.selection_mode".into(),
            "unique".into()
        )));
        assert!(
            adapter
                .validate(&serde_json::json!({"roleIds": ["not-a-discord-id"]}))
                .iter()
                .any(|issue| issue.code == "invalid_role_ids")
        );
        assert!(
            adapter
                .validate(&serde_json::json!({"selectionMode": "unbounded"}))
                .iter()
                .any(|issue| issue.code == "invalid_selection_mode")
        );
    }

    #[test]
    fn role_panel_evaluator_matches_unique_and_toggle_rules() {
        let unique = evaluate_role_panel(&RolePanelObservation {
            panel_role_ids: vec![11, 22, 33],
            selected_role_ids: vec![11],
            clicked_role_id: 22,
            selection_mode: "unique".into(),
            remove_on_unselect: true,
        });
        assert!(unique.allowed);
        assert!(unique.assign_clicked);
        assert_eq!(unique.remove_role_ids, vec![11]);
        assert_eq!(unique.reason_code, "role_assigned_unique");

        let removed = evaluate_role_panel(&RolePanelObservation {
            panel_role_ids: vec![11, 22],
            selected_role_ids: vec![22],
            clicked_role_id: 22,
            selection_mode: "multiple".into(),
            remove_on_unselect: true,
        });
        assert!(!removed.assign_clicked);
        assert_eq!(removed.remove_role_ids, vec![22]);

        let kept = evaluate_role_panel(&RolePanelObservation {
            panel_role_ids: vec![11, 22],
            selected_role_ids: vec![22],
            clicked_role_id: 22,
            selection_mode: "multiple".into(),
            remove_on_unselect: false,
        });
        assert_eq!(kept.reason_code, "role_kept");
        assert!(kept.remove_role_ids.is_empty());

        let invalid = evaluate_role_panel(&RolePanelObservation {
            panel_role_ids: vec![11],
            selected_role_ids: vec![],
            clicked_role_id: 99,
            selection_mode: "multiple".into(),
            remove_on_unselect: true,
        });
        assert!(!invalid.allowed);
        assert_eq!(invalid.reason_code, "role_not_in_panel");
    }

    #[test]
    fn role_panel_simulation_uses_the_shared_selection_evaluator() {
        let adapter = feature_adapter("community.role_panels").expect("role panel adapter");
        let effects = adapter.simulate(
            &serde_json::json!({
                "roleIds": ["11", "22"],
                "selectionMode": "unique",
                "removeOnUnselect": true
            }),
            &serde_json::json!({
                "selectedRoleIds": ["11"],
                "clickedRoleId": "22"
            }),
        );
        assert!(effects[0].contains("Assign role 22"));
        assert!(effects[0].contains("Remove first: 11"));
        assert!(effects.iter().any(|effect| {
            effect.contains("community.role_panels.selection_mode") && effect.contains("unique")
        }));
    }

    #[test]
    fn temporary_channel_evaluator_matches_limit_and_name_template() {
        let allowed = evaluate_temp_channel("{user} hangout", "Rexy", 2, 3);
        assert!(allowed.allowed);
        assert_eq!(allowed.room_name, "Rexy hangout");

        let limited = evaluate_temp_channel("{user}'s room", "Rexy", 3, 3);
        assert!(!limited.allowed);
        assert_eq!(limited.reason_code, "active_limit_reached");

        let fallback = evaluate_temp_channel("\u{0000}", "Rexy", 0, 0);
        assert!(fallback.allowed);
        assert_eq!(fallback.max_active, 1);
        assert_eq!(fallback.room_name, "Rexy's room");
    }

    #[test]
    fn temporary_channel_simulation_uses_the_shared_limit_decision() {
        let adapter = feature_adapter("utility.temp_channels").expect("temp channel adapter");
        let effects = adapter.simulate(
            &serde_json::json!({"nameTemplate":"{user} lounge", "maxActive":2}),
            &serde_json::json!({"userName":"Rexy", "activeTempRooms":2}),
        );
        assert!(effects[0].contains("active_limit_reached"));
        assert!(effects.iter().any(|effect| {
            effect.contains("utility.temp_channels.max_active") && effect.contains("2")
        }));
    }

    #[test]
    fn embeds_adapter_projects_safe_visual_defaults() {
        let adapter = feature_adapter("utility.embeds").expect("embeds adapter");
        assert_eq!(adapter.descriptor().source, "embeds_adapter_v2");
        assert!(
            adapter
                .validate(&serde_json::json!({
                    "maxDescription": 1200,
                    "defaultColor": "#5865F2",
                    "defaultFooter": "Vozen Helper"
                }))
                .is_empty()
        );
        assert!(
            adapter
                .validate(&serde_json::json!({"defaultColor": "blue"}))
                .iter()
                .any(|issue| issue.path == "defaultColor")
        );
        let projection = adapter.runtime_projection(&serde_json::json!({
            "maxDescription": 1200,
            "defaultColor": "#5865F2",
            "defaultFooter": "Vozen Helper"
        }));
        assert!(projection.contains(&("utility.embeds.default_color".into(), "#5865F2".into())));
        assert!(projection.contains(&(
            "utility.embeds.default_footer".into(),
            "Vozen Helper".into()
        )));
    }

    #[test]
    fn embed_evaluator_matches_runtime_limits_and_defaults() {
        let config = serde_json::json!({
            "maxDescription": 12,
            "defaultColor": "#5865F2",
            "defaultFooter": "Vozen"
        });
        let ready = evaluate_embed(&config, "  Title  ", "a bounded description", None, None);
        assert!(ready.allowed);
        assert_eq!(ready.title, "Title");
        assert_eq!(ready.description, "a bounded de");
        assert_eq!(ready.color.as_deref(), Some("#5865F2"));
        assert_eq!(ready.footer, "Vozen");

        let invalid = evaluate_embed(&config, "Title", "Description", Some("blue"), None);
        assert!(!invalid.allowed);
        assert_eq!(invalid.reason_code, "invalid_color");

        let adapter = feature_adapter("utility.embeds").expect("embeds adapter");
        let effects = adapter.simulate(
            &config,
            &serde_json::json!({
                "title": "Title",
                "description": "Description",
                "color": "blue"
            }),
        );
        assert!(effects[0].contains("invalid_color"));
    }

    #[test]
    fn privacy_and_help_simulations_use_shared_decisions() {
        let privacy = feature_adapter("management.privacy").expect("privacy adapter");
        let privacy_config = serde_json::json!({
            "allowMemberExport": false,
            "allowMemberErase": true,
            "maxExportBytes": 750000
        });
        let export = privacy.simulate(
            &privacy_config,
            &serde_json::json!({"privacyAction": "export"}),
        );
        assert!(export[0].contains("action_disabled"));
        let erase = privacy.simulate(
            &privacy_config,
            &serde_json::json!({"privacyAction": "erase"}),
        );
        assert!(erase[0].contains("Erase voluntary member data"));
        assert!(erase.iter().any(|effect| {
            effect.contains("management.privacy.max_export_bytes") && effect.contains("750000")
        }));

        let help = feature_adapter("utility.help").expect("help adapter");
        let help_effects = help.simulate(
            &serde_json::json!({"showModules": false, "showDashboard": true}),
            &serde_json::json!({}),
        );
        assert!(help_effects[0].contains("dashboard link"));
        assert!(!help_effects[0].contains("module summary"));
        assert!(help_effects.iter().any(|effect| {
            effect.contains("utility.help.show_modules") && effect.contains("false")
        }));
    }

    #[test]
    fn invite_and_emoji_simulations_use_bounded_inventory_decisions() {
        let invites = feature_adapter("management.invite_tracker").expect("invite adapter");
        let invite_effects = invites.simulate(
            &serde_json::json!({"maxEntries": 2, "includeInviter": false}),
            &serde_json::json!({"inviteCount": 5}),
        );
        assert!(invite_effects[0].contains("Display 2 of 5"));
        assert!(invite_effects.iter().any(|effect| {
            effect.contains("management.invite_tracker.max_entries") && effect.contains("2")
        }));

        let emojis = feature_adapter("utility.emojis").expect("emoji adapter");
        let emoji_effects = emojis.simulate(
            &serde_json::json!({"maxEntries": 3, "animatedOnly": true}),
            &serde_json::json!({"emojiCount": 8, "animatedEmojiCount": 4}),
        );
        assert!(emoji_effects[0].contains("Display 3 of 4"));
        assert!(emoji_effects[0].contains("animated only"));
        assert!(emoji_effects.iter().any(|effect| {
            effect.contains("utility.emojis.animated_only") && effect.contains("true")
        }));
    }

    #[test]
    fn search_simulation_uses_the_same_provider_allowlist_as_runtime() {
        let adapter = feature_adapter("utility.search").expect("search adapter");
        let config = serde_json::json!({
            "maxResults": 3,
            "allowWikipedia": true,
            "allowAniList": false,
            "allowBluesky": true,
            "allowYouTube": false,
            "allowTwitch": false
        });
        let allowed = adapter.simulate(
            &config,
            &serde_json::json!({"searchProvider": "wikipedia", "searchQuery": "rust"}),
        );
        assert!(allowed[0].contains("Search wikipedia"));
        assert!(allowed[0].contains("3 bounded result"));
        let disabled = adapter.simulate(
            &config,
            &serde_json::json!({"searchProvider": "youtube", "searchQuery": "rust"}),
        );
        assert!(disabled[0].contains("provider_disabled"));
    }
}
