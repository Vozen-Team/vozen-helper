//! Stable contracts shared by the bot, API and panel.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const API_VERSION: &str = "v1";
pub const PRODUCT_ID: &str = "vozen-helper";

/// The panel only offers Unicode reactions. Custom emoji references embed a
/// guild-specific ID and would make an exported workflow non-portable.
pub const WORKFLOW_REACTION_MAX_CHARS: usize = 16;

/// Accept one short, visible Unicode reaction and reject Discord's custom
/// emoji syntax, whitespace and control characters. Discord remains the
/// final authority for whether a particular Unicode sequence is a valid
/// reaction, but this shared guard keeps the API, imports and gateway on the
/// same safe contract.
pub fn is_valid_workflow_reaction(raw: &str) -> bool {
    let value = raw.trim();
    let character_count = value.chars().count();
    (1..=WORKFLOW_REACTION_MAX_CHARS).contains(&character_count)
        && !value.is_ascii()
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
        && !value.contains('<')
        && !value.contains('>')
        && !value.contains(':')
}

/// Lifecycle state exposed by the configuration catalogue.  The panel must
/// never infer this state from a boolean toggle: a feature can be configured
/// without having a runtime adapter, or can be temporarily unhealthy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureMaturity {
    Operational,
    Beta,
    Planned,
    Blocked,
    Degraded,
}

/// Operational health is deliberately separate from product maturity. A
/// feature can be released globally while one guild is misconfigured or one
/// provider is temporarily unavailable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureHealthStatus {
    Ready,
    Degraded,
    Misconfigured,
    DependencyDown,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationIssue {
    pub path: String,
    pub code: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureRevision {
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureHealth {
    pub maturity: FeatureMaturity,
    pub status: FeatureHealthStatus,
    pub operational: bool,
    #[serde(default)]
    pub adapter: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    pub issues: Vec<ValidationIssue>,
    pub last_applied_at: Option<DateTime<Utc>>,
}

/// The API and panel consume this descriptor instead of inventing local
/// schemas. The JSON schema is intentionally bounded and UI-oriented; the
/// runtime policy remains typed in `helper-core`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureAdapterDescriptor {
    pub key: String,
    pub source: String,
    pub schema_version: u32,
    pub schema: serde_json::Value,
    pub defaults: serde_json::Value,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureDescriptor {
    pub key: String,
    pub label: String,
    pub description: String,
    pub category: String,
    pub capability: String,
    pub maturity: FeatureMaturity,
    pub configurable: bool,
    pub config_schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureState {
    pub descriptor: FeatureDescriptor,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub revision: FeatureRevision,
    pub health: FeatureHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationResult {
    pub key: String,
    pub would_apply: bool,
    pub issues: Vec<ValidationIssue>,
    pub effects: Vec<String>,
}

/// A bounded, guild-scoped policy for detecting message spam. The policy is
/// independent from Discord so API simulation and the live gateway share the
/// same decision function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AntiSpamPolicy {
    pub flood_count: u32,
    pub window_seconds: u64,
    pub duplicate_limit: u32,
    pub mention_limit: u32,
    pub max_links: u32,
    pub caps_percent: u32,
    pub caps_min_letters: u32,
    pub timeout_seconds: u64,
    pub ignored_channels: Vec<String>,
    pub ignored_roles: Vec<String>,
    pub alert_only: bool,
    pub delete_message: bool,
}

impl Default for AntiSpamPolicy {
    fn default() -> Self {
        Self {
            flood_count: 6,
            window_seconds: 10,
            duplicate_limit: 3,
            mention_limit: 5,
            max_links: 5,
            caps_percent: 80,
            caps_min_letters: 8,
            timeout_seconds: 60,
            ignored_channels: Vec::new(),
            ignored_roles: Vec::new(),
            alert_only: false,
            // Do not silently change the enforcement of existing guilds. New
            // configurations can explicitly opt in to deletion.
            delete_message: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiSpamObservation {
    pub channel_id: String,
    #[serde(default)]
    pub role_ids: Vec<String>,
    pub message_count: u32,
    pub duplicate_count: u32,
    pub mention_count: u32,
    #[serde(default)]
    pub link_count: u32,
    #[serde(default)]
    pub uppercase_letters: u32,
    #[serde(default)]
    pub letter_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiSpamDecision {
    pub ignored: bool,
    pub matched: Vec<String>,
    pub should_act: bool,
    #[serde(default)]
    pub should_delete: bool,
    pub timeout_seconds: u64,
    pub reason: String,
}

/// Curated, moderator-safe backgrounds available to every guild.
pub const RANK_CARD_BACKGROUND_PRESETS: &[(&str, &str)] = &[
    ("aurora-lake", "Aurora Lake"),
    ("neon-rain", "Neon Rain"),
    ("enchanted-forest", "Enchanted Forest"),
    ("desert-ruins", "Desert Ruins"),
    ("coral-cavern", "Coral Cavern"),
    ("sky-islands", "Sky Islands"),
    ("volcanic-forge", "Volcanic Forge"),
    ("moonlit-village", "Moonlit Village"),
    ("starship-hangar", "Starship Hangar"),
    ("lavender-storm", "Lavender Storm"),
    ("crystal-cavern", "Crystal Cavern"),
    ("sakura-shrine", "Sakura Shrine"),
    ("cosmic-nebula", "Cosmic Nebula"),
    ("frost-citadel", "Frost Citadel"),
    ("tropical-lagoon", "Tropical Lagoon"),
    ("clockwork-library", "Clockwork Library"),
];

/// Guild-scoped visual configuration used by the `/rank` card and its panel
/// preview. Keeping this contract shared prevents the API and Discord gateway
/// from silently rendering different defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RankCardConfig {
    pub font: String,
    pub primary_color: String,
    pub text_color: String,
    pub background_color: String,
    pub overlay_opacity: f32,
    pub background_preset: Option<String>,
    /// Kept for wire compatibility with older stored settings. New writes
    /// intentionally reject custom URLs and data URLs in favour of presets.
    pub background_url: Option<String>,
    pub background_data: Option<String>,
    pub avatar_ring_color: String,
    pub avatar_ring_width: u8,
}

impl Default for RankCardConfig {
    fn default() -> Self {
        Self {
            font: "system".into(),
            primary_color: "#8EE5D2".into(),
            text_color: "#F4F7FB".into(),
            background_color: "#101725".into(),
            overlay_opacity: 0.36,
            background_preset: None,
            background_url: None,
            background_data: None,
            avatar_ring_color: "#8EE5D2".into(),
            avatar_ring_width: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuildRef {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Plan {
    Free,
    Plus,
    Premium { guild_limit: u16 },
}

impl Plan {
    pub fn guild_limit(&self) -> u16 {
        match self {
            Self::Free => 1,
            Self::Plus => 1,
            Self::Premium { guild_limit } => *guild_limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementSnapshot {
    pub product: String,
    pub subject_id: String,
    pub plan: Plan,
    pub active: bool,
    pub version: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub fetched_at: DateTime<Utc>,
}

impl EntitlementSnapshot {
    pub fn free(subject_id: impl Into<String>) -> Self {
        Self {
            product: PRODUCT_ID.to_string(),
            subject_id: subject_id.into(),
            plan: Plan::Free,
            active: true,
            version: 0,
            expires_at: None,
            fetched_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionClaims {
    pub session_id: Uuid,
    pub user_id: String,
    pub guild_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageQuota {
    pub key: String,
    pub used: u64,
    pub limit: u64,
    pub resets_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}
